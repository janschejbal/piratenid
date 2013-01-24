<?php

// TODO: 3rd-party-review

// This file needs to be placed on the system doing the export and requires piratenid-verify.php
// Remember to update the secret in both this file and piratenid-import.php on the server receiving the import!

// This script exports token data from SAGE to PiratenID.
// The token state as reported by the server is output to the feedback table and can be used to determine whether a token may be re-issued.
// The "active" flag in the feedback table means the token has been sent (or will be sent very shortly) to the server.
// (If an update fails, this flag stays on until a successful update resets it to its correct value.)
// The "used" flag indicates whether the token has already been used on the server. As used tokens are never removed, it will never be unset once it is set.
// You may create a new token for a user ("re-issue the token") if AND ONLY IF both flags are false (or there is no entry for that token in the table).
// Use an atomic operation to check the flags and update the token colum! (e.g. UPDATE data SET token = NULL WHERE reset_pending = 1 AND active = 0 AND used = 0)

// Data is fetched from a MSSQL database via PDO/ODBC.
// A DB-based application lock prevents multiple instances of this script from running.
// Before fetching the token data, an exclusive table lock is applied to the token feedback table (which contains token active/used flags).
// All tokens which will be sent to the server are marked as active in the feedback table
// Only then are the tokens actually sent to the ID server.
// If the import is successful, the server responds with a list of active tokens (identical to the submitted token list) and a list of used tokens.
// (Note that the used token list may contain outdated tokens no longer on the active token list!)
// This script then updates the feedback table to match the active/used state reported by the server.

// Locking the feedback table before reading token data prevents the following scenario:
//   A new token is being sent to the server. A re-issue request for this token is pending.
//   The export script reads the token and is planning to set the active flag to true before sending it to the server
//   Now, the re-issue script sees the re-issue request, the still "false" active flag (this is what the lock prevents), and reissues the token
//   The export script activates the old token, as it has already obtained it



require_once('piratenid-verify.php');
require_once('piratenid-export-config.php');


function PiratenIDImport_mapNulls(&$var) {
	if (empty($var)) return ''; // fix false/null etc.
	if ($var = "NULL") return ''; // fix string "NULL"
	return $var;
}

// Shows the last DB error together with the given message and terminates the programm
function dbError($msg, $statement = null) {
	global $pdo;
	$errorsource = (empty($statement)? $pdo : $statement);
	if (!empty($errorsource)) {
		$errorinfo = $errorsource->errorInfo();
		$err = (empty($errorinfo[2]))? "no error info" : $errorinfo[2];
		PiratenIDImport_err($msg .": ". $err);
	} else {
		PiratenIDImport_err($msg .": ". "no database PDO");
	}
}

if (!empty($_SERVER['REQUEST_METHOD'])) PiratenIDImport_err("This is not a web script. Run it from the command line!");
if (strncmp ($TARGETURL, 'https://', 8) != 0) PiratenIDImport_err("Target URL must use HTTPS");

// Fetch data
$pdo = new PDO($SOURCEPDO, $SOURCEUSER, $SOURCEPASS) or PiratenIDImport_err("Could not connect to data source");

if ($pdo->exec("SET NOCOUNT ON") === false) dbError("Failed to disable row count reporting");

// Use applock to prevent multiple instances from running and causing nasty race conditions (which might allow active codes to be reset!)
$lockresult = "FAIL"; // ensure failure is interpreted as failure to obtain lock
$statement = $pdo->prepare("EXEC ? = sp_getapplock 'PiratenIDUpdaterLock', 'Exclusive', 'Session', 0") or dbError("Cannot prepare lock statement");
$statement->bindParam(1, $lockresult, PDO::PARAM_STR, 32) or dbError("Cannot bind lock result variable", $statement);
$statement->execute() or dbError("Failed to execute lock request", $statement);
$statement->fetchAll(); // may be needed for MSSQL, discard results, the interesting info is in the bound variable
if ($lockresult !== "0") {
	PiratenIDImport_err("Failed to obtain applock - is another instance running? (Code: $lockresult)");
}
echo "DB connection established, application lock obtained.\n";

// String concatenation in SQL and no way around it... strict checking of the table name first (even if they come from config)!
$dbElementRegexp = '/^[a-zA-Z0-9]{1,100}/D';
if (!preg_match($dbElementRegexp, $SOURCETABLE)) PiratenIDImport_err("Invalid table name (validation with regexp failed)"); 
if (!preg_match($dbElementRegexp, $COLUMN_TOKEN)) PiratenIDImport_err("Invalid token column name (validation with regexp failed)"); // MSSQL doesn't like variable ORDER BY colums, we will have to build the query manually
// Used later when writing to the feedback table, verify now:
if (!preg_match($dbElementRegexp, $FEEDBACKTABLE)) PiratenIDImport_err("Invalid table name (validation with regexp failed)"); 
if (!preg_match($dbElementRegexp, $COLUMN_FEEDBACK_TOKEN)) PiratenIDImport_err("Invalid token column name (validation with regexp failed)");
if (!preg_match($dbElementRegexp, $COLUMN_FEEDBACK_ACTIVE)) PiratenIDImport_err("Invalid token column name (validation with regexp failed)");
if (!preg_match($dbElementRegexp, $COLUMN_FEEDBACK_USED)) PiratenIDImport_err("Invalid token column name (validation with regexp failed)");

// Lock table for initial update using a dummy statement
$pdo->beginTransaction() or dbError("Failed to start transaction for pre-update"); // transaction ends after tokens have been pre-marked as active
$statement = $pdo->prepare('SELECT * FROM ['.$FEEDBACKTABLE.'] WITH (HOLDLOCK, TABLOCKX) WHERE 1=2') or dbError('Could not prepare pre-update lock statement');
$statement->execute() or dbError("Could not execute pre-update lock statement", $statement);

$statement = $pdo->prepare('SELECT * FROM ['.$SOURCETABLE.'] ORDER BY ['.$COLUMN_TOKEN.']') or dbError("Could not prepare data query");
$statement->execute() or dbError("Could not fetch data", $statement);
$input_data = $statement->fetchAll(PDO::FETCH_ASSOC);

if (empty($input_data)) PiratenIDImport_err("Could not fetch data - empty data set received");
if (count($input_data) < 2) PiratenIDImport_err("Invalid data: less than 2 entries");

// Convert data
$output_data = array();
$statsverifier = new PiratenIDImport_StatsVerifier();

$sent_tokens = array();

foreach ($input_data as $entry) {
	if (empty($entry[$COLUMN_TOKEN])) PiratenIDImport_err('Missing token field. Check value of $COLUMN_TOKEN.');
	if (!isset($entry[$COLUMN_LAND])) PiratenIDImport_err('Missing "Land" field. Check value of $COLUMN_LAND.');
	if (!isset($entry[$COLUMN_STIMMBERECHTIGT])) PiratenIDImport_err('Missing "stimmberechtigt" field. Check value of $COLUMN_STIMMBERECHTIGT.');
	
	$token = $entry[$COLUMN_TOKEN];
	$mitgliedschaft_bund   = 'ja';
	$mitgliedschaft_land   = $entry[$COLUMN_LAND];
	$mitgliedschaft_bezirk = $COLUMN_BEZIRK ? PiratenIDImport_mapNulls($entry[$COLUMN_BEZIRK]) : '';
	$mitgliedschaft_kreis  = $COLUMN_KREIS  ? PiratenIDImport_mapNulls($entry[$COLUMN_KREIS])  : '';
	$mitgliedschaft_ort    = $COLUMN_ORT    ? PiratenIDImport_mapNulls($entry[$COLUMN_ORT])   : '';
	$stimmberechtigt       = (($entry[$COLUMN_STIMMBERECHTIGT] == 1) ? 'ja' : 'nein');
	
	$sent_tokens[] = $token;
	
	$out_entry = array($token, $mitgliedschaft_bund, $mitgliedschaft_land, $mitgliedschaft_bezirk, $mitgliedschaft_kreis, $mitgliedschaft_ort, $stimmberechtigt);
	$statsverifier->verifyEntry($out_entry);
	$output_data[] = $out_entry;
	$output_hash = $statsverifier->getStateHash();
}

unset($input_data); // conserve memory

// Mark the exported tokens as active before sending to server.
// This ensures that they cannot be re-issued and leads to a safe state (token will not be reissued) if the script fails after this point.
// Once the script completes, the table will be cleared and replaced with the updated values
$statement = $pdo->prepare(
		''.
		'UPDATE ['.$FEEDBACKTABLE.'] SET ['.$COLUMN_FEEDBACK_ACTIVE.'] = 1 WHERE ['.$COLUMN_FEEDBACK_TOKEN.'] = ? '.
		'IF (@@ROWCOUNT = 0 ) BEGIN '.
			'INSERT INTO ['.$FEEDBACKTABLE.'] (['.$COLUMN_FEEDBACK_TOKEN.'], ['.$COLUMN_FEEDBACK_ACTIVE.'], ['.$COLUMN_FEEDBACK_USED.']) VALUES(?, 1, 0) '.
		'END'
	) or dbError("Could not prepare pre-update statement");

foreach ($sent_tokens as $token) {
	$statement->execute(array($token, $token)) or dbError("Could not execute pre-update statement", $statement);
	$statement->closeCursor();
}

// Commit and release lock
$pdo->commit() or dbError("Failed to commit pre-update");


$json = json_encode(array("time" => time(), "data" => $output_data, "datahash" => $output_hash));
unset($output_data); // conserve memory

// Derive keys
if (empty($SECRET)) PiratenIDImport_err("no secret for key derivation");
$key_crypto_raw = hash('sha256', 'crypto|'.$SECRET, true); // encryption key
$key_hmac_raw = hash('sha256', 'hmac|'.$SECRET, true);     // HMAC integrity key
$key_auth_raw = hash('sha256', 'auth|'.$SECRET, true);    // Auth token
if (strlen($key_crypto_raw) != 32 || strlen($key_hmac_raw) != 32 || strlen($key_auth_raw) != 32 ) PiratenIDImport_err("Key derivation failed");


// generate secure IV
$strong = false;
$iv_raw = openssl_random_pseudo_bytes(16, $strong);
if (strlen($iv_raw) != 16 || !$strong) PiratenIDImport_err("IV generation failed");

// Calculate HMAC
$hmac_hex = hash_hmac('sha256', $json, $key_hmac_raw, false);
if (strlen($hmac_hex) != 64) PiratenIDImport_err("HMAC calculation failed");

// Encrypt
$encrypted = openssl_encrypt($hmac_hex.$json, 'aes-256-cbc' , $key_crypto_raw, true, $iv_raw);
if ($encrypted === false) PiratenIDImport_err("Encryption failed");
unset($json); // conserve memory

// Send

$context = stream_context_create(
			array(
				'http' =>
					array(
						'method'  => 'POST',
						'ignore_errors' => true,
						'header' => 'Content-type: application/octet-stream',
						'content' => $key_auth_raw.$iv_raw.$encrypted,
						'timeout'  => 30
					),
				'ssl' =>
					array(
						'verify_peer' => true,
						'cafile' => $SERVER_CERT,
						'local_cert' => $CLIENT_CERT,
					)
			)
		);

$result = file_get_contents($TARGETURL, false, $context);


$result_parts = explode("\n", $result, 2);

if ($result_parts[0] === "Import successful") {
	echo "Server reported successful import.\n\n";
	echo "Stats:\n";
	echo $statsverifier->getStats();
} else {
	echo "Server response:\n-------------------------------\n";
	echo $result;
	echo "\n-------------------------------\n";
	PiratenIDImport_err("Looks like the import failed.");
}

$newState = json_decode($result_parts[1], true);

if (!is_array($newState) || empty($newState['valid']) || empty($newState['used'])) {
	PiratenIDImport_err("Invalid newState; some tokens marked active in the feedback table may be inactive (but not the other way around)");
}

$validTokens = $newState['valid'];
$usedTokens = $newState['used'];
if (count(array_diff($newState['valid'], $sent_tokens)) !== 0 || count(array_diff($sent_tokens, $newState['valid'])) !== 0) { // check BOTH ways, array_diff only checks one direction!
	PiratenIDImport_err("Sent tokens do not match returned token list. Aborting.");
}

$data = array();
foreach ($validTokens as $token) $data[$token]['valid'] = true;
foreach ($usedTokens as $token)  $data[$token]['used']  = true;

$pdo->beginTransaction() or dbError("Could not start PDO transaction to write feedback; some tokens marked active in the feedback table may be inactive (but not the other way around)");
// Table and column names verified above
if ($pdo->exec('DELETE FROM ['.$FEEDBACKTABLE.'] WITH (HOLDLOCK, TABLOCKX)') === false) dbError("Failed to clear feedback table");
$statement = $pdo->prepare(
		'INSERT INTO ['.$FEEDBACKTABLE.'] (['.$COLUMN_FEEDBACK_TOKEN.'],['.$COLUMN_FEEDBACK_ACTIVE.'],['.$COLUMN_FEEDBACK_USED.']) VALUES (?,?,?)'
	) or dbError("could not prepare feedback INSERT");
// bind params, then loop and execute
$statement->bindParam(1, $token,   PDO::PARAM_STR);
$statement->bindParam(2, $isValid, PDO::PARAM_INT);
$statement->bindParam(3, $isUsed,  PDO::PARAM_INT);
foreach ($data as $token => $state) {
	// Check exact length with binary-safe function to prevent attacks with null bytes etc.
	if (!is_string($token) || strlen($token) !== 64 || !preg_match('/^[a-f0-9]{64}$/D', $token)) PiratenIDImport_err("INVALID TOKEN REPORTED FROM ID SERVER");
	$isValid = empty($state['valid']) ? 0 : 1;
	$isUsed  = empty($state['used'])  ? 0 : 1;
	$statement->execute() or dbError("Failed to insert into feedback table", $statement);
}
$pdo->commit() or dbError("Could not commit");


if ($pdo->exec("EXEC sp_releaseapplock 'PiratenIDUpdaterLock', 'Session'") === false) dbError("Failed to release applock");


echo "\nEverything OK, export finished.\n";
exit(0);