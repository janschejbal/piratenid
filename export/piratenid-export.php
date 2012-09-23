<?php

// TODO: review

// This file needs to be placed on the system doing the export and requires piratenid-verify.php
// Remember to update the secret in both this file and piratenid-import.php on the server receiving the import!

//   USE ONLY ON A PROTECTED, INTERNAL NETWORK! The encryption is an additional security feature.

require_once('piratenid-verify.php');
require_once('piratenid-export-config.php');

function PiratenIDImport_mapNulls(&$var) {
	if (empty($var)) return ''; // fix false/null etc.
	if ($var = "NULL") return ''; // fix string "NULL"
	return $var;
}

if (!empty($_SERVER['REQUEST_METHOD'])) die("This is not a web script. Run it from the command line!");

$statLVs = PiratenIDImport_getLVs();

// Fetch data
$pdo = new PDO($SOURCEPDO, $SOURCEUSER, $SOURCEPASS) or PiratenIDImport_err("Could not connect to data source");

// String concatenation in SQL and no way around it... strict checking of the table name first!
if (!preg_match('/^[a-zA-Z0-9_-]{1,100}/D', $SOURCETABLE)) PiratenIDImport_err("Invalid table name (validation with regexp failed)"); 
if (!preg_match('/^[a-zA-Z0-9_-]{1,100}/D', $COLUMN_TOKEN)) PiratenIDImport_err("Invalid token column name (validation with regexp failed)"); // MSSQL doesn't like variable ORDER BY colums
$statement = $pdo->prepare('SELECT * FROM ['.$SOURCETABLE.'] ORDER BY ['.$COLUMN_TOKEN.']') or PiratenIDImport_err("Could not prepare query");
if ($statement->execute()) {
	$input_data = $statement->fetchAll(PDO::FETCH_ASSOC);
} else {
	$err = $statement->errorInfo();
	PiratenIDImport_err("Could not fetch data: " . $err[2]);
}

if (empty($input_data)) PiratenIDImport_err("Could not fetch data - empty data set received");
if (count($input_data) < 2) die("Invalid data: less than 2 entries");

// Convert data
$output_data = array();
$statsverifier = new PiratenIDImport_StatsVerifier();

foreach ($input_data as $entry) {
	if (empty($entry[$COLUMN_TOKEN])) PiratenIDImport_err("Missing field: token");
	if (!isset($entry[$COLUMN_LAND])) PiratenIDImport_err("Missing field: USER_LV");
	if (!isset($entry[$COLUMN_STIMMBERECHTIGT])) PiratenIDImport_err("Missing field: stimmberechtigt");
	
	$token = $entry[$COLUMN_TOKEN];
	$mitgliedschaft_bund   = 'ja';
	$mitgliedschaft_land   = $entry[$COLUMN_LAND];
	$mitgliedschaft_bezirk = $COLUMN_BEZIRK ? PiratenIDImport_mapNulls($entry[$COLUMN_BEZIRK]) : '';
	$mitgliedschaft_kreis  = $COLUMN_KREIS  ? PiratenIDImport_mapNulls($entry[$COLUMN_KREIS])  : '';
	$mitgliedschaft_ort    = $COLUMN_ORT    ? PiratenIDImport_mapNulls($entry[$COLUMN_ORT])   : '';
	$stimmberechtigt       = (($entry[$COLUMN_STIMMBERECHTIGT] == 1) ? 'ja' : 'nein');
	
	$out_entry = array($token, $mitgliedschaft_bund, $mitgliedschaft_land, $mitgliedschaft_bezirk, $mitgliedschaft_kreis, $mitgliedschaft_ort, $stimmberechtigt);
	$statsverifier->verifyEntry($out_entry);
	$output_data[] = $out_entry;
}

unset($input_data); // conserve memory

$json = json_encode(array("time" => time(), "data" => $output_data));
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
					)
			)
		);

$result = file_get_contents($TARGETURL, false, $context);

echo "Server response:\n-------------------------------\n";
echo $result;
echo "\n-------------------------------\n";

if ($result === "Import successful") {
	echo "Looks like the import was successful!\n\n";
	echo "Stats:\n";
	echo $statsverifier->getStats();
} else {
	echo "Looks like the import failed!";
	exit(1);
}
