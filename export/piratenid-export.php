<?php

// TODO: Self-review, Fremd-review

// This file needs to be placed on the system doing the export and requires piratenid-verify.php
// Remember to update the secret in both this file and piratenid-import.php on the server receiving the import!

//   USE ONLY ON A PROTECTED, INTERNAL NETWORK!
//   The encryption is an additional security feature. It does NOT prevent against replay attacks!
//   (i.e. if an attacker get a copy of a valid request, AND can send data to the import script,
//   he can send the same data again and the importer will import the old data)


/// CONFIG ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Shared secret for encrypting and authenticating token imports - needs to match secret in piratenid-import.php
// If compromised, replace with new random value in export and import file and re-import token table
$SECRET = "7EbkyTL7N0npJhc4Gv2oXvm4mhDyYXk8cTMg2fa1bcOiiun3Xh7l5YsNNqw0";

// Source Excel file for export data (full path, remember that backslashes need to be doubled)
$SOURCEFILE = 'C:\\Users\\Jan\\Documents\\Projekte\\piratenpartei\\piratenid\\export\\piratenidtest.xlsx';

// maximum age of the source file in seconds
$MAXAGE = 10*60*60;

// URL of the piratenid-import.php script that should receive the export data (internal network only!)
$TARGETURL = 'http://127.0.0.1:80/testimport.php'; 

/// END OF CONFIG ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////






require_once('piratenid-verify.php');
$statLVs = PiratenIDImport_getLVs();

// make sure errors are fatal
error_reporting(E_ALL & E_STRICT);
function fatalErrors($errno, $errstr) { PiratenIDImport_err("Fehler $errno:\n$errstr\n"); }
set_error_handler("fatalErrors");


// check source file
if (!is_file($SOURCEFILE)) PiratenIDImport_err('missing source file');
if (filemtime($SOURCEFILE) < (time() - $MAXAGE)) PiratenIDImport_err('source data too old');


// Fetch table name
$odbc = odbc_connect("Driver={Microsoft Excel Driver (*.xls, *.xlsx, *.xlsm, *.xlsb)};DBQ=".$SOURCEFILE, "", "") or PiratenIDImport_err("Could not open data source");
$tablelist = odbc_tables($odbc) or PiratenIDImport_err("Could not query tables");
$tablearr = odbc_fetch_array($tablelist) or PiratenIDImport_err("Could not get table info");
odbc_close($odbc);
if (empty($tablearr['TABLE_NAME'])) PiratenIDImport_err("Table name not found");
$tablename = $tablearr['TABLE_NAME'];


// Fetch data
$pdo = new PDO("odbc:Driver={Microsoft Excel Driver (*.xls, *.xlsx, *.xlsm, *.xlsb)};DBQ=".$SOURCEFILE) or PiratenIDImport_err("Could not connect to data source");
// String concatenation in SQL and no way around it... strict checking of the table name first!
if (!preg_match('/^[a-zA-Z0-9_-]{1,28}\\$$/D', $tablename)) PiratenIDImport_err("Invalid table name");
$statement = $pdo->prepare('SELECT * FROM ['.$tablename.'] ORDER BY user_token') or PiratenIDImport_err("Could not prepare query");
if ($statement->execute()) {
	$input_data = $statement->fetchAll(PDO::FETCH_ASSOC);
} else {
	$err = $statement->errorInfo();
	PiratenIDImport_err("Could not fetch data: " . $err[2]);
}

if (empty($input_data)) PiratenIDImport_err("Could not fetch data - empty data set received");
if (empty($input_data)) PiratenIDImport_err("Could not fetch data - empty data set received");
if (count($input_data) < 2) die("Invalid data: less than 2 entries");

// Convert data
$output_data = array();
$count_total = array();
$count_stimmberechtigt = array();

foreach ($statLVs as $lv) {
	$count_total[$lv] = 0;
	$count_stimmberechtigt[$lv] = 0;
}

foreach ($input_data as $entry) {
	if (empty($entry['user_token'])) PiratenIDImport_err("Missing field: user_token");
	if (empty($entry['USER_LV'])) PiratenIDImport_err("Missing field: USER_LV");
	if (empty($entry['USER_Stimmberechtigt'])) PiratenIDImport_err("Missing field: USER_Stimmberechtigt");
	
	$token = $entry['user_token'];
	$mitgliedschaft_bund   = 'ja';
	$mitgliedschaft_land   = $entry['USER_LV'];
	$mitgliedschaft_kreis  = '';
	$mitgliedschaft_bezirk = '';
	$mitgliedschaft_ort    = '';
	$stimmberechtigt       = (($entry['USER_Stimmberechtigt'] == -1) ? 'ja' : 'nein');
	$out_entry = array($token, $mitgliedschaft_bund, $mitgliedschaft_land, $mitgliedschaft_kreis, $mitgliedschaft_bezirk, $mitgliedschaft_ort, $stimmberechtigt);
	PiratenIDImport_verifyEntry($out_entry);
	$output_data[] = $out_entry;
	
	$count_total[$mitgliedschaft_land]++;
	if ($stimmberechtigt === 'ja') $count_stimmberechtigt[$mitgliedschaft_land]++;
}

unset($input_data); // conserve memory

$json = json_encode($output_data);
unset($output_data); // conserve memory

// Derive keys
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
	foreach ($statLVs as $lv) {
		$statLVstr = $lv;
		if ($statLVstr === '') $statLVstr = 'XX';
		printf(" | $statLVstr = %6d | $statLVstr-stimmberechtigt = %6d\n", $count_total[$lv], $count_stimmberechtigt[$lv]);
	}
} else {
	echo "Looks like the import failed!";
	exit(1);
}
