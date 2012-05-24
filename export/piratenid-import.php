<?php

// TODO: Self-review, Fremd-review

// This file needs to be placed on the PiratenID server and requires piratenid-verify.php
// It should be reachable only from the server doing the export
// Suggestion: Deploy as a separate site, listening on a separate port


/// CONFIG ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Shared secret for encrypting and authenticating token imports - needs to match secret in piratenid-export.php
// If compromised, replace with new random value in export and import file and re-import token table
$SECRET = "7EbkyTL7N0npJhc4Gv2oXvm4mhDyYXk8cTMg2fa1bcOiiun3Xh7l5YsNNqw0";

$ALLOWED_IP = '127.0.0.1'; // IP from which tokens will be imported. Only this IP will be allowed to request token imports

function getDatabaseImportPDO() { // Database login data for token import
	return new PDO('mysql:dbname=piratenid;host=127.0.0.1', "root", "");
}

/// END OF CONFIG ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////







error_reporting(E_ALL & E_STRICT);
function fatalErrors($errno, $errstr) { die("Fehler $errno:\n$errstr\n"); }
set_error_handler("fatalErrors");


// verifies an entry (single row)
// function "err($errormessage)" needs to be defined!
function PiratenIDImport_verifyEntry($entry) {
	if (!is_array($entry)) die("Invalid data: entry not an array");
	if (count($entry) != 7) die("Invalid data: wrong number of values");
	for ($i = 0; $i<7; $i++) {
		if (!is_string($entry[$i])) die("Invalid data: value not a string");
		if (strlen($entry[$i]) > 100) die("Invalid data: value too long");
		if (strpos($entry[$i], "\xC3\x83") !== false) die("Invalid data: looks like double UTF-8 encoding");
		if (!mb_detect_encoding($entry[$i], 'UTF-8', true)) die("Invalid data: value not UTF-8");
		if (!mb_check_encoding($entry[$i], 'UTF-8')) die("Invalid data: invalid UTF-8 sequence");
		
	}
	
	if (!preg_match('/^[a-f0-9]{64}$/D', $entry[0])) die("Invalid data: invalid token value");
	if ($entry[0] == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') die("Invalid data: Token is hash of empty string");
	
	
	if ($entry[1] !== 'ja' && $entry[1] !== 'nein') die("Invalid data: mitgliedschaft-bund must be either 'ja' or 'nein'");
	if (!in_array($entry[2], array('', 'BW', 'BY', 'BE', 'BB', 'HB', 'HH', 'HE', 'MV', 'NI', 'NW', 'RP', 'SL', 'SN', 'ST', 'SH', 'TH') ,true)) {
		die("Invalid data: value for mitgliedschaft-land is not in whitelist");
	}
	if ($entry[6] !== 'ja' && $entry[6] !== 'nein' && $entry[6] !== '') die("Invalid data: stimmberechtigt must be 'ja', 'nein' or empty string");
}

/*	
	PiratenIDImport_import($db, $dataarray, $ignorelength = false): Importiert Token-Daten in PiratenID
		$db: Datenbank-PDO mit ausreichenden Zugriffsrechten
		$dataarray: Die zu importierenden Daten als array von arrays. Jedes sub-array hat folgendes Format:
				[0] => SHA256-Hash des Tokens (Hex-String, Kleinbuchstaben)
				[1] => mitgliedschaft-bund - String, der die Piratenmitgliedschaft (Bundesebene) anzeigt. Entweder "ja" oder "nein".
				[2] => mitgliedschaft-land
				[3] => mitgliedschaft-bezirk
				[4] => mitgliedschaft-kreis
				[5] => mitgliedschaft-ort
				[6] => stimmberechtigt -  String, der die Stimmberechtigung anzeigt. Entweder "ja" oder "nein" oder leer (unbekannt).
			Die Strings dürfen eine Länge von 100 Byte nicht überschreiten und müssen UTF8-kodiert sein.
			Ist eine Angabe nicht bekannt, so muss in einem Feld ein leerer String übergeben werden.
			Ist bekannt, dass ein Pirat auf der jeweiligen Ebene in keinem Verband Mitglied ist,
			so muss der entsprechende String "---" (drei normale Bindestriche) lauten.
			Es ist sicherzustellen, dass alle Mitglieder eines Verbands den gleichen Bezeichner eingetragen bekommen,
			d.h. es darf nicht vorkommen, dass bei einem Mitglied des Kreisverbands Frankfurt am Main z. B. der Wert
			"KV Frankfurt" und bei einem anderen "KV Frankfurt am Main" eingetragen ist.
			Die Verbandsbezeichnungen dürfen nicht geändert werden. Würde beispielsweise der "KV Frankfurt" in
			"KV Frankfurt am Main" umbennant, könnte dies dazu führen, dass eine Anwednung Mitgliedern des
			"KV Frankfurt am Main" Zugriff auf einen Bereich verweigert, weil dieser nur für Mitglieder des "KV Frankfurt"
			zugänglich ist.
		$ignorelength: Zum Testen mit kleinen Datensätzen auf "true" setzen.
			Ist dieser Wert false oder nicht gesetzt, wird ein Import abgelehnt, wenn weniger als 1000 Datensätze geliefert werden.
			Dies soll verhindern, dass durch einen defekten Import die Token-Datenbank gelöscht wird.
*/
function PiratenIDImport_import($db, $dataarray, $ignorelength = false) {
	if (!$db) die("No database connection");
	if (!is_array($dataarray)) die("Invalid data: data not an array");
	if (empty($dataarray)) die("Invalid data: data is empty");
	if (count($dataarray) < 2) die("Invalid data: less than 2 entries");
	if (!$ignorelength && count($dataarray) < 1000) die("Invalid data: less than 1000 entries, data probably incomplete");
	
	$seenTokens = array();
	foreach ($dataarray as $entry) {
		PiratenIDImport_verifyEntry($entry);
		if (array_key_exists($entry[0], $seenTokens)) die("Invalid data: DUPLICATE TOKEN - SOMETHING IS *SERIOUSLY* WRONG");
		$seenTokens[$entry[0]] = 1;
	}
	
	try {
		$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
		$db->exec("SET sql_mode = TRADITIONAL");
		$db->exec("SET NAMES 'utf8'");
		
		$db->beginTransaction(); // "die()" will now cause an automatic rollback
		$numDeleted = $db->exec("DELETE FROM tokens"); // Empty table. "TRUNCATE" not used due to transaction incompatibility.
		
		$statement = $db->prepare(
				"INSERT INTO tokens (`token`, `mitgliedschaft-bund`, `mitgliedschaft-land`, `mitgliedschaft-bezirk`, `mitgliedschaft-kreis`, `mitgliedschaft-ort`, `stimmberechtigt`) VALUES (?,?,?,?,?,?,?)"
			);
		
		foreach ($dataarray as $entry) { // entry has exactly the order required by the SQL statement
			$statement->execute($entry);
		}
		
		$db->commit();
		
	} catch (PDOException $e) {
		die('Database error: ' . $e->getMessage()); // automatic rollback
	}
}

function PiratenIDImport_importFromPost($db, $ignorelength = false) {
	global $SECRET;
	global $ALLOWED_IP;
	if (empty($SECRET)) die("Server misconfiguration: Token import secret not set");
	if (empty($ALLOWED_IP)) die("Server misconfiguration: Token import IP not set");
	
	if (empty($_SERVER['REQUEST_METHOD'])) die("Cannot be used from command line");
	if ($_SERVER['REQUEST_METHOD'] !== "POST") die("Must use POST");
	if ($_SERVER['REMOTE_ADDR'] !== $ALLOWED_IP) die("IP not authorized for import");
	
	$postdata = file_get_contents('php://input');
	if (strlen($postdata) < 50) die("Invalid data (too short)");
	
	$auth = substr($postdata, 0,32);
	$iv = substr($postdata, 32,16);
	$encrypted = substr($postdata, 48);
	unset($postdata);

	$key_crypto_raw = hash('sha256', 'crypto|'.$SECRET, true); // encryption key
	$key_hmac_raw = hash('sha256', 'hmac|'.$SECRET, true);     // HMAC integrity key
	$key_auth_raw = hash('sha256', 'auth|'.$SECRET, true);    // Authentication token
	if (strlen($key_crypto_raw) != 32 || strlen($key_hmac_raw) != 32 || strlen($key_auth_raw) != 32 ) die("Key derivation failed");
	
	if ($key_auth_raw !== $auth) die("Invalid authorization");
	
	$decrypted = openssl_decrypt($encrypted, 'aes-256-cbc' , $key_crypto_raw, true, $iv);
	if ($decrypted === false) die("Decryption failed");
	unset($encrypted); // conserve memory
	
	$hmac = substr($decrypted, 0, 64);
	$json = substr($decrypted, 64);
	if (!$json) die("Parsing failed");
	unset($decrypted); // conserve memory
	
	if ($hmac != hash_hmac('sha256', $json, $key_hmac_raw)) die("Wrong HMAC authentication value");
	
	$data = json_decode($json);
	PiratenIDImport_import($db, $data, $ignorelength);
	echo "Import successful";
}

PiratenIDImport_importFromPost(getDatabaseImportPDO(), true); // TODO Remove "true" for production use!

/* Example:

$db = new PDO('mysql:dbname=piratenid;host=127.0.0.1', "root", "");
$data = array(
		array(hash('sha256','a'), 'ja', 'Hessen', '---', 'Frankfurt am Main', '', 'ja'),
		array(hash('sha256','b'), 'nein', 'land', 'bezirk', 'kreis', 'ort', 'nein'),
	);

// Remove "true" for production use!
PiratenIDImport_import($db, $data, true); 

*/

