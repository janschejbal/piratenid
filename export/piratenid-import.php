<?php

// TODO: review

// This file needs to be placed on the PiratenID server and requires piratenid-verify.php
// It should be reachable only from the server doing the export and require SSL client certificate authentication
// Suggestion: Deploy as a separate site, listening on a separate port

require_once('piratenid-verify.php');
require_once('piratenid-import-config.php');

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
	
	Rückgabewert: Assoziatives Array mit zwei Werten:
						"valid" (beinhaltet ein Array mit allen aktuell gültigen Token-Hashes)
						"used"  (beinhaltet ein Array mit allen aktuell verwendeten Token-Hashes)
*/
function PiratenIDImport_import($db, $dataarray, $ignorelength = false) {
	if (!$db) die("No database connection");
	if (!is_array($dataarray)) die("Invalid data: data not an array");
	if (empty($dataarray)) die("Invalid data: data is empty");
	if (count($dataarray) < 2) die("Invalid data: less than 2 entries");
	if (!$ignorelength && count($dataarray) < 1000) die("Invalid data: less than 1000 entries, data probably incomplete");
	
	$statsverifier = new PiratenIDImport_StatsVerifier();
	
	$seenTokens = array();
	foreach ($dataarray as $entry) {
		$statsverifier->verifyEntry($entry);
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
		die('Database error: ' . htmlspecialchars($e->getMessage())); // automatic rollback
	}
	
	// Import successful. Write stats.
	global $STATSFILE;
	if (!empty($STATSFILE)) {
		$outfile = fopen($STATSFILE, 'w');
		// htmlspecialchars just to be safe if IE decides to interpret text/plain as HTML - there should never be any special chars, so it doesn't hurt
		fwrite($outfile, htmlspecialchars("Last successful update: ". date('c') . "\n\n"));
		fwrite($outfile, htmlspecialchars("Stats:\n". $statsverifier->getStats() . "\n"));
		fclose($outfile);
	}
	
	try {
		$valid_tokens = $db->query("SELECT token FROM tokens", PDO::FETCH_COLUMN, 0)->fetchAll();
		$used_tokens = $db->query("SELECT token FROM users",  PDO::FETCH_COLUMN, 0)->fetchAll();
		
		$valid_tokens = array_filter($valid_tokens);
		sort($valid_tokens);
		$used_tokens = array_filter($used_tokens);
		sort($used_tokens);
		
		return array('valid' => $valid_tokens, 'used' => $used_tokens);
	} catch (PDOException $e) {
		die('Database error: ' . htmlspecialchars($e->getMessage())); // automatic rollback
	}
}

function PiratenIDImport_importFromPost($db, $ignorelength = false) {
	global $SECRET;
	global $ALLOWED_IP;
	if (empty($SECRET)) die("Server misconfiguration: Token import secret not set");
	if (empty($ALLOWED_IP)) die("Server misconfiguration: Token import IP not set");
	
	if (empty($_SERVER['REQUEST_METHOD'])) die("Cannot be used from command line");
	if ($_SERVER['REQUEST_METHOD'] !== "POST") die("Must use POST");
	if (empty($_SERVER['REMOTE_ADDR'])) die("Server did not provide remote IP");
	if ($_SERVER['REMOTE_ADDR'] !== $ALLOWED_IP) die("IP not authorized for import");
	
	$postdata = file_get_contents('php://input');
	if (strlen($postdata) < 50) die("Invalid data (too short)");
	
	$auth = substr($postdata, 0,32);
	$iv = substr($postdata, 32,16);
	$encrypted = substr($postdata, 48);
	unset($postdata);

	// Derive keys
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
	
	if ($hmac !== hash_hmac('sha256', $json, $key_hmac_raw)) die("Wrong HMAC authentication value");
	
	$data = json_decode($json, true);
	if (empty($data)) die("JSON decode failed");
	
	if ( empty($data['time']) || empty($data['data']) || !is_int($data['time']) || !is_array($data['data']) ) die("Invalid data format");

	$timedelta = time() - $data['time'];
	if (abs($timedelta) > 5*60) die("Data time mismatch (too old or server clocks out of sync)");
	
	$newState = PiratenIDImport_import($db, $data['data'], $ignorelength);
		
	echo "Import successful\n" . json_encode($newState);
}


PiratenIDImport_importFromPost(getDatabaseImportPDO(), $TESTING);

/* Example:

$db = new PDO('mysql:dbname=piratenid;host=127.0.0.1', "root", "");
$data = array(
		array(hash('sha256','a'), 'ja', 'Hessen', '---', 'Frankfurt am Main', '', 'ja'),
		array(hash('sha256','b'), 'nein', 'land', 'bezirk', 'kreis', 'ort', 'nein'),
	);

// Remove "true" for production use!
PiratenIDImport_import($db, $data, true); 

*/

