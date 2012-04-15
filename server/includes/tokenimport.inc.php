<?PHP

die("DO NOT USE - contains totally untested functions. import will probably have to be done differently anyways");



/*

This code needs the following additions to siteconstants.inc.php - WARNING, CSV/POST IMPORT UNTESTED!
	
#########################################################################################################################	
// SHA256 hash of key required to perform token imports.
// If key is compromised, replace with new random value and re-import token table
$tokenimport_key = "6b1382dd00b77cd2dd40688f03f7093753be09ab88ad5f23171fe867144bdf97"; // Jzbj8CfJ1nGLZxAByRca

// Key for authenticating token imports using HMAC
// If key is compromised, replace with new random value and re-import token table
$tokenimport_hmac_key = "adhzbxHFTInvMM7zn8jBxfI9VR5moVRzX6Yj5tpIB3piBNHPy3adIeUq1Cq7";

// IP from which tokens will be imported. Only this IP will be allowed to request token imports
$tokenimport_ip = "127.0.0.1";

// Database login data for token import - change if regular DB user has insufficient permissions
function getDatabaseImportPDO() {
	return getDatabasePDO();
}

#########################################################################################################################	


*/








/*
	Diese Datei bietet eine Funktion "PiratenIDImport_import" für den Datenimport in PiratenID.
	
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

// verifies an entry (single row)
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
	if ($entry[6] !== 'ja' && $entry[6] !== 'nein' && $entry[6] !== '') die("Invalid data: stimmberechtigt must be 'ja', 'nein' or empty string");
}

// see top for doc
function PiratenIDImport_import($db, $dataarray, $ignorelength = false) {
	if (!$db) die("No database connection");
	if (!is_array($dataarray)) die("Invalid data: data not an array");
	if (empty($dataarray)) die("Invalid data: data is empty");
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


// completely untested and abandoned for now, as this is probably not a realistic way to do imports
function PiratenIDImport_importCSV($csv) {
	die("abandoned function");
	$csv = str_replace("\r\n","\n",$csv); // normalize line endings
	$lines = explode("\n", $csv);
	$data = array();
	foreach ($lines as $line) {
		if (empty($line)) continue;
		$cells = explode("\t", $line);
		$data[] = $cells;
	}
	PiratenIDImport_import($data);
}

// completely untested and abandoned for now, as this is probably not a realistic way to do imports
function PiratenIDImport_importFromPost() {
	die("abandoned function");
	global $tokenimport_key;
	global $tokenimport_hmac_key;
	global $tokenimport_ip;
	if (empty($tokenimport_key)) die("Server misconfiguration: Token import key not set");
	if (empty($tokenimport_hmac_key)) die("Server misconfiguration: Token import HMAC key not set");
	if (empty($tokenimport_ip)) die("Server misconfiguration: Token import IP not set");
	
	if ($_SERVER['REQUEST_METHOD'] !== "POST") die("Must use POST");
	if ($_SERVER['REMOTE_ADDR'] !== $tokenimport_ip) die("IP not authorized for import");
	if (empty($_POST['key'])) die("No import key provided");
	if (empty($_POST['data'])) die("No import data provided");
	if (empty($_POST['hmac'])) die("No import HMAC provided");
	$keyhash = hash('sha256',$_POST['key']);
	if (strlen($keyhash) != 64) die("Hash function failed");
	if ($keyhash === $tokenimport_key) {
		$hmac = hash_hmac('sha256', $_POST['data'], $tokenimport_hmac_key);
		if (strlen($hmac) != 64) die("Hash function (HMAC) failed");
		if ($_POST['hmac'] === $hmac) {
			PiratenIDImport_importCSV($_POST['data']);
		} else {
			die("HMAC authentication incorrect");
		}
	} else {
		die("Incorrect import key");
	}
}


/* Example:

$db = new PDO('mysql:dbname=piratenid;host=127.0.0.1', "root", "");
$data = array(
		array(hash('sha256','a'), 'ja', 'Hessen', '---', 'Frankfurt am Main', '', 'ja'),
		array(hash('sha256','b'), 'nein', 'land', 'bezirk', 'kreis', 'ort', 'nein'),
	);

// Remove "true" for production use!
PiratenIDImport_import($db, $data, true); 

*/

