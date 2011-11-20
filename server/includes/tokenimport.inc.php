<?PHP

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
	if (count($entry) != 6) die("Invalid data: wrong number of values");
	for ($i = 0; $i<6; $i++) {
		if (!is_string($entry[$i])) die("Invalid data: value not a string");
		if (strlen($entry[$i]) > 100) die("Invalid data: value too long");
		if (!mb_detect_encoding($entry[$i], 'UTF-8', true)) die("Invalid data: value not UTF-8");
		if (!mb_check_encoding($entry[$i], 'UTF-8')) die("Invalid data: invalid UTF-8 sequence");
		
	}
	
	if (!preg_match('/^[a-f0-9]{64}$/D', $entry[0])) die("Invalid data: invalid token value");
	if ($entry[0] == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') die("Invalid data: Token is hash of empty string");
	
	if ($entry[1] !== 'ja' && $entry[1] !== 'nein') die("Invalid data: mitgliedschaft-bund must be either 'ja' or 'nein'");
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
				"INSERT INTO tokens (`token`, `mitgliedschaft-bund`, `mitgliedschaft-land`, `mitgliedschaft-bezirk`, `mitgliedschaft-kreis`, `mitgliedschaft-ort`) VALUES (?,?,?,?,?,?)"
			);
		
		foreach ($dataarray as $entry) { // entry has exactly the order required by the SQL statement
			$statement->execute($entry);
		}
		
		$db->commit();
		
	} catch (PDOException $e) {
		die('Database error: ' . $e->getMessage()); // automatic rollback
	}

}


/* Example:

$db = new PDO('mysql:dbname=piratenid;host=127.0.0.1', "root", "");
$data = array(
		array(hash('sha256','a'), 'ja', 'Hessen', '---', 'Frankfurt am Main', ''),
		array(hash('sha256','b'), 'nein', 'land', 'bezirk', 'kreis', 'ort'),
	);

// Remove "true" for production use!
PiratenIDImport_import($db, $data, true); 

*/
























