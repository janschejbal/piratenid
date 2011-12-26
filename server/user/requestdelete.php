<?PHP
$PAGETITLE = 'Account löschen';
require("../includes/header.inc.php");



function requesetDeletion(&$error) {
	$db = DB::get();

	if ($_POST['loeschen'] !== "LOESCHEN" && $_POST['loeschen'] !== "'LOESCHEN'") {
		$error = "Bitte das Bestätigungsfeld korrekt ausfüllen";
		return false;
	}

	$userarray = getUser($error);
	if ($userarray === false) {
		return false; // error set by getUser()
	}
	
	// Everything ok, create and send token
	
	$deletekey = generateNonce(16);
	$hashedkey = hash('sha256',$deletekey);
	
	global $sitepath;
	$deletelink = $sitepath."user/dodelete.php?key=".$deletekey;

	if (empty($hashedkey)) {
		$error .= 'Konnte Key nicht erstellen';
		return false;
	}
	
	if ( false === $db->query("UPDATE users SET deletetoken = ?, deletetime = NOW() WHERE username = ?",
							array($hashedkey, $userarray['username'])) ) {
		$error = "Datenbankfehler";
		return false;
	}
	
	$subject = "PiratenID Accountloeschung";
	$text ="Hallo,\n". // Observe max line length, consider variable lengths!
			"du hast darum gebeten, dass dein Piraten-ID-Account geloescht wird.\n\n".
			"Der Benutzername lautet: ".$userarray['username']."\n\n".
			"Beachte: Verbrauchte Token bleiben gesperrt und werden NICHT neu\n".
			"ausgestellt! Wenn du dir wirklich sicher bist, klicke auf folgenden Link,\n".
			"um deinen Account zu loeschen:\n\n".
			$deletelink."\n\n".
			"Bei Fragen wende dich bitte an die IT der Piratenpartei unter:\n".
			"piratenid@helpdesk.piratenpartei.de\n\n";
		global $mailheaders;
		if (empty($mailheaders)) die('e-mail headers not configured');
		$success = mail($userarray['email'], $subject, $text, $mailheaders);
	if ($success) {
		?>
			<h2>E-Mail verschickt</h2>
			<p>Eine E-Mail mit dem Löschlink wurde an die mit dem Account verknüpfte E-Mail-Adresse verschickt.</p>
		
		<?php
		return true;
	} else {
		$error = "Fehler beim Mailversand.";
		return false;
	}

}

$success = false;
$error = "";


if ($_SERVER['REQUEST_METHOD'] === "POST") {
	$success = requesetDeletion($error);
} 

if (!$success) {
	?>
	<h2>Account löschen</h2>
	<p>Hier kannst du beantragen, deinen Account endgültig und unwiderbringlich zu löschen.
	Falls bereits ein Token eingetragen war, wird dieses in der Datenbank als gesperrt markiert; es kann <strong>nicht</strong> wieder verwendet werden.
	Die Accountdaten inklusive eines zum Berechnen der Pseudonyme nötigen Geheimnisses werden gelöscht, die Pseudonyme des Accounts werden somit dauerhaft unbrauchbar.
	</p>
	<p><strong>
		Wenn du einen Account mit eingetragenem Token löschst, bleibt es gesperrt und dir wird <span style="text-decoration: underline;">kein</span> neues Token ausgestellt.
		Du verlierst damit <span style="text-decoration: underline;">dauerhaft und unwiderruflich</span> die Möglichkeit, das ID-System zu nutzen!
	</strong></p>
	<div class="error"><?PHP safeout($error); ?></div>
	<form method="POST" action="" accept-charset="utf-8">
		<table>
			<?php printLoginFields(); ?>
			<tr>
				<td>Bestätigung: 'LOESCHEN' eintragen</td>
				<td><input type="text" name="loeschen">
				</td>
			</tr>
			<tr>
				<td>&nbsp;</td>
				<td><input type="submit" value="Account löschen"></td>
			</tr>
		</table>
	</form>
	<?php
}


include("../includes/footer.inc.php");
?>