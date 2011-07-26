<?PHP
$PAGETITLE = 'Account löschen';
require("../includes/header.inc.php");



function deleteAccount(&$error) {
	$db = DB::get();

	if ($_POST['loeschen'] !== "LOESCHEN" && $_POST['loeschen'] !== "'LOESCHEN'") {
		$error = "Bitte das Bestätigungsfeld korrekt ausfüllen";
		return false;
	}

	$userarray = getUser($error);
	if ($userarray === false) {
		return false; // error set by getUser()
	}
	
	
	$randomname = "DELETEDUSER_". generateNonce(16);;
	if (false !== $db->query("UPDATE users SET username = ?, usersecret = '', pwhash = '', email = '', email_activationkey = '', mitgliedsnr = NULL, realname = NULL, resettoken = NULL, resettime = NULL WHERE username = ?",
						array($randomname, $userarray['username']))) {
		// TODO: Benutzer benachrichtigen?
		?>
			<h2>Account gelöscht</h2>
			<p>Der Account wurde erfolgreich gelöscht.</p>
		
		<?php
		return true;
	} else {
		$error = "Datenbankfehler.";
		return false;
	}
}

$success = false;
$error = "";


if ($_SERVER['REQUEST_METHOD'] === "POST") {
	$success = deleteAccount($error);
} 

if (!$success) {
	?>
	<h2>Account löschen</h2>
	<p>Hier kannst du deinen Account endgültig und unwiderbringlich löschen.
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