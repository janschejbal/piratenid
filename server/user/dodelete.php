<?PHP
$PAGETITLE = 'Account löschen';
require("../includes/header.inc.php");



function performDeletion(&$error) {
	$key = prefilter($_GET['key'], $error);
	if ($key === false) {
		$error = "Kein Key angegeben";
		return false;
	}
	$key = hash('sha256',$key);
	
	$db = DB::get();
	$result = $db->query("SELECT username, email FROM users WHERE deletetoken = ?", array($key));
	if ($result === false) {
		$error = "Fehler: Datenbankfehler";
		return false;
	}
	if (count($result) !== 1) {
		$error = "Fehler: Ungültiger Lösch-Key.";
		return false;
	}
	$username = $result[0]['username'];
	$email = $result[0]['email'];

	
	$randomname = "DELETEDUSER_". generateNonce(16);;
	// keep email_verified = 1, otherwise account might be deleted during cleanup of non-activated accounts
	$result = $db->query("UPDATE users SET username = ?, usersecret = '', pwhash = '', email = NULL, email_activationkey = '', mitgliedsnr = NULL, realname = NULL, resettoken = NULL, resettime = NULL, deletetoken = NULL, deletetime = NULL, createtime = NULL WHERE username = ?",
						array($randomname, $username));
						
	if (false !== $result) {
		$subject = "PiratenID Accountloeschung erfolgreich";
		$text ="Hallo,\n". // Observe max line length, consider variable lengths!
				"dein PiratenID-Account wurde wie angefordert geloescht.\n\n".
				"Der Benutzername lautete: ".$username."\n\n".
				"Beachte: Verbrauchte Token werden NICHT neu ausgestellt!\n".
				"Solltest du das nicht gewollt haben, kontaktiere SOFORT die IT.\n".
				"Eventuell kann dein Account aus einem Backup wiederhergestellt werden.\n\n".
				"Bei Fragen wende dich bitte an die IT der Piratenpartei unter:\n".
				"piratenid@helpdesk.piratenpartei.de\n\n";
		$success = mail($email, $subject, $text, 'From: PiratenID <noreply@piratenpartei.de>'); // TODO from/reply-to?
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


if (!performDeletion($error)) {
	echo '<h2>Fehler</h2><p>Der Account wurde nicht gelöscht, weil ein Fehler aufgetreten ist: '.htmlspecialchars($error).'</p>';
}


include("../includes/footer.inc.php");
?>