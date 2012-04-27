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
	$result = $db->query("SELECT username, token, email FROM users WHERE deletetoken = ?", array($key));
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
	
	$hadToken = false;
	if (empty($result[0]['token'])) {
		// Deleting account that does not have a token - just delete the entry completely
		$result = $db->query("DELETE FROM users WHERE username = ?", array($username));
	} else {
		$hadToken = true;
		// Deleting account with token - entry with token must be kept to ensure that token cannot be reused
		// --> keep email_verified = 1, otherwise account entry might be deleted during cleanup of non-activated accounts
		// usersecret will be kept to allow account recovery in case of malicious deletion.
		// The usersecret can be deleted manually if requested (on paper) for privacy reasons; THE TOKEN MUST BE KEPT!
		// Replace username with random unique value; blank all other fields
		$randomname = "DELETEDUSER_". generateNonce(16);
		$result = $db->query("UPDATE users SET username = ?, pwhash = '', email = NULL, email_activationkey = '', mitgliedsnr = NULL, realname = NULL, resettoken = NULL, resettime = NULL, deletetoken = NULL, deletetime = NULL, createtime = NULL WHERE username = ?",
							array($randomname, $username));	
	}
	

						
	if (false !== $result) {
		$tokenText = ($hadToken?
				"Dein Account war mit einem Token verbunden.\n".
				"Dieses Token bleibt gespeichert und dauerhaft gesperrt.\n".
				"Du kannst KEIN neues Token erhalten. Damit dein Account\n".
				"(z. B. im Fall einer missbraeuchlichen Loeschung)\n".
				"widerhergestellt werden kann, bleibt aber die Zuordnung\n".
				"zwischen deinen Pseudonymen und deinem Token gespeichert\n".
				"(der Accountname hingegen wurde entfernt).\n".
				"Solltest du wollen, dass auch diese Zuordnung entfernt\n".
				"wird, geht dies aus Sicherheitsgruenden nur schriftlich.\n".
				"Wende dich hierzu bitte an deinen GenSek bzw. die\n".
				"Mitgliederverwaltung.\n\n"
			:
				"Da dein Account nicht mit einem Token verbunden war,\n".
				"wurden Account und Daten komplett entfernt.\n\n"
			);
		$subject = "PiratenID Accountloeschung erfolgreich";
		$text ="Hallo,\n". // Observe max line length, consider variable lengths!
				"dein PiratenID-Account wurde wie angefordert geloescht.\n\n".
				"Der Benutzername lautete: ".$username."\n\n".
				$tokenText.
				"Bei Fragen wende dich bitte an die IT der Piratenpartei unter:\n".
				"piratenid@helpdesk.piratenpartei.de\n\n";
		global $mailheaders;
		if (empty($mailheaders)) die('e-mail headers not configured');
		$success = mail($email, $subject, $text, $mailheaders);
		?>
			<h2>Account gelöscht</h2>
			<p>Der Account wurde erfolgreich gelöscht.</p>
		<?php
			echo '<p>'.$tokenText.'</p>';
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