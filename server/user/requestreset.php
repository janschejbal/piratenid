<?PHP
$PAGETITLE = 'Kennwort vergessen';
require("../includes/header.inc.php");

function requestReset(&$error) {
	
	$email = prefilter($_POST['email']);
	if ($email === false) {
		$error .= "Ungültige E-Mail-Adresse";
		return false;
	}
	
	//  valid (regexp)
	if (!preg_match('/^[a-zA-Z0-9_\-\.\+\^!#\$%&*+\/\=\?~]+@(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.?){1,200}$/D', $email)) {
		$error .= 'Ungültige E-Mail-Adresse';
		return false;
	} 
	
	$db = DB::get();
	$result = $db->query("SELECT username FROM users WHERE email = ? AND email_verified = 1 AND resettoken IS NULL", array($email));
	if ($result === false) {
		$error .= 'Datenbankfehler';
		return false;
	}
	
	
	if (count($result) !== 1) {
		// attackers can already find out if an address is in the DB as the user registration warns on already used addresses.
		$error .= 'E-Mail-Adresse existiert nicht, ist nicht bestätigt oder Reset-Mail wurde bereits verschickt';
		return false;
	}
	
	$username = $result[0]['username'];
	
	$resetkey = generateNonce(16);
	
	$hashedkey = hash('sha256',$resetkey);

	if (empty($hashedkey)) {
		$error .= 'Konnte Key nicht erstellen';
		return false;
	}
	
	if ( false === $db->query("UPDATE users SET resettoken = ?, resettime = NOW() WHERE email = ?",
							array($hashedkey, $email)) ) {
		$error = "Datenbankfehler";
		return false;
	}
	
	global $sitepath;
	$resetlink = $sitepath."user/doreset.php?key=".$resetkey;
	$subject = "Passwortreset PiratenID";
	$text ="Hallo,\n". // Observe max line length, consider variable lengths!
			"auf dem PiratenID-Server wurde ein Passwort-Reset mit deiner Mailadresse\n".
			"angefordert.\n\n".
			"Der Benutzername lautet: ".$username."\n\n".
			"Um ein neues Kennwort zu setzen, klicke auf den folgenden Link:\n\n".
			$resetlink."\n\n".
			"Solltest du diese Mail nicht angefordert haben, ignoriere sie bitte.\n".
			"Dein Kennwort bleibt dann erhalten.\n\n".
			"Bei Fragen wende dich bitte an die IT der Piratenpartei unter:\n".
			"piratenid@helpdesk.piratenpartei.de\n\n";
	global $mailheaders;
	if (empty($mailheaders)) die('e-mail headers not configured');	
	$success = mail($email, $subject, $text, $mailheaders);
	if (!$success) {
		$error = "Fehler beim Mailversand.";
		return false;
	}
	return true;
}



$success = false;
$error = "";


if ($_SERVER['REQUEST_METHOD'] === "POST") {
	$success = requestReset($error);
} 

if ($success) {
	?>
	<h2>Mail versendet</h2>
	<p>Du solltest eine Mail mit einem Rücksetzlink erhalten haben.</p>
	<?php
} else {
	?>
	<h2>Login vergessen?</h2>
	<p>Wenn du deinen Benutzernamen oder Kennwort vergessen hast, kannst du hier eine Mail mit deinem Benutzernamen und einem Link zum Zurücksetzen des Kennworts anfordern.</p>
	<div class="error"><?PHP safeout($error); ?></div>
	<form method="POST" action="" accept-charset="utf-8">
		<table>
			<tr>
				<td>E-Mail-Adresse</td>
				<td><input type="text" name="email">
				</td>
			</tr>
			<tr>
				<td>&nbsp;</td>
				<td><input type="submit" value="Link anfordern"></td>
			</tr>
		</table>
	</form>
	<?php
}


include("../includes/footer.inc.php");
?>