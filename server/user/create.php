<?PHP
require("../includes/header.inc.php");

$usernameerror = '';
$passworderror = '';
$mailerror = '';

$valid = false;
if ($_SERVER['REQUEST_METHOD'] === "POST") {
	$db = DB::get();
	
	
	$username = strtolower(prefilter($_POST['username'])); // a 'false' from prefilter will create "" will be considered invalid
	$password = $_POST['password']; // will be run trough checkPassword which includes prefiltering.
	$password2 = $_POST['password2']; // will be run trough checkPassword which includes prefiltering.
	$mail = $_POST['mail']; // will be run trough checkMail which includes prefiltering.
	
	
	// username checks
		//  valid (regexp)
	if (!preg_match('/^[a-z0-9._-]{3,30}$/', $username)) {
		$usernameerror = 'Ungültiger Benutzername';
	} else {
		//  check: name is not yet used (db)
		if ( false !== ($result = $db->query("SELECT username FROM users WHERE username=?",array($username))) ) {
			if ( count($result) > 0) $usernameerror = "Dieser Benutzername wird bereits verwendet";
		} else {
			$usernameerror = "Datenbankfehler.";
		}
	}

	checkPassword($password, $password2, $passworderror);
	checkMail($mail, $mailerror);
	
	$valid = empty($usernameerror) && empty($passworderror) && empty($mailerror);
}

if ($valid) {
	$success = false;
	$usersecret = generateNonce(32);
	$pwhash = hashPassword($username, $password);
	$activationkey = generateNonce(16);;

	
	$result = $db->query("INSERT INTO users (username, usersecret, pwhash, email, email_activationkey) values (?,?,?,?,?)",
											array($username, $usersecret, $pwhash, $mail, hash('sha256',$activationkey) ) );
	$success = (false !== $result);

	
	if ($success) {  
		global $sitepath;
		$activationlink = $sitepath."user/confirm.php?key=".$activationkey;
		$subject = "Aktivierung des PiratenID-Accounts";
		$text ="Hallo,\n".  // Observe max line length, consider lengths of variables!
				"auf dem PiratenID-Server wurde ein Benutzerkonto mit dieser Mailadresse\n".
				"erstellt. Um das Konto zu aktivieren, klicke auf den folgenden Link:\n\n".
				$activationlink."\n\n".
				"Der Benutzername lautet: ".$username."\n\n".
				"Solltest du dieses Konto nicht erstellt haben, ignoriere diese Mail bitte.\n".
				"Das Benutzerkonto wird dann nicht aktiviert.\n\n".
				"Bei Fragen wende dich bitte an die IT der Piratenpartei unter:\n".
				"piratenid@helpdesk.piratenpartei.de\n\n";
		// TODO DEBUG send activation mail
		echo("<pre>Text der Aktivierungsmail:\n\n$text</pre>"); // TODO DEBUG REMOVE
		// $success = mail($mail, $subject, $text);
	}
	
	if ($success) {
		?>
		<h2>Account erstellt</h2>
		<p>Der Account wurde erstellt. Du solltest eine E-Mail mit einem Bestätigungslink erhalten. Klicke auf den Link, um deinen Account zu aktivieren.</p>
		<?php
	} else {
		?>
		<h2>Fehler bei der Accounterstellung</h2>
		<p>Bei der Erstellung des Accounts ist ein Fehler aufgetreten. Bitte versuche es später noch einmal oder benachrichtige die IT, wenn das Problem weiter auftritt.</p>
		<?php	
	}
} else {
	?>
	<h2>Account erstellen</h2>
	<!-- Einwilligung nach BDSG §4a -->
	<p>Ich möchte einen PiratenID-Account haben.</p>
	<p><em>Ich bin damit einverstanden, dass die von mir eingegebenen Daten gespeichert
	und über das im nächsten Schritt einzugebende Token mit den Informationen über meine Gliederungsmitgliedschaften verknüpft werden,
	damit ich diese im ID-System nutzen und gegenüber anderen Webseiten bestätigen lassen kann.<br>
	Ohne diese Einwilligung kann das ID-System nicht genutzt werden.</em></p>
	<div>
		<form action="create.php" method="POST" accept-charset="utf-8">
			<table>
				<tr>
					<td>Benutzername</td>
					<td><input type="text" name="username" value="<?php safeout($_POST['username']); ?>">
						<span class="error"><?PHP safeout($usernameerror); ?></span><br>
						Nur normale Buchstaben, Zahlen, Punkte und Binde- sowie Unterstrich sind erlaubt (3-30 Zeichen). Der Benutzername kann später nicht mehr geändert werden!
					</td>
				</tr>
				<tr>
					<td>Kennwort</td>
					<td><input type="password" name="password">
						<span class="error"><?PHP safeout($passworderror); ?></span><br>
						Mindestens 8 Zeichen, mindestens 2 Arten von Zeichen (Kleinbuchstaben, Großbuchstaben, Zahlen, Sonderzeichen).
					</td>
				</tr>
				<tr>
					<td>Kennwort bestätigen</td>
					<td><input type="password" name="password2">
					</td>
				</tr>
				<tr>
					<td>E-Mail</td>
					<td><input type="text" name="mail" value="<?php safeout($_POST['mail']); ?>">
						<span class="error"><?PHP safeout($mailerror); ?></span>
					</td>
				</tr>
				<tr>
					<td>&nbsp;</td>
					<td><input type="submit"></td>
				</tr>
			</table>
		</form>
	</div>
	<?php
}

include("../includes/footer.inc.php");
?>