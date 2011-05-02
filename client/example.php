<?php
	require_once("piratenid.php");
	PiratenID::session_init(); // VOR allen anderen Ausgaben aufrufen, damit das Session-Cookie gesetzt werden kann!

?>
<html>
<head>
<title>PiratenID-Demo</title>
</head>
<body>
<h1>PiratenID-Demo</h1>
<p>Diese Seite demonstriert, wie das PiratenID-System funktioniert.</p>
<div>
<?php


	// NOTE: PHP_SELF und ähnliche sind BÖSE!
	// http://blog.oncode.info/2008/05/07/php_self-ist-boese-potentielles-cross-site-scripting-xss/
	$domain = "localhost.janschejbal.de";
	$returnto = "https://$domain/example.php";
	
	// Login-Handling
	if (!empty($_GET['action']) && $_GET['action'] === 'login') {
		if (!PiratenID::session_request("pseudonym,mitgliedschaft-bund,mitgliedschaft-land", $returnto, $domain )) {
			// Alle Ausgaben müssen escaped werden!
			echo "<p><strong>Fehler beim Erstellen der Login-Anfrage (".htmlspecialchars(PiratenID::session_pollError()).")</strong></p>\n";
		}
	}

	// Logout-Handling
	if (!empty($_GET['action']) && $_GET['action'] === 'logout') {
		PiratenID::session_reset();
		echo "<p>Abgemeldet</p>\n";
	}
	
	// Response-handler - empfängt Antwort des PiratenID-Servers
	if (isset($_POST['piratenid_response'])) {
		if (PiratenID::session_handle()) {
			echo "<p><strong>Login erfolgreich</strong></p>\n";
		} else {
			// Alle Ausgaben müssen escaped werden!
			echo "<p><strong>Login fehlgeschlagen (".htmlspecialchars(PiratenID::session_pollError()).")</strong></p>\n";
		}
	}

	if (PiratenID::session_isAuthenticated()) {
		// Nutzer ist angemeldet. Es steht aber noch nicht fest, dass er auch Pirat ist!
		?>
		<p>Du bist angemeldet. <a href="?action=logout">Abmelden</a></p>
		<?php
		$attrib = PiratenID::session_getAttributes();
		
		echo "<p>Dein Pseudonym lautet: ".htmlspecialchars($attrib['pseudonym'])."</p>\n";
		
		// Pirateneigenschaft explizit prüfen!
		if ($attrib['mitgliedschaft-bund'] === "JA") {
			echo "<p>Du bist Pirat!</p>\n";
			echo "<p>Landesverband: ".htmlspecialchars($attrib['mitgliedschaft-land'])."</p>\n";
		} else {
			echo "<p>Du bist KEIN Pirat!</p>\n";
		}
	} else {
		?>
		<p>Du bist nicht angemeldet. <a href="?action=login">Jetzt mit PiratenID einloggen!</a></p>
		<?php
	}
?>
</div>
</body>
</html>