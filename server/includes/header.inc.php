<?php

error_reporting(E_ALL);

// make sure that all unnormal activity including warnings and notices are fatal
function suppressErrors($errno, $errstr) {
	  echo "Es ist ein Fehler aufgetreten.";
	  die();
} 
// DEBUG TODO ENABLE
//set_error_handler("suppressErrors");



if (ini_get('register_globals')) die("I respectfully refuse. I will not work on a server with such settings. Fix it. (register_globals must be off)");


header("X-Frame-Options: deny"); // clickjacking protection
header("Strict-Transport-Security: max-age:7776000"); // 90 days
require_once('siteconstants.inc.php');
require_once('functions-global.inc.php');

?>
<!DOCTYPE HTML>
<html>
<head>
	<meta charset="utf-8">
	<title>PiratenID</title>
	<link rel="stylesheet" type="text/css" href="/static/style.css">
</head>
<body>

<div id="banner">
	<div id="banner-inner">
		<?php
			$banners = array(
				'<img width="728" height="90" src="/static/banner/ssl.png">',
				'<img width="728" height="90" src="/static/banner/updates.png">',
				'<img width="728" height="90" src="/static/banner/passwort.png">',
				'<img width="728" height="90" src="/static/banner/emailsecurity.png">'
			);
			shuffle($banners);
			echo implode($banners); // safe, source is a constant
		
		?>
	</div>
	<script>
		var bannertag = document.getElementById("banner-inner");
		var pos = 0;
		var up = false;
		function move() {
			pos += up ? -9 : 9;
			bannertag.style.marginTop = "" + (-pos) + "px";
			if (pos >= bannertag.offsetHeight-90) up = true;
			if (pos <= 0) up = false;
			setTimeout("move()", ((pos % 90) == 0)? 7000:50);
		}
		setTimeout("move()",7000);
	</script>
</div>

<div id="container">

<div id="sidebar">
	<div id="logo">
		<img src="/static/icon128.png" style="vertical-align: middle" width="128" height="128">
		<h1><a href="/">PiratenID</a></h1>
	</div>
	<a href="/user/create.php">Account erstellen</a>
	<a href="/user/entertoken.php">Token eingeben</a>
	<a href="/user/changepw.php">Kennwort ändern</a>
	<a href="/user/requestreset.php">Login vergessen</a>
	<a href="/user/delete.php">Account löschen</a>
	<a href="/help/user.php" style="border-top:10px solid #b0b0b0;">Hilfe für Benutzer</a>
	<a href="/help/dev.php">Hilfe für Entwickler</a>
	<a href="/help/tech.php">Source und Doku</a>
</div>

<div id="maincontent">

<!-- block IE 6 -->
<!--[if lt IE 7]>
	<h2>Das ist kein Browser</h2>
	<p>
		Du versuchst, mit einem Internet Explorer 6 oder älter auf das ID-System zuzugreifen.
		Sogar Microsoft selbst (der Hersteller) rät von der Benutzung dieses "Browsers" ab.
		Der IE6 wird nicht mehr mit Sicherheitsupdates versorgt und hat zahlreiche bekannte Sicherheitslücken.
		Eine sichere Internetnutzung ist damit nicht möglich.
		Bringe dein <strong>gesamtes</strong> System bitte auf den neuesten Stand - dir fehlen vermutlich noch viele andere wichtige Updates.
	</p>
	<div>Besorge dir bitte einen vernünftigen Browser, um auf das ID-System zuzugreifen, zum Beispiel:
		<ul>
			<li><a href="http://www.mozilla.com/de/firefox/">Mozilla Firefox</a></li>
			<li><a href="http://www.google.com/chrome/intl/de/landing_win.html?hl=de&hl=de">Google Chrome</a></li>
		</ul>
	</div>
<![endif]-->
<!--[if gte IE 7]><!-->



