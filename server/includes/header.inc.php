<?php

require_once('techheader.inc.php'); //include the "technical" header that sets settings, http headers etc.

// Avoid newline before DOCTYPE:
?><!DOCTYPE HTML>
<html>
<head>
	<meta charset="utf-8">
	<?php
	if (empty($PAGETITLE)) {
		echo '<title>PiratenID</title>';
	} else {
		echo '<title>PiratenID - '.htmlspecialchars($PAGETITLE).'</title>';
	}
	?>	<link rel="stylesheet" type="text/css" href="/static/style.css">
	<link rel="shortcut icon" href="/static/icon32.png" />
</head>
<body>

<div id="banner">
	<div id="banner-inner">
		<?php
			$banners = array(
				'<img width="728" height="90" src="/static/banner/ssl.png" alt="Sicherheitsbanner SSL">',
				'<img width="728" height="90" src="/static/banner/updates.png" alt="Sicherheitsbanner Updates">',
				'<img width="728" height="90" src="/static/banner/passwort.png" alt="Sicherheitsbanner Passwort">',
				'<img width="728" height="90" src="/static/banner/emailsecurity.png" alt="Sicherheitsbanner Mailaccount">'
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
		<img src="/static/icon128.png" style="vertical-align: middle" width="128" height="128" alt="PiratenID-Logo">
		<h1><a href="/">PiratenID</a></h1>
	</div>
	<a href="/user/create.php">Account erstellen</a>
	<a href="/user/entertoken.php">Token eingeben</a>
	<a href="/user/changepw.php">Kennwort ändern</a>
	<a href="/user/requestreset.php">Login vergessen</a>
	<a href="/user/requestdelete.php">Account löschen</a>
	<a href="/" style="border-top:10px solid #b0b0b0;">Infos &amp; Hilfe</a>
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



