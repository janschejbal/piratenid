<?php
error_reporting(E_ALL);

// make sure that all unnormal activity including warnings and notices are fatal
function suppressErrors($errno, $errstr) {
	echo "Es ist ein Fehler aufgetreten.";
	die();
}

set_error_handler("suppressErrors");


require_once('siteconstants.inc.php');
require_once('functions-global.inc.php');


if (ini_get('register_globals')) die("I respectfully refuse. I will not work on a server with such settings. Fix it. (register_globals must be off)");

header("X-Frame-Options: deny"); // clickjacking protection
header("Strict-Transport-Security: max-age:7776000"); // 90 days
header("X-XRDS-Location: ".$sitepath."/openid/xrds.php");

?>