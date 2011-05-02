<?PHP
require("../includes/header.inc.php");

if (prefilter($_GET['key']) === false) {
	?>
	Kein gültiger Aktivierungsschlüssel angegeben
	<?php
} else {
	
	$db = DB::get();
	
	$key = hash('sha256',$_GET['key']); // key field is prefiltered
	
	$result = $db->query("UPDATE users SET email_verified = 1, email_activationkey = NULL WHERE email_activationkey = ?", array($key));
	
	if ($result !== false && $db->statement && $db->statement->rowCount() === 1) {
		?>
		Dein Account ist nun aktiviert. Als nächstes solltest du <a href="entertoken.php">unter diesem Link</a> dein Token eingeben, um den Account voll nutzen zu können.
		<?php
	} else {
		?>
		Beim Aktivieren des Accounts ist ein Fehler aufgetreten - Datenbankfehler oder unbekannter/verbrauchter Aktivierungsschlüssel. Vielleicht ist dein Account schon aktiviert?
		<?php
	}

	
}

include("../includes/footer.inc.php");
?>