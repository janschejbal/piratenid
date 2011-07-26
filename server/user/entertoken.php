<?PHP
$PAGETITLE = 'Token eingeben';
require("../includes/header.inc.php");



function enterToken(&$error) {
	$db = DB::get();
	
	$token = prefilter($_POST['token']);
	if ($token === false) {
		$error = "Ungültiges Token";
		return false;
	}
	
	$token = hash('sha256',$token);
	
	$userarray = getUser($error);
	if ($userarray === false) {
		return false; // error set by getUser()
	}
	
	if ($userarray['token'] !== null) {
		$error = "Dieser Benutzer hat bereits ein Token eingetragen";
		return false;
	}
		
	if ( false !== ($result = $db->query("SELECT username FROM users WHERE token = ?",array($token))) ) {
		if ( count($result) > 0) {
			$error = "Dieses Token wird bereits verwendet"; // user friendlyness/additional security only, database constraint prevents token reuse
			return false;
		}
	} else {
		$error = "Datenbankfehler.";
		return false;
	}
	
	if ( false !== ($result = $db->query("SELECT token FROM tokens WHERE token = ?",array($token))) ) {
		if ( count($result) !== 1) {
			$error = "Ungültiges Token";
			return false;
		}
	} else {
		$error = "Datenbankfehler.";
		return false;
	}
	
	// Token gültig, noch nicht verwendet, User hat noch kein Token
	if (false !== $db->query("UPDATE users SET token = ? WHERE username = ?", array($token, $userarray['username']))) {
		?>
			<h2>Token-Eingabe</h2>
			<p>Token erfolgreich eingetragen. Der Account kann jetzt verwendet werden.</p>
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
	$success = enterToken($error);
}

if (!$success) {
	?>
	<h2>Token-Eingabe</h2>
	<p>Hier kannst du deinem Account ein Token hinzufügen.
	Dieses solltest du vom Vorstand per E-Mail erhalten haben.
	Jedes Token kann nur einmal verwendet werden.
	Ist einem Account einmal ein Token zugeordnet, kann es nicht mehr geändert oder entfernt werden.</p>
	<div class="error"><?PHP safeout($error); ?></div>
	<form method="POST" action="" accept-charset="utf-8">
		<table>
			<?php printLoginFields(); ?>
			<tr>
				<td>Token (nur A-Teil!)</td>
				<td><input type="text" name="token">
				</td>
			</tr>
			<tr>
				<td>&nbsp;</td>
				<td><input type="submit" value="Token eintragen"></td>
			</tr>
		</table>
	</form>
	<?php
}


include("../includes/footer.inc.php");
?>