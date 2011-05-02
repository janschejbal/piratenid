<?PHP
require("../includes/header.inc.php");

function changePassword(&$error) {
	$db = DB::get();

	$userarray = getUser($error);
	if ($userarray === false) {
		return false; // error set by getUser()
	}
	
	if (!checkPassword($_POST['newpw1'], $_POST['newpw2'], $error)) return false; // checkPassword contains prefilter
	
	// Password ok, hash and change
	$newhash = hashPassword($userarray['username'], $_POST['newpw1']); // newpw1 field was checked above
	if ( false !== $db->query("UPDATE users SET pwhash = ? WHERE username = ?", array($newhash, $userarray['username'])) ) {
		return true;
	} else {
		$error = "Datenbankfehler";
		return false;
	}
}



$success = false;
$error = "";


if ($_SERVER['REQUEST_METHOD'] === "POST") {
	$success = changePassword($error);
} 

if ($success) {
	?>
	<h2>Kennwort geändert</h2>
	<p>Das Kennwort wurde geändert.</p>
	<?php
} else {
	?>
	<h2>Kennwort ändern</h2>
	<p>Hier kannst du dein Kennwort ändern.</p>
	<div class="error"><?PHP safeout($error); ?></div>
	<form method="POST" action="" accept-charset="utf-8">
		<table>
			<?php printLoginFields(); ?>
			<tr>
				<td>Neues Kennwort</td>
				<td><input type="password" name="newpw1">
				</td>
			</tr>
			<tr>
				<td>Neues Kennwort bestätigen</td>
				<td><input type="password" name="newpw2">
				</td>
			</tr>
			<tr>
				<td>&nbsp;</td>
				<td><input type="submit" value="Kennwort ändern"></td>
			</tr>
		</table>
	</form>
	<?php
}


include("../includes/footer.inc.php");
?>