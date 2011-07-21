<?PHP
require("../includes/header.inc.php");

function resetPassword(&$error) {
	$key = prefilter($_POST['key'], $error);
	if ($key === false) return false;
	$key = hash('sha256',$key);
	
	if (!checkPassword($_POST['newpw1'], $_POST['newpw2'], $error)) return false; // checkPassword contains prefilter
	
	$db = DB::get();
	$result = $db->query("SELECT username FROM users WHERE resettoken = ?", array($key));
	if ($result === false) {
		$error = "Fehler: Datenbankfehler";
		return false;
	}
	if (count($result) !== 1) {
		$error = "Fehler: Ungültiger Reset-Key.";
		return false;
	}
	$username = $result[0]['username'];
	
	
	// Password ok, hash and change
	$newhash = hashPassword($username, $_POST['newpw1']); // newpw1 field was checked above
	if ( false !== $db->query("UPDATE users SET pwhash = ?, resettoken = NULL, resettime = NULL WHERE username = ? AND resettoken = ?",
									array($newhash, $username, $key)) ) {
		return true;
	} else {
		$error = "Datenbankfehler";
		return false;
	}
}



$success = false;
$error = "";

if ($_SERVER['REQUEST_METHOD'] === "POST") {
	$success = resetPassword($error);
} 

if ($success) {
	?>
	<h2>Kennwort geändert</h2>
	<p>Das Kennwort wurde geändert.</p>
	<?php
} else {
	?>
	<h2>Kennwort zurücksetzen</h2>
	<p>Hier kannst du ein neues Kennwort setzen.</p>
	<div class="error"><?PHP safeout($error); ?></div>
	<form method="POST" action="" accept-charset="utf-8">
		<input type="hidden" name="key" value="<?php safeout($_GET['key']);?>">
		<table>
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