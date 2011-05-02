<?php 
require('../includes/header.inc.php');
require_once('validation.inc.php');

$error = false;

$nonce = prefilter($_POST['nonce'], $error);
$domain = prefilter($_POST['domain'], $error);
$returnurl = prefilter($_POST['returnurl'], $error);
$attributes = prefilter($_POST['attributes'], $error);

if ($error === false) {
	$error = checkForErrors($nonce, $domain, $returnurl, $attributes);
}

if ($error === false) {
	$attribhtml = "";
	$attrarray = explode(',', $attributes);
	foreach ($attrarray as $attrib) {
		$attribtext = "";
		switch ($attrib) {
			case 'pseudonym': $attribtext = 'Ein seitenspezifisches Pseudonym'; break;
			case 'mitgliedschaft-bund': $attribtext = 'Die Information, ob du in der Piratenpartei Mitglied bist'; break;
			case 'mitgliedschaft-land': $attribtext = 'Die Information, in welchem Landesverband du Mitglied bist'; break;
			case 'mitgliedschaft-bezirk': $attribtext = 'Die Information, in welchem Bezirksverband du Mitglied bist'; break;
			case 'mitgliedschaft-kreis': $attribtext = 'Die Information, in welchem Kreisverband du Mitglied bist'; break;
			case 'mitgliedschaft-ort': $attribtext = 'Die Information, in welchem Ortsverband du Mitglied bist'; break;
			case 'realname': $attribtext = '<span class="attribut-kritsch">Dein voller Name</span>'; break;
			case 'mitgliedsnummer': $attribtext = '<span class="attribut-kritsch">Deine Mitgliedsnummer bei der Piratenpartei</span>'; break;
			default: $attribtext = "FEHLER - UNBEKANNTES ATTRIBUT. BITTE VORGANG ABBRECHEN UND DER IT MELDEN."; break;
		}
		$attribhtml .= "\t\t\t<li><tt>".htmlspecialchars($attrib).'</tt>: '.$attribtext ."</li>\n";
	}
	?>
	<h1>Identifizierungsanfrage</h1>
	<p>Die Seite <strong><?php safeout($domain); ?></strong> möchte folgende Daten abfragen:
	<div><ul>
		<?php echo $attribhtml; /*pre-escaped*/ ?>
	</ul></div>
	<p>Wenn du dieser Seite vertraust und ihr die genannten Daten geben möchtest, überprüfe ob du dich auf der korrekten, HTTPS-gesicherten Website des ID-Systems befindest und gib Benutzername und Kennwort ein:</p>
	<div>
		<form action="verify.php" method="POST" accept-charset="utf-8">
		<table>
			<?php printLoginFields(); ?>
			<tr><td>&nbsp;</td><td><input type="submit"></td></tr>
		</table>
		<input type="hidden" name="action" value="confirm">
		<input type="hidden" name="nonce" value="<?php safeout($nonce); ?>">
		<input type="hidden" name="domain" value="<?php safeout($domain); ?>">
		<input type="hidden" name="returnurl" value="<?php safeout($returnurl); ?>">
		<input type="hidden" name="attributes" value="<?php safeout($attributes); ?>">
		</form>
	</div>
	<div>
		<form action="verify.php" method="POST" accept-charset="utf-8">
		<input type="submit" value="Vorgang abbrechen">
		<input type="hidden" name="action" value="cancel">
		<input type="hidden" name="nonce" value="<?php safeout($nonce); ?>">
		<input type="hidden" name="domain" value="<?php safeout($domain); ?>">
		<input type="hidden" name="returnurl" value="<?php safeout($returnurl); ?>">
		<input type="hidden" name="attributes" value="<?php safeout($attributes); ?>">
		</form>
	</div>
	<?php
} else {
	// error - user will NOT be directed to return url, as it may be invalid
	?>
	<h1>Identifizierungsanfrage - FEHLER</h1>
	<p>Die Identifizierungsanfrage ist ungültig. Es ist folgender Fehler aufgetreten:</p>
	<p><em><?php safeout($error); ?></em></p>
	<?php
}

include('../includes/footer.inc.php');

?>

