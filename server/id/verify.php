<?php 
require('../includes/header.inc.php');
require_once('validation.inc.php');

function generateResponseAttributes($userdata, $attributes, $domain, &$error) {
	global $extendedAttributeDomains;
	global $pseudonymsecret;
	$responseattributes = array();
	$attrarray = explode(',', $attributes);
	foreach ($attrarray as $attrib) {
		switch ($attrib) {
			case 'pseudonym':
				if (empty($userdata['usersecret'])) {
					$error = "pseudonym creation failed for this user";
					return false;
				}
				$pseudo = hash('sha256','piratenid-pseudonym|'.$pseudonymsecret.'|'.$userdata['usersecret'].'|'. $domain);
				if (strlen($pseudo) != 64) die('failed pseudnym hashing'); // just in case...
				array_push($responseattributes, array('name' => 'pseudonym', 'value' => $pseudo));
				break;
			case 'mitgliedschaft-bund': // falltrough
			case 'mitgliedschaft-land': // falltrough
			case 'mitgliedschaft-bezirk': // falltrough
			case 'mitgliedschaft-kreis': // falltrough
			case 'mitgliedschaft-ort':
				// always available for members, but may be empty.
				if (!isset($userdata[$attrib]) || $userdata[$attrib] === null) {
					$error = "membership attribute unavailable for this user";
					return false;
				}
				array_push($responseattributes, array('name' => $attrib, 'value' => $userdata[$attrib]));
				break;
			case 'realname': // falltrough
			case 'mitgliedsnummer':
				// may be unavailable - if so, cause error
				if (empty($userdata[$attrib])) {
					$error = "exteded attribute unavailable for this user";
					return false;
				}
				if (!in_array($domain, $extendedAttributeDomains, true)) {
					$error = "domain has no permission to request extended attributes";
					return false;				
				}
				array_push($responseattributes, array('name' => $attrib, 'value' => $userdata[$attrib]));
				break;
			default:
				$error = "undefined attribute";
				return false;
		}
	}
	return $responseattributes;
}

function makeResponse($nonce, $domain, $attributes, $error = null) {
	$response = new SimpleXMLElement("<PiratenIDResponse></PiratenIDResponse>");
	// do NOT use addChild: http://bugs.php.net/bug.php?id=36795
	$response->nonce = $nonce;
	$response->domain = $domain;
	if ($error===null) {
		$response->type = 'success';
		$i = 0;
		foreach ($attributes as $attrib) {
			$response->attribute[$i]->name = $attrib['name'];
			$response->attribute[$i]->value = $attrib['value'];
			$i++;
		}
	} else {
		$response->type = 'error';
		$response->error = $error;
	}
	return $response->asXML();
}

function makeSignature($response) {
	global $signaturekey_pem;
	$signaturekey_id = openssl_get_privatekey($signaturekey_pem);
	openssl_sign($response, $sig, $signaturekey_id, "sha512");
	openssl_free_key($signaturekey_id);
	if (empty($sig)) die('signature failed');
	return base64_encode($sig);
}

function makeResponseForm($nonce, $domain, $returnurl, $attributes, $error = null) {
	$response = makeResponse($nonce, $domain, $attributes, $error);
	$sig = makeSignature($response);
	?>
	<form name="piratenid_responseform" action="<?php safeout($returnurl); ?>" method="POST">
		<input type="hidden" name="piratenid_response" value="<?php safeout(base64_encode($response)); ?>">
		<input type="hidden" name="piratenid_sig" value="<?php safeout($sig);?>">
		<input type="submit" value="Weiter ohne JavaScript &gt;&gt;&gt;">
	</form>
	<script type="text/javascript">
		document.forms['piratenid_responseform'].submit();
	</script>
	<?php
}

$error = false;

$nonce = prefilter($_POST['nonce'], $error);
$domain = prefilter($_POST['domain'], $error);
$returnurl = prefilter($_POST['returnurl'], $error);
$attributes = prefilter($_POST['attributes'], $error);

if ($error === false) {
	$error = checkForErrors($nonce, $domain, $returnurl, $attributes);
}
if ($error === false) {
	if ($_POST['action'] === 'cancel') {
		$response = makeResponseForm($nonce, $domain, $returnurl, null, "cancelled");
	} if ($_POST['action'] === 'confirm') {
		$userdata = getUser($error);
		if ($userdata) {
			$responseattributes = generateResponseAttributes($userdata, $attributes, $domain, $error);
			if ($responseattributes) {
				// success
				$response = makeResponseForm($nonce, $domain, $returnurl, $responseattributes);
			} else {
				// fail (not all attributes could be obtained)
				?>
				<h1>Fehler</h1>
				<p>Es konnten nicht alle Attribute abgerufen werden (<?php safeout($error); ?>).</p>
				<?php
			}
		} else {
			// wrong login
			?>
			<h1>Fehler</h1>
			<p>Benutzername oder Kennwort falsch.</p>
			<?php
		}
		
		?>
		<div>	
			<form name="piratenid_requestform" action="request.php" method="POST">
				<input type="hidden" name="nonce" value="<?php safeout($nonce); ?>">
				<input type="hidden" name="domain" value="<?php safeout($domain); ?>">
				<input type="hidden" name="returnurl" value="<?php safeout($returnurl); ?>">
				<input type="hidden" name="attributes" value="<?php safeout($attributes); ?>">
				<input type="submit" value="&lt; &lt; Zurück">
			</form>
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
		?>
		<h1>Fehler</h1>
		<p>Es wurde eine ungültige Aktion angegeben.</p>
		<?php
	}
} else { // should happen only if somebody tries to hack, as all this was already checked by request.php
	?>
	<h1>Fehler</h1>
	<p>Es wurden ungültige Daten gesendet.</p>
	<?php
}

include('../includes/footer.inc.php');

?>