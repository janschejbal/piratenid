<?php 
require_once('../includes/techheader.inc.php');

function sendIndirectResponse($fields, $target) {
	$fields['openid.ns'] = 'http://specs.openid.net/auth/2.0';
	include('../includes/header.inc.php');
	echo '<h2>Fertig</h2>';
	echo '<form name="piratenid_responseform" action="'. htmlspecialchars($target).'" method="POST" accept-charset="utf-8">';
	foreach ($fields as $key => $value) {
		echo '<input type="text" name="'.htmlspecialchars($key).'" value="'.htmlspecialchars($value).'">'; // TODO DEBUG HIDDEN
	}
	?>
	<input type="submit" value="Zurück zur anfragenden Seite &gt;&gt;&gt;">
	</form>
	<script type="text/javascript">
		// disabled to make sure user knows he is leaving the ID system (to avoid phishing attacks, for example using http basic auth)
		//document.forms['piratenid_responseform'].submit();
	</script>
	<?php
	include('../includes/footer.inc.php');
}

function sendIndirectError($error, $target) {
	sendIndirectResponse(array('openid.mode' => 'error', 'openid.error' => $error), $target);
}

// Encodes the supplied fields in key:value encoding.
// If order is given, encodes only the named fields in the named order, and returns null if one of the fields does not exist
function getKeyValueString($fields, $order = null) {
	if ($order === null) {
		$result = "";
		foreach ($fields as $key => $value) {
			$result .= "$key:$value\n";
		}
		return $result;
	} else {
		$result = "";
		$orderarr = explode(',',$order);
		foreach ($orderarr as $keyname) {
			$keyname = "openid.$keyname";
			if (isset($fields[$keyname])) {
				$result .= "$keyname:".$fields[$keyname]."\n";
			} else {
				return null;
			}
		}
		return $result;
	}
}

function sendDirectResponse($fields) {
	$fields['ns'] = 'http://specs.openid.net/auth/2.0';
	header('Content-Type: text/plain');
	echo getKeyValueString($fields);
}

function sendDirectError($error) {
	header("HTTP/1.0 400 Bad Request");
	sendDirectResponse(array('error'=>$error));
}

function getOpenIDFields() {
	// TODO prefilter
	$source = ($_SERVER['REQUEST_METHOD'] === "POST") ? $_POST : $_GET;
	$result = array();
	foreach ($source as $key => $value) {
		// PHP replaces dots with underscores. We need to fix that.
		if (substr($key,0,7) === "openid_") {
			$fixedkey = "openid.".substr($key,7);
			$result[$fixedkey] = $value;
		}
	}	
	return $result;
}

 
function handleFieldsError($reason = "") {
	include('../includes/header.inc.php');
	?>
		<h2>OpenID-Fehler</h2>
		<p>Dies ist ein Endpoint für OpenID 2.0.<br>Es wurde keine (gültige) OpenID 2.0-Anfrage übermittelt.</p>
	<?php
		echo '<p type="error">'.htmlspecialchars($reason).'</p>';
	include('../includes/footer.inc.php');
}



function handleCheckidImmediate($reqfields) {
	sendIndirectResponse(array('openid.mode'=>'setup_required'), $reqfields['openid.return_to']);
}

// Checks the openid.* fields for auth requests and confirmations
function evaluateFields(&$reqfields, &$error, &$usePseudonym, &$implicitMembership, &$attributes) {
	// check claimed_id and identity
	if (  (isset($reqfields['openid.claimed_id']) && $reqfields['openid.claimed_id'] !== "http://specs.openid.net/auth/2.0/identifier_select") ||
			(isset($reqfields['openid.identity']) && $reqfields['openid.identity'] !== "http://specs.openid.net/auth/2.0/identifier_select")   ) {
		$error = "For anonymous mode, do not supply any (not even empty) claimed_id or identity. For pseudonymous mode, use the identifier_select magic as per the OpenID 2.0 spec.";
		return false;
	}
	
	// ensure no association handle is sent (we don't do associations)
	if (isset($reqfields['openid.assoc_handle'])) {
		$error = "association handle sent - we do not do any associations";
		return false;
	}
	
	// check realm
	if (!isset($reqfields['openid.realm'])) $reqfields['openid.realm'] = $reqfields['openid.return_to']; // default: return_to url
	if (!validURL($reqfields['openid.realm'])) {
		$error = "realm is not a valid url";
		return false;
	}
	
	// must start with https:// and end with slash, must NOT contain query parameters (?param1=value1&param2=value2) or fragment (#anchor)
	if (!preg_match('%^https://[a-zA-Z0-9$_.+!*\'(),/;:-]+/$%', $reqfields['openid.realm']) ) {
		$error = "must start with https:// and end with slash, must NOT contain query parameters or fragment (#anchor)";
		return false;
	}
	
	// check return_to (general URL validity already checked)
	if (strpos($reqfields['openid.return_to'], $reqfields['openid.realm']) !== 0) {
		$error = "return_to does not match realm";
		return false;
	}
	
	// check referer
	if ( !empty($_SERVER['HTTP_REFERER']) ) {
		global $sitepath;
		
		// ignore port number on realm for referer checking (required for example for JanRain)
		$cleanedRealm = preg_replace('|(https://[^/]+):443/|', "$1/", $reqfields['openid.realm']);
		
		if ( strpos($_SERVER['HTTP_REFERER'], $cleanedRealm) !== 0 && strpos($_SERVER['HTTP_REFERER'], $sitepath) !== 0) {
			// just an additional check to make CSRF and similar more annoying to try (the password in each request is the real protection)
			// referer headers can be spoofed, but usually not without a decent amount of control over the client
			$error = "referer exists but is invalid - must come from specified domain (or ID system) and be HTTPS";
			return false;
		}
	}

	$usePseudonym = isset($reqfields['openid.claimed_id']) || isset($reqfields['openid.identity']);

	$implicitMembership = true; // init
	
	// check attribute list
	if ( isset($reqfields['openid.ax.mode']) && $reqfields['openid.ax.mode'] === 'fetch_request' ) {
		// precheck
		if ( !isset($reqfields['openid.ax.required']) || !preg_match('%^[a-z_-]+(,[a-z_-]+)*$%', $reqfields['openid.ax.required']) ) {
			$error = "invalid AX attribute list";
			return false;
		}
		
		// attribute whitelist and type checking
		$supported = array('mitgliedschaft-bund','mitgliedschaft-land','mitgliedschaft-bezirk','mitgliedschaft-kreis','mitgliedschaft-ort'/*,'realname','mitgliedsnummer'*/); // Die Abfrage von Realidentitätsdaten ist fürs Erste deaktiviert.
		$attrarray = explode(',', $reqfields['openid.ax.required']);
		foreach ($attrarray as $attrname) {
			if (!in_array($attrname, $supported, true)) {
				$error = "unsupported attribute requested";
				return false;
			}
			if (!isset($reqfields["openid.ax.type.$attrname"]) || $reqfields["openid.ax.type.$attrname"] !== "https://id.piratenpartei.de/openid/schema/$attrname") {
				$error = "wrong attribute type requested";
				return false;
			}
			if ($attrname === 'mitgliedschaft-bund') $implicitMembership = false;
		}
		$attributes = $attrarray;
	} else { // no AX requested
		$attributes = null;
		$implicitMembership = true;
	}
	
	return true;
}

function printOpenIDFields($reqfields) {
	foreach ($reqfields as $key => $value) {
		echo '<input type="hidden" name="'.htmlspecialchars($key).'" value="'.htmlspecialchars($value).'">';
	}
}

function handleCheckidSetup($reqfields, $errormessage = null) {
	$error = null;
	$usePseudonym = false;
	$implicitMembership = false;
	$attribarray = null;
	if (!evaluateFields($reqfields, $error, $usePseudonym, $implicitMembership, $attribarray)) {
		sendIndirectError($error, $reqfields['openid.return_to']);
	} else { // success
		$attribhtml = "";
		if ($usePseudonym) {
			$attribhtml .= "\t\t\t<li>Dein seitenspezifisches Pseudonym</li>\n";
		}
		if ($implicitMembership) {
			$attribhtml .= "\t\t\t<li>Deinen Mitgliedsstatus (implizit: Ein Login ist nur möglich, wenn du ein Mitglied bist und ein gültiges Token eingetragen hast)</li>\n";
		}
		if ($attribarray !== null) {
			foreach ($attrarray as $attrib) {
				$attribtext = "";
				switch ($attrib) {
					case 'mitgliedschaft-bund': $attribtext = 'Die Information, ob du in der Piratenpartei Mitglied bist'; break;
					case 'mitgliedschaft-land': $attribtext = 'Die Information, in welchem Landesverband du Mitglied bist'; break;
					case 'mitgliedschaft-bezirk': $attribtext = 'Die Information, in welchem Bezirksverband du Mitglied bist'; break;
					case 'mitgliedschaft-kreis': $attribtext = 'Die Information, in welchem Kreisverband du Mitglied bist'; break;
					case 'mitgliedschaft-ort': $attribtext = 'Die Information, in welchem Ortsverband du Mitglied bist'; break;
					case 'realname': $attribtext = '<span class="attribut-kritsch">Dein voller Name</span>'; break;
					case 'mitgliedsnummer': $attribtext = '<span class="attribut-kritsch">Deine Mitgliedsnummer bei der Piratenpartei</span>'; break;
					default: $attribtext = "FEHLER - UNBEKANNTES ATTRIBUT. BITTE VORGANG ABBRECHEN UND DER IT MELDEN."; break;
				}
				$attribhtml .= "\t\t\t<li>".$attribtext ."</li>\n";
			}
		}
		include('../includes/header.inc.php');
		?>
		<h1>Identifizierungsanfrage</h1>
		<?php
		if (!empty($errormessage)) {
			echo '<p class="error">'.htmlspecialchars($errormessage).'</p>';
		}
		?>
		<p>Die Seite <strong><?php safeout($reqfields['openid.realm']); ?></strong> möchte folgende Daten abfragen:
		<div><ul>
			<?php echo $attribhtml; /*pre-escaped*/ ?>
		</ul></div>
		<p>Wenn du dieser Seite vertraust und ihr die genannten Daten geben möchtest, überprüfe ob du dich auf der korrekten, HTTPS-gesicherten Website des ID-Systems befindest und gib Benutzername und Kennwort ein:</p>
		<div>
			<form action="" method="POST" accept-charset="utf-8">
			<table>
				<?php printLoginFields(); ?>
				<tr><td>&nbsp;</td><td><input type="submit"></td></tr>
			</table>
			<input type="hidden" name="action" value="confirm">
			<?php
				printOpenIDFields($reqfields);
			?>
			</form>
		</div>
		<div>
			<form action="" method="POST" accept-charset="utf-8">
			<input type="submit" value="Vorgang abbrechen">
			<input type="hidden" name="action" value="cancel">
			<?php
				printOpenIDFields($reqfields);
			?>
			</form>
		</div>
		<?php
		include('../includes/footer.inc.php');
	}
}

function addAXAttributes(&$response, $attribarray, $userdata, &$error) {
	global $extendedAttributeRealms;
	$response["openid.ax.mode"] = "fetch_response";
	$response["openid.signed"] .= ",ax.mode";
	foreach ($attribarray as $attrib) {
		switch ($attrib) {
			case 'realname': // falltrough
			case 'mitgliedsnummer':
				if (!in_array($realm, $extendedAttributeRealms, true)) {
					$error = "Diese Seite darf keine Personendaten abfragen";
					return false;				
				}
				// falltrough!
			case 'mitgliedschaft-bund': // falltrough
			case 'mitgliedschaft-land': // falltrough
			case 'mitgliedschaft-bezirk': // falltrough
			case 'mitgliedschaft-kreis': // falltrough
			case 'mitgliedschaft-ort':
				// always available for members, but may be empty.
				if (!isset($userdata[$attrib]) || $userdata[$attrib] === null) {
					$error = "Dieser Nutzer hat nicht alle angeforderten Attribute (Token eingetragen?)";
					return false;
				}
				if (strpos($userdata[$attrib], ':') !== false || strpos($userdata[$attrib], "\n") !== false ) {
					$error = "Ungültige Zeichen im Attributwert. Bitte wende dich an die BundesIT.";
					return false;
				}
				$response["openid.ax.type.$attrib"] = "https://id.piratenpartei.de/openid/schema/$attrib";
				$response["openid.signed"] .= ",ax.type.$attrib";
				$response["openid.ax.value.$attrib"] = $userdata[$attrib];
				$response["openid.signed"] .= ",ax.value.$attrib";

				break;
			default:
				$error = "UNBEKANNTES ATTRIBUT - DIES SOLLTE NIE PASSIEREN. Bitte der BundesIT melden!";
				return false;
		}
	}
	return true;
}

function handleUserConfirm($reqfields) {
	$error = null;
	$usePseudonym = false;
	$implicitMembership = false;
	$attribarray = null;
	
	// verify input (in case of attacks - errors by mistake are already caught when the data first arrives in handleCheckidSetup()
	if (!evaluateFields($reqfields, $error, $usePseudonym, $implicitMembership, $attribarray)) {
		include('../includes/header.inc.php');
		?>
		<h2>Fehler</h2>
		<p>Es wurden ungültige Feldwerte übergeben.</p>
		<?php
		include('../includes/footer.inc.php');
		return;
	}
	$userdata = getUser($error);
	
	
	// user login check
	if ($userdata == false) {
		handleCheckidSetup($reqfields, "Benutzername oder Kennwort falsch");
		return;
	}
	
	if ($implicitMembership !== false && $userdata['mitgliedschaft-bund'] !== 'ja') { // TODO column type
		handleCheckidSetup($reqfields, "Dieses Benutzerkonto kann nicht zum Anmelden bei dieser Seite benutzt werden: ".
										"Du bist kein Pirat oder dein Token ist nicht richtig eingetragen");
		return;
	}
	
	// General OpenID fields
	global $sitepath;
	$response = array();
	$response['openid.signed'] = "op_endpoint,return_to,response_nonce,assoc_handle";
	$response['openid.mode'] = "id_res";
	$response['openid.op_endpoint'] = $sitepath."openid/endpoint.php";
	$response['openid.return_to'] = $reqfields['openid.return_to'];
	$response['openid.response_nonce'] = gmdate("Y-m-d\TH:i:s\Z")."-".generateNonce(32);
	$response['openid.assoc_handle'] = "private";
	
	// Pseudonym
	if ($usePseudonym) {
		global $pseudonymsecret;
		if (empty($userdata['usersecret']) || empty($pseudonymsecret) || empty($reqfields['openid.realm'])) die('failed pseudonym creation');
		$pseudo = hash('sha256','piratenid-pseudonym|'.$pseudonymsecret.'|'.$userdata['usersecret'].'|'. $reqfields['openid.realm']);
		if (strlen($pseudo) != 64) die('failed pseudnym hashing');

		$response['openid.claimed_id'] = $sitepath.'openid/pseudonym.php?id='.$pseudo;
		$response['openid.identity'] = $response['openid.claimed_id'];
		$response['openid.signed'] .= ",claimed_id,identity";
	
	}
	

	// Attributes
	if ($attribarray != null) {
		$errormessage = "";
		if (!addAXAttributes($response, $attribarray, $userdata, $errormessage)) {
			handleCheckidSetup($reqfields, $errormessage);
			return;
		}
	}
	
	// HMAC-sign
	$responseString = getKeyValueString($response, $response['openid.signed']);
	if (empty($responseString)) die("failed key-value formatting");
	global $openid_hmacsecret;
	$hmac = base64_encode(hash_hmac("sha256", $responseString, $openid_hmacsecret, true));
	if (strlen($hmac) != 44) die('failed HMAC calculation');
	$response['openid.sig'] = $hmac;
	
	// add to db
	$db = DB::get();
	if (false === $db->query("INSERT INTO openid (hmac, nonce) VALUES (?,?)", array($hmac, $response['openid.response_nonce']))) {
			handleCheckidSetup($reqfields, "Es ist ein Datenbankfehler aufgetreten. Versuche es später noch einmal.");
			return;
	}
	
	// send response
	sendIndirectResponse($response, $reqfields['openid.return_to']);
}

function handleCheckAuth($reqfields) {
	$reqString = getKeyValueString($reqfields, $reqfields['openid.signed']);
	if ($reqString === null) { // invalid fields
		sendDirectResponse(array('is_valid'=>'false'));
		return;
	}
	global $openid_hmacsecret;
	$hmac = base64_encode(hash_hmac("sha256", $reqString, $openid_hmacsecret, true));
	if (strlen($hmac) != 44) die('failed HMAC calculation');
	if ($hmac !== $reqfields['openid.sig']) {
		sendDirectResponse(array('is_valid'=>'false'));
		return;
	}
	
	$db = DB::get();
	if (false === $db->query("DELETE FROM openid WHERE hmac = ? AND nonce = ?", array($hmac, $reqfields['openid.response_nonce']))
			|| !$db->statement || $db->statement->rowCount() !== 1) {
		sendDirectResponse(array('is_valid'=>'false'));
		return;
	}
	
	sendDirectResponse(array('is_valid'=>'true'));
}

function validURL(&$url) {
	if ( empty($url) ) return false;
	if ( strpos($url, "https://") !== 0 ) return false;	// ensures https AND avoids "javascript:" urls
	if ( !preg_match('|^[a-zA-Z0-9$_.+!*\'(),/?=&#;:%-]+$|', $url) ) return false;
	if( !filter_var($url, FILTER_VALIDATE_URL) ) return false;
	return true;
}


// Main dispatcher

$reqfields = getOpenIDFields();

/* DEBUG
header("Content-Type: text/plain");
var_dump($reqfields);
die();
//*/

// Handle invalid requests
if (empty($reqfields['openid.mode']) || empty($reqfields['openid.ns']) || $reqfields['openid.ns'] !== 'http://specs.openid.net/auth/2.0') handleFieldsError();
elseif (!validURL($reqfields['openid.return_to'])) handleFieldsError("Return-URL ungültig (Hinweis: nur https-URLs werden akzeptiert)");

// Handle responses from user
elseif (!empty($_POST['action']) && $_POST['action'] == "cancel") sendIndirectResponse(array('openid.mode'=>'cancel'), $reqfields['openid.return_to']);
elseif (!empty($_POST['action']) && $_POST['action'] == "confirm") handleUserConfirm($reqfields);

// Handle OpenID requests
else {
	$mode = $reqfields['openid.mode'];
	switch ($mode) {
		case 'associate': sendDirectError(array('error'=>'Association not supported, use direct verification', 'error_code'=>'unsupported-type')); break;
		case 'checkid_immediate': handleCheckidImmediate($reqfields); break;
		case 'checkid_setup': handleCheckidSetup($reqfields); break;
		case 'check_authentication': handleCheckAuth($reqfields); break;
		default: sendIndirectError("Unknown openid.mode", $reqfields['openid.return_to']);
	}
}


?>