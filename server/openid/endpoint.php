<?php 
require_once('../includes/techheader.inc.php');

// Checks if the given key-value pair is valid, i.e. is set, is a string, and does not contain newlines (key and value) or colons (key only)
// Additionally, length restrictions (key: 250, value: 2500) are imposed.
//   $key: the key to check
//   $value: the value to check
// returns: true if valid, false if invalid 
function isValidKeyValue(&$key, &$value) {
	if ( !isset($key) || !isset($value) || !is_string($key) || !is_string($value) ) return false;
	if ( strpos($key, ':') !== false ) return false;
	if ( strpos($key, "\n") !== false ) return false;
	if ( strpos($value, "\n") !== false ) return false;
	if (strlen($key) > 250 || strlen($value) > 2500) return false;
	return true;
}

// Encodes the supplied fields in key:value encoding.
//   $fields: named array of OpenID fields, including the "openid." prefix in the name.
//   $order: comma-separated lists of field names WITHOUT the "openid." prefix (used to get KV encoding for signatures)
//           If order is given, encodes only the named fields in the named order, and returns null if one of the fields does not exist
// returns: values as encoded KV-form string or null on error (invalid field name in $order, invalid key/value)
function getKeyValueString($fields, $order = null) {
	if ($order === null) {
		$result = "";
		foreach ($fields as $key => $value) {
			if (!isValidKeyValue($key, $value)) return null;
			$result .= "$key:$value\n";
		}
		return $result;
	} else {
		$result = "";
		$orderarr = explode(',',$order);
		foreach ($orderarr as $keyname) {
			$keyname = "openid.$keyname";
			if (!isValidKeyValue($keyname, $fields[$keyname])) return null;
			$result .= "$keyname:".$fields[$keyname]."\n";
		}
		return $result;
	}
}

// Prints hidden form fields for indirect responses and re-submissions that contain the given (OpenID) key-value-pairs
//   $reqfields: the OpenID request fields (named array of OpenID fields, including the "openid." prefix in the name)
// returns: nothing, dies on invalid fields
function printOpenIDFields($reqfields) {
	foreach ($reqfields as $key => $value) {
		if (!isValidKeyValue($key,$value)) die("Invalid key or value");
		echo '<input type="hidden" name="'.htmlspecialchars($key).'" value="'.htmlspecialchars($value).'">';
	}
}

// Sends an indirect response (i.e. a HTML form that will be submitted to the target by the browser)
//   $fields: named array of OpenID fields, including the "openid." prefix in the name.
//   $target: URL to which the form will be sent
//   $isError: Boolean indicating if this is an error response (influences text displayed to user)
// returns: nothing
function sendIndirectResponse($fields, $target, $isError = false) {
	$fields['openid.ns'] = 'http://specs.openid.net/auth/2.0';
	$PAGETITLE = 'Authentifikation abgeschlossen';
	include('../includes/header.inc.php');
	if (!$isError) {
		?>
		<h2>Fertig</h2>
		<p>Die PiratenID-Authentifikation ist abgeschlossen.</p>
		<?php
	} else {
		?>
		<h2>Fehler</h2>
		<p class="error">Die PiratenID-Authentifikation ist fehlgeschlagen.</p>
		<?php
	}
	?>
	<p>
		Mit einem Klick auf den unten stehenden Button gelangst du zurück zur anfragenden Seite.
		Solltest du nach dem Klick auf den Button z. B. aufgefordert werden, ein Kennwort einzugeben, stammt diese Aufforderung nicht mehr vom ID-System!
	</p>
	<script>
		function updateSkipSetting(sourcebox) {
			document.cookie="piratenid_noexitwarning="+sourcebox.checked+"; expires=Mon Feb 01 2038 00:00:00 GMT;";
		}
	</script>
	<p>
		<input type="checkbox" onchange="updateSkipSetting(this)">Warnung automatisch überspringen (Cookies + JavaScript erforderlich)
	</p>
	<?php
	echo '<form name="piratenid_responseform" action="'. htmlspecialchars($target).'" method="POST" accept-charset="utf-8">';
	printOpenIDFields($fields);
	?>
	<input type="submit" value="Zurück zur anfragenden Seite &gt;&gt;&gt;">
	</form>
	<script type="text/javascript">
		if (document.cookie.indexOf("piratenid_noexitwarning=true") > -1) { // good enough for this purpose
			document.forms['piratenid_responseform'].submit();
		}
	</script>
	<?php
	include('../includes/footer.inc.php');
}

// Sends an indirect error response (see also: sendIndirectResponse)
//   $error: Error message (string)
//   $target: URL to which the response will be sent
// returns: nothing
function sendIndirectError($error, $target) {
	sendIndirectResponse(array('openid.mode' => 'error', 'openid.error' => $error), $target, true);
}

// Sends a response to a direct request (i.e. text/plain answer directly to the requesting party)
//   $fields: Array of fields to include, exactly as supposed to be encoded
// returns: nothing
function sendDirectResponse($fields) {
	$fields['ns'] = 'http://specs.openid.net/auth/2.0';
	header('Content-Type: text/plain');
	echo getKeyValueString($fields);
}

// Sends an error response to a direct request
//   $error: The error string to send
// returns: nothing
function sendDirectError($error) {
	header("HTTP/1.0 400 Bad Request"); // as required by standard
	sendDirectResponse(array('error'=>$error));
}

// Retrieves the "openid." fields from the request, be it POST or GET
//    $error: On error, an error message will be put into this variable
// returns: a named array containing the fields, including the "openid." prefix in the name
function getOpenIDFields(&$error) {
	// prefiltering done manually - type guaranteed by explode, isset() is checked,
	// empty values in key will be rejected by substring-test, in value they are allowed,
	// length (especially of openid.signed field) can become rather large - checked, but allows up to 2.5kb for value
	if ($_SERVER['REQUEST_METHOD'] === "POST") {
		if ($_SERVER["CONTENT_TYPE"] !== "application/x-www-form-urlencoded") {
			$error = "Falscher Content-Type";
			return false;
		}
		$source = file_get_contents('php://input');
	} else {
		$source = $_SERVER['QUERY_STRING'];
	}
	$pairs = explode('&', $source);
	$result = array();
	
	foreach ($pairs as $pair) {
		$pairarr = explode("=",$pair);
		if (!isset($pairarr[0]) || !isset($pairarr[1])) {
			$error = "Ungültige Parameter";
			return false;
		}
		$key = urldecode($pairarr[0]);
		$value = urldecode($pairarr[1]);
		if (substr($key,0,7) === "openid.") {
			if (!isValidKeyValue($key, $value)) {
				$error = "Ungültige Parameter";
				return false;
			}
			$result[$key] = $value;
		}
	}
	return $result;
}

// Handles a request with invalid OpenID fields - no return to the returnURL will be made as fields are considered too broken.
//   $reason: Optional text that will be displayed
// returns: nothing
function handleFieldsError($reason = "") {
	$PAGETITLE = 'Fehler';
	include('../includes/header.inc.php');
	?>
		<h2>OpenID-Fehler</h2>
		<p>Dies ist ein Endpoint für OpenID 2.0.<br>Es wurde keine (gültige) OpenID 2.0-Anfrage übermittelt.</p>
	<?php
		echo '<p type="error">'.htmlspecialchars($reason).'</p>';
	include('../includes/footer.inc.php');
}

// Handles (unsupported) "immediate" OpenID requests by sending the appropriate response indicating that this is not supported.
//   $reqfields: the OpenID request fields (named array of OpenID fields, including the "openid." prefix in the name)
// returns: nothing
function handleCheckidImmediate($reqfields) {
	sendIndirectResponse(array('openid.mode'=>'setup_required'), $reqfields['openid.return_to']);
}

// Checks and parses the openid.* fields for auth requests and confirmations
//   $reqfields: the OpenID request fields (named array of OpenID fields, including the "openid." prefix in the name)
//   $error: On error, an error message will be put into this variable
//   $usePseudonym: This variable is set to indicate if the fields ask for an anonymous (false) or pseudonymous (true) authentication
//   $implicitMembership: This variable is set to indicate if only logins by verified members should be accepted
//   $attributes: This variable is set to a numbered array containing the names of the requested attributes
// returns: true on success, false if errors are detected (note values returned in call-by-reference vars!)
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
		$error = "realm is not a valid HTTPS url";
		return false;
	}
	
	// realm must start with https:// and end with slash, must NOT contain query parameters (?param1=value1&param2=value2) or fragment (#anchor)
	if (!preg_match('%^https://[a-zA-Z0-9$_.+!*\'(),/;:-]+/$%D', $reqfields['openid.realm']) ) {
		$error = "realm must start with https:// and end with slash, must NOT contain query parameters or fragment (#anchor)";
		return false;
	}
	
	// check return_to (general URL validity already checked)
	if (strpos($reqfields['openid.return_to'], $reqfields['openid.realm']) !== 0) {
		$error = "return_to does not match realm";
		return false;
	}
	
	// check referer
	// just an additional check to make CSRF and similar more annoying to try (the password in each request is the real protection)
	if ( !empty($_SERVER['HTTP_REFERER']) ) { // do not reject clients that refuse to send a referer
		
		// ignore port number on realm for referer checking (required for example for JanRain)
		$cleanedRealm = preg_replace('|(https://[^/]+):443/|D', "$1/", $reqfields['openid.realm']);
		
		global $sitepath;
		if ( strpos($_SERVER['HTTP_REFERER'], $cleanedRealm) !== 0 && strpos($_SERVER['HTTP_REFERER'], $sitepath) !== 0) {
			$error = "referer exists but is invalid - must come from specified domain (or ID system) and be HTTPS";
			return false;
		}
	}

	$usePseudonym = isset($reqfields['openid.claimed_id']) || isset($reqfields['openid.identity']);

	$implicitMembership = true; // init
	
	// check attribute list
	if ( isset($reqfields['openid.ax.mode']) && $reqfields['openid.ax.mode'] === 'fetch_request' ) {
		// precheck
		if ( !isset($reqfields['openid.ax.required']) || !preg_match('%^[a-z_-]+(,[a-z_-]+)*$%D', $reqfields['openid.ax.required']) ) {
			$error = "invalid AX attribute list";
			return false;
		}
		
		// attribute whitelist and type checking
		$supported = array('mitgliedschaft-bund','mitgliedschaft-land','mitgliedschaft-bezirk','mitgliedschaft-kreis','mitgliedschaft-ort', 'stimmberechtigt');
		
		// Die Abfrage von Realidentitätsdaten ist fürs Erste deaktiviert.
		/*
		global $extendedAttributeRealms;
		if (in_array($reqfields['openid.realm'], $extendedAttributeRealms, true)) {
			$supported[] = 'realname';				
			$supported[] = 'mitgliedsnummer';				
		}
		*/
		
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

// Handles OpenID authentication requests by printing the appropriate form
//   $reqfields: the OpenID request fields (named array of OpenID fields, including the "openid." prefix in the name)
//   $errormessage: an optional error message to display (if this is a retry, for example after a wrong password was entered)
// returns: nothing
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
			foreach ($attribarray as $attrib) {
				$attribtext = "";
				switch ($attrib) {
					case 'mitgliedschaft-bund': $attribtext = 'Die Information, ob du in der Piratenpartei Mitglied bist'; break;
					case 'mitgliedschaft-land': $attribtext = 'Die Information, in welchem Landesverband du Mitglied bist'; break;
					case 'mitgliedschaft-bezirk': $attribtext = 'Die Information, in welchem Bezirksverband du Mitglied bist'; break;
					case 'mitgliedschaft-kreis': $attribtext = 'Die Information, in welchem Kreisverband du Mitglied bist'; break;
					case 'mitgliedschaft-ort': $attribtext = 'Die Information, in welchem Ortsverband du Mitglied bist'; break;
					case 'stimmberechtigt': $attribtext = 'Die Information, ob du stimmberechtigt bist'; break;
					case 'realname': $attribtext = '<span class="attribut-kritisch">Dein voller Name</span>'; break;
					case 'mitgliedsnummer': $attribtext = '<span class="attribut-kritisch">Deine Mitgliedsnummer bei der Piratenpartei</span>'; break;
					default: die("FEHLER - UNBEKANNTES ATTRIBUT. BITTE VORGANG ABBRECHEN UND DER IT MELDEN."); break; // should not be able to happen, attribs are verified
				}
				$attribhtml .= "\t\t\t<li>".$attribtext ."</li>\n";
			}
		}
		$PAGETITLE = 'Login';
		include('../includes/header.inc.php');
		?>
		<h2>Identifizierungsanfrage</h2>
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
			<?php
				printOpenIDFields($reqfields);
			?>
			<input type="hidden" name="action" value="confirm">
			<table>
				<?php printLoginFields(); ?>
				<tr><td>&nbsp;</td><td><input type="submit" value="Anmelden"></td></tr>
			</table>
			</form>
		</div>
		<div>
			<form action="" method="POST" accept-charset="utf-8">
			<?php
				printOpenIDFields($reqfields);
			?>
			<input type="hidden" name="action" value="cancel">
			<input type="submit" value="Vorgang abbrechen">
			</form>
		</div>
		<?php
		include('../includes/footer.inc.php');
	}
}

// Adds AX fields to an OpenID response field array
//   $response: the response array that will be extended
//   $attribarray: the numbered array containing the names of the attributes to add
//   $userdata: the user data array (from the database) containing the user data
//   $error: On error, an error message will be put into this variable
// returns: true on success, false if some attributes could not be added
function addAXAttributes(&$response, $attribarray, $userdata, &$error) {
	$response["openid.ns.ax"] = "http://openid.net/srv/ax/1.0";
	$response["openid.ax.mode"] = "fetch_response";
	$response["openid.signed"] .= ",ax.mode,ns.ax";
	foreach ($attribarray as $attrib) {
		switch ($attrib) {
			case 'realname': // falltrough
			case 'mitgliedsnummer': // falltrough!
			case 'mitgliedschaft-bund': // falltrough
			case 'mitgliedschaft-land': // falltrough
			case 'mitgliedschaft-bezirk': // falltrough
			case 'mitgliedschaft-kreis': // falltrough
			case 'mitgliedschaft-ort': // falltrough
			case 'stimmberechtigt':
				// always available for members, but may be empty. undef/null if no valid token provided.
				if (!isset($userdata[$attrib]) || $userdata[$attrib] === null) {
					// Explizite Abfrage von mitgliedschaft-bund wäre sinnlos, wenn wir bei fehlendem Token fehlschlagen lassen
					//  $error = "Dieser Nutzer hat nicht alle angeforderten Attribute (Token eingetragen?)";
					//  return false;
					$userdata[$attrib] = "";
				}
				if (strpos($userdata[$attrib], "\n") !== false ) {
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

// Handles the POST with which the user confirms that he wants to perform the authentication (containing username and password)
// Checks the login and creates the OpenID response.
//   $reqfields: the OpenID request fields (named array of OpenID fields, including the "openid." prefix in the name)
// returns: nothing
function handleUserConfirm($reqfields) {
	$error = null;
	$usePseudonym = false;
	$implicitMembership = false;
	$attribarray = null;
	
	// verify input (in case of attacks - errors by mistake are already caught when the data first arrives in handleCheckidSetup()
	if (!evaluateFields($reqfields, $error, $usePseudonym, $implicitMembership, $attribarray)) {
		$PAGETITLE = 'Fehler';
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
		handleCheckidSetup($reqfields, $error); // show form again with login error
		return;
	}
	
	if ( $implicitMembership !== false && (empty($userdata['mitgliedschaft-bund']) || $userdata['mitgliedschaft-bund'] !== 'ja') ) {
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
	if (empty($openid_hmacsecret)) die("missing HMAC secret");
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


// Handles the (direct) check_authentication requests from relying parties
// (checks signature against sig value and database)
//   $reqfields: the OpenID request fields (named array of OpenID fields, including the "openid." prefix in the name)
// returns: nothing
function handleCheckAuth($reqfields) {
	$reqString = getKeyValueString($reqfields, $reqfields['openid.signed']);
	if ($reqString == null) { // invalid fields
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

// Checks a (return_to/realm) URL for validity - may be too strict in some places and miss some special cases, but should be secure for this use
// Allows only HTTPS urls.
//   $url: the URL to check
// returns: true if valid, false if not
function validURL(&$url) {
	if ( empty($url) ) return false;
	if ( strpos($url, "https://") !== 0 ) return false;	// ensures https AND avoids "javascript:" urls
	if ( !preg_match('|^[a-zA-Z0-9$_.+!*\'(),/?=&#;:%-]+$|D', $url) ) return false;
	if( !filter_var($url, FILTER_VALIDATE_URL) ) return false;
	return true;
}


// Main dispatcher
$error = null;
$reqfields = getOpenIDFields($error);

/* DEBUG
header("Content-Type: text/plain");
var_dump($reqfields);
die();
//*/

// Handle invalid requests
if (empty($reqfields) || !$reqfields || empty($reqfields['openid.mode']) || empty($reqfields['openid.ns']) || $reqfields['openid.ns'] !== 'http://specs.openid.net/auth/2.0') handleFieldsError($error);
elseif (!validURL($reqfields['openid.return_to'])) handleFieldsError("Return-URL ungültig (Hinweis: nur https-URLs werden akzeptiert)");

// Handle responses from user
elseif (!empty($_POST['action']) && $_POST['action'] === "cancel") sendIndirectResponse(array('openid.mode'=>'cancel'), $reqfields['openid.return_to']);
elseif (!empty($_POST['action']) && $_POST['action'] === "confirm") handleUserConfirm($reqfields);

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