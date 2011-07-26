<?php

class PiratenID {
	// Set these parameters before calling run() - no need to modify this file, see example.php if unsure
	public static $realm = null;          // OpenID realm to use. MANDATORY. Most often set to the site root, i.e. 'https://www.example.com/'.
											// Security critical, must be under your exclusive control, do NOT use values from $_SERVER!
											// See documentation for format restrictions.
	public static $returnurl = null;      // OpenID return_to URL. Optional, must start with realm if set. Otherwise, will be auto-detected.
	public static $imagepath = '';        // String to prepend in front of button image URLs, i.e. '', '/', '/piratenid/' or 'https://images.example.com/'
	public static $attributes = '';       // Comma-separated list of attributes to request. See documentation for list of attributes.
	                                      // Note that 'mitgliedschaft-bund' has a special meaning (requesting it also allows non-member logins)
	public static $usePseudonym = true;   // True if the pseudonym should be requested, false for anonymous authentication (useful only in very special cases).
	
	public static $logouturl = null;      // URL to which the logout button directs the user. Defaults to realm.
											// See also $handleLogout.
	public static $handleLogout = true;   // If true, run() will generate a random token once the user logs in.
											// A GET parameter (piratenid_logout) containing that token will be appended to the logout URL.
											// run() will look for that parameter and log the user out if the correct value is detected.
											// The parameter will be removed from the $_GET array.
											// As long as you use the default button and make sure that run() is called on requests to the logout URL,
											// this will take care of your entire logout handling.
										
	public static $loginCallback = null;  // Allows to specify a login callback.
											// run() will call this in case of a successful login before actually performing the login.
											// The array returned by handle() will be passed as a parameter
											// The callback should return null to allow the login, or an error message.
											// If a non-null value is returned, the login is not performed and the error message is shown.
											// This can be used for example to implement a user blacklist or more specific attribute requirements.
											
	public static $logoutCallback = null; // Allows to specify a logout callback.
											// run() will call this in case of a successful logout just before actually performing the logout.
											// No parameters are passed; the return value is ignored.
	
	
	// For cookies, will be set by initParams().
	private static $realm_domain = null; 
	private static $realm_path = null;
	
	public static $error = null;
	private static $hasRun = false;
	
	// OpenID endpoint to use (TODO)
	const serverCN   = 'localhost';
	const serverroot = 'https://piratenid.janschejbal.de/';
	const endpoint   = 'https://piratenid.janschejbal.de/openid/endpoint.php';

	
	
	// WARNING: THIS IS NOT AN OpenID CLIENT IMPLEMENTATION
	// This is a *partial* implementation of the OpenID protocol for usage with a single, hardcoded trusted provider only.
	// It does not perform all checks required to ensure security when more than one OpenID provider is accepted!
	// Furthermore, protocol variants not used by the PiratenID software are ignored.

	
	
	
	
	// Processes the request, returning HTML code for a login/logout button to display.
	// You must set the parameters before calling this.
	public static function run() {
		if (self::$hasRun) return self::error('local: run() called multiple times');
		self::$hasRun = true;
		
		self::initSession();
		$errormsg = self::initParams();
		if ($errormsg !== null) return self::error($errormsg);
		
		$logouterror = false;
		if (self::$handleLogout && isset($_GET['piratenid_logout'])) {
			if (!empty($_SESSION['piratenid_user']['logouttoken']) && $_GET['piratenid_logout'] === $_SESSION['piratenid_user']['logouttoken']) {
				if (is_callable(self::$logoutCallback)) {
					call_user_func(self::$logoutCallback);
				}
				$_SESSION['piratenid_user'] = array('authenticated' => false);
			} else {
				$logouterror = true;
			}
			unset($_GET['piratenid_logout']);
		}
		
		if (isset($_POST['openid_mode'])) {
			$result = self::handle();
			if ($result['error'] === null && $result['authenticated'] === true) {
				
				// Login-Callback
				if (is_callable(self::$loginCallback)) {
					$callbackerror = call_user_func(self::$loginCallback, $result);
					if ($callbackerror !== null) {
						return self::error($callbackerror);
					}
				}
				
				// successful authentication, copy information to session
				$_SESSION['piratenid_user']['authenticated'] = true;
				$_SESSION['piratenid_user']['attributes'] = $result['attributes'];
				if (self::$usePseudonym) {
					$_SESSION['piratenid_user']['pseudonym'] = $result['pseudonym'];
				}
				// the logout token generation may not be very secure, but should be good enough for this purpose
				// and is as good as it gets without breaking compatibility
				$_SESSION['piratenid_user']['logouttoken'] = substr(md5(mt_rand().mt_rand().mt_rand().mt_rand()),0,16); 
			} else {
				// error occurred
				return self::error($result['error']);
			}
		}
		
		if ($logouterror) {
			return self::error('logout failed - wrong token');
		}
		
		return self::autoButton();
	}
	
	// set error, return error button
	private static function error($text) {
		$html = self::autoButton($text); // may overwrite self::$error
		self::$error = $text;
		return $html;
	}
	
	// Returns a login/logout button of the appropriate type (login, logout or error), or null if params are invalid
	// The basic type (login/logout) is determined according to the session state, the session is initialized if that has not already happened.
	// If $errortext is set, an error button is returned with the specified text in the tooltip.
	public static function autoButton($errortext = null) {
		if (session_id() == '') self::initSession();
		return self::button($_SESSION['piratenid_user']['authenticated']===true, $errortext);
	}
	
	// Returns a login/logout button of the appropriate type (login, logout or error), or null if params are invalid
	// if $logout is true, a logout-button is generated (otherwise a login-button is generated)
	// If $errortext is set, an error button is returned with the specified text in the tooltip.
	public static function button($logout, $errortext = null) {
		if (self::initParams() !== null) return null;

		if (!$logout) {
			$type = "login";
			$title = "Nicht eingeloggt. Klicken zum Einloggen per PiratenID.";
			$targeturl = self::makeOpenIDURL();
		} else {
			$type = "logout";
			$title = "Eingeloggt per PiratenID. Klicken zum Ausloggen.";
			$targeturl = self::$logouturl;
			if (self::$handleLogout) {
				if (!empty($_SESSION['piratenid_user']['logouttoken'])) {
					$anchor = '';
					if (preg_match('/(#.*)$/', $targeturl, $matches)) { // remove anchor (will be re-added)
						$targeturl = preg_replace('/(#.*)$/', '', $targeturl);
						$anchor = $matches[1];
					}
					$separator = (strpos($targeturl, '?') === false) ? '?' : '&';
					$targeturl = $targeturl . $separator . 'piratenid_logout=' . $_SESSION['piratenid_user']['logouttoken'] . $anchor;
				} else {
					$errortext = 'WRONG USAGE OF PIRATENID LIBRARY. Tried to generate button with $handleLogout=true without correctly initialized session.';
				}
			}
		}
		
		if ($errortext !== null) {
			$type  = 'error';
			$title = "PiratenID-Fehler: $errortext ($title)";
		}
		
		$imgurl = self::$imagepath.'button-'.$type.'.png';
		return '<a title="'.htmlspecialchars($title).'" href="'.htmlspecialchars($targeturl).'">'.
			'<img alt="'.htmlspecialchars($title).'" style="border: none;" width="120" height="48" src="'.htmlspecialchars($imgurl).'"></a>';
	}

	// Logs the user out, if any is logged in (starting the session if necessary)
	public static function logout() {
		if (session_id() == '') self::initSession();
		$_SESSION['piratenid_user'] = array('authenticated' => false);
	}
	
	
	// Securely initializes the session. Call before ANY output (including UTF-8 byte-order-mark or DOCTYPE header).
	// If cookie parameters are set, and the cookie is set to be secue-site only, the parameters are kept.
	// If the cookie is not set to be secure, it will be set to be both secure and HTTP-only.
	// Session ID may be regenerated automatically each call, so do not rely on it.
	// If you set session.use_only_cookies to 1 in the php.ini or allow the script to do it,
	// it will be protected against session fixation without the need to regenerate IDs.
	// If you start the session before this is run, the ID will be regenerated to ensure the cookie security is applied.
	public static function initSession() {
		if (headers_sent()) {
			die('PiratenID: Cannot init session, headers already sent'); // make sure its fatal.
		}
		
		// Try to get better session IDs. As creating them using OpenSSL would be a mess,
		// and the regular algorithm is reasonably secure on current PHP, ignore failure.
		@ini_set('session.entropy_file','/dev/urandom'); // will be ignored on windows
		@ini_set('session.entropy_length','32');

		// Try to enhance security, ignore if it fails (will be detected later)
		@ini_set('session.use_only_cookies',1);

		$cookieChanged = false;
		$params = session_get_cookie_params();
		if (!$params['secure']) {
			session_set_cookie_params(0,self::$realm_path,self::$realm_domain, true, true);
			$cookieChanged = true;
		}
	
		$alreadyStarted = session_id() !== '';
		$onlyCookies = ini_get('session.use_only_cookies') === '1';
		
		if (!$alreadyStarted) session_start();
		
		if ($alreadyStarted || !$onlyCookies || !isset($_SESSION['piratenid_user']) || $cookieChanged) {
			session_regenerate_id(true); // ensure params are applied, prevent session fixation attack
		}

		if (!isset($_SESSION['piratenid_user'])) {
			$_SESSION['piratenid_user']['authenticated'] = false;
		}
	}
	

	// Handles a response from the authentication server.
	// Call when receiving the POST on the return url, or each time you receive a POST with openid_mode set.
	// Checks if the relevant POST fields exist, and if they do, tries to verify the response.
	// returns an array, on error it contains the fields 'error' with the error message and 'authenticated' = false,
	//                   on success it contains 'authenticated' = true, 'error' = NULL, 'attributes' containing the requested attributes,
	//                       'pseudonym' containing a user pseudonym (safe for usage, derived by hashing the identity URL), and
	//                       'rawIdentityURL' containing the raw OpenID identity URL (should not be used if possible)
	public static function handle() {
		
		$result = array('error'=>null, 'authenticated'=>false);
		
		$error = null;
		$postFields = self::getOpenIDFields($error);
		
		if ($error !== null) {
			$result['error'] = 'local: OpenID data error - ' . $error;
			return $result;
		}
		
		$error = self::initParams();
		if ($error !== null) {
			$result['error'] = 'local: Parameter error - ' . $error;
			return $result;
		}
		
		if ( empty($postFields) || empty($postFields['openid.mode']) || empty($postFields['openid.ns']) || $postFields['openid.ns'] !== 'http://specs.openid.net/auth/2.0' ) {
			$result['error'] = 'local: no OpenID response in POST';
			return $result;
		}
		
		if ( $postFields['openid.mode'] == 'cancel' ) {
			$result['error'] = 'user: cancelled';
			return $result;
		}

		if ( $postFields['openid.mode'] == 'error' ) {
			$result['error'] = 'remote: '.$postFields['openid.error'];
			return $result;
		}
		
		if ( $postFields['openid.mode'] !== 'id_res' ) {
			$result['error'] = 'local: unknown openid.mode';
			return $result;
		}
		
		if ( $postFields['openid.return_to'] !== self::$returnurl ) {
			$result['error'] = 'local: return url mismatch';
			return $result;
		}
		
		if ( $postFields['openid.op_endpoint'] !== self::endpoint ) {
			$result['error'] = 'local: endpoint mismatch';
			return $result;
		}
		
		$requiredSignedFields = array('op_endpoint', 'return_to', 'response_nonce', 'assoc_handle');
		
		if ( self::$usePseudonym ) {
			if (empty($postFields['openid.identity']) || empty($postFields['openid.claimed_id']) ) {
				$result['error'] = 'local: pseudonym requested but not provided';
				return $result;
			}
			if ($postFields['openid.identity'] !== $postFields['openid.claimed_id'] ) {
				$result['error'] = 'local: claimed_id / identity mismatch';
				return $result;
			}
			if (preg_match('|^'.str_replace('.','\\.',self::serverroot).'openid/pseudonym\\.php\\?id=[0-9a-f]{64}$|', $postFields['openid.identity'])) {
				$pseudonym = hash('sha256', $postFields['openid.identity']);
				$rawIdentityURL = $postFields['openid.identity'];
				if (strlen($pseudonym) !== 64) die('Pseudonym hashing failed');
			} else {
				$result['error'] = 'local: invalid pseudonym format (pseudonym must start with serverroot)';
				return $result;
			}
			$requiredSignedFields[] = 'identity';
			$requiredSignedFields[] = 'claimed_id';
		} else {
			if (!empty($postFields['openid.identity']) || !empty($postFields['openid.claimed_id']) ) {
				$result['error'] = 'local: pseudonym not requested but provided';
				return $result;
			}
		}
		
		if ( self::$attributes === null ) {
			if (!empty($postFields['openid.ax.mode']) ) {
				$result['error'] = 'local: no attributes requested but got attribute response';
				return $result;
			}
		} else {
			if (empty($postFields['openid.ax.mode']) || $postFields['openid.ax.mode'] !== 'fetch_response' ) {
				$result['error'] = 'local: attributes requested but not provided';
				return $result;
			}
			$requiredSignedFields[] = 'ax.mode';
			$reqAttrArray = explode(',',self::$attributes);
			$tmpAttributes = array();
			foreach ($reqAttrArray as $attr) {
				if (!isset($postFields["openid.ax.value.$attr"])) {
					$result['error'] = 'local: requested attribute(s) missing';
					return $result;				
				}
				if (empty($postFields["openid.ax.type.$attr"]) || $postFields["openid.ax.type.$attr"] !== "https://id.piratenpartei.de/openid/schema/$attr" ) {
					$result['error'] = 'local: invalid attribute type';
					return $result;				
				}
				$requiredSignedFields[] = "ax.type.$attr";
				$requiredSignedFields[] = "ax.value.$attr";

				$tmpAttributes[$attr] = $postFields["openid.ax.value.$attr"];
			}
		}
		
		// check if necessary fields signed
		$actualSignedFields = explode(',',$postFields['openid.signed']); 
		foreach ($requiredSignedFields as $field) {
			if (!in_array($field, $actualSignedFields)) {
				$result['error'] = 'local: not all required fields are signed';
				return $result;
			}
		}
		
		// Additional check: Check that ALL fields are signed
		foreach ($postFields as $field => $value) {
			if ($field === "openid.mode") continue;
			if ($field === "openid.signed") continue;
			if ($field === "openid.sig") continue;
			if ($field === "openid.ns") continue;
			if (!in_array(substr($field,7), $actualSignedFields)) {
				$result['error'] = 'local: unexpected unsigned fields in response';
				return $result;
			}
		}
		
		$error = null;
		if (self::checkSignature($postFields, $error) !== true) {
				$result['error'] = 'local: signature verification failed - '.$error;
				return $result;			
		}
		
		// set attributes etc.
		$result['authenticated'] = true;
		$result['error'] = null;
		$result['attributes'] = $tmpAttributes;
		if (self::$usePseudonym) {
			$result['pseudonym'] = $pseudonym;
			$result['rawIdentityURL'] = $rawIdentityURL;
		}
		
		return $result;
	}
	
	// Returns the URL to start the OpenID request. Make sure all settings are set before you call this.
	public static function makeOpenIDURL() {
		self::$error = self::initParams();
		if (self::$error !== null) return null;
	
		$req = self::getOpenIDRequest();
	
		return self::endpoint .'?'. http_build_query($req,'','&');
	}
	
	// Returns the fields for a OpenID request with the currently set parameters as an associative array (or null if parameters are invalid)
	public static function getOpenIDRequest() {
		self::$error = self::initParams();
		if (self::$error !== null) return null;
		
		$fields = array(
			'openid.ns'         => 'http://specs.openid.net/auth/2.0',
			'openid.mode'       => 'checkid_setup',
			'openid.realm'      => self::$realm,
			'openid.return_to'  => self::$returnurl
		);
		
		if (self::$usePseudonym) {
			$fields['openid.claimed_id'] = 'http://specs.openid.net/auth/2.0/identifier_select';
			$fields['openid.identity']   = 'http://specs.openid.net/auth/2.0/identifier_select';
		}
		
		if (!empty(self::$attributes)) {
			$fields['openid.ns.ax']       = 'http://openid.net/srv/ax/1.0';
			$fields['openid.ax.mode']     = 'fetch_request';
			$fields['openid.ax.required'] = self::$attributes;

			$reqAttrArray = explode(',',self::$attributes);
			foreach ($reqAttrArray as $attr) { // $attr can only contain characters in [a-z-]
				$fields["openid.ax.type.$attr"] = "https://id.piratenpartei.de/openid/schema/$attr";
			}
		}
		return $fields;
	}

	// Checks parameters, initializes defaults.
	// returns: null if everything ok, error string otherwise
	private static function initParams() {
		if (self::$realm == null) return 'local: realm not set';
		// Find base (domain) in realm, and verify realm
		if (!preg_match('%^(https://[a-zA-Z0-9.-]+)(/(?:[a-zA-Z0-9$_.+!*\'(),/;:-]+/)?)$%', self::$realm, $matches)) return 'local: invalid realm';
		self::$realm_domain = $matches[1];
		self::$realm_path = $matches[2];
		if (self::$returnurl == null) {
			$uri = $_SERVER['REQUEST_URI'];
			if (self::$handleLogout) {
				$uri = preg_replace('/[?&]piratenid_logout=[a-f0-9]{16}$/',"",$uri);
			}
			self::$returnurl = $matches[1].$uri; // request_uri may be malicious, but all outputs are escaped.
		}
		if (!preg_match('%^([a-z-]+)?(,([a-z-]+))*$%', self::$attributes)) return 'local: invalid attribute list';
		if (self::$logouturl === null) self::$logouturl = self::$realm;
		return null;
	}
	
	// Tests/guesses if the current page is being loaded via HTTPS
	public static function isSSL() {
		if ($_SERVER['SERVER_PORT']==443) return true;
		if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS']==='on') return true;
		return false;
	}
	
	// Checks an OpenID signature with the OpenID provider (dumb mode)
	private static function checkSignature($fields, &$error) {
		$fields['openid.mode'] = 'check_authentication';
		$urlEncodedFields = http_build_query($fields, '', '&');
		$options = array(
				'http' => array(
					'method' => 'POST',
					'header'  => 'Content-type: application/x-www-form-urlencoded',
					'user_agent' => "phpPiratenIDclient/1.0",
					'content' => $urlEncodedFields,
					'max-redirects' => 0,
					'timeout' => 10,
					'ignore_errors' => false
				),
				'ssl' => array(
					'verify_peer'       => true,
					'CN_match'          => self::serverCN,
					'verify_depth'      => 9,     // OpenSSL default, only to prevent problems in case of insane PHP defaults
					'allow_self_signed' => false,
					'capture_peer_cert' => false, // Change to be able to inspect certificate
					'ciphers'           => "aRSA+kEDH+TLSv1+HIGH", // only high-security TLSv1 ciphers featuring ephemeral keys and RSA authentication allowed
					'cafile'            => __DIR__."/certificate.pem" // This file shall contain the cert of the server or the CA used for that cert
				)
			);
		$context = stream_context_create($options);
		$response = @file_get_contents(self::endpoint, false, $context);
		if (!$response) {
			$error = "could not get response from server";
			return false;
		}
		
		// Parse KV form
		$lines = explode("\n", $response);
		$responseArray = array();
		foreach ($lines as $line) {
			if ($line == '') continue;
			$parts = explode(":",$line, 2);
			if (count($parts) != 2 || !self::isValidKeyValue($parts[0], $parts[1])) {
				$error = "invalid response from server";
				return false;
			}
			$responseArray[$parts[0]] = $parts[1];
		}
		
		if (empty($responseArray['ns']) || $responseArray['ns'] !== 'http://specs.openid.net/auth/2.0' ) {
			$error = "invalid response from server";
			return false;
		}
		
		if (!empty($responseArray['is_valid']) && $responseArray['is_valid'] === 'true') {
			return true;
		} else {
			$error = "server rejected signature";
			return false;
		}
		
	}
	
	private static function getOpenIDFields(&$error) {
		// prefiltering done manually - type guaranteed by explode, isset() is checked,
		// empty values in key will be rejected by substring-test, in value they are allowed, length is checked.
		if ($_SERVER['REQUEST_METHOD'] === 'POST') {
			if ($_SERVER['CONTENT_TYPE'] !== 'application/x-www-form-urlencoded') {
				$error = 'Falscher Content-Type';
				return false;
			}
			$source = file_get_contents('php://input');
		} else {
			$source = $_SERVER['QUERY_STRING'];
		}
		$pairs = explode('&', $source);
		$result = array();
		foreach ($pairs as $pair) {
			$pairarr = explode('=',$pair);
			if (!isset($pairarr[0]) || !isset($pairarr[1])) {
				$error = 'Ungültige Parameter';
				return false;
			}
			$key = urldecode($pairarr[0]);
			$value = urldecode($pairarr[1]);
			if (substr($key,0,7) === 'openid.') {
				if (!self::isValidKeyValue($key, $value)) {
					$error = 'Unzulässiger Parameter';
					return false;
				}
				$result[$key] = $value;
			}
		}
		return $result;
	}
	
	// Checks if the given key-value pair is valid, i.e. is set, is a string, and does not contain newlines (key and value) or colons (key only)
	// Additionally, length restrictions (key: 250, value: 2500) are imposed.
	//   $key: the key to check
	//   $value: the value to check
	// returns: true if valid, false if invalid 
	private static function isValidKeyValue(&$key, &$value) {
		if ( !isset($key) || !isset($value) || !is_string($key) || !is_string($value) ) return false;
		if ( strpos($key, ':') !== false ) return false;
		if ( strpos($key, "\n") !== false ) return false;
		if ( strpos($value, "\n") !== false ) return false;
		if (strlen($key) > 250 || strlen($value) > 2500) return false;
		return true;
	}	
}

// Require SSL if this file is included
if (!PiratenID::isSSL()) die('PiratenID included on non-HTTPS page. You will be handling sensitive user data and are required to use it on the whole site.');

?>