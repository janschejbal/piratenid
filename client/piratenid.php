<?php

die("incomplete - especially, the signature verification is missing. DO NOT EVEN THINK ABOUT USING THIS.");

class PiratenID {
	// OpenID endpoint to use
	const serverroot = "https://piratenid.janschejbal.de/";

	// WARNING: THIS IS NOT AN OpenID CLIENT IMPLEMENTATION
	// This is a partial implementation of the OpenID protocol for usage with a single trusted provider.
	// It does not perform all checks required to ensure security when more than one OpenID provider is accepted!
	// Furthermore, protocol variants not used by the PiratenID software are ignored.

	// static convenience methods that automate session-handling
	// These methods wrap the class methods below, applying them to an automatically created instance that is stored in the session
	
	
	// initializes the session. Call before ANY output (including UTF-8 byte-order-mark or DOCTYPE header).
	// If cookie parameters are set, and the cookie is set to be secue-site only, the parameters are kept.
	// If the cookie is not set to be secure, it will be set to be both secure and HTTP-only.
	// Session ID may be regenerated automatically each call, so do not rely on it.
	// If you set session.use_only_cookies to 1 in the php.ini or allow the script to do it,
	// it will be protected against session fixation without the need to regenerate IDs.
	// If you start the session before this is run, the ID will be regenerated to ensure the cookie security is applied.
	static function session_init() {
		if (headers_sent()) {
			die("Cannot init session, headers already sent"); // make sure its fatal.
		}
		
		// Try to get better session IDs. As creating them using OpenSSL would be a mess,
		// and the regular algorithm is reasonably secure on current PHP, ignore failure.
		@ini_set("session.entropy_file",'/dev/urandom'); // will be ignored on windows
		@ini_set("session.entropy_length",'32');

		// Try to enhance security, ignore if it fails (will be detected later)
		@ini_set("session.use_only_cookies",1);

		$params = session_get_cookie_params();
		if (!$params['secure']) session_set_cookie_params($params['lifetime'],$params['path'],$params['domain'], true, true);
	
		$alreadyStarted = session_id() !== "";
		$onlyCookies = ini_get("session.use_only_cookies") === '1';
		
		if (!$alreadyStarted) session_start();
		if ($alreadyStarted || !$onlyCookies) session_regenerate_id(true); // ensure params are applied, prevent session fixation attack

		if (empty($_SESSION['piratenid_instance'])) {
			self::storeToSession(new PiratenID());
		}
	}
	
	static function session_isAuthenticated() {
		return self::getFromSession()->isAuthenticated();
	}
	
	static function session_getAttributes() {
		return self::getFromSession()->getAttributes();
	}

	static function session_pollError() {
		$instance = self::getFromSession();
		$result = $instance->pollError();
		self::storeToSession($instance);
		return $result;
	}
	
	static function session_handle() {
		$instance = self::getFromSession();
		$result = $instance->handle();
		self::storeToSession($instance);
		return $result;
	}
	
	static function session_printLoginForm($returnurl, $realm, $pseudonym = true, $attributes = null) {
		$instance = self::getFromSession();
		$result = $instance->printLoginForm($returnurl, $realm, $pseudonym, $attributes);
		self::storeToSession($instance);
		return $result;
	}
	
	static function session_reset() {
		$instance = self::getFromSession();
		$instance->reset();
		self::storeToSession($instance);
	}

	
	private static function getFromSession() {
		if (empty($_SESSION['piratenid_instance'])) die("Uninitialized session used in PiratenID");
		return unserialize($_SESSION['piratenid_instance']);
	}
	
	private static function storeToSession($instance) {
		$_SESSION['piratenid_instance'] = serialize($instance);
	}


	private static function safeout(&$text) {
		if (empty($text)) return false;
		echo htmlspecialchars($text, ENT_QUOTES);
		return true;
	}
	
	private $authenticated = false;
	private $error = null;
	private $attributes = array();
	
	private $returnurl = null;
	private $usePseudonym = true;
	private $requestedAttributes = null;
	
	// returns true if the user is authenticated
	function isAuthenticated() {
		if ( $this->blockNonSSL() ) return false;
		return $this->authenticated;
	}
	
	// returns the attributes returned in the last successful authentication attempt (or null if no authentication succeeded yet)
	function getAttributes() {
		if ( $this->blockNonSSL() ) return null;
		return $this->attributes;
	}

	// returns and resets the error value
	function pollError() {
		$err = $this->error;
		$this->error = null;
		return $err;
	}	
	
	// Handles a response from the authentication server, if previously requested using request()
	// Call when receiving the POST on the return url, or each time you receive a POST.
	// Checks if the relevant POST fields exist, and if they do, tries to verify the response.
	// If successfully authenticated, isAuthenticated() will start returning true and you will be able to retrieve the attributes with getAttributes()
	// If any step fails, the old authentication status and attributes are left unchanged. Use reset() to forget them if you want to.
	// returns: true if successful, false if error (use pollError to get error message)
	function handle() {
		if ( $this->blockNonSSL() ) return false;

		$postFields = getOpenIDFields();
		
		if ( empty($postFields) || empty($postFields['openid.mode']) || empty($postFields['openid.ns']) || $postFields['openid.ns'] !== "http://specs.openid.net/auth/2.0" ) {
			$this->error = "local: no OpenID response in POST";
			return false;
		}
		
		if ( empty($this->returnurl) ) {
			$this->error = "local: no outstanding request";
			return false;
		}
		
		if ( $postFields['openid.mode'] == "cancel" ) {
			$this->error = "user: cancelled";
			return false;
		}

		if ( $postFields['openid.mode'] == "error" ) {
			$this->error = "remote: ".$postFields['openid.error'];
			return false;
		}
		
		if ( $postFields['openid.mode'] !== "id_res" ) {
			$this->error = "local: unknown openid.mode";
			return false;
		}
		
		if ( $postFields['openid.return_to'] !== $this->returnurl ) {
			$this->error = "local: return url mismatch";
			return false;
		}
		
		if ( $postFields['openid.op_endpoint'] !== self::serverroot.'openid/endpoint.php' ) {
		if ( $postFields['openid.op_endpoint'] !== self::serverroot.'openid/endpoint.php' ) {
			$this->error = "local: endpoint mismatch";
			return false;
		}
		
		$tmpAttributes = array();
		$requiredSignedFields = array('op_endpoint', 'return_to', 'response_nonce', 'assoc_handle');
		
		if ( $this->usePseudonym ) {
			if (empty($postFields['openid.identity']) || empty($postFields['openid.claimed_id']) ) {
				$this->error = "local: pseudonym requested but not provided";
				return false;
			}
			if ($postFields['openid.identity'] !== $postFields['openid.claimed_id'] ) {
				$this->error = "local: claimed_id / identity mismatch";
				return false;
			}
			if (preg_match('|^'.str_replace('.','\\.',self::serverurl).'openid/openid/pseudonym\\.php\\?id=[0-9a-f]{64}$|', $postFields['openid.identity'])) {
				$tmpAttributes['pseudonym'] = hash('sha256', $postFields['openid.identity']);
				$tmpAttributes['pseudonym_url'] = $postFields['openid.identity'];
				if (str_len($tmpAttributes['pseudonym']) !== 64) die("Pseudonym hashing failed");
			} else {
				$this->error = "local: invalid pseudonym format";
				return false;
			}
			$requiredSignedFields[] = "identity";
			$requiredSignedFields[] = "claimed_id";
		} else {
			if (!empty($postFields['openid.identity'] || !empty($postFields['openid.claimed_id']) ) {
				$this->error = "local: pseudonym not requested but provided";
				return false;
			}
		}
		
		if ( $this->requestedAttributes === null ) {
			if (!empty($postFields['openid.ax.mode']) ) {
				$this->error = "local: no attributes requested but got attribute response";
				return false;
			}
		} else {
			if (empty($postFields['openid.ax.mode'] || $postFields['openid.ax.mode'] !== "fetch_response" ) ) {
				$this->error = "local: attributes requested but not provided";
				return false;
			}
			$requiredSignedFields[] = "ax.mode";
			$reqAttrArray = explode(',',$this->requestedAttributes);
			foreach ($reqAttrArray as $attr) {
				if (!isset($postFields["openid.ax.value.$attr"])) {
					$this->error = "local: requested attribute(s) missing";
					return false;				
				}
				if (empty($postFields["openid.ax.type.$attr"]) || $postFields["openid.ax.type.$attr"] !== "https://id.piratenpartei.de/openid/schema/$attr" ) {
					$this->error = "local: invalid attribute type";
					return false;				
				}
				$requiredSignedFields[] = "ax.type.$attr";
				$requiredSignedFields[] = "ax.value.$attr";

				$tmpAttributes[$attr] = $postFields["openid.ax.value.$attr"];
			}
		}
		
		// check if necessary fields signed
		$actualSignedFields = explode(',',$postFields["openid.signed"]); 
		foreach ($requiredSignedFields as $field) {
			if (!in_array($field, $actualSignedFields)) {
				$this->error = "local: not all required fields are signed";
				return false;
			}
		}
		
		// TODO check signature (remote)
		
		// set attributes etc.
		$this->authenticated = true;
		$this->error = null;
		$this->attributes = $tmpAttributes;
		$this->returnurl = null;
		
		return true;
	}
	
	// Requests authentication by printing a self-submitting HTML login form which will submit to the ID server
	// Parameters:
	//     $returnurl: a URL that will handle the OpenID response. Must be inside realm.
	//     $realm: The realm for which authentication is requested. Must end with a / (i.e. be a directory).
	//             Current URL and returnurl must be inside realm, https is required.
	//             The pseudonyms are calculated per realm, i.e. different realm means different pseudonyms
	//     $usePseudonym: boolean indicating if a pseudonymous login should be requested (false = anonymous)
	//     $attributes: additional attributes to request, for example "mitgliedschaft-bund, mitgliedschaft-land"
	//                  If "mitgliedschaft-bund" is NOT one of the requested attributes, only verified members will be allowed to log in.
	//                  If you request "mitgliedschaft-bund", its your own duty to check for membership (if you want to).
	// returns: true if successfully printed the form, false if any error occured (use pollError to get error message)
	function request($returnurl, $realm, $usePseudonym = true, $attributes = null) {
		if ( $this->blockNonSSL() ) return false;
	
		// TODO check realm and returnurl
		
		if ( !preg_match('/^[a-z_-]+(,[a-z_-]+)*$/', $attributes) ) {
			$this->error = "local: request failed - invalid attribute list. Use comma separated attributes without spaces, containing only lowercase letters, dashes and underscores.";
			return false;
		}
		
		$this->returnurl = $returnurl;
		$this->usePseudonym = $usePseudonym;
		$this->requestedAttributes = $attributes;
		// TODO
		?>
		<form name="piratenid_requestform" action="<?php echo htmlspecialchars(self::serverurl); ?>" method="POST">
			<input type="hidden" name="nonce" value="<?php self::safeout($this->nonce); ?>">
			<input type="hidden" name="domain" value="<?php self::safeout($domain); ?>">
			<input type="hidden" name="returnurl" value="<?php self::safeout($returnurl); ?>">
			<input type="hidden" name="attributes" value="<?php self::safeout($attributes); ?>">
			<input type="submit" value="Weiter ohne JavaScript &gt;&gt;&gt;">
		</form>
		<script type="text/javascript">
			document.forms['piratenid_requestform'].submit();
		</script>
		<?php
		return true;
	}

	// Resets the object to its initial state; forgets nonce, authentiction status, errors and attributes
	function reset() {
		$this->authenticated = false;
		$this->error = null;
		$this->attributes = array();
		$this->returnurl = null;
		$this->usePseudonym = true;
		$this->requestedAttributes = null;
	}
	
	// Tests if the current page is being loaded via HTTPS
	public static function isSSL() {
		if ($_SERVER['SERVER_PORT']==443) return true;
		if ($_SERVER['HTTPS']==='on') return true;
		return false;
	}
	
	private static sfunction getOpenIDFields(&$error) {
		// prefiltering done manually - type guaranteed by explode, isset() is checked,
		// empty values in key will be rejected by substring-test, in value they are allowed, length is checked.
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
			if (substr($key,0,7) !== "openid.") {
				if (strlen($key) > 250 || strlen($value) > 250) {
					$error = "Parameter zu lang";
					return false;
				}
				$result[$key] = $value;
			}
		}
		return $result;
	}

	// If current page is not being loaded via HTTPS, sets error and returns true
	private function blockNonSSL() {
		if (!self::isSSL()) {
			$this->error = "local: you do not seem to be using HTTPS. You will be handling sensitive user data and are required to use it on the whole site.";
			return true;
		}
		return false;
	}
}

// Require SSL even if this file is only included, not just when executing functions
if (!PiratenID::isSSL()) die("PiratenID included on non-HTTPS page. You will be handling sensitive user data and are required to use it on the whole site.");

?>