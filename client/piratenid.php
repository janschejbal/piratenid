<?php

class PiratenID {
	// HTTPS url to which requests will be sent
	const serverurl = "https://piratenid.janschejbal.de/id/request.php";
	
	// insert the message signing RSA public key of the ID server here
	const serverpubkey = <<<END
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxXBlghOWQAtXEbC++VT9
mD5XTUPzsLNoJWrtaXgEKfdFQonY7SK/wqJHYJmQ09IIOg3m3DnYP4mWC2L2dovZ
2YKyRpWUA/7UGs3pIE5NAySJmIaimWYs0Q+WpDsOn4sEqF2Wy87P7dhRi/s6Soa8
KBdMXCJlSDee4gld81/binhp/lOIzJmI8OcMp4bTpM4eqWWRzO/TX2ggP3BpGyKo
77Dg0QH2+Y/TWvTf/UTvaMZXoYUxRYojWV2k9W7u1rDb8H8xwMTejIU76W2KxyUq
ZbjFLsjEu3/GARqol5Vk7+iiopRT4pfa2vz1iVTh71TvqEsaElyphA2nmpSsem4J
3QIDAQAB
-----END PUBLIC KEY-----
END;

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
	
	static function session_request($attributes, $returnurl, $domain) {
		$instance = self::getFromSession();
		$result = $instance->request($attributes, $returnurl, $domain);
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
	private $nonce = null;
	private $domain = null;
	
	// returns true if the user is authenticated (not necessarily a pirate!)
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
	
	// Handles a response from the authentication server
	// Call when receiving the POST on the return url, or each time you receive a POST.
	// Checks if the relevant POST fields exist, and if they do, tries to verify the response.
	// If successfully authenticated, isAuthenticated() will start returning true and you will be able to retrieve the attributes with getAttributes()
	// If any step fails, the old authentication status and attributes are left unchanged. Use reset() to forget them if you want to.
	// returns: true if successful, false if error (use pollError to get error message)
	function handle() {
		if ( $this->blockNonSSL() ) return false;

		if ( empty($_POST['piratenid_response']) || empty($_POST['piratenid_sig']) ) {
			$this->error = "local: no response in POST";
			return false;
		}
		
		$response = $_POST['piratenid_response'];
		$sig      = $_POST['piratenid_sig'];
		
		$response = base64_decode($response);
		$sig      = base64_decode($sig);

		$pubkeyid = openssl_get_publickey(self::serverpubkey);
		$result = openssl_verify($response, $sig, $pubkeyid, "sha512");
		openssl_free_key($pubkeyid);
		
		if ($result !== 1) {
			$this->error = "local: invalid signature";
			return false;
		}
		
		// if we get here, we have a correctly signed response
		
		$xml = simplexml_load_string($response);
		
		// prevent re-use of a ticket created for another site (in case nonce was stolen by attacker)
		if ($this->domain == null || ((string)$xml->domain) !== $this->domain) {
			$this->error = "local: domain mismatch";
			return false;
		}
		
		if ($this->nonce == null || ((string)$xml->nonce) !== $this->nonce) {
			$this->error = "local: nonce mismatch";
			return false;
		}
		
		$this->nonce = null;
		
		if (((string)$xml->type) !== "success") {
			$this->error = "remote: ". $xml->error;
			return false;
		}
		
		$this->authenticated = true;
		$this->attributes = array();
		
		for ($i=0; $i < count($xml->attribute); $i++) {
			$this->attributes[(string)($xml->attribute[$i]->name)] = (string)($xml->attribute[$i]->value);
		}

		return true;
	}
	
	// Requests authentication
	// Prints a self-submitting HTML form which will submit to the ID server; a nonce is automatically created
	// Parameters:
	//     $attributes: attributes to request, for example "pseudonym,mitgliedschaft-bund"
	//     $domain: domain of the service for which the authentication is valid (currently needs to match return url and current domain name exactly)
	//     $returnurl: https url to which the browser will be directed after finishing authentication (needs to call handle() on this object!)
	// returns: true if sucessfully authenticated, false if any error occured (use pollError to get error message)
	function request($attributes, $returnurl, $domain) {
		if ( $this->blockNonSSL() ) return false;
	
		if ( !preg_match('/^([a-z-]+\\.)+[a-z]+$/', $domain) ) {
			$this->error = "local: request failed - invalid domain format";
			return false;
		}
		
		if ( (!empty($_SERVER['HTTP_HOST'])) && ($domain !== $_SERVER['HTTP_HOST']) ) {
			$this->error = "local: request failed - domain does not match current host";
			return false;
		}
		
		$prefix = "https://$domain/";
		if ( strpos($returnurl, $prefix) !== 0 ) {
			$this->error = "local: request failed - return url must start with \"$prefix\"";
			return false;
		}
		
		if ( !preg_match('/^[a-z_-]+(,[a-z_-]+)*$/', $attributes) ) {
			$this->error = "local: request failed - invalid attribute list. Use comma separated attributes without spaces, containing only lowercase letters, dashes and underscores.";
			return false;
		}
		
		$this->nonce = self::generateNonce(32);
		$this->domain = $domain;
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
		$this->nonce = null;
		$this->domain = null;
	}
	
	// Tests if the current page is being loaded via HTTPS
	public static function isSSL() {
		if ($_SERVER['SERVER_PORT']==80) return false;
		if ($_SERVER['SERVER_PORT']==443) return true;
		if ($_SERVER['HTTPS']==='on') return true;
		return false;
	}
	
	// If current page is not being loaded via HTTPS, sets error and returns true
	private function blockNonSSL() {
		if (!self::isSSL()) {
			$this->error = "local: you do not seem to be using HTTPS. You will be handling sensitive user data and are required to use it on the whole site.";
			return true;
		}
		return false;
	}
	
	// Generates a highly secure random nonce with the given number of bytes in hex format. Dies on failure.
	public static function generateNonce($entropy) {
		$strong = false;
		$result = bin2hex(openssl_random_pseudo_bytes($entropy, $strong));
		if ($strong !== true || strlen($result) != (2*$entropy)) die("openssl_random_pseudo_bytes failed");
		return $result;
	}
}

// Require SSL even if this file is only included, not just when executing functions
if (!PiratenID::isSSL()) die("PiratenID included on non-HTTPS page. You will be handling sensitive user data and are required to use it on the whole site.");

?>