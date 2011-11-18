<?php
require_once('siteconstants.inc.php');

// TODO Startseite
// TODO Hilfe, Doku
// TODO full test again, especially clickjacking protection with/without JS (regular case/attack case), IE6 blocker, extendedAttributeDomains (in siteconstants)
// TODO encodings checken (vor allem db-daten)
// TODO-later? stored procedures
// TODO-later? PGP/GPG support

// TODO search for TODOs (also in client!)

/* use instead of echo. escapes all output and avoids notice if variable is unset/empty.
   returns: false if variable was empty, true otherwise.
*/
function safeout(&$text) { // call by ref to avoid "unset variable" notice on call
	if (empty($text)) return false;
	echo htmlspecialchars((string)$text, ENT_QUOTES);
	return true;
}

/* ensures the given value is a string and (unless allowEmpty is true) non-empty
   on error, sets the error parameter if passed and returns false   */
function prefilter(&$param, &$error = null, $allowEmpty = false) {
	if (!isset($param) || (empty($param) && !$allowEmpty) || !is_string($param) || strlen($param) > 250) {
		$error .= "Ungültiger Parameter. ";
		return false;
	}
	return $param;
}

function logPrefilter(&$param) {
	if (!isset($param)) return "<none>";
	if (!is_string($param)) return "<notString>";
	if (empty($param)) return "<empty>";
	if (strlen($param)>230) return "<truncated> ".substr($param,0,230);
	return $param;
}

/* generates the given number of secure random bytes, hex-encoded */
function generateNonce($entropy) {
	$strong = false;
	$result = bin2hex(openssl_random_pseudo_bytes($entropy, $strong));
	if ($strong !== true || strlen($result) != (2*$entropy)) die("openssl_random_pseudo_bytes failed");
	return $result;
}

/* hashes the given password, using the given username as salt */
function hashPassword($username, $pw) {
	global $passwordsaltsecret;
	$rawhash = hash("sha256", "$username|$pw|$passwordsaltsecret");
	
	// check that hash works.
	// checking in hashPassword avoids overhead and still makes sure no critical part can run with broken hashing
	if (strlen($rawhash) != 64) die("Password hashing failed");
	
	$h = $rawhash;
	for ($i = 0; $i < 100000; $i++) {
		$h =  hash("sha256", "$i|$h|$rawhash");
	}
	return $h;
}

class DB {
	public $connection = null;
	public $statement = null;
	public $error = null;
	
	private static $instance = null;
	
	private function __construct() {
		try {
			$this->connection = @getDatabasePDO(); 
			if (false === $this->query("SET sql_mode = TRADITIONAL")) {
				die("Failed to set SQL connection mode"); // should never happen
			}
			if (false === $this->query("SET NAMES 'utf8'")) {
				die("Failed to set SQL connection charset"); // should never happen
			}
		} catch (PDOException $e) {
			$tmperror = $e->errorInfo;
			if (is_array($tmperror)) {
				$this->error = $tmperror;
			} else {
				$this->error = array("XXXXX", "0", "PDO Exception: ".$e->getMessage()); // follow errorInfo structure
			}
			$this->connection = null;
		}
	}
	
	/**
		Performs a database query (using a prepared statement)
		querystring must be a constant or come from a trusted source, no escaping is done on it.
		returns the result of the query or "false" on error.
		On error, $error is set
		Note that empty arrays can be returned which are interpreted as "false":
			checking for if ($db->query(...)) may not work as expected, if an empty array is returned the if-branch would not run
			check for false !== $db->query(...) to check for success.
	*/
	public function query($querystr, $paramarray = array()) {
		if ($this->connection == null) return false;
		
		$error = null;
		
		foreach ($paramarray as $value) {
			if (strlen($value) > 250) {
				$this->error = array("XXXXX", "1", "DB class self-check detected overlong value"); // follow errorInfo structure
				return false;
			}
		}

		
		$this->statement = $this->connection->prepare($querystr);
		if ($this->statement->execute($paramarray)) {
			return $this->statement->fetchAll();
		} else {
			$this->error = $this->statement->errorInfo();
			return false;
		}
	}
	
	public function cleanup() {
		$this->query("UPDATE users SET resettoken = NULL, resettime = NULL WHERE resettime < TIMESTAMPADD(DAY,-2,NOW())", array());
		$this->query("DELETE FROM users WHERE email_verified = 0 AND token <=> NULL AND createtime < TIMESTAMPADD(DAY,-2,NOW())", array());
		$this->query("DELETE FROM loginfailures WHERE timestamp < TIMESTAMPADD(MINUTE,-30,NOW())", array());
		$this->query("DELETE FROM loginfailures_log WHERE timestamp < TIMESTAMPADD(WEEK,-4,NOW())", array());
		$this->query("DELETE FROM openid WHERE createtime < TIMESTAMPADD(HOUR,-1,NOW())", array());
	}
	
	// singleton getter
	public static function get() {
		if (self::$instance === null) {
			self::$instance = new DB();
			self::$instance->cleanup();
		}
		return self::$instance;
	}
}

/**
 If the POST variables "username" and "password" contain a valid user login and a correct clickjacking protection token is supplied,
 returns the user array containing all information about the user. Otherwise returns false.
*/
function getUser(&$error) {
	global $remoteClientIP;
	$ip = $remoteClientIP;

	if (empty($ip) || !preg_match('/^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$/D', $ip)) { // TODO-later: when implementing IPv6 support, normalize IP and truncate to /64!
		$error = "Login fehlgeschlagen: Konfigurationsfehler (ungültige IP)";
		return false;
	}
	
	// Make CSRF login attempts that could lock the user out (due to bruteforce protection) more difficult
	global $sitepath;
	if ( !empty($_SERVER['HTTP_REFERER']) ) {
		if (strpos($_SERVER['HTTP_REFERER'], $sitepath) !== 0) {
			$error = "Login fehlgeschlagen: Unzulässiger Referer";
			return false;
		}
	}
	
	if (strlen($_POST['clickjackprotect1']) !== 3 || ($_POST['clickjackprotect1'] !==$_POST['clickjackprotect2'])) {
		$error = "Login fehlgeschlagen: Clickjacking-Schutz falsch ausgefüllt";
		return false;
	}

	if (empty($_POST['username']) || empty($_POST['password'])) {
		$error = "Login fehlgeschlagen: Benutzername oder Kennwort fehlt.";
		return false;
	}
	
	$username = strtolower(prefilter($_POST['username'])); // a 'false' from prefilter will create "" will be considered invalid
	$pw = prefilter($_POST['password']);
	
	if ($username === false || $pw === false) {
		$error = "Login fehlgeschlagen: Benutzername oder Kennwort ungültig.";
		return false;	
	}
	
	$db = DB::get();
	$result = $db->query("SELECT COUNT(*) FROM loginfailures WHERE ip = ?", array($ip));
	if ($result === false || count($result) !== 1) {
		$error = "Login fehlgeschlagen: Datenbankfehler";
		return false;
	}
	if ($result[0][0] >= 3) {
		$error = "Login fehlgeschlagen: Zu viele Fehlversuche. Bitte 30 Minuten warten.";
		return false;
	}
	
	$pwhash = hashPassword($username, $pw);
	$result = $db->query("SELECT * FROM users LEFT JOIN tokens ON users.token = tokens.token WHERE username = ? AND pwhash = ?", array($username, $pwhash));
	if ($result === false) {
		$error = "Login fehlgeschlagen: Datenbankfehler";
		return false;
	}
	if (count($result) !== 1) {
		$db->query("INSERT INTO loginfailures (ip) VALUES (?)", array($ip));
		$useragent = logPrefilter($_SERVER["HTTP_USER_AGENT"]);
		$referer   = logPrefilter($_SERVER["HTTP_REFERER"]);
		$db->query("INSERT INTO loginfailures_log (ip,useragent,referer) VALUES (?,?,?)", array($ip, $useragent, $referer));
		$error = "Login fehlgeschlagen: Benutzername oder Kennwort falsch." . (($result === false) ? " Datenbankfehler." : "");
		return false;
	}
	if ($result[0]['email_verified'] !== '1') {
		$error = "Login fehlgeschlagen: Account inaktiv.";
		return false;
	}
	return $result[0];
}

/**
 Outputs login form fields consisting of username, password and clickjacking protection
 Note that the clickjacking protection is NOT a protection against CSRF (that is what the password is for)
 nor a CAPTCHA (bruteforce attempts are stopped by complex passwords and a strong password strengthenig, possibly IP blacklisting).
*/
function printLoginFields() {
	// mt_srand((int)hexdec(generateNonce(4))); // enable for more random clickjacking tokens, should be unnecessary
	$clickjackcode = "".mt_rand(0,9).mt_rand(0,9).mt_rand(0,9);
	$clickjackprompt = "";
	for ($i = 0; $i<3; $i++) {
		switch ($clickjackcode[$i]) {
			case '0': $clickjackprompt .= "Null "; break;
			case '1': $clickjackprompt .= "Eins "; break;
			case '2': $clickjackprompt .= "Zwei "; break;
			case '3': $clickjackprompt .= "Drei "; break;
			case '4': $clickjackprompt .= "Vier "; break;
			case '5': $clickjackprompt .= "Fünf "; break;
			case '6': $clickjackprompt .= "Sechs "; break;
			case '7': $clickjackprompt .= "Sieben "; break;
			case '8': $clickjackprompt .= "Acht "; break;
			case '9': $clickjackprompt .= "Neun "; break;
		}
	}
	$toppadding = "".mt_rand(0,60);
	$botpadding = "".mt_rand(0,60);
	?>
	<tr>
		<td>Benutzername</td>
		<td><input type="text" name="username" value="<?php safeout($_POST['username']); ?>"></td>
	</tr>
	<tr>
		<td>Kennwort</td>
		<td><input type="password" name="password"></td>
	</tr>
	<tr id="clickjackprompt">
		<td style="padding-top: <?php safeout($toppadding); ?>px; padding-bottom: <?php safeout($botpadding); ?>px;">
			Gebe folgende Ziffern ein:<br><?php safeout($clickjackprompt) ?>
		</td>
		<td style="padding-top: <?php safeout($toppadding); ?>px; padding-bottom: <?php safeout($botpadding); ?>px;">
			<input type="text" id="clickjackprotect2" name="clickjackprotect2"><br>
			Da JavaScript deaktiviert ist, musst du diese Zahlen eingeben, um Clickjacking zu erschweren.
		</td>
	</tr>
	<input type="hidden" name="clickjackprotect1" id="clickjackprotect1" value="<?php safeout($clickjackcode) ?>">
	<script>
		document.getElementById('clickjackprotect2').value = document.getElementById('clickjackprotect1').value;
		document.getElementById('clickjackprompt').style.display = 'none';
	</script>
	<?php
}

/* checks if a password and password confirmation combination (supplied when changing passwords) is valid */
function checkPassword($password, $password2, &$passworderror) {
	$passworderror = null;
	
	if (prefilter($password, $passworderror, true) === false || prefilter($password2, $passworderror, true) === false) {
		return false;
	}
	
	//  length
	if (strlen($password) < 8) {
		$passworderror .= "Kennwort zu kurz. ";
	}

	//  characters
	$charclasses = 0;
	if ( preg_match('/[a-z]/', $password) ) $charclasses++;
	if ( preg_match('/[A-Z]/', $password) ) $charclasses++;
	if ( preg_match('/[0-9]/', $password) ) $charclasses++;
	if ( preg_match('/[^a-zA-Z0-9]/', $password) ) $charclasses++;
	if ($charclasses < 2) {
		$passworderror .= "Kennwort erfüllt Sicherheitsanforderungen nicht. ";
	}

	//  verification matches
	if ($password !== $password2) {
		$passworderror .= "Kennwort und Kennwortbestätigung stimmen nicht überein. ";
	}
	
	return $passworderror === null;
}

/* checks if a supplied mail address can be used to create an account */
function checkMail($mail, &$mailerror) {
	$mailerror = null;
	
	$db = DB::get();
	if (prefilter($mail, $mailerror, true) === false) {
		return false;
	}
	
	//  valid (regexp)
	if (!preg_match('/^[a-zA-Z0-9_\-\.\+\^!#\$%&*+\/\=\?~]+@(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.?)+$/D', $mail)) {
		$mailerror .= 'Ungültige E-Mail-Adresse';
		return false;
	} 

	//  check: address is not yet used (db)
	if ( false !== ($result = $db->query("SELECT username FROM users WHERE email=?",array($mail))) ) {
		if ( count($result) > 0) {
			$mailerror = "Diese Mailadresse wird bereits verwendet";
			return false;
		}
	} else {
		$mailerror = "Datenbankfehler.";
	}
	return $mailerror === null;
}
