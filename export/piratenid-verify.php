<?php

// make sure errors are fatal
error_reporting(E_ALL | E_STRICT);
function fatalErrors($errno, $errstr) { PiratenIDImport_err("Fehler $errno:\n$errstr\n"); }
set_error_handler("fatalErrors");


// Replacement for die() which sets the exit code (ERRORLEVEL on win)
function PiratenIDImport_err($str) {
	echo $str;
	exit(1);
}

function PiratenIDImport_getLVs() {
	return array('BW', 'BY', 'BE', 'BB', 'HB', 'HH', 'HE', 'MV', 'NI', 'NW', 'RP', 'SL', 'SN', 'ST', 'SH', 'TH', 'Ausland', 'Bund', '');
}

// verifies an entry (single row), terminating on error
function PiratenIDImport_verifyEntry($entry) {
	$LVs = PiratenIDImport_getLVs();
	if (!is_array($entry)) PiratenIDImport_err("Invalid data: entry not an array");
	if (count($entry) != 7) PiratenIDImport_err("Invalid data: wrong number of values");
	for ($i = 0; $i<7; $i++) {
		if (!is_string($entry[$i])) PiratenIDImport_err("Invalid data: value not a string");
		if (strpos($entry[$i], "\0") !== false) PiratenIDImport_err("Invalid data: contains NULL byte");
		if (strlen($entry[$i]) > 100) PiratenIDImport_err("Invalid data: value too long");
		if (strpos($entry[$i], "\xC3\x83") !== false) PiratenIDImport_err("Invalid data: looks like double UTF-8 encoding");
		if (!mb_detect_encoding($entry[$i], 'UTF-8', true)) PiratenIDImport_err("Invalid data: value not UTF-8");
		if (!mb_check_encoding($entry[$i], 'UTF-8')) PiratenIDImport_err("Invalid data: invalid UTF-8 sequence");
		
	}
	
	if (!preg_match('/^[a-f0-9]{64}$/D', $entry[0])) PiratenIDImport_err("Invalid data: invalid token value");
	if ($entry[0] == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855') PiratenIDImport_err("Invalid data: Token is hash of empty string");
	
	
	if ($entry[1] !== 'ja' && $entry[1] !== 'nein') PiratenIDImport_err("Invalid data: mitgliedschaft-bund must be either 'ja' or 'nein'");
	if (!in_array($entry[2], $LVs ,true)) {
		PiratenIDImport_err("Invalid data: value for mitgliedschaft-land is not in whitelist");
	}
	if ($entry[6] !== 'ja' && $entry[6] !== 'nein' && $entry[6] !== '') PiratenIDImport_err("Invalid data: stimmberechtigt must be 'ja', 'nein' or empty string");
}

// Wrapper for PiratenIDImport_verifyEntry which generates statistics on the fly
class PiratenIDImport_StatsVerifier {
	private $lv_total = array();
	private $lv_stimmberechtigt = array();
	
	function __construct() {
		foreach (PiratenIDImport_getLVs() as $lv) {
			$this->lv_total[$lv] = 0;
			$this->lv_stimmberechtigt[$lv] = 0;
		}
	}
	
	function verifyEntry($entry) {
		PiratenIDImport_verifyEntry($entry);
		$mitgliedschaft_land = $entry[2];
		$stimmberechtigt = $entry[6];
		$this->lv_total[$mitgliedschaft_land]++;
		if ($stimmberechtigt === 'ja') $this->lv_stimmberechtigt[$mitgliedschaft_land]++;
	}
	
	function getStats() {
		$result = "";
		$total = 0;
		$total_stimmberechtigt = 0;
		foreach (PiratenIDImport_getLVs() as $lv) {
			$statLVstr = $lv;
			if ($statLVstr === '') $statLVstr = 'XX';
			$result .= sprintf(" | %8s = %6d | %8s-stimmberechtigt = %6d\n", $statLVstr, $this->lv_total[$lv], $statLVstr, $this->lv_stimmberechtigt[$lv]);
			$total += $this->lv_total[$lv];
			$total_stimmberechtigt += $this->lv_stimmberechtigt[$lv];
		}
		$result .= sprintf(" | %8s = %6d | %8s-stimmberechtigt = %6d\n", "TOTAL", $total, "TOTAL", $total_stimmberechtigt);
		return $result;
	}
}