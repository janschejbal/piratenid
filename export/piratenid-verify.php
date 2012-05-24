<?php

// Replacement for die() which sets the exit code (ERRORLEVEL on win)
function PiratenIDImport_err($str) {
	echo $str;
	exit(1);
}

function PiratenIDImport_getLVs() {
	return array('BW', 'BY', 'BE', 'BB', 'HB', 'HH', 'HE', 'MV', 'NI', 'NW', 'RP', 'SL', 'SN', 'ST', 'SH', 'TH', '');
}

// verifies an entry (single row)
function PiratenIDImport_verifyEntry($entry) {
	$LVs = PiratenIDImport_getLVs();
	if (!is_array($entry)) PiratenIDImport_err("Invalid data: entry not an array");
	if (count($entry) != 7) PiratenIDImport_err("Invalid data: wrong number of values");
	for ($i = 0; $i<7; $i++) {
		if (!is_string($entry[$i])) PiratenIDImport_err("Invalid data: value not a string");
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