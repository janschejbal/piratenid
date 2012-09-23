<?php
/// CONFIG FOR IMPORT ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Shared secret for encrypting and authenticating token imports - needs to match secret in piratenid-export-config.php
// If compromised, replace with new random value here and in export config and re-import token table
$SECRET = "7EbkyTL7N0npJhc4Gv2oXvm4mhDyYXk8cTMg2fa1bcOiiun3Xh7l5YsNNqw0";

$ALLOWED_IP = '127.0.0.1'; // IP from which tokens will be imported. Only this IP will be allowed to request token imports

function getDatabaseImportPDO() { // Database login data for token import
	return new PDO('mysql:dbname=piratenid;host=127.0.0.1', "root", "");
}

$TESTING = false; // set to true to allow imports with less than 1000 entries

$STATSFILE = '/srv/www/piratenid_test_import/stats/importstats.txt'; // Stats file - set to false to disable