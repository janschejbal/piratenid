#!/usr/bin/php5-cgi
<?php

# Dieses Skript dient zur bequemen Erzeugung von Tokens auf dem Testserver

require('/srv/www/piratenid_test/includes/siteconstants.inc.php');
	
$bin = openssl_random_pseudo_bytes(200, $strong);
if ($strong !== true) die("Weak randomness");
if (strlen($bin) != 200) die("Random failed");
$token = substr(preg_replace("/[^a-zA-Z0-9]/", "", base64_encode($bin)), 5,20);
if (strlen($token) != 20) die("Try again");
$hash = hash('sha256', $token);

echo "Token: $token\nHash: $hash\n";

$db = getDatabasePDO();
$db->exec("SET sql_mode = TRADITIONAL");
$db->exec("SET NAMES 'utf8'");
$statement = $db->prepare(
                                "INSERT INTO tokens (`token`, `mitgliedschaft-bund`, `mitgliedschaft-land`, `mitgliedschaft-bezirk`, `mitgliedschaft-kreis`, `mitgliedschaft-ort`, `stimmberechtigt`) VALUES (?,?,?,?,?,?,?)"
                        ) or die("Failed to prepare");
$statement->execute(array($hash, "ja", "", "", "", "", "ja")) or die("Failed to insert");
echo "Token inserted.\n";