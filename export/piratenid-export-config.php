<?php
/// CONFIG FOR EXPORT ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Shared secret for encrypting and authenticating token imports - needs to match secret in piratenid-import.php
// If compromised, replace with new random value in export and import config and re-import token table
$SECRET = "7EbkyTL7N0npJhc4Gv2oXvm4mhDyYXk8cTMg2fa1bcOiiun3Xh7l5YsNNqw0";

// URL of the piratenid-import.php script that should receive the export data (internal network only!)
$TARGETURL = 'https://10.10.4.2:10443/import'; 

// Where to find the SSL certificate of the server
$SERVER_CERT = '/temp/openssltest/output/idserver.crt';

// Where to find the file containing both the client certificate and the corresponding private key
$CLIENT_CERT = '/temp/openssltest/output/updater.key';


// Source database PDO String
$SOURCEPDO  =  'odbc:Driver={SQL Server};Server={(local)\\sqlexpress};Database={sagesim};'; // different on linux!
$SOURCEUSER =  'piratenid_export';
$SOURCEPASS =  'test';
$SOURCETABLE = 'PiratenIDExportView';
$FEEDBACKTABLE = 'PiratenIDFeedbackTable'; // Table to which feedback (i.e. list of used tokens) should be written

// Required columns
$COLUMN_TOKEN            = 'PiratenID';
$COLUMN_LAND             = 'Landesverband';
$COLUMN_STIMMBERECHTIGT  = 'RealStimmberechtigt';

// Optional columns (set to false to force values to be empty)
$COLUMN_BEZIRK           = false; // 'Bezirk';
$COLUMN_KREIS            = false; // 'Kreisverband';
$COLUMN_ORT              = false; // 'Ortsverband';

// Feedback columns
$COLUMN_FEEDBACK_TOKEN   = 'token';
$COLUMN_FEEDBACK_ACTIVE  = 'active';
$COLUMN_FEEDBACK_USED    = 'used';

