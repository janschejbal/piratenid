<?php
require_once('../includes/techheader.inc.php');
header('Content-Type: application/xrds+xml');

echo '<?xml version="1.0" encoding="UTF-8"?>'; // tags will cause php trouble otherwise
?>
<xrds:XRDS xmlns:xrds="xri://$xrds" xmlns="xri://$xrd*($v*2.0)">
  <XRD>
	<Service xmlns="xri://$xrd*($v*2.0)">
		<Type>http://specs.openid.net/auth/2.0/server</Type>
		<Type>http://openid.net/srv/ax/1.0</Type>
		<URI><?php safeout($sitepath); ?>openid/endpoint.php</URI>
	</Service>
  </XRD>
</xrds:XRDS>
