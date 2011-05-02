<?php

function validateAttributes($attributes) {
	$attrarray = explode(',', $attributes);
	$supported = array('pseudonym','mitgliedschaft-bund','mitgliedschaft-land','mitgliedschaft-bezirk','mitgliedschaft-kreis','mitgliedschaft-ort'/*,'realname','mitgliedsnummer'*/); // Die Abfrage von Realidentitätsdaten ist fürs Erste deaktiviert.
	foreach ($attrarray as $attrib) {
		if (!in_array($attrib, $supported, true)) return false;
	}
	return true;
}

function checkForErrors($nonce, $domain, $returnurl, $attributes) {
	if ( !preg_match('%^[a-zA-Z0-9!.:;|/+_-]{20,128}$%', $nonce) ) {
		return "invalid nonce format, must be 20-128 characters from the set [a-zA-Z0-9!.:;|/+_-]";
	}

	if ( !preg_match('%^([a-z-]+\\.)+[a-z]+$%', $domain) ) {
		return "invalid domain format";
	}

	$prefix = "https://$domain/";
	if ( strpos($returnurl, $prefix) !== 0 ) {
		return "invalid return url - return url must start with \"$prefix\""; // ensures https AND avoids "javascript:" urls
	}
	
	if ( !preg_match('%^[a-zA-Z0-9$_.+!*\'(),/?=&#;:-]+$%', $returnurl) ) {
		return "invalid return url format";
	}

	if ( !empty($_SERVER['HTTP_REFERER']) ) {
		if ( strpos($_SERVER['HTTP_REFERER'], $prefix) !== 0 && strpos($_SERVER['HTTP_REFERER'], 'https://'.$_SERVER['HTTP_HOST'].'/') !== 0) {
			// just an additional check to make CSRF and similar more annoying to try (the password in each request is the real protection)
			// referer and host headers can be spoofed, but usually not without a decent amount of control over the client
			return "referer exists but is invalid - must come from specified domain (or ID system) and be HTTPS";
		}
	}
	
	if ( !preg_match('%^[a-z_-]+(,[a-z_-]+)*$%', $attributes) ) {
		return "invalid attribute list. Use comma separated attributes without spaces, containing only lowercase letters, dashes and underscores.";
	}
	
	if ( !validateAttributes($attributes) ) {
		return "unsupported attribute in attribute list";
	}
	
	return false;
}

?>