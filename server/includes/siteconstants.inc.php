<?php
// this file defines site-specific constants and secrets

// used for e-mails
$sitepath = "https://127.0.0.1/";

// List of domains that may receive extended attributes
$extendedAttributeDomains = array();

// Database login data
function getDatabasePDO() {
	return new PDO('mysql:dbname=piratenid;host=127.0.0.1', "root", "");
}

// The pseudonym secret is used for pseudonym calculation.
// If changed, all pseudonyms will change.
// Provides additional security, but is not critical as long as the user secrets (in the database) stay secret.
// If only this secret is compromised, it does NOT need to be changed immediately.
// Disclosure of this secret AND the user secrets allows an attacker to link pseudonyms
// Suggested procedure in case of compromise:
//   Notify web services
//   Create a new attribute "old_pseudonym" calculated using the old values (which are kept under a different name)
//   Create new values for this secret and user secrets
$pseudonymsecret = "cfS5Ld1oVxfKbrtgFrHi"; 

// An additional salt used for hashing passwords.
// If changed, all password hashes become invalid!
// Provides some additional security, in particular, making it impossible to bruteforce the passwords if the attacker has only the database.
$passwordsaltsecret = "1nNEwuawyI0ZOn7WAt9u";

// use a 2048 bit (or more) RSA key - the hash algorithm causes this not to work with smaller keys!
// In case of compromise, an attacker can forge response signatures and thus responses. Notify relying parties and change key.
// Attackers knowing (only) this key cannot access any non-public data on this server or decrypt anything,
// but can gain access to the third-party services under existing or completely forged identities.
$signaturekey_pem = <<<EOD
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxXBlghOWQAtXEbC++VT9mD5XTUPzsLNoJWrtaXgEKfdFQonY
7SK/wqJHYJmQ09IIOg3m3DnYP4mWC2L2dovZ2YKyRpWUA/7UGs3pIE5NAySJmIai
mWYs0Q+WpDsOn4sEqF2Wy87P7dhRi/s6Soa8KBdMXCJlSDee4gld81/binhp/lOI
zJmI8OcMp4bTpM4eqWWRzO/TX2ggP3BpGyKo77Dg0QH2+Y/TWvTf/UTvaMZXoYUx
RYojWV2k9W7u1rDb8H8xwMTejIU76W2KxyUqZbjFLsjEu3/GARqol5Vk7+iiopRT
4pfa2vz1iVTh71TvqEsaElyphA2nmpSsem4J3QIDAQABAoIBAAgogMlDLe4vicV9
XCbJUEE+MjVLHYKrpx4EsRKult11DjOVppUF3o6YTgK71bQq9ZQQhv2Klljpwn1t
9WkoljPapqsr+xW/Ldx9rahcE+qRU+4tggJ8qlVpI3xdxFjrUaHzXAvH2+ekDJqQ
IvR5ZMTzUYBtG2pEghgs8ujfiR7LkFQo3o7Udz0CivVNd2yIk+RU+hN5Nvr4jnfr
+m/kSzyD5XXNiVDELIjWnU93DHnUeCQb6Rnl3p5oL+ik3Led/UtpywqiKNYpvE1f
KmVYnpEVc5cXvo0L2T03kwB+PzOYqCWs8mLSND4MfT0rpFRW9gy9diR6G22kHAcy
e99RTLECgYEA8idHL1SN6uAdChgGuBwHouMtvJKtiOZCvsq1IFYlN58pnMA1KUBy
IqqekWILybSDTN3cI74/whpZxayAq4Hzihe8BxRuI5gVL/+B9NYe/FIFJNY+vKaG
9etkc4zWooUTQevBqV7QJgcVYVrEOMYvhdwSVvyVnv/X9clbmT+uOD8CgYEA0LqT
FpEYR1UQWMpzLqFarHfceUwZOE4U/BHOWKniTI8A1wBBu1rRj7HuHaE9T/j+aZ9a
qegw/udmWPeO1+TuxQvluTDztUCUHWR80CBidD/xMwMkiPPY1UcryaToYjIgRgYg
71ukP/V9Y5+LmmpAyqEo/GEA58BgpQauYtizVuMCgYAcgZk0riyCwN1KSefIlqwj
dcD1mQLKweiLk0tdQibhdGAursXTVF3bTOCb1sHyfciTLO70WjohPH7i8Vq4VfT4
hbDB2Jran9Wmr9p5mxdMts8aNgpupN/wZUSPAb5mpWnN8dX7fUjdoSnYKxo8YMBJ
bs3N5bArZozix1B8Ku30ewKBgG+Sy/1MIgY/WjWcQmWyqp12lMvh+bk3Q9BaVErg
xK7X4kMLSBe2PD7rhbUg831EQ/qBzBz2mPopB3SXICwXm+qIqYuMtzk0A/iSNoWq
SfaKF4yFKYprjoSzPpzTIcUbtlS4AfLwsaPevd/68Mzh7zBhZV9DGxDGrOKJ572+
yF6xAoGAXw0/cfXtNmY0sq02CTyzTruFRKuk2zqwhtxxkUiX+Q+W70lfel168qz5
EGvwaWG3eNT/9leV/nh921NgF/l7C9KGmYEnSRH+UhuNC9b7ufWMBpi3Dd/VlnM1
zdI57Uhlc/olLLirgizuNT3bbmjtkNJBLoE7NuGiN4SBFMFrr+0=
-----END RSA PRIVATE KEY-----
EOD;


?>