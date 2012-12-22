== Funktionsbeschreibung PiratenID Export/Import ==
Das Export-Skript auf einem Exportserver holt die Daten von einer Datenbank und konvertiert sie.
Anschließend sendet es sie verschlüsselt und authentifiziert per HTTP POST an das Import-Skript auf dem PiratenID-Server.
Das Importskript importiert die Daten in die PiratenID-Datenbank und erstellt optional eine Textdatei mit Statistiken.

Beide Skripte prüfen die Gültigkeit der Daten. Das Exportskript zeigt bei gelungenem Export Statistiken an.

Das Importskript meldet anschließend an das Importskript, welche Token nun gültig sind, und welche bereits verbraucht sind.
(Beachte: Nicht mehr gültige Token können verbraucht sein!)
Das Exportskript schreibt diese Informationen in eine separate Tabelle auf dem SAGE-Datenbankserver.
So erhält SAGE Zugriff auf diese Informationen und kann z. B. das Neuausstellen von verlorenen Token automatisieren.

=== Sicherheit ===
Die Daten werden ausschließlich über das gesicherte, interne Netzwerk übertragen.
Die Token-Hashes werden vom Exportskript sortiert, um Rückschlüsse aus der Reihenfolge zu verhindern.
Die übertragenen Daten bestehen aus einem Token-Hash, Informationen über Verbandsmitgliedschaften und die Stimmberechtigung.
Sie enthalten keine personenbezogenen Angaben und müssen daher nicht besonders geschützt werden.

Dennoch wird durch mehrere Maßnahmen sichergestellt, dass die Daten nicht in fremde Hände gelangen:
* Die Datenübertragung erfolgt über ein internes, gesichertes und vertrauenswürdes Netzwerk
* Für die Übertragung wird SSL mit Clientauthentifizierung mit fest installierten Zertifikaten verwendet
* Die Daten, welche vom Export-Server zum PiratenID-Server gesendet werden, werden zusätzlich symmetrisch verschlüsselt

Durch mehrere Maßnahmen wird sichergestellt, dass keine verfälschten Daten importiert werden können:
* Die Datenübertragung erfolgt über ein internes, gesichertes und vertrauenswürdes Netzwerk
* Für die Übertragung wird SSL mit Clientauthentifizierung mit fest installierten Zertifikaten verwendet
* Nur der Export-Server kann auf das Importskript zugreifen.
  * Die Webserver-Konfiguration erlaubt nur Zugriffe von der IP des Export-Servers
  * Das Importskript prüft die IP erneut
* Ein Import erfolgt nur, wenn die Nachricht einen (konstanten) Authentifizierungssschlüssel enthält
* Die Daten werden mit einem symmetrischen Schlüssel integritätsgesichert
* Um Replay-Attacken zu verhindern, wird ein Timestamp mitsigniert.

Durch folgende Maßnahmen wird sichergestellt, dass die Rückmeldung vom ID-Server zum Export-Server nicht verfälscht werden kann:
* Die Datenübertragung erfolgt über ein internes, gesichertes und vertrauenswürdes Netzwerk
* Für die Übertragung wird SSL mit Clientauthentifizierung mit fest installierten Zertifikaten verwendet
  * die Rückmeldung erfolgt über die selbe Verbindung, über welche auch die Übertragung erfolgt ist


=== Dateien ===
* README.txt ist diese Hilfedatei
* piratenid-verify.php enthält gemeinsame Routinen zur Datenprüfung
* piratenid-import.php ist das Importskript
* piratenid-import-config.php ist die Konfigurationsdatei für das Importskript
* piratenid-export.php ist das Exportskript
* piratenid-export-config.php ist die Konfigurationsdatei für das Exportskript
* piratenid-mktoken.php ist KEIN Teil der Export/Import-Architektur, sondern dient zur Erstellung von Testtokens auf dem Testserver
* Das Verzeichnis cert-generator enthält ein Skript zur Erstellung von Zertifikaten (siehe "Konfiguration von SSL")

== Installationsanleitung für PiratenID Export/Import ==

=== Konfiguration von SSL ===
Sowohl für den Server als auch für den Client müssen Zertifikate erstellt werden.
Hierfür beinhaltet das Verzeichnis "cert-generator" eine OpenSSL-Config und ein entsprechendes Skript.
ACHTUNG: Unter Windows benötigt dieses Skript korrekt installierte UnxUtils und OpenSSL!
Trotz der Dateiendung kann das Skript unter Linux auch als Shellskript benutzt werden!

Das Skript erstellt im Verzeichnis "output" folgende Dateien:
 * idserver.crt         - öffentliches (Server-)Zertifikat für den Import-Endpoint. Wird auf dem Export-Server installiert.
 * idserver.key         - privater Schlüssel (inkl. Zertifikat) für den Import-Endpoint. Wird NUR auf dem ID-Server installiert!
 * updater.crt          - öffentliches Clientzertifikat für den Export-Server. Wird auf dem ID-Server installiert.
 * updater.key          - privater Schlüssel (inkl. Zertifikat) für den Export-Server. Wird NUR auf dem Export-Server installert!

Alternativ können die Schlüssel und Zertifikate natürlich mit den Befehlen aus dem Skript manuell auf den jeweiligen Hosts erstellt werden,
sodass die privaten Schlüssel sich nie außerhalb des jeweiligen Hosts aufhalten.
Die öffentlichen Zertifikate müssen jeweils auf den anderen Host übertragen werden.

Die privaten Schlüssel sollten durch entsprechende Rechtevergabe geschützt werden
  # ID-Server
  chmod 400 idserver.key
  chown root idserver.key
  # Export-Server
  chown 400 updater.key
  chown export-user updater.key

Auf dem ID-Server sind die Pfade zu Schlüssel und Zertifikaten in der nginx.conf einzutragen (siehe unten).
Auf dem Update-Server sind die Pfade in der piratenid-export-config.php einzutragen (siehe Kommentare in der Datei).
 
=== Importseite (auf PiratenID-Server) ===

1. piratenid-verify.php, piratenid-import.php und piratenid-import-config.php in ein nicht öffentlich zugängigliches Verzeichnis auf dem Server platzieren.
2. Datenbankzugang mit ausreichenden Rechten (nur SELECT, DELETE und INSERT nur auf die Tabelle "tokens", zusätzlich SELECT auf token-Spalte in users) anlegen
3. (Optional) Verzeichnis für Statistiken anlegen, in welchem PHP schreiben darf, und per Statistikdatei per Alias öffentlich lesbar machen:
----------------------------------------------------------------------------------------------------
		# Innerhalb der Server-Direktive fuer den OEFFENTLICHEN Teil des Servers!
		location /stats.txt {
			alias /srv/www/piratenid_test_import/stats/importstats.txt;
		}
----------------------------------------------------------------------------------------------------

4. piratenid-import-config.php anpassen
    * Neues Secret generieren und eintragen (dieses muss später auch in piratenid-export-config.php eingetragen werden)
    * IP, von welcher die Importe kommen, eintragen
    * DB-Zugangsdaten eintragen
	* Pfad zur Statistikdatei eintragen oder auf false setzen.

5. Nginx einrichten.
   Nur der Export-Server darf auf das Import-Skript zugreifen, und die Zugriffsmöglcihkeiten sind restriktiv zu vergeben.
   Es muss SSL mit Clientzertifikaten verwendet werden.
   Eine Beispielkonfiguration folgt, darin müssen Pfade und die allow-IP (IP des Export-Servers) angepasst werden:
----------------------------------------------------------------------------------------------------
	server { # HTTPS endpoint for imports
		listen 10443;
		ssl on;
		ssl_verify_client on;
		ssl_certificate /srv/www/piratenid_test_import/idserver.key;
		ssl_certificate_key /srv/www/piratenid_test_import/idserver.key;
		ssl_client_certificate /srv/www/piratenid_test_import/updater.crt;

		server_name idtest-import;
		access_log /var/log/nginx/piratenid_test_import-access.log;
		error_log /var/log/nginx/piratenid_test_import-error.log;
		root /dev/null;

		location /import {
			allow 10.20.1.34;
			deny all;

			include /etc/nginx/fastcgi_params;
			fastcgi_pass 127.0.0.1:9000;
			fastcgi_param SCRIPT_FILENAME /srv/www/piratenid_test_import/piratenid-import.php;
		}

		location / {
			deny all;
		}
	}
----------------------------------------------------------------------------------------------------

==== Troubleshooting ====
Wenn das Importskript nur eine weiße Seite liefert, deutet das auf einen Internal Server Error hin -- Errorlog prüfen!
Häufigste Ursache: PDO (Datenbankzugriff) falsch konfiguriert.



=== Exportseite (auf einem Export-Server) ===
Der Export-Server benötigt Zugriff auf eine Datenbank, welche die Export-Daten bereitstellt und Rückmeldungsdaten entgegennimmt.
Er muss HTTP-Zugang zum oben konfigurierten Import-Endpunkt haben.

Für den Export sollte ein separater Datenbank-Benutzer angelegt werden, welcher nur auf die Export-Daten zugreifen und Rückmeldungsdaten schreiben kann.
Der Export-Nutzer sollte nur vom Export-Server aus nutzbar sein, und der Export-Server sollte sich nur mit dem Export-Nutzer auf die DB zugreifen können.

Auf dem Export-Server muss eine aktuelle PHP-Version vorhanden sein, welche per PDO auf die Datenbank zugreifen kann.
Es muss somit für die verwendete Datenbank entweder ein PDO-Treiber vorhanden sein, oder ODBC muss korrekt konfiguriert sein.
Beim Zugriff auf eine MSSQL-Datenbank sollte ODBC verwendet werden.

Unter Ubuntu kann ODBC mit folgenden Befehlen eingerichtet werden:
    sudo apt-get install freetds-bin freetds-common tdsodbc odbcinst php5-odbc unixodbc
    sudo cp /usr/share/doc/freetds-common/examples/odbcinst.ini /etc/odbcinst.ini
(Falls ODBC auch aus Webanwendungen heraus genutzt werden soll, müssen noch der Webserver bzw. php-fastcgi neu gestartet werden.)
Anschließend kann mit folgenden Einstellungen gearbeitet werden:
  $SOURCEPDO = 'odbc:Driver=FreeTDS; Server=127.0.0.1; Port=1433; Database=datenbank; UID=benutzername; PWD=passwort';
  $SOURCEUSER = ''; // User und Passwort MUESSEN im PDO-String angegeben werden, Variablen bleiben leer!
  $SOURCEPASS = '';
IP und Port sind anzupassen, "datenbank", "benutzername" und "passwort" jeweils durch Datenbanknamen, Benutzername und Passwort zu ersetzen.
	
Auf dem Export-Server werden die Dateien piratenid-verify.php, piratenid-export.php und piratenid-export-config.php benötigt.
Die Konfiguration ist entsprechend anzupassen (gleiches Secret wie in der Import-Config).

Der Export/Import wird durch einfaches Ausführen des Skripts piratenid-export.php durchgeführt. Dies kann manuell oder automatisiert erfolgen.

