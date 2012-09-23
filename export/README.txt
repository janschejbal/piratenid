== Funktionsbeschreibung PiratenID Export/Import ==
Das Export-Skript auf einem Exportserver holt die Daten von einer Datenbank und konvertiert sie.
Anschließend sendet es sie verschlüsselt und authentifiziert per HTTP POST an das Import-Skript auf dem PiratenID-Server.
Das Importskript importiert die Daten in die PiratenID-Datenbank und erstellt optional eine Textdatei mit Statistiken.

Beide Skripte prüfen die Gültigkeit der Daten. Das Exportskript zeigt bei gelungenem Export Statistiken an.

=== Sicherheit ===
Die Daten werden ausschließlich über das gesicherte, interne Netzwerk übertragen.
Die Token-Hashes werden vom Exportskript sortiert, um Rückschlüsse aus der Reihenfolge zu verhindern.
Die übertragenen Daten bestehen aus einem Token-Hash, Informationen über Verbandsmitgliedschaften und die Stimmberechtigung.
Sie enthalten keine personenbezogenen Angaben und müssen daher nicht besonders geschützt werden.

Dennoch wird durch mehrere Maßnahmen sichergestellt, dass die Daten nicht in fremde Hände gelangen:
* Die Datenübertragung erfolgt über ein internes, gesichertes und vertrauenswürdes Netzwerk
* Die Daten werden symmetrisch verschlüsselt

Durch mehrere Maßnahmen wird sichergestellt, dass keine verfälschten Daten importiert werden können:
* Die Datenübertragung erfolgt über ein internes, gesichertes und vertrauenswürdes Netzwerk
* Nur der Export-Server kann auf das Importskript zugreifen.
  * Die Webserver-Konfiguration erlaubt nur Zugriffe von der IP des Export-Servers
  * Das Importskript prüft die IP erneut
* Ein Import erfolgt nur, wenn die Nachricht einen (konstanten) Authentifizierungssschlüssel enthält
* Die Daten werden mit einem symmetrischen Schlüssel integritätsgesichert
* Um Replay-Attacken zu verhindern, wird ein Timestamp mitsigniert.

=== Dateien ===
* README.txt ist diese Hilfedatei
* piratenid-verify.php enthält gemeinsame Routinen zur Datenprüfung
* piratenid-import.php ist das Importskript
* piratenid-import-config.php ist die Konfigurationsdatei für das Importskript
* piratenid-export.php ist das Exportskript
* piratenid-export-config.php ist die Konfigurationsdatei für das Exportskript
* piratenid-mktoken.php ist KEIN Teil der Export/Import-Architektur, sondern dient zur Erstellung von Testtokens auf dem Testserver


== Installationsanleitung für PiratenID Export/Import ==

=== Importseite (auf PiratenID-Server) ===

1. piratenid-verify.php, piratenid-import.php und piratenid-import-config.php in ein nicht öffentlich zugängigliches Verzeichnis auf dem Server platzieren.
2. Datenbankzugang mit ausreichenden Rechten (nur DELETE und INSERT nur auf die Tabelle "tokens") anlegen
3. (Optional) Verzeichnis für Statistiken anlegen, in welchem PHP schreiben darf, und per Statistikdatei per Alias öffentlich lesbar machen:
----------------------------------------------------------------------------------------------------
		# Innerhalb der Server-Direktive fuer den OEFFENTLICHEN Teil des Servers!
		location /stats.txt {
			alias /srv/www/piratenid_test_import/stats/importstats.txt;
		}
----------------------------------------------------------------------------------------------------

4. piratenid-import-config.php anpassen
    * DB-Zugangsdaten eintragen
    * IP, von welcher die Importe kommen, eintragen
    * Neues Secret generieren und eintragen (dieses muss später auch in piratenid-export-config.php eingetragen werden)

5. Nginx einrichten. Nur der Export-Server darf auf das Import-Skript zugreifen, und die Zugriffsmöglcihkeiten sind restriktiv zu vergeben.
   Eine Beispielkonfiguration folgt, darin müssen Pfade und die allow-IP (IP des Export-Servers) angepasst werden:
----------------------------------------------------------------------------------------------------
	server { # HTTP endpoint for imports
		listen 81;
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
Der Export-Server benötigt Zugriff auf eine Datenbank, welche die Export-Daten bereitstellt.
Er muss HTTP-Zugang zum oben konfigurierten Import-Endpunkt haben.

Für den Export sollte ein separater Datenbank-Benutzer angelegt werden, welcher nur auf die Export-Daten zugreifen kann.
Der Export-Nutzer sollte nur vom Export-Server aus nutzbar sein, und der Export-Server sollte sich nur mit dem Export-Nutzer auf die DB zugreifen können.

Auf dem Export-Server muss eine aktuelle PHP-Version vorhanden sein, welche per PDO auf die Datenbank zugreifen kann.
Es muss somit für die verwendete Datenbank entweder ein PDO-Treiber vorhanden sein, oder ODBC muss korrekt konfiguriert sein.
Beim Zugriff auf eine MSSQL-Datenbank sollte ODBC verwendet werden.

Auf dem Export-Server werden die Dateien piratenid-verify.php, piratenid-export.php und piratenid-export-config.php benötigt.
Die Konfiguration ist entsprechend anzupassen (gleiches Secret wie in der Import-Config).

Der Export/Import wird durch einfaches Ausführen des Skripts piratenid-export.php durchgeführt. Dies kann manuell oder automatisiert erfolgen.

