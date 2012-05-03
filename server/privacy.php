<?php 
require('includes/header.inc.php');
?>
<h2>Datenschutzerkärung</h2>

<div>
Der PiratenID-Server speichert folgende Daten:
<ul>
	<li>normale Webserverlogs, gespeichert werden angefragte URLs, Zeitstempel, verweisende Website und verwendeter Browser</li>
	<ul>
		<li>IP-Adressen werden dort <strong>nicht</strong> gespeichert
		<li>POST-Parameter (dort stehen z. B. Benutzernamen) werden <strong>nicht</strong> gespeichert</li>
		<li>Logs werden automatisch nach einiger Zeit gelöscht</li>
		<li>Diese Protokolle dienen der Fehlersuche und der Erkennung von Angriffen</li>
	</ul>
</ul>

<ul>
	<li>Die Token-Datenbank, bestehend aus Einträgen über alle existierenden Token:</li>
	<ul>
		<li>Hashwert (SHA256) des Tokens</li>
		<li>Gliederungen, in denen der Besitzer des Tokens Mitglied ist</li>
		<li>Stimmberechtigung des Tokenbesitzers</li>
	</ul>
</ul>

<ul>
	<li>Die Benutzerdatenbank, welche zu jedem angemeldeten Benutzer enthält:</li>
	<ul>
		<li>Benutzername</li>
		<li>Zufallswert für Pseudonymberechnung</li>
		<li>Hashwert des Kennworts</li>
		<li>e-Mail-Adresse für Passwortresets, Benachrichtigungen und sonstige administrative Zwecke</li>
		<li>Hashwert des Tokens, falls eingegeben (wird mit Token-Datenbank verknüpft)</li>
		<li>Zeitstempel, Flags und Zufallsschlüssel (z. B. für die E-Mail-Verifikation)</li>
	</ul>
</ul>


<ul>
	<li>Die Login-Fehlerprotokolle</li>
	<ul>
		<li>Es werden <strong>nur fehlgeschlagene</strong> Logins protokolliert</li>
		<li>Der verwendete Benutzername wird <strong>nicht</strong> protokolliert</li>
		<li>Es werden für die Dauer von ca. einem Monat gespeichert:</li>
  		<li>IP, von welcher die Anfrage kam</li>
  		<li>Zeitstempel der Anfrage</li>
  		<li>Verwendeter Browser</li>
  		<li>Verweisende Seite</li>
		<li>Diese Daten sind für die Erkennung und Verhinderung von Brute-Force-Angriffen unverzichtbar.</li>
	</ul>
</ul>

<ul>
	<li>Temporäre Authentifizierungsdaten, bestehend aus Zeitstempeln, Zufallswerten und Prüfsummen.</li>
</p>

<p>
Die PiratenID-Daten werden in einem verschlüsselten Datenbereich gespeichert.
Der Server wird nur von den zuständigen Mitgliedern der BundesIT administiert, welche eine Datenschutzverpflichtung abgegeben haben.
</p>

<p>
Das PiratenID-System funktioniert nach folgendem Verfahren (siehe auch <a href="http://vorstand.piratenpartei.de/wp-content/uploads/2011/03/Stellungnahme-ID_Server-280211.pdf">Stellungnahme der Rechtsabteilung zum ID-Server</a> vom 28.02.2011):
</p>

<p>
Für jeden Piraten wird ein Token erstellt und dem Piraten geschickt. *)
Der Hashwert wird in der Mitgliederverwaltung gespeichert.
</p>

<p>
Die Liste von Token-Hashes und zugehörigen Gliederungsmitgliedschaften/Stimmberechtigungen wird regelmäßig automatisiert auf dem Mitgliederverwaltungsserver erstellt, nach Tokenhash sortiert (um Rückschlüsse aus der Reihenfolge der Einträge zu verhindern) und über das gesicherte interne Netzwerk an den PiratenID-Server übertragen.
</p>

<p>
Piraten können sich auf dem PiratenID-Server mit einem selbst gewählten Benutzernamen und Passwort sowie einer E-Mail-Adresse (diese muss NICHT mit der in der MV erfassten übereinstimmen) einen Account erstellen (siehe Benutzerdatenbank). Dabei wird für die Benutzer ein Zufallswert erstellt und auf dem Server gespeichert. Dieser wird für die Berechnung der Pseudonyme genutzt.
Sie können ihr Token eingeben, welches daraufhin fest mit ihrem Account verknüpft wird. Bei der Anmeldung wird eine Einwilligung nach  §4a BDSG eingeholt (siehe https://id.piratenpartei.de/user/create.php).
</p>

<p>
Möchte der Nutzer sich via PiratenID bei einem Dienst anmelden, stellt der Dienst eine Anfrage an den ID-Server. Der Pirat bekommt angezeigt, welcher Dienst welche Daten abfragt. Möchte er die Übertragung der Daten erlauben, bestätigt er dies durch Eingabe von Benutzername und Kennwort. Daraufhin werden die Daten über eine verschlüsselte Verbindung vom ID-Server an den Dienst übertragen. Zu den abfragbaren Daten gehört auch ein Pseudonym. Dieses wird aus dem Namen des Dienstes und der in der Benutzerdatenbank erfassten Zufallszahl des Benutzers berechnet und ist somit für jeden Dienst unterschiedlich. Die Pseudonyme können ohne Kenntniss der Zufallszahl weder mit einem Benutzerkonto noch mit anderen Pseudonymen verknüpft werden. Die Weitergabe findet somit ausschließlich automatisch, verschlüsselt und nur mit Zustimmung des Nutzers in jedem Einzelfall statt. (Siehe auch Stellungnahme Punkte II.7 und III)
</p>

<p>
Möchte ein Nutzer seine Benutzerkonto löschen, kann er dies online über den entsprechenden Menüpunkt tun. Hierbei wird aus Sicherheitsgründen eine E-Mail-Bestätigung verlangt. Benutzerkonten ohne eingetragenes Token werden nach Bestätigung vollständig und unwiderruflich gelöscht. Bei Benutzerkonten mit eingetragenem Token bleiben der Zufallswert für die Pseudonymberechnung, das Token und die Zuordnung zwischen diesen erhalten. Dies dient dazu, um (z. B. im Fall von missbräuchlicher Löschung gehackter Benutzerkonten) das Benutzerkonto wieder herstellen zu können. Alle anderen Daten, insbesondere Benutzername, E-Mail-Adresse, und Kennworthash, werden gelöscht. Möchte der Nutzer auch die Zufallszahl für die Pseudonymberechnung und somit seine Pseudonyme löschen lassen, kann er dies beantragen (aus Sicherheitsgründen muss dies jedoch schriftlich erfolgen). Der Nutzer wird darauf ausdrücklich hingewiesen.
</p>

<p>
Bestimmte Vorgänge (z. B. Wiederherstellung eines gelöschten Accounts) erfordern eine Deanonymisierung (Zuordnung des Accounts anhand des Token-Hashes und der Mitgliederverwaltung). Hierzu wird die Einverständnis des Nutzers eingeholt und seine Identität außerhalb des Systems (z. B. durch ein persönliches Treffen mit Ausweiskontrolle) geprüft.
</p>


<small>
*) Da keine regelmäßigen Postsendungen an alle Piraten mehr existieren, werden die Token vermutlich per E-Mail an die in der Mitgliederverwaltung erfasste E-Mail-Adresse aus der MV versendet. Ursprünglich sollte das Token dreiteilig sein. Da es aufgrund des (kostengünstigen) E-Mail-Versands keinen Grund gibt, weitere Tokenteile auf Vorrat anzulegen, wird nur der erste Teil erstellt und stellt "das Token" dar. Die ursprünglich angedachte Möglichkeit, Klarnamen zu erfassen (Stellungnahme Punkt II.6), wird es erst einmal nicht geben.
</small>
</div>

<?php
include("includes/footer.inc.php");
?>