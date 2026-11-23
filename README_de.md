# IPFire-API-v2
![IPFire API v2](docs/images/ipfire-api-logo-v2.svg)
Ein modularer, Perl-basierter API-Dienst für IPFire, der sichere Fernverwaltung und Monitoring über WebSocket mit TLS ermöglicht.
Diese Version wurde mit ChatGPT erstellt. Sie basiert auf meiner IPFire API.

> **Entwicklungsstand:** Frühe Entwicklungsphase. Die API ist noch nicht funktionsfähig.

## Inhaltsverzeichnis

- [Projektziele](#projektziele)
- [Geplante Architektur](#geplante-architektur)
  - [Aufgaben der Module](#aufgaben-der-module)
- [IPFire-Kompatibilität](#ipfire-kompatibilität)
  - [Client-Zugriff auf IPFire verwalten](#client-zugriff-auf-ipfire-verwalten)
  - [Verbindungs- und Anfragelimits](#verbindungs--und-anfragelimits)
  - [Erlaubte Client-Netze konfigurieren](#erlaubte-client-netze-konfigurieren)
  - [API-Verwaltungsseite verwenden](#api-verwaltungsseite-verwenden)
  - [Beide Dienste auf IPFire automatisch starten](#beide-dienste-auf-ipfire-automatisch-starten)
  - [TLS-Listener auf IPFire testen](#tls-listener-auf-ipfire-testen)
  - [JSON-Anfrage senden](#json-anfrage-senden)
  - [Monitoring-Ereignisse abonnieren](#monitoring-ereignisse-abonnieren)
  - [Java-Ereignisclient starten](#java-ereignisclient-starten)
  - [API auf IPFire testen](#api-auf-ipfire-testen)
- [Entwicklungsplan](#entwicklungsplan)
  - [Phase 1 – Projektgrundlagen](#phase-1--projektgrundlagen)
  - [Phase 2 – TLS-Server](#phase-2--tls-server)
  - [Phase 3 – WebSocket-Protokoll](#phase-3--websocket-protokoll)
  - [Phase 4 – JSON-API-Protokoll](#phase-4--json-api-protokoll)
  - [Phase 5 – Authentifizierung und Sicherheit](#phase-5--authentifizierung-und-sicherheit)
  - [Phase 6 – Monitoring und Ereignisse](#phase-6--monitoring-und-ereignisse)
  - [Phase 7 – IPFire-Integration](#phase-7--ipfire-integration)
  - [Phase 8 – Künftige Kompatibilität](#phase-8--künftige-kompatibilität)
- [Hinweise zur Entwicklung](#hinweise-zur-entwicklung)
- [Lizenz](#lizenz)

## Projektziele

Das Ziel ist eine modulare API für IPFire, die eine dauerhafte Kommunikation in beide Richtungen zwischen IPFire und externen Clients ermöglicht.

Die Implementierung soll folgende Anforderungen erfüllen.

- Nach Möglichkeit Perl und bereits auf IPFire vorhandene Module verwenden.
- Zusätzliche Laufzeitabhängigkeiten vermeiden.
- Sichere WebSocket-Verbindungen (WSS) bereitstellen.
- Mehrere Clients gleichzeitig unterstützen.
- JSON für Anfragen, Antworten und Ereignisse verwenden.
- Monitoring und später ausgewählte Verwaltungsfunktionen unterstützen.
- Unabhängig von der bestehenden IPFire API v1 bleiben.

Die Entwicklung erfolgt schrittweise. Getestet wird auf einer echten IPFire-Installation.

## Geplante Architektur

Die API soll als eigenständiger Perl-Daemon laufen.

Als erstes Kommunikationsprotokoll ist WebSocket über TLS (WSS) auf TCP-Port `8444` vorgesehen.

Die geplante Projektstruktur sieht wie folgt aus.

```text
IPFire-API-v2/
├── bin/
│   ├── ipfire-api-admin.pl
│   ├── ipfire-api-clients.pl
│   └── ipfire-api-daemon.pl
├── cgi-bin/
│   └── api.cgi
├── lib/
│   └── IPFire/
│       └── API/
│           ├── AdminPage.pm
│           ├── AdminProtocol.pm
│           ├── AdminService.pm
│           ├── Auth.pm
│           ├── Client.pm
│           ├── Config.pm
│           ├── NetworkPolicy.pm
│           ├── NetworkSettings.pm
│           ├── Protocol.pm
│           ├── Server.pm
│           ├── System.pm
│           └── WebSocket.pm
├── t/
├── .gitignore
├── LICENSE
└── README.md
```

### Aufgaben der Module

| Modul | Aufgabe |
|---|---|
| `Auth.pm` | Client-Tokens, Authentifizierung und Ermittlung der Rolle |
| `AdminPage.pm` | WebGUI-Formulare zur Verwaltung von Clients und Netzwerkeinstellungen mit Authentifizierung |
| `AdminProtocol.pm` | Verpacken lokaler Nachrichten zwischen CGI und Verwaltungsdienst |
| `AdminService.pm` | Lokale Verwaltungsanfragen und Prüfung der WebGUI-Prozesse |
| `Config.pm` | Serverkonfiguration, lokale Adresse, Port und Pfade zu den TLS-Zertifikaten |
| `NetworkPolicy.pm` | Prüfung lokaler Adressen und der Client-Netze |
| `NetworkSettings.pm` | Validierung und atomares Speichern der Netzwerkeinstellungen der Verwaltungsseite |
| `Server.pm` | TCP-/TLS-Listener, Verbindungsverwaltung und Ereignisschleife |
| `Client.pm` | Einzelne Client-Verbindungen und ihr Verbindungszustand |
| `WebSocket.pm` | WebSocket-Handshake, Verarbeitung von Frames und Protokollsteuerung |
| `Protocol.pm` | Verarbeitung von JSON-Nachrichten, Weiterleitung von Anfragen an die zuständige Methode und Antworten |
| `System.pm` | Lesender Zugriff auf Systeminformationen |
| `ipfire-api-daemon.pl` | Startpunkt des API-Dienstes |

## IPFire-Kompatibilität

Die ersten Abhängigkeitsprüfungen wurden mit folgenden Versionen durchgeführt.

- IPFire 2.29 Core Update 205
- Perl 5.42.2

Dabei wurde die Verfügbarkeit der folgenden Module geprüft.

| Perl-Modul | Status |
|---|---|
| `IO::Socket::INET` | Verfügbar |
| `IO::Socket::SSL` | Verfügbar |
| `Net::SSLeay` | Verfügbar |
| `IO::Select` | Verfügbar |
| `Digest::SHA` | Verfügbar |
| `MIME::Base64` | Verfügbar |
| `Protocol::WebSocket` | Nicht verfügbar |

Die bestehende API v1 verwendet bereits JSON.

Nach der ersten Einschätzung lässt sich ein WebSocket-Server ohne zusätzliche Perl-Pakete umsetzen. Das muss noch praktisch überprüft werden.

### Client-Zugriff auf IPFire verwalten

Die folgenden Befehle im Projektverzeichnis mit demselben lokalen Benutzerkonto ausführen, unter dem der Daemon läuft.

```sh
perl bin/ipfire-api-clients.pl add home-assistant
perl bin/ipfire-api-clients.pl list
perl bin/ipfire-api-clients.pl revoke home-assistant
```

`add` legt einen Client mit der Rolle `monitoring` an und gibt dessen Token einmalig aus. Den Token im Client hinterlegen. Das Werkzeug speichert einen SHA-256-Hash im privaten Client-Verzeichnis des Daemons. Für Tests einen eigenen Namen wie `smoke-test` verwenden.

Clients senden beim WebSocket-Upgrade über TLS den Header `Authorization: Bearer <token>`. Bei fehlenden, ungültigen oder widerrufenen Tokens antwortet der Server mit HTTP 401. Die Monitoring-Rolle erlaubt `system.ping` und `system.info`. Ein Widerruf gilt für nachfolgende Anfragen auf bestehenden Verbindungen und für alle neuen Verbindungen. Der Daemon übernimmt neu angelegte und widerrufene Zugänge ohne Neustart.

### Verbindungs- und Anfragelimits

Der API-Daemon akzeptiert über alle Listener hinweg bis zu 32 gleichzeitige Verbindungen. Dazu zählen auch Verbindungen während des TLS-Handshakes oder des WebSocket-Upgrades. Alle Verbindungen, die denselben authentifizierten Token verwenden, teilen sich ein Anfragekontingent. Ein Client kann bis zu 10 Anfragen unmittelbar hintereinander senden. Das Kontingent füllt sich um 2 Anfragen pro Sekunde wieder auf. Ist es ausgeschöpft, beantwortet der Daemon Anfragen mit gültiger ID mit `rate_limited`. Die WebSocket-Verbindung bleibt offen, damit der Client es später erneut versuchen kann. WebSocket-Steuerframes verbrauchen kein Kontingent.

### Erlaubte Client-Netze konfigurieren

Ohne gespeicherte Einstellungen oder ausdrückliche Vorgabe lauscht der Daemon auf `127.0.0.1`. Für eine manuelle Konfiguration `IPFIRE_API_HOST` auf eine bestimmte lokale IPFire-Adresse setzen und in `IPFIRE_API_ALLOWED_NETWORKS` die IPv4- oder IPv6-Client-Netze als kommaseparierte Liste in CIDR-Schreibweise angeben. Die Dokumentationsadressen im Beispiel durch die eigene IPFire-Adresse und das freizugebende Client-Netz ersetzen.

```sh
IPFIRE_API_HOST=192.0.2.1 IPFIRE_API_ALLOWED_NETWORKS=192.0.2.0/24 \
  perl bin/ipfire-api-daemon.pl
```

Der Daemon prüft die Quell-IP-Adresse jeder TCP-Verbindung vor dem TLS-Handshake. Auch Clients aus erlaubten Netzen benötigen einen gültigen Token. Eine explizite Netzwerkliste ersetzt die Loopback-Standardwerte. Bei einem Loopback-Listener mit eigener Liste `127.0.0.0/8` aufnehmen, wenn lokale IPv4-Clients zugelassen werden sollen. Der Listener lauscht auf einer konkreten IP-Adresse. Außerhalb von Loopback ist eine explizite Netzwerkliste erforderlich. Änderungen an diesen Umgebungsvariablen gelten ab dem Start des Daemons.

### API-Verwaltungsseite verwenden

`/cgi-bin/api.cgi` liefert weiterhin JSON für HA-IPFire. Die Antwort enthält die von HA-IPFire gelesenen Daten. Die vorhandenen Anfragen zum Verbinden, Trennen, Aktualisieren und Neustarten verwenden weiterhin ihre bisherigen API-Header. In der angemeldeten IPFire-WebGUI unter **Dienste → IPFire API v2** lassen sich API-v2-Clients und erlaubte Netze verwalten. Die Seite ist direkt unter `/cgi-bin/api.cgi?view=admin` erreichbar. Den Token eines neuen Clients kopieren, wenn er angezeigt wird.

Den Menüeintrag aus dem Projektverzeichnis als `root` installieren.

```sh
install -o root -g root -m 0644 deploy/ipfire/EX-ipfire-api-v2.menu /var/ipfire/menu.d/EX-ipfire-api-v2.menu
```

Für die Bedienelemente unter **API daemon** das Init-Skript und die Startlinks wie unten beschrieben installieren. **Start** und **Stop** ändern den aktuellen Betriebszustand. **Start at system boot** steuert unabhängig davon den nächsten Systemstart. Der Verwaltungsdienst läuft weiter, sodass sich die API auch im gestoppten Zustand starten und konfigurieren lässt.

Auf einem IPFire-Testsystem die Perl-Module so installieren, dass `/usr/local/lib/ipfire-api-v2/IPFire/API/AdminPage.pm` vorhanden ist. Eine bestehende Datei `/srv/web/ipfire/cgi-bin/api.cgi` vor der Installation der neuen CGI-Datei mit den Rechten `0755` sichern. Den lokalen Verwaltungsdienst aus dem Projektverzeichnis starten und als Argument den Apache-Benutzer aus `/etc/httpd/conf/uid.conf` übergeben.

```sh
perl bin/ipfire-api-admin.pl nobody
```

Den Verwaltungsdienst und den TLS-Daemon unter demselben lokalen Benutzerkonto ausführen. Der Verwaltungsdienst prüft, ob die Gegenstelle am Unix-Socket dem angegebenen WebGUI-Benutzer entspricht. Er nutzt dasselbe private Client-Verzeichnis wie der Daemon. Während der Nutzung der Seite muss der Verwaltungsdienst laufen.

Unter **Network access** im Bereich **Allowed networks** die Zonen auswählen. Bei einer frischen Einrichtung ist GREEN vorausgewählt. ORANGE und BLUE stehen zur Auswahl, sofern sie eingerichtet sind. Für jede ausgewählte Zone wird ein Listener auf der IPFire-Adresse der jeweiligen Schnittstelle aktiviert. Er akzeptiert Verbindungen aus dem IPv4-Subnetz dieser Zone. Adresse und Subnetz stehen neben dem Kontrollkästchen.

Beim Speichern wird die Zonenauswahl in `/var/ipfire/api-v2-network.json` geschrieben. Ein laufender API-Daemon lädt die Listener innerhalb von etwa einer Sekunde automatisch neu. Ändert sich die Listener-Konfiguration, werden bestehende WebSocket-Verbindungen geschlossen. Die Clients können sich anschließend neu verbinden. Kann ein neuer Listener nicht geöffnet werden, protokolliert der Daemon den Fehler, behält die bisherigen Listener und versucht es erneut. Die IPFire-Firewallregeln gelten weiterhin. Gegebenenfalls muss der API-Port auf der IPFire-Adresse der Zone freigegeben werden. Die WebGUI regelt ihren Zugriff selbst.

Eine Änderung über die WebGUI ersetzt zuvor manuell gespeicherte Listener- und CIDR-Einstellungen. `IPFIRE_API_HOST` oder `IPFIRE_API_ALLOWED_NETWORKS` aktiviert für diesen Prozess den manuellen Betrieb mit einem einzelnen Listener. Dabei sind automatische Konfigurationsupdates deaktiviert.

### Beide Dienste auf IPFire automatisch starten

Das SysV-Init-Skript startet den API-Daemon und den lokalen Verwaltungsdienst aus `/root/IPFire-API-v2`. Es liest den Apache-Benutzer aus `/etc/httpd/conf/uid.conf` und verwendet die Standardpfade des Projekts. Vor dem Wechsel zum Init-Skript die manuell gestarteten Instanzen in ihren jeweiligen Terminals mit Strg+C beenden.

Das Skript auf IPFire als `root` installieren und starten.

```sh
cd /root/IPFire-API-v2 &&
install -o root -g root -m 0755 deploy/ipfire/ipfire-api-v2 /etc/rc.d/init.d/ipfire-api-v2 &&
/etc/rc.d/init.d/ipfire-api-v2 start &&
/etc/rc.d/init.d/ipfire-api-v2 status
```

Sobald beide Prozesse laufen, den automatischen Start nach der Netzwerkkonfiguration sowie das Stoppen beim Herunterfahren oder Neustart einrichten.

```sh
ln -s ../init.d/ipfire-api-v2 /etc/rc.d/rc3.d/S99ipfire-api-v2 &&
ln -s ../init.d/ipfire-api-v2 /etc/rc.d/rc0.d/K20ipfire-api-v2 &&
ln -s ../init.d/ipfire-api-v2 /etc/rc.d/rc6.d/K20ipfire-api-v2
```

Die Startlinks starten den Verwaltungsdienst und berücksichtigen die Autostart-Einstellung des API-Daemons. Der API-Autostart ist standardmäßig aktiviert. Beim Deaktivieren wird `/etc/sysconfig/ipfire-api-v2.no-autostart` angelegt.

Mit `/etc/rc.d/init.d/ipfire-api-v2 stop`, `restart` oder `status` lassen sich beide Prozesse gemeinsam verwalten. Ein gemeinsamer Neustart berücksichtigt die Autostart-Einstellung. Mit `daemon-start` oder `daemon-stop` lässt sich der API-Daemon einzeln steuern. Seine und die Meldungen des Verwaltungsdienstes stehen als `ipfire-api-daemon` und `ipfire-api-admin` im IPFire-Systemprotokoll. Nach dem nächsten IPFire-Neustart mit `status` den Zustand und mit `ss -ltnp 'sport = :8444'` den erwarteten Listener prüfen. Anschließend die Verwaltungsseite öffnen und prüfen, ob sie den Verwaltungsdienst erreicht.

### TLS-Listener auf IPFire testen

Die API benötigt mindestens TLS 1.2. Sie verwendet standardmäßig das Zertifikat und den privaten Schlüssel der IPFire-WebGUI. Clients müssen das Zertifikat gegen eine vertrauenswürdige Zertifizierungsstelle und den erwarteten Servernamen prüfen. Bei einem selbstsignierten IPFire-Zertifikat eine vertrauenswürdige Kopie des öffentlichen Zertifikats als CA-Datei verwenden. Der private Schlüssel bleibt auf IPFire. Nur die Dienste, die ihn benötigen, sollen Lesezugriff erhalten. Nach einem Austausch des Zertifikats oder Schlüssels den Daemon neu starten.

Für einen lokalen Test im Projektverzeichnis auf IPFire den Daemon mit expliziten Loopback-Einstellungen starten.

```sh
IPFIRE_API_HOST=127.0.0.1 IPFIRE_API_ALLOWED_NETWORKS=127.0.0.0/8 perl bin/ipfire-api-daemon.pl
```

In einer zweiten Shell auf derselben IPFire-Installation mit dem Listener verbinden.

```sh
openssl s_client -connect 127.0.0.1:8444 \
  -servername ipfire.local -verify_hostname ipfire.local \
  -CAfile /etc/httpd/server.crt -verify_return_error </dev/null
```

`ipfire.local` durch den Namen aus dem eigenen IPFire-Zertifikat ersetzen. Der Daemon lässt bis zu fünf Sekunden für den TLS-Handshake und weitere fünf Sekunden für das WebSocket-Upgrade zu. Zum Anhalten `Ctrl+C` drücken oder `SIGTERM` an den Daemon-Prozess senden. Der Daemon schließt Listener und Client-Verbindungen, gibt `IPFire API v2 stopped` aus und beendet sich erfolgreich. Wurde das Serverzertifikat von einer CA ausgestellt, deren Zertifikat für `-CAfile` verwenden.

Die API-v2-Dienstprotokolle enthalten Start- und Stoppereignisse, Zeitüberschreitungen und allgemeine Fehlermeldungen. Bearer-Tokens, Token-Hashes und rohe Client-Anfragen werden ausgelassen.

Zur Prüfung des Handshake-Timeouts in der zweiten Shell auf IPFire eine TCP-Verbindung ohne TLS öffnen.

```sh
time timeout 8 bash -c 'exec 3<>/dev/tcp/127.0.0.1/8444; cat <&3'
```

Die Verbindung sollte nach etwa fünf Sekunden geschlossen werden. Der Daemon sollte `TLS handshake failed: timed out` protokollieren. Unmittelbar danach den [API-Kurztest](#api-auf-ipfire-testen) ausführen, um sicherzustellen, dass der Daemon einen weiteren Client bedient.

Für den Test des WebSocket-Upgrades in der zweiten Shell den folgenden Befehl ausführen.

```sh
key=$(openssl rand -base64 16)
read -rs -p 'Client token: ' token
printf '\n'
printf 'GET / HTTP/1.1\r\nHost: 127.0.0.1:8444\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: %s\r\nAuthorization: Bearer %s\r\n\r\n' "$key" "$token" |
  openssl s_client -quiet -connect 127.0.0.1:8444 \
    -CAfile /etc/httpd/server.crt -verify_return_error
unset token
```

Erwartet werden `HTTP/1.1 101 Switching Protocols` und ein `Sec-WebSocket-Accept`-Header. Nach dem Upgrade bleibt die Verbindung offen. Der Daemon wartet bis zu 30 Sekunden auf jeden Frame. Für das Senden eines Antwortframes sind bis zu fünf Sekunden vorgesehen. Bei einer Zeitüberschreitung schließt der Daemon die Verbindung. Die geltenden Limits stehen unter [Verbindungs- und Anfragelimits](#verbindungs--und-anfragelimits). Eine Nachricht darf einschließlich ihrer Fragmente maximal 64 KiB groß sein. Auf Ping folgt Pong. Close beendet die Verbindung.

### JSON-Anfrage senden

Pro WebSocket-Textnachricht ein JSON-Objekt senden. Jede Anfrage enthält eine Zeichenkette `id` mit 1 bis 128 Zeichen sowie eine Zeichenkette `method`. Die erste Methode `system.ping` nimmt keine Parameter entgegen. Das Feld `params` kann entfallen oder ein leeres Objekt enthalten.

```json
{"id":"ping-1","method":"system.ping"}
```

Die Antwort enthält dieselbe ID und ein `result`- oder `error`-Objekt, wie im folgenden Beispiel.

```json
{"id":"ping-1","result":{"pong":true}}
```

Fehler enthalten `code` und `message`. Hat die Anfrage keine gültige ID, lautet die Antwort-ID `null`. Aktuell sind die Fehlercodes `invalid_json`, `invalid_request`, `method_not_found`, `invalid_params`, `access_denied`, `rate_limited` und `internal_error` vorgesehen. Schlägt eine Methode intern fehl, enthält die Antwort weiterhin die Anfrage-ID. Der Client kann dieselbe Verbindung weiterverwenden.

`{"id":"info-1","method":"system.info"}` liefert den Hostnamen, die IPFire-Version und die Zeit seit dem Systemstart in ganzen Sekunden. Die Felder heißen `hostname`, `ipfire_release` und `uptime_seconds`. Sind die Quellen für Version oder Laufzeit nicht verfügbar, lautet der jeweilige Wert `null`. Auch diese Methode nimmt keine Parameter entgegen.

### Monitoring-Ereignisse abonnieren

Ein authentifizierter Monitoring-Client kann Ereignisse auf seiner WebSocket-Verbindung abonnieren.

```json
{"id":"watch-1","method":"events.subscribe","params":{"event":"system.info"}}
```

Die Antwort lautet `{"id":"watch-1","result":{"event":"system.info","subscribed":true}}`. Anschließend sendet der Daemon etwa alle fünf Sekunden eine Benachrichtigung, sofern die Verbindung das Senden zulässt. Eine Benachrichtigung enthält den Ereignisnamen und die Daten. Sie hat keine Anfrage-ID. Die Daten enthalten dieselben Felder wie die Methode `system.info`.

```json
{"event":"system.info","data":{"hostname":"ipfire","ipfire_release":"IPFire","uptime_seconds":3600}}
```

Zur Überwachung der RED-Schnittstelle das Ereignis `red.status` abonnieren.

```json
{"id":"watch-red","method":"events.subscribe","params":{"event":"red.status"}}
```

Der Daemon sendet nach der Abo-Bestätigung den aktuellen RED-Status. Anschließend prüft er etwa alle fünf Sekunden, ob sich der Status oder der Verbindungszeitstempel geändert hat, und sendet bei einer Änderung ein Ereignis.

```json
{"event":"red.status","data":{"status":"connected","connected_since":1795383000}}
```

Der Status lautet `connected`, solange die IPFire-Markierungsdatei `/var/ipfire/red/active` existiert. Fehlt sie bei vorhandenem RED-Verzeichnis, lautet er `disconnected`. Kann der RED-Status nicht gelesen werden, lautet er `unknown`. `connected_since` gibt die Änderungszeit der Markierungsdatei in Unix-Sekunden an und ist bei den anderen Zuständen `null`. Das Ereignis meldet den RED-Zustand aus Sicht von IPFire. Die Erreichbarkeit des Internets lässt sich separat prüfen.

`events.unsubscribe` mit denselben `params` aufrufen, um Benachrichtigungen abzubestellen. Jedes Ereignis lässt sich unabhängig abonnieren und abbestellen. Beide Anfragen lassen sich gefahrlos wiederholen. Jedes Abo gehört zur jeweiligen Verbindung. Nach einer Wiederverbindung muss der Client es erneut anlegen. Vor jeder eingeplanten Benachrichtigung prüft der Daemon den Client-Token.

### Java-Ereignisclient starten

Zum Testen von IPFire API v2 steht ein einfacher grafischer Java-Client bereit. Er verbindet sich über WSS, abonniert `system.info` und `red.status` und zeigt die Abo-Antworten sowie die JSON-Benachrichtigungen an. Er verwendet nur die Java-Standardbibliothek. Das [Beispiel-JAR](examples/java/ipfire-events.jar) herunterladen und mit Java 11 oder neuer über `java -jar ipfire-events.jar` starten. Wer den Client aus dem Quellcode bauen möchte, benötigt ein JDK.

```sh
cd examples/java
javac -encoding UTF-8 --release 11 -d build/classes IPFireEvents.java IPFireEventsWindow.java
jar --create --file build/ipfire-events.jar --main-class IPFireEvents -C build/classes .
```

Den grafischen Client aus einer Desktop-Sitzung starten.

```sh
java -jar build/ipfire-events.jar
```

Die WebSocket-URL eingeben, etwa `wss://ipfire.local:8444/`, und den Token in das verdeckte Eingabefeld einfügen. Verwendet IPFire ein selbstsigniertes Zertifikat, im Zertifikatsfeld eine vertrauenswürdige Kopie des öffentlichen Zertifikats auswählen. Der Zertifikatsdialog zeigt standardmäßig PEM-Dateien an. Über **Alle Dateien** lassen sich Zertifikate mit anderer Dateiendung auswählen.

Vor dem Verbinden oberhalb der Ausgabe **System**, **RED-Status** oder **Alle verfügbaren** auswählen. Die übrigen Themen aus API v1 bleiben ausgegraut, bis API v2 sie unterstützt. Mit **Verbinden** beginnt der Empfang der JSON-Nachrichten. **Trennen** beendet die Sitzung.

Bricht eine zuvor erfolgreich aufgebaute Verbindung ab, versucht der grafische Client die Wiederverbindung mit zunehmender Wartezeit von bis zu 30 Sekunden und stellt die ausgewählten Abos wieder her. **Trennen** bricht die Wiederverbindungsversuche ab. Wird der Token abgelehnt oder schlägt die Zertifikatsprüfung fehl, hält der Client an, damit sich die Einstellungen korrigieren lassen.

Wird beim Start des JARs eine URL übergeben, läuft der Client im Kommandozeilenmodus.

```sh
java -jar build/ipfire-events.jar wss://ipfire.local:8444/ ipfire-public.pem
```

Bei einem selbstsignierten IPFire-Zertifikat eine vertrauenswürdige Kopie des öffentlichen Serverzertifikats verwenden. Bei einem von einer CA ausgestellten Zertifikat das Zertifikat der ausstellenden CA im PEM-Format übergeben. Ohne zweites Argument verwendet Java seinen Standard-Truststore. Java prüft den Servernamen in beiden Fällen. Den Client-Token bei der Eingabeaufforderung eingeben. Im nicht interaktiven Betrieb kann der Token auch über die Standardeingabe übergeben werden. Den Client mit Strg+C beenden.

### API auf IPFire testen

In der ersten SSH-Sitzung den Daemon wie oben beschrieben mit den Loopback-Testeinstellungen starten. In einer zweiten Bash-Sitzung auf IPFire im Projektverzeichnis den folgenden Befehl ausführen und einen gültigen Client-Token eingeben.

```sh
read -rs -p 'Client token: ' token
printf '\n'
printf '%s\n' "$token" | perl -Ilib t/ipfire-smoke.pl ipfire.local
unset token
```

`ipfire.local` durch den Namen aus dem eigenen IPFire-Zertifikat ersetzen. Zum Testen des laufenden Dienstes auf GREEN die IP-Adresse seines Listeners als zweites Argument übergeben, etwa `perl -Ilib t/ipfire-smoke.pl ipfire.local 192.168.0.254`. Wurde das Zertifikat von einer CA ausgestellt, als drittes Argument den Pfad zu deren Zertifikat übergeben. Erwartet werden die geprüfte TLS-Version, `Upgrade OK`, `Pong OK`, `system.ping OK`, die Systeminformationen als JSON, `system.info OK` und `Close OK`.

Den Test für gleichzeitige Verbindungen auf IPFire aus dem Projektverzeichnis mit `perl -Ilib t/server-concurrency.t` starten. Er startet einen eigenen Daemon auf einem freien Loopback-Port und verwendet ein temporäres, mit OpenSSL erzeugtes Zertifikat. Er prüft, ob andere Clients weiterhin eine Antwort erhalten, während ein TLS-Handshake oder ein WebSocket-Frame unvollständig bleibt. Zudem prüft er das Beenden mit `SIGTERM` und die erneute Verwendung des Listener-Ports, weist fehlende und ungültige Tokens ab und prüft den Widerruf im laufenden Betrieb. Zwei konfigurierte Zonen-Listener müssen denselben Port mit getrennten Quellnetzen verwenden können. Der Test prüft außerdem TLS-Versionen, Zertifikatsvertrauen und Hostnamenprüfung sowie, dass keine Zugangsdaten im Daemon-Protokoll auftauchen.

Die vollständige Testsuite auf Entwicklungssystemen mit `prove -l t` ausführen.

| Umgebungsvariable | Standardwert |
|---|---|
| `IPFIRE_API_HOST` | `127.0.0.1` |
| `IPFIRE_API_ALLOWED_NETWORKS` | `127.0.0.0/8,::1/128` für Loopback-Listener |
| `IPFIRE_API_PORT` | `8444` |
| `IPFIRE_API_CERT_FILE` | `/etc/httpd/server.crt` |
| `IPFIRE_API_KEY_FILE` | `/etc/httpd/server.key` |
| `IPFIRE_API_CLIENT_DIR` | `/var/ipfire/api-v2-clients` |
| `IPFIRE_API_NETWORK_SETTINGS_FILE` | `/var/ipfire/api-v2-network.json` |
| `IPFIRE_API_ADMIN_SOCKET` | `/run/ipfire-api-v2-admin/control.sock` |

## Entwicklungsplan

### Phase 1 – Projektgrundlagen

- [x] GitHub-Repository erstellen.
- [x] Branch `develop` anlegen.
- [x] Erste Architektur festlegen.
- [x] Projektverzeichnisse anlegen.
- [x] Perl- und TLS-Abhängigkeiten auf IPFire Core 205 prüfen.
- [x] Eine erste Version von `Config.pm` erstellen.
- [x] Grundgerüst von `Server.pm` erstellen.
- [x] `ipfire-api-daemon.pl` implementieren.
- [x] Perl-Syntax und das Laden der Module prüfen.
- [x] Verwendbare Pfade zum TLS-Zertifikat und zum privaten Schlüssel bestätigen.
- [x] Konfigurierbare Adresse und konfigurierbaren Port für den Listener einbauen.

### Phase 2 – TLS-Server

- [x] TLS-Listener implementieren.
- [x] Eingehende Client-Verbindungen annehmen.
- [x] Verbindungszeitlimits und Fehlerbehandlung implementieren.
- [x] Auf IPFire Core Update 205 prüfen, dass ein TLS-Handshake abläuft und der nächste Client erfolgreich bedient wird.
- [x] Nicht blockierende TLS-Operationen mit `IO::Select` verwenden.
- [x] Mehrere gleichzeitige Clients unterstützen und über TLS auf Linux-Loopback prüfen.
- [x] Mehrere gleichzeitige Clients auf IPFire Core Update 205 prüfen.
- [x] Geordneten Start und geordnetes Beenden implementieren.
- [x] Start, Beenden mit `SIGTERM`, Trennen der Clients und Wiederverwendung des Ports auf IPFire Core Update 205 prüfen.
- [x] Einen TLS-1.3-Handshake über Loopback auf IPFire prüfen.

### Phase 3 – WebSocket-Protokoll

- [x] HTTP-Handshake für das WebSocket-Upgrade implementieren.
- [x] Header `Sec-WebSocket-Key` validieren.
- [x] Antwortheader `Sec-WebSocket-Accept` erzeugen.
- [x] HTTP-Upgrade über TLS auf IPFire prüfen.
- [x] Client-Frames auswerten und Steuerframes des Servers kodieren.
- [x] Maskierung durch den Client und fragmentierte Nachrichten unterstützen.
- [x] Ping-/Pong-Frames implementieren.
- [x] Close-Frames und das Aufräumen von Verbindungen implementieren.
- [x] Nachrichtengrößen begrenzen und das Protokoll validieren.
- [x] Ping/Pong und Close über TLS auf IPFire prüfen.
- [x] WebSocket-Verbindung und beide JSON-Methoden mit `wscat` auf Debian 13 über lokales TLS prüfen.

### Phase 4 – JSON-API-Protokoll

- [x] Einheitliches JSON-Nachrichtenformat festlegen.
- [x] IDs für Anfragen und Antworten implementieren.
- [x] Strukturierte Fehlerantworten implementieren.
- [x] Eine einfache Anfrage `system.ping` ergänzen.
- [x] `system.ping` und die Antwort-ID über TLS auf IPFire prüfen.
- [x] Eine erste lesende Anfrage `system.info` ergänzen.
- [x] `system.info` über TLS auf IPFire Core Update 205 prüfen.
- [x] Anfragen anhand des Methodennamens an die zuständige Funktion weiterleiten.
- [x] Automatisierte Protokolltests ergänzen.

### Phase 5 – Authentifizierung und Sicherheit

- [x] Für jeden Client einen eigenen Bearer-Token verlangen.
- [x] Eine Monitoring-Rolle mit Lesezugriff definieren und bei jeder Anfrage ihre Berechtigungen prüfen.
- [x] Lokale Befehle zum Anlegen, Auflisten und Widerrufen von Client-Zugängen ergänzen.
- [x] Client-Authentifizierung und Widerruf auf IPFire Core Update 205 prüfen.
- [x] Den Listener auf eine konkrete Adresse beschränken und die Liste erlaubter Client-Netze vor TLS prüfen.
- [x] Auf IPFire Core Update 205 prüfen, dass die Netzliste eine freigegebene Loopback-Adresse zulässt und Verbindungen aus anderen Netzen vor TLS schließt.
- [x] Gleichzeitige Verbindungen begrenzen und API-Anfragen je authentifiziertem Client über alle seine Verbindungen hinweg drosseln.
- [x] Auf IPFire Core Update 205 prüfen, dass Verbindungen mit demselben Token das Anfragelimit teilen, andere Tokens davon unabhängig sind und Anfragen nach Wiederauffüllen des Kontingents wieder erfolgreich sind.
- [x] Eingabevalidierung und Fehlerbehandlung der API v2 prüfen. Fehlerhafte Upgrades, Methodenfehler und die Validierung des Netzwerkformulars testen.
- [x] Auf IPFire Core Update 205 prüfen, dass die Verwaltungsseite die GREEN-Auswahl speichert und die API weiterhin auf der GREEN-Adresse lauscht.
- [x] Die API-v2-Protokollierung prüfen und bestätigen, dass der Daemon keine Tokens oder Token-Hashes protokolliert.
- [x] Mindestens TLS 1.2 verlangen sowie Zertifikatsvertrauen und Hostnamenprüfung testen.
- [x] Auf IPFire Core Update 205 prüfen, dass TLS 1.2 und 1.3 funktionieren, TLS 1.1 abgewiesen wird, der Client nicht vertrauenswürdige Testzertifikate und solche mit unpassendem Namen ablehnt und das Daemon-Protokoll keine Test-Tokens oder deren Hashes enthält.

### Phase 6 – Monitoring und Ereignisse

- [x] Client-Abos für `system.info` implementieren.
- [x] Nachrichtenformate für Ereignisse festlegen.
- [x] Vom Server ausgelöste Benachrichtigungen implementieren.
- [x] Auf IPFire prüfen, dass ein Client `system.info` empfängt und nach dem Abbestellen keine weiteren Ereignisse erhält.
- [x] Prüfen, dass der grafische Java-Client `system.info` über WSS abonniert und regelmäßige Ereignisse von IPFire Core Update 205 anzeigt.
- [x] Benachrichtigungen zum Zustand der RED-Schnittstelle mit Anfangszustand und Änderungserkennung ergänzen.
- [x] Auf IPFire den anfänglichen RED-Status und simulierte Statuswechsel prüfen.
- [x] Abos beim Schließen der zugehörigen WebSocket-Verbindung entfernen.
- [x] Auf IPFire prüfen, dass sich der grafische Java-Client erneut verbindet und die ausgewählten Abos wiederherstellt.
- [x] Den PEM-Dateifilter im Zertifikatsdialog des grafischen Java-Clients prüfen.
- [ ] MQTT als mögliche künftige Schnittstelle für Ereignisse bewerten.

### Phase 7 – IPFire-Integration

#### 7.1 Funktionsumfang der API v2 festlegen

- [ ] Die lesenden Funktionen und Verwaltungsoperationen von API v1 (`api.cgi`) erfassen und ermitteln, welche Anwendungen sie verwenden.
- [ ] Festlegen, welche v1-Funktionen in v2 benötigt werden, welche später folgen können und welche einen Ersatz brauchen. Pro Funktion die v2-Methode oder das Ereignis, die erforderliche Berechtigung und den Abnahmetest festhalten.
- [ ] Neue v2-Funktionen separat priorisieren. Den Umfang jeder Veröffentlichung anhand der Anforderungen der Clients und der Rückmeldungen aus der Community festlegen.

#### 7.2 Monitoring von API v1 auf v2 übertragen

- [ ] Wiederverwendbare IPFire-Systemschnittstellen und Funktionen ermitteln.
- [ ] Die benötigten lesenden v2-Methoden und Ereignisse für Systeminformationen, RED-Verbindungsstatus, Datenverkehr, Netzwerk, DHCP-Leases, Dienste, Add-ons und Update-Status implementieren. Auf den bestehenden Ereignissen `system.info` und `red.status` aufbauen.
- [ ] Die v2-Daten auf IPFire mit API v1 vergleichen und prüfen, ob sie den vereinbarten Monitoring-Umfang und den Datenbedarf von HA-IPFire abdecken.

#### 7.3 Benutzer- und Clientverwaltung erweitern

- [ ] Ausgehend von der vorhandenen Monitoring-Rolle mit Lesezugriff festlegen, welche Rechte Benutzer und API-Clients für Monitoring und Verwaltung benötigen.
- [ ] Die Verwaltungsseite um Rollenzuweisung und Verwaltung der Client-Zugangsdaten erweitern, einschließlich Austausch und Widerruf von Tokens.
- [ ] Prüfen, dass jede Rolle ihre erlaubten Operationen ausführen kann und die übrigen abgewiesen werden. Sicherstellen, dass bestehende Monitoring-Clients ihren Lesezugriff behalten.

#### 7.4 Freigegebene Verwaltungsoperationen aus API v1 übertragen

- [ ] Festlegen, wie v2 die vier v1-Operationen behandelt: RED verbinden, RED trennen, IPFire aktualisieren und IPFire neu starten.
- [ ] Nach Einführung des Berechtigungsmodells die im Funktionsumfang freigegebenen Operationen implementieren. Validierung, Rechteprüfung und die Rückmeldung von Erfolg oder Fehler an Clients festlegen.
- [ ] Freigegebene Operationen auf IPFire prüfen, bevor Clients sie verwenden können.

#### 7.5 API v2 auf IPFire installieren und betreiben

- [x] Ein SysV-Init-Skript ergänzen und seine Einbindung in Start und Herunterfahren dokumentieren.
- [x] Auf IPFire Core Update 205 prüfen, dass beide Dienste nach einem Neustart anlaufen, die API auf der gespeicherten GREEN-Adresse lauscht und die Verwaltungsseite den Verwaltungsdienst erreicht.
- [x] In `api.cgi` eine API-v2-Verwaltungsoberfläche für Client-Zugänge und erlaubte Netze ergänzen.
- [x] Einen Menüeintrag unter Dienste und getrennte Bedienelemente für den laufenden API-Daemon und seinen Autostart hinzufügen.
- [x] Prüfen, dass sich die Verwaltungsseite in der IPFire-WebGUI öffnen lässt.
- [x] Prüfen, dass HA-IPFire die benötigten Monitoring-Daten weiterhin über `api.cgi` erhält.
- [x] Prüfen, dass die IPFire-WebGUI beim Anlegen eines Clients dessen Token anzeigt.
- [x] Prüfen, dass beim Löschen eines Clients über die IPFire-WebGUI dessen Eintrag aus der Client-Liste verschwindet.
- [x] Auf IPFire prüfen, dass über die WebGUI gespeicherte Netzwerkeinstellungen automatisch wirksam werden.
- [ ] Installation und Konfiguration dokumentieren.

### Phase 8 – Künftige Kompatibilität

- [ ] Mit HA-IPFire prüfen, ob die nach API v2 übernommenen Monitoring-Funktionen alle benötigten Daten liefern.
- [ ] Verbindungsprüfungen und Ausweichmöglichkeiten in der folgenden Reihenfolge in HA-IPFire ergänzen.
- [ ] Die API anhand von Tests und Rückmeldungen aus der Community erweitern.

| Priorität | Schnittstelle | Wann HA-IPFire sie verwendet |
|---|---|---|
| Bevorzugt | API v2 | Wenn sich HA-IPFire mit API v2 verbinden und sie für das Monitoring verwenden kann |
| Erste Ausweichmöglichkeit | `api.cgi` | Wenn API v2 nicht verfügbar oder nicht nutzbar ist und `api.cgi` funktioniert |
| Zweite Ausweichmöglichkeit | `speed.cgi` | Wenn weder `api.cgi` noch API v2 nutzbar sind. Damit lässt sich der Datenverkehr auf der RED-Schnittstelle grundlegend überwachen. |

## Hinweise zur Entwicklung

API v2 soll zur primären Schnittstelle für HA-IPFire und andere Clients werden, sobald sie die erforderlichen Monitoring-Funktionen bereitstellt. `api.cgi` bleibt als Ausweichmöglichkeit für bestehende Installationen verfügbar und erhält die nötige Wartung und Fehlerkorrekturen.

API v2 entsteht schrittweise. Funktionen, Schnittstellen und Implementierungsdetails können sich während der Entwicklung ändern.

Der erste Meilenstein ist ein minimaler TLS-geschützter WebSocket-Server, der eine Verbindung annimmt und eine einfache JSON-Anfrage beantwortet.

## Lizenz

GPL-3.0
