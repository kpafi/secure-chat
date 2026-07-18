# Secure Chat — Sicherheits-Audit

**Datum:** 18. Juli 2026  
**Geprüfter Stand:** `70bbfcc29d428c880303271ad000f0ef50e35f74`  
**Scope:** Web-Client, Python/FastAPI-Relay, Abhängigkeiten und Android-Wrapper. Die öffentliche Instanz wurde nicht belastend getestet. Infrastrukturdateien für Caddy/Tor/Host-Härtung lagen nicht im Repository vor.

## Kurzfazit

Die Anwendung hat eine gute Sicherheitsbasis: Ende-zu-Ende-Kryptografie findet im Client statt, der Relay verarbeitet Inhalte nur als undurchsichtige Daten, Eingaben und Größen sind an vielen Stellen begrenzt, und die vorhandenen Unit-Tests sind umfassend.

Vor einem produktiven Einsatz müssen jedoch ein **hoher Vertrauensbindungsfehler bei asynchronen Nachrichten** sowie zwei bestätigte Starlette-Befunde behoben werden. Der erste Befund kann bei einem kompromittierten oder bösartigen Verzeichnisserver dazu führen, dass eine als verifiziert angezeigte Person Nachrichten mit fremden Verschlüsselungsschlüsseln erhält.

## Befunde

| Priorität | Befund | Auswirkung |
|---|---|---|
| Hoch | Asynchrone Verschlüsselungsschlüssel sind nicht vollständig in die Nutzerverifikation eingebunden | Vertraulichkeit asynchroner Nachrichten kann bei manipuliertem Verzeichnisserver verloren gehen. |
| Mittel | Starlette-Host-Header-Problem umgeht die Sperre von Entwicklungsdateien | Öffentliche Preisgabe eigentlich gesperrter Client-/Testdateien möglich. |
| Mittel | Starlette verarbeitet bestimmte Range-Anfragen mit quadratischem Aufwand | Nicht authentifizierter CPU-DoS gegen die statische Web-Auslieferung. |
| Mittel | 64-KiB-WebSocket-Limit greift erst nach Annahme einer bis zu 16-MiB-großen Nachricht | Speicher-/Verfügbarkeitsrisiko bei vielen Verbindungen. |
| Niedrig | PBKDF2-Iterationszahl aus Import-/Local-Storage-Daten ist nicht begrenzt | Eine präparierte Backup-/Pad-Datei kann die Client-Oberfläche blockieren. |
| Niedrig | Android zeigt JavaScript-Prompt-Eingaben im Klartext | Chat-Passphrasen können beim Eingeben mitgelesen werden. |
| Niedrig | Python-Abhängigkeiten sind nicht reproduzierbar gelockt und enthalten weitere bekannte Advisories | Update-/Supply-Chain-Risiko; die meisten Cryptography-Funde sind im aktuellen Codepfad nicht direkt ausnutzbar. |

### H-01 — Verifikation deckt die Schlüssel für asynchrone Nachrichten nicht zuverlässig ab

**Bestätigt.** Die asynchrone Nachrichtenzustellung verwendet ECDH- und ML-KEM-Schlüssel des Kontakts. Der sichtbare Kontakt-Fingerprint berechnet sich jedoch nur aus den beiden Signaturschlüsseln. Damit kann eine Nutzerin oder ein Nutzer die Anzeige persönlich vergleichen und eine Person als verifiziert markieren, ohne die für die asynchrone Verschlüsselung verwendeten Schlüssel verglichen zu haben.

Zusätzlich erkennt `contacts.upsert` einen Wechsel dieser Schlüssel nur, wenn sowohl der alte als auch der neue Eintrag einen Wert besitzen. Ein bisheriger, verifizierter Kontakt ohne diese Felder bleibt daher verifiziert, wenn später neue Verschlüsselungsschlüssel geliefert werden. Dieser Fall wurde lokal reproduziert: Der Kontakt blieb `verified: true`, obwohl beide Verschlüsselungsschlüssel ersetzt waren.

**Betroffene Stellen:**

- `client/app.js:562` — Fingerprint erhält nur `ed` und `mldsa`.
- `client/contacts.js:188-205` — unvollständiger Schlüsselvergleich.
- `client/contacts.js:137-140` und `client/app.js:158-160` — Pins/Bundle-Vergleich speichern bzw. vergleichen nur Signaturschlüssel.

**Abhilfe:**

1. Fingerprints, Safety Numbers, Pins und Gleichheitsvergleiche immer über alle vier öffentlichen Schlüssel bilden: `ed`, `mldsa`, `ecdh`, `mlkem`.
2. Fehlend und vorhanden als echten Schlüsselwechsel behandeln; normalisierte Werte vergleichen, z. B. `old.ecdh ?? null` gegen `new.ecdh ?? null`.
3. Bestehende Alt-Pins nur als *nicht ausreichend verifiziert* migrieren. Für asynchrone Nachrichten muss eine erneute persönliche Prüfung stattfinden.
4. Regressionstests ergänzen: alter Kontakt ohne Verschlüsselungsschlüssel + neue fremde Schlüssel muss die Verifikation zwingend entfernen; der angezeigte Fingerprint muss sich bei jedem der vier Schlüssel ändern.

### M-01 — Umgehbare Sperre statischer Entwicklungsdateien

**Bestätigt, lokal.** Das Middleware-Gate prüft `request.url.path` in `backend/main.py:116-119`. Die verwendete Starlette-Version rekonstruiert diese Eigenschaft aus dem HTTP-Host-Header. Dadurch kann sie vom tatsächlich gerouteten Pfad abweichen. Der lokale Test lieferte für die normale Anfrage auf `package.json` einen 404, bei einem manipulierten Host-Header aber HTTP 200 mit der Paketdatei.

Der gegenwärtig bestätigte Schaden ist die Offenlegung von `package.json`, `package-lock.json` und Testmodulen. Jede spätere Authentifizierungs- oder Zugriffskontrolle, die dasselbe Muster nutzt, wäre deutlich schwerwiegender betroffen.

**Abhilfe:**

1. Sofort `request.scope["path"]` statt `request.url.path` für Pfadentscheidungen nutzen.
2. Entwicklungsdateien nicht in das Produktions-Asset-Verzeichnis kopieren/deployen.
3. FastAPI/Starlette gemeinsam auf eine kompatible Version mit Starlette **mindestens 1.0.1** anheben und einen Integrationstest mit fehlerhaften Host-Headern hinzufügen.
4. Im Reverse Proxy ausschließlich erwartete Hostnamen akzeptieren und ungültige Header ablehnen.

Referenz: [GitHub Advisory GHSA-86qp-5c8j-p5mr](https://github.com/advisories/GHSA-86qp-5c8j-p5mr).

### M-02 — CPU-DoS über Range-Verarbeitung von StaticFiles

**Bestätigt, lokal.** Der Relay mountet `StaticFiles` in `backend/main.py:259-263`, während Starlette 0.46.2 verwendet wird. Diese Version ist von CVE-2025-62727 betroffen. Ein kontrollierter lokaler Lauf gegen die Parserfunktion zeigte beim Verdoppeln der kleinen Testeingabe ungefähr die erwartete Vervierfachung der Laufzeit (1.000: 0,0019 s; 2.000: 0,0084 s; 4.000: 0,0294 s). Es wurde kein DoS gegen die öffentliche Instanz ausgeführt.

**Abhilfe:**

1. FastAPI/Starlette auf einen kompatiblen Patchstand anheben; mindestens Starlette **0.49.1** behebt diesen konkreten Befund, eine aktuelle kompatible FastAPI/Starlette-Kombination ist vorzuziehen.
2. Bis zum Update Range-Requests im Reverse Proxy begrenzen oder für statische Assets deaktivieren.
3. Request-Header-Limits und globale Rate-Limits am Proxy konfigurieren.

Referenz: [GitHub Advisory GHSA-7f5h-v6xp-fcq8](https://github.com/advisories/GHSA-7f5h-v6xp-fcq8).

### M-03 — WebSocket-Größenlimit wird zu spät wirksam

**Bestätigt durch Code und Laufzeitkonfiguration.** Das Anwendungs-Limit beträgt 64 KiB (`backend/config.py:22`), wird aber erst nach `receive_text()` geprüft (`backend/main.py:193-203`). Der verwendete Uvicorn-Standard akzeptiert bis zu 16 MiB pro WebSocket-Nachricht. Das bedeutet, dass eine Verbindung die große Nachricht bereits im Speicher erzeugen kann, bevor die Anwendung sie zurückweist. Bei dem konfigurierten Maximum von 200 Verbindungen ist dies ein relevantes Verfügbarkeitsrisiko.

**Abhilfe:**

1. Uvicorn mit `--ws-max-size 65536` (ggf. mit kleinem Protokoll-Overhead) starten.
2. Dasselbe Limit am Reverse Proxy setzen und das Verhalten mit einer Oversize-Integrationstestnachricht prüfen.
3. Einen separaten Prozess-/Container-Speichergrenzwert und Alerting für abgewiesene Oversize-Frames einrichten.

### L-01 — Nicht begrenzte PBKDF2-Iterationszahl

**Bestätigt durch Code.** Identitäts-, Kontakt- und OTP-Import lesen `iters` aus externen bzw. persistenten Daten und übergeben den Wert direkt an WebCrypto. Eine sehr hohe Zahl kann die Browser-/WebView-Oberfläche für lange Zeit blockieren. Der Angreifer benötigt dafür eine importierte Datei oder Zugriff auf den lokalen Speicher; es ist kein Remote-Code-Execution-Befund.

**Abhilfe:** Format und Werte vor der KDF strikt validieren: Ganzzahl, erlaubte Versionswerte sowie Ober- und Untergrenze. Bei älteren Formaten nur explizit bekannte Legacy-Werte akzeptieren. Auch Dateigröße, Salt-, IV- und Ciphertext-Länge vor `JSON.parse`, Base64-Dekodierung und PBKDF2 begrenzen.

### L-02 — Android-Prompt für Passphrasen ist sichtbar

`MainActivity.kt:151-167` nutzt für alle JavaScript-Prompts ein normales Textfeld. Der asynchrone AES-Chatmodus fragt darin eine gemeinsame Passphrase ab. Dies ist ein lokaler Sichtbarkeits-/Shoulder-Surfing-Befund.

**Abhilfe:** Für als geheim klassifizierte Eingaben eine eigene native Passwortdialog-Bridge mit `TYPE_TEXT_VARIATION_PASSWORD` verwenden. Besser: Passphrasen nicht über generische `window.prompt()`-Flows anfordern.

### L-03 — Abhängigkeits- und Build-Härtung

`pip-audit` meldet 15 Advisories in `starlette`, `cryptography` und der nur für Tests genutzten Bibliothek `pytest`. Für `cryptography` 43.0.3 betreffen die meisten gemeldeten Fälle X.509-/SECT-/OpenSSL-Pfade, die im geprüften Code nicht verwendet werden; trotzdem muss die veraltete Version aktualisiert werden. Die Backend-Anforderungen verwenden offene Patch-/Minor-Bereiche statt eines gelockten, mit Hashes gesicherten Satzes. Für den Android-Wrapper ist keine Dependency Verification konfiguriert; die Gradle-Distribution hat zudem keinen Checksum-Eintrag in `gradle-wrapper.properties`.

**Abhilfe:**

1. Für Python ein gelocktes Constraints-/Lockfile mit Hashes verwenden und CI gegen bekannte CVEs laufen lassen.
2. `cryptography` auf einen aktuellen kompatiblen Stand heben; [GHSA-537c-gmf6-5ccf](https://github.com/advisories/GHSA-537c-gmf6-5ccf) erfordert für die betroffenen Wheels mindestens 48.0.1.
3. Gradle-Distribution mit `distributionSha256Sum` pinnen und Gradle Dependency Verification aktivieren.
4. Android-Abhängigkeiten regelmäßig automatisiert scannen; die Android-Tests konnten in dieser Umgebung mangels Java-Runtime nicht ausgeführt werden.

## Positiv geprüfte Kontrollen

- Web-Client-Testreihe vollständig erfolgreich, einschließlich Authentisierung des Handshakes, Replay-/Manipulationsschutz, Ratchet-Tests, versiegelter Sender und OTP-Rollback-Tripwire.
- Backend-Testreihe vollständig erfolgreich: **71 Tests bestanden**.
- `npm audit`: keine gemeldeten npm-Abhängigkeitsschwachstellen.
- Bandit: nur ein niedriger Hinweis auf bewusst unterdrückte Sendefehler bei getrennten WebSocket-Peers; kein Hoch-/Mittel-Befund.
- Keine Klartext-Private-Keys oder verbreiteten Tokenmuster im Repository gefunden.
- Android-Wrapper beschränkt Navigation auf die lokale Asset-Origin, deaktiviert Datei-/Content-Zugriff und erlaubt Backups nicht.
- Static Assets und vendored Noble-Dateien wurden gegen die installierten Paketdateien verglichen; keine Codeabweichung festgestellt (die mitgelieferte Vendor-README hat naturgemäß keine Entsprechung im Paket).

## Priorisierter Härtungsplan

1. **Sofort vor Release:** H-01 beheben, Alt-Pins/Alt-Kontakte als nicht ausreichend verifiziert behandeln und die vier Regressionstests ergänzen.
2. **Sofort:** FastAPI/Starlette als Paar aktualisieren; danach Host-Header- und Range-Tests in CI festschreiben. Bis dahin statische Assets über den Proxy mit strengen Host-/Header-Regeln ausliefern.
3. **Sofort:** Uvicorn und Proxy auf die gewünschte WebSocket-Maximalgröße begrenzen.
4. **Nächster Sprint:** KDF-/Importgrenzen, Passwort-Eingabe im Android-Wrapper und reproduzierbare Dependency-Locks umsetzen.
5. **Vor Produktion:** Caddy-/Tor-/Firewall-Konfiguration, TLS, Prozessrechte, Backup-/Restore-Prozess, Monitoring und Rate Limits als separaten Infrastruktur-Audit prüfen. Der aktuelle Repository-Scope enthält diese Konfiguration nicht.

## Testgrenzen

Dieses Audit ist ein Source- und lokaler Sicherheitstest. Es enthielt keine Last-/DoS-Angriffe gegen den externen Host, keine Social-Engineering-Prüfung und keinen physischen Android-Test, weil in der Umgebung keine Java-Runtime vorhanden war. Ein E2EE-Messenger benötigt zusätzlich einen unabhängigen Kryptografie-Review und ein Staging-Pentest der gesamten Deployment-Kette.
