# fxcloud Nutzerhandbuch

Dieses Handbuch richtet sich an Menschen, die eine fxcloud-Instanz
*benutzen*: wie man sich registriert, mit Dateien arbeitet, sie teilt,
verschlüsselt und sich mit einem Passkey anmeldet. Es führt außerdem
einen Administrator durch den einen Deployment-Schritt, den Passkeys
brauchen (HTTPS hinter einem Reverse Proxy mit `FXCLOUD_ORIGIN`).

Dokumente für Entwickler:

- [README.md](README.md) - die Funktionsliste und die Karte dieser Dokumentation
- [INSTALL.md](INSTALL.md) - Installation, Konfigurationstabelle, systemd-Unit
- [API.md](API.md) - HTTP-Endpunkte und Protokelldetails
- [ENCRYPTION.md](ENCRYPTION.md) - das kryptografische Design im Volltext
- [ARCHITECTURE.md](ARCHITECTURE.md) - Code-Struktur, Speicherung, Kontingente

## Inhalte

1. [Installation](#1-installation)
2. [Das erste Konto](#2-das-erste-konto)
3. [Anmelden](#3-anmelden)
4. [Deine Dateien](#4-deine-dateien)
5. [Teilen](#5-teilen)
6. [Gruppenordner](#6-gruppenordner)
7. [Papierkorb](#7-papierkorb)
8. [Kontingente](#8-kontingente)
9. [Benutzerverwaltung](#9-benutzerverwaltung)
10. [Deine Kontoeinstellungen](#10-deine-kontoeinstellungen)
11. [Verschlüsselung](#11-verschlusselung)
12. [Passkeys](#12-passkeys)
13. [HTTPS hinter einem Reverse Proxy (durchgerechnetes Beispiel)](#13-https-hinter-einem-reverse-proxy-durchgerechnetes-beispiel)
14. [WebDAV](#14-webdav)
15. [Fehlerbehebung](#15-fehlerbehebung)

## 1. Installation

fxcloud ist eine einzelne Binary: SQLite und die Weboberfläche sind
eingebaut, es gibt keinen Datenbankserver und keine Laufzeitabhängigkeit.

**Eine Zeile** - installiert fxcloud als systemd-Dienst auf jedem Linux
mit `curl` (als Root); dieselbe Zeile erneut ausführt aktualisiert es:

```bash
curl -fsSL https://raw.githubusercontent.com/floyd54/fxcloud/main/install.sh | sh
```

**Fertige Binary** - jede markierte Version auf [GitHub
Releases](https://github.com/floyd54/fxcloud/releases) enthält einen
vollständig statischen Linux-x86_64-Build (~6 MB):

```bash
chmod +x fxcloud-<tag>-x86_64-unknown-linux-musl
FXCLOUD_DATA=/srv/fxcloud ./fxcloud-<tag>-x86_64-unknown-linux-musl
```

**Aus dem Quellcode**:

```bash
cargo build --release
./target/release/fxcloud      # legt ./data mit DB und Datei-Blobs an
```

Öffne <http://127.0.0.1:8080>. Um es als Dienst unter Linux zu betreiben,
nutze die gehärtete Unit aus [`deploy/fxcloud.service`](deploy/fxcloud.service) -
die [INSTALL.md](INSTALL.md#deployment) hat die Schritt-für-Schritt-Anleitung.
Alle Einstellungen sind Umgebungsvariablen (Bind-Adresse, Port,
Datenverzeichnis, kontingentbezogene Grenzen, ...); die vollständige
Tabelle steht in [INSTALL.md](INSTALL.md#configuration).

## 2. Das erste Konto

Auf einer frischen Instanz den Tab **Konto erstellen** öffnen, einen
Benutzernamen (3 Zeichen oder mehr), optional einen Anzeigenamen und ein
Passwort (8 Zeichen oder mehr) wählen.

Das **erste Konto**, das auf einer Instanz angelegt wird, wird sofort
aktiviert und dessen Administrator. Jedes danach angelegte Konto startet
inaktiv: die Registrierung gelingt, aber die Anmeldung wird mit dem Hinweis
abgelehnt, den Administrator zu kontaktieren, bis ein aktives Konto es
aktiviert (siehe [Benutzerverwaltung](#9-benutzerverwaltung)).

## 3. Anmelden

Die Anmeldeseite hat drei Tabs:

- **Anmelden** - Benutzername und Passwort.
- **Passkey** - nur Benutzername; das Gerät fragt danach nach PIN oder
  Biometrie (siehe [Passkeys](#12-passkeys)).
- **Konto erstellen** - Registrierung wie oben.

Sitzungen dauern standardmäßig7 Tage (`FXCLOUD_SESSION_TTL`, gleitend bei
Benutzung).

### Als App installieren

fxcloud installiert sich wie jede andere Web-App: in Chrome/Edge über
**App installieren** in der Adressleiste, auf iPhone/iPad-Safari über
**Teilen > Zum Home-Bildschirm**, in Android-Chrome über
**Menü > Zum Startbildschirm hinzufügen**. Die App öffnet sich danach
über ihr eigenes Icon in einem Fenster ohne Browser-Chrome - dasselbe
Konto, dieselbe Sitzung, nichts zu konfigurieren.

Zwei ehrliche Hinweise: die Installation ist nur ein Startschalter (es
gibt keinen Offline-Modus - fxcloud ist ein Client deines Servers), und
der Service Worker, der die Installation ermöglicht, **cacht aus Prinzip
nichts**, eine installierte App zeigt also immer exakt das, was der
Server ausliefert ([ENCRYPTION.md](ENCRYPTION.md), Abschnitt11).

Direkt nach der Installation prüfen, dass JavaScript für die App aktiv
ist: auf manchen Geräten starten frisch installierte Web-Apps damit
**aus**, und der Installationsdialog bietet keinen Schalter (berichtet auf
einem Google Pixel). Das Symptom ist eine tote Anmeldeseite - siehe
[Fehlerbehebung](#15-fehlerbehebung); langes Drücken auf das Icon >
Einstellungen > JavaScript behebt das.

## 4. Deine Dateien

Die Dateiverwaltung arbeitet wie ein Desktop-Dateimanager, im Browser:

- **Neue Datei** / **Neuer Ordner** legen Einträge im aktuellen Ordner an;
  eine neue Textdatei öffnet direkt im eingebauten Editor (mit
  Markdown-Vorschau-Umschalter und **Speichern**).
- **Datei hochladen** / **Ordner hochladen** oder Drag & Drop auf die
  Ablagefläche laden Dateien oder ganze Ordnerbäume (auch leere
  Unterordner).
- **Versteckte anzeigen** blendet Einträge ein, deren Name mit einem Punkt
  beginnt; die Auswahl bleibt im Browser gespeichert.
- Ein Klick auf eine Datei zeigt eine Vorschau: Bilder, Video, Audio, PDF,
  HTML und Text öffnen im Lightbox; Textdateien öffnen im Editor.
- Den Editor mit ungespeicherten Änderungen schließen - oder mit den
  Gallery-Pfeilen zu einer anderen Datei wechseln - fragt nach, mit
  **Speichern** als fokussierter Voreinstellung (Enter), **Verwerfen**
  und **Abbrechen**. Schlägt das Speichern fehl, bleibt das Lightbox offen
  und die Statuszeile trägt den Fehler, der Text geht nie verloren.
- Auswahl-Kästchen (Shift+Klick erweitert über einen Bereich) geben die
  Sammelleiste: **Herunterladen** (die ganze Auswahl als eine ZIP),
  **Verschieben nach...**, **Kopieren nach...**, **Freigeben**,
  **Löschen** und **Auswahl aufheben**.
- Jede Zeile hat außerdem ein Menü (Herunterladen, Freigeben,
  Verschieben, Kopieren, Umbenennen, Löschen).
- Ordnerzeilen zeigen ihre rekursive Größe; die Kruste navigiert den Baum
  hinab.

ZIP-Downloads werden pro Anfrage zusammengesetzt und bei unkomprimierten
1 GiB gedeckelt; nehmt weniger Items, wenn der Fehler euch das sagt.

### Versionsverlauf

Jede Inhaltsersetzung - **Speichern** im Editor, ein WebDAV-`PUT` - hält
die ersetzten Bytes als wiederherstellbare Version, ein falsches Speichern
ist also nie das Ende einer Datei. **Versionsverlauf** im Zeilenmenü öffnet
die Historie der Datei, neueste zuerst, mit Zeit und Größe pro Version:

- **Herunterladen** holt die exakten Bytes dieser Version, Bereiche
  eingeschlossen (ein Player kann in einer Version suchen wie in der
  aktuellen Datei).
- **Versionsverlauf** tauscht: die gewählte Version wird zum Inhalt der
  Datei und das Aktuelle wird zur neuesten Version - eine Wiederherstellung
  ist selbst rückgängig zu machen.
- **Löschen** entfernt eine Version zusammen mit ihren Bytes.

Eine Nur-Lese-Freigabe sieht die Historie und kann Versionen herunterladen;
Änderungen brauchen Schreibrechte. Aufbewahrte Versionen zählen gegen dein
Kontingent, und der Papierkorb behält die Historie einer Datei, bis die
Datei endgültig gelöscht wird. Zwei Grenzen in den **Einstellungen**
("Versionsverlauf") halten die Historie in Schach: wie viele Versionen pro
Datei aufbewahrt werden und ein Alter in Tagen - `0` deaktiviert jeweils
eine Grenze. Ein Hintergrund-Sweep wendet die Altersgrenze im gleichen
Rhythmus wie die Papierkorb-Löschung an; die Zahlen-Grenze wird bei jeder
gespeicherten Version angewendet.

### Office-Dokumente

Wenn deine Instanz eine Office-Engine betreibt (siehe
[INSTALL.md](INSTALL.md#office-integration-optional)), öffnen
Office-Dateien - docx, xlsx, pptx, odt, ods, odp - in einem Browser-Editor
statt träge zu bleiben: Datei klicken (oder **Im Office-Editor öffnen** im
Zeilenmenü), bearbeiten, schließen. Das Speichern läuft durch dieselben
Türen wie jeder andere Schreibvorgang: es zählt gegen das Kontingent,
erscheint im obigen Versionsverlauf und wird für verschlüsselte Dateien
abgelehnt (der eingebaute Editor bearbeitet die). Ohne konfigurierte Engine
ändert sich nichts - die Zeilen verhalten sich exakt wie vorher.

## 5. Teilen

Dateien oder Ordner mit anderen Konten derselben Instanz teilen:

1. Ein oder mehrere Einträge auswählen und **Freigeben** drücken.
2. Die Person aus dem Dropdown wählen.
3. Die zu vergebenden Rechte abhaken: **Lesen**, **Schreiben**,
   **Erstellen**, **Löschen** (ein fünftes Kästchen, Weitergeben, ist für
   das Weitergeben reserviert und hat noch keine Wirkung).
4. **Freigeben** drücken.

Eine Freigabe erscheint im Dateibaum der anderen Person, markiert mit
deinem Namen; ist der Name dort vergeben, bekommt er ein Suffix
(`Projekte` wird zu `Projekte (alice) 2`). Alles, was sie in einem
geteilten Ordner anlegen, landet in *deinem* Baum und zählt gegen *dein*
Kontingent.

Zum Widerrufen den **Freigabe**-Dialog des Eintrags erneut öffnen und
neben der Person **Entfernen** drücken.

Wenn die [Verschlüsselung](#11-verschlusselung) auf beiden Seiten aktiv
ist, trägt die Freigabe außerdem einen Schlüsselumschlag, der auf den
öffentlichen Schlüssel der anderen Person versiegelt ist - deren
Schlüsselfingerabdruck wird im Dialog angezeigt, damit du ihn außerhalb
vergleichen kannst, bevor du dem Tausch vertraust.

### Öffentliche Links

Ein öffentlicher Link übergibt einen Ordner oder eine einzelne Datei
jedem, der die URL hat - kein Konto, keine Anmeldung. Er lebt im eigenen
Abschnitt **Öffentlicher Link** des [Freigabe](#5-teilen)-Dialogs:

1. Wählen, was Besucher dürfen: **Lesen - ansehen und herunterladen**,
   **Hinzufügen - nur hochladen** oder **Voll - hochladen, herunterladen
   und löschen**.
2. Ablauf wählen: **30/90 Tage nach letztem Aufruf** (rollierend,
   Standard), **30/90 Tage nach Erstellung** (fest) oder **Nie**.
3. Optional eine **Bezeichnung** eingeben, um die Links später
   unterscheiden zu können.
4. **Link erstellen** drucken. Die URL wird einmalig mit einem Button
   **Link kopieren** angezeigt - jetzt kopieren. Der Server speichert nur
   einen Hash des Tokens und kann die URL nie wieder zeigen.

Wer den Link öffnet, sieht eine schlichte Seite mit dem Inhalt des Ordners
(Ordner eine Ebene pro Runde, Downloads als Anhänge) - keine Anmeldung,
keine Referrer, keine Indexierung durch Suchmaschinen. Der Link erreicht
genau den Eintrag, für den er erstellt wurde, und alles darunter; sonst
nichts an deinem Konto ist exponiert.

Der Abschnitt listet außerdem jeden von dir erstellten Link: Bezeichnung,
Preset, Frist, letzten Besuch und Download-Zahl, mit **Entfernen** zum
Widerrufen. Der Widerruf wirkt sofort - die URL antwortet ab der nächsten
Anfrage mit *nicht gefunden*.

Was sich lohnt zu wissen:

- **Rollierend vs. fest:** ein rollierender Link stirbt erst nach der
  gewählten Anzahl Tage *ohne* Aufruf, und jeder Aufruf schiebt die Frist
  wieder auf ein volles Fenster hinaus. Ein fester Link läuft genau N Tage
  nach der Erstellung ab, egal wie oft er geöffnet wird. Ein abgelaufener
  Link antwortet zuerst „verschwunden" und kurz danach endgültig - er
  kommt nie durch erneutes Öffnen zurück.
- **Hinzufügen und Voll sind schreibbare Postfach-Links:** jeder mit der
  URL kann Dateien in *deinen* Baum legen (sie zählen gegen *dein*
  Kontingent). Ein **Hinzufügen**-Besucher bekommt nur das Upload-Feld -
  er kann weder auflisten noch herunterladen, nicht einmal die Dateinamen.
  Mit **Voll** kann er zusätzlich im geteilten Ordner stöbern und löschen
  - Löschungen landen in *deinem* Papierkorb, und der geteilte Ordner
  selbst ist über seinen eigenen Link nie löschbar. **Lesen** wählen,
  wenn ihr nur etwas aushändigen wollt.
- **Nur Klartext:** eine verschlüsselte Datei oder ein verschlüsselter
  Ordner kann nicht verlinkt werden (der Abschnitt sagt das direkt vor
  Ort), und verschlüsselte Dateien in einem verlinkten Ordner bleiben für
  Besucher unsichtbar.
- **Gruppenordner können nicht verlinkt werden** - die Mitgliedschaft
  gewährt dort den Zugang.

## 6. Gruppenordner

Ein Gruppenordner gehört einer *Gruppe*, nicht einer Person: ein
gemeinsamer Arbeitsbereich mit eigenem Kontingent, verwalteter
Mitgliedschaft und demselben Baum für jedes Mitglied. Gruppenordner tragen
den Namen der Gruppe als Abzeichen in deiner Wurzel, damit sie sich von
einem persönlichen Ordner desselben Namens unterscheiden lassen.

**Anlegen.** Ein Administrator legt die Gruppe selbst an (siehe
[Benutzerverwaltung](#9-benutzerverwaltung): Name, Kontingent in MiB und
die Mitglieder mit ihren Rollen - der Ersteller wird ihr erster Manager).
Danach erstellst du den Wurzelordner der Gruppe selbst mit dem Button
**Neuer Gruppenordner...** oben in deiner Dateiliste - nur in der
Wurzelliste angeboten und nur, solange du einer Gruppe angehörst. Von da an
sieht jedes Mitglied diesen Ordner in seiner Wurzel und arbeitet am ganzen
Baum - hochladen, umbenennen, verschieben, Papierkorb - ohne einzelne
Freigaben. Ein Gruppenordner kann nicht an eine Person weitergegeben
werden: die Mitgliedschaft gewährt den Zugang.

**Kontingent.** Der Speicher der Gruppe ist ein eigenes Budget, vom
Administrator gesetzt. Schreibvorgänge in einen Gruppenordner zählen gegen
die Gruppe, nie gegen dein persönliches Kontingent; eine volle Gruppe
lehnt weitere Uploads mit `507 Insufficient Storage` ab, bis das Budget
erhöht wird oder jemand Platz schafft. Dateien im Papierkorb zählen weiter,
bis sie endgültig gelöscht sind.

**Schlüssel.** Mit eingeschalteter Verschlüsselung verteilt ein Manager
die Ordner-Schlüssel: das Zeilenmenü des Gruppenwurzelordners (die
„..."-Spalte) öffnen und **Ordner-Schlüssel verteilen** wählen, dann
jeweils an ein Mitglied wrappen und senden. Ein Mitglied ohne Schlüssel
sieht die Dateinamen, kann den Inhalt aber nicht entschlüsseln, und ein
Mitglied, das die Dateiverschlüsselung noch nicht eingerichtet hat, kann
keinen empfangen (der Button sagt das). Schlüssel folgen der
Mitgliedschaft: ein entferntes Mitglied verliert auch seine Umschläge für
diese Gruppe.

**Papierkorb und Löschung.** Gruppendateien landen wie jede andere im
Papierkorb, und jedes Mitglied sieht die gelöschten Zeilen der Gruppe in
seinem eigenen Papierkorb - Wiederherstellen und endgültiges Löschen sind
jedem Mitglied offen. Die Gruppe selbst löscht ein Administrator, sobald
sie leer ist: keine Mitglieder, keine Ordner.

## 7. Papierkorb

Nichts wird sofort gelöscht: **Löschen** verschiebt Einträge in deinen
persönlichen Papierkorb, wo sie **Wiederhergestellt** oder **Endgültig
gelöscht** werden können. **Papierkorb leeren** räumt auf einmal alles.

Ein Hintergrund-Sweep entfernt gelöschte Einträge nach30 Tagen endgültig
(`FXCLOUD_TRASH_DAYS`); die Papierkorb-Liste zeigt die Frist pro Eintrag,
und gelöschter Inhalt zählt weiter gegen dein Kontingent, solange er dort
liegt.

## 8. Kontingente

Jedes Konto hat ein Speicher-Kontingent - standardmäßig1 GiB, vom
Administrator pro Konto gesetzt. Zählt wird alles, was *dir gehört*:
hochgeladene Dateien, Kopien, die du erstellt hast; Inhalt, den andere
*dir* teilen, zählt gegen den ursprünglichen Besitzer. Überschreiten
ergibt eine klare `507 Insufficient Storage`-Meldung in der Weboberfläche
und in WebDAV; deine aktuelle Nutzung zeigt **Einstellungen**
("Speicher: verwendet von Kontingent").

## 9. Benutzerverwaltung

Administratoren finden einen Eintrag **Benutzerverwaltung** im Menü hinter
ihrem Namen in der oberen Leiste. Der Dialog öffnet auf dem Tab
**Benutzer**; das danebenliegende Tab **Gruppenordner** enthält die
Gruppenverwaltung aus [Abschnitt6](#6-gruppenordner). Auf dem Benutzer-Tab
können sie:

- Konten **aktivieren / deaktivieren** (wirkt sofort: Sitzungen und WebDAV
  inklusive; ein Administrator kann sich nicht selbst deaktivieren),
- die **Administrator-Rolle vergeben / entziehen** (der letzte aktive
  Administrator kann weder deaktiviert noch herabgestuft werden),
- das **Speicher-Kontingent** pro Konto setzen,
- ein **Passwort zurücksetzen**, was dem Nutzer ein einmaliges
  temporäres Passwort für die nächste Anmeldung zurückgibt.

Deaktivierte Konten können sich weder anmelden noch WebDAV nutzen und
bekommen ein403 mit dem Hinweis, den Administrator zu kontaktieren.
Anzeigename, Theme und Passwort stehen *nicht* auf dieser Liste: die
ändert jeder selbst in den **Einstellungen**.

Dieselben Schalter weiterhin direkt in der Datenbank (kein Neustart
nötig). Bei einer systemd-Installation ist die Datei
`/home/fxcloud/data/fxcloud.db`, in der Entwicklung `./data/fxcloud.db`:

```bash
DB=/home/fxcloud/data/fxcloud.db

# Übersicht
sqlite3 "$DB" "SELECT id, username, is_active, is_admin, quota_bytes FROM users ORDER BY id;"

# aktivieren / deaktivieren (wirkt sofort: Sitzungen + WebDAV inklusive)
sqlite3 "$DB" "UPDATE users SET is_active = 1 WHERE username = 'max';"
sqlite3 "$DB" "UPDATE users SET is_active = 0 WHERE username = 'max';"

# Administrator-Rolle
sqlite3 "$DB" "UPDATE users SET is_admin = 1 WHERE username = 'max';"

# Kontingent (Bytes;1073741824 =1 GiB, das Standard für jedes Konto)
sqlite3 "$DB" "UPDATE users SET quota_bytes = 2147483648 WHERE username = 'alice';"
```

## 10. Deine Kontoeinstellungen

Das Menü hinter deinem Namen in der oberen Leiste öffnet die
**Einstellungen**:

- **Konto** - Benutzername, Mitglied seit, Speicher verwendet vom
  Kontingent.
- **Anzeigename** - von dir änderbar, wird anderen Nutzern angezeigt.
- **Theme** - Hell oder Dunkel.
- **Passwort** - ändern; das aktuelle Passwort wird zuerst gefragt.
- **Passkeys** - deine Anmeldegeräte verwalten (siehe unten).

## 11. Verschlüsselung

fxcloud kann Dateien **in deinem Browser** verschlüsseln, bevor sie dein
Gerät verlassen: der Server speichert ciphertext und einen gewrappten
Schlüssel und sieht weiterhin Dateinamen, Größen und Freigaben - das ist
alles, was der Speicherdienst braucht. Das vollständige Design
(Bedrohungsmodell, Schlüsselhierarchie, die DECISIONs) steht in
[ENCRYPTION.md](ENCRYPTION.md); hier die Nutzersicht:

- Das Abzeichen in der oberen Leiste zeigt den Status: **Uploads
  verschlüsseln** (noch nicht eingerichtet), **Unverschlüsselt** oder
  **Verschlüsselt**.
- Beim Einschalten wählst du zwischen **Mein fxcloud-Anmeldepasswort
  verwenden** (Standard) und **Eigenes Passwort wählen**.
- Danach siehst du einen **Recovery-Key** (64 Hex-Ziffern). Speichere ihn:
  er ist der einzige Weg zurück zu deinen Dateien, wenn das Passwort
  vergessen ist.
- Die Schlüssel leben nur im Speicher des aktuellen Tabs - ein Reload
  bringt dich zurück auf **Unverschlüsselt**, und die Entsperren-Leiste
  fragt das Passwort erneut.
- Mit eingeschalteter Verschlüsselung werden Uploads verschlüsselt,
  Downloads und Vorschauen im Browser entschlüsselt, und das Teilen
  trägt den oben beschriebenen Schlüsselumschlag. WebDAV-Desktop-Clients
  verschlüsseln nicht: verschlüsselte Dateien sind dort als Ciphertext
  sichtbar und können nicht über sie geschrieben werden.

### Auto-Entsperrung: ohne Passwort öffnen

**Einstellungen > Konto > Auto-Entsperrung** ist ein Schalter, der mit
deinem Konto reist: sobald ein Gerät einmal entsperrt hat, behält dieser
Browser einen zufälligen Geräteschlüssel mit deinem gewrappten
Kontoschlüssel (`localStorage`, nie dein Passwort), und jedes spätere
Öffnen - Reload, neuer Tab, Passwort- **oder** Passkey-Anmeldung - startet
entsperrt. Das Passwort wird pro Gerät genau einmal mehr gefragt, an dem
einen bewussten Moment: wenn du das Abzeichen von **Unverschlüsselt** zu
**Verschlüsselt** umschaltest, während ein Tab läuft. Ein brandneues
Gerät fragt einmal, dann auch still. **Aus** löscht das gespeicherte
Entsperren und kehrt zum strengen Verhalten zurück: Schlüssel leben nur im
aktuellen Tab. Der Kompromiss, offen: wer dieses Browser-Profil im Ganzen
lesen kann, erhält die Schlüssel dieses Kontos auf diesem Gerät - deshalb
ist der Schalter standardmäßig aus (ENCRYPTION.md5.7, DECISION7).

### Bestehende Dateien verschlüsseln

**Einstellungen > Konto > Bestehende Dateien verschlüsseln** läuft durch
den ganzen Baum in diesem Browser, verschlüsselt jede gefundene
Klartextdatei und verwirft die alte Versionshistorie jeder Datei - diese
Historie *ist* der Klartext. Der Dialog zeigt `i von n`, ist jederzeit
abbrechbar und macht dort weiter, wo er stoppte: erneutes Ausführen
überspringt alles bereits Verschlüsselte. Wenn das Kontingent voll ist,
pausiert er mit der Kontingents-Meldung und bietet **Weiter nach Platz
schaffen**. Das Zeilenmenü eines Ordners hat dieselbe Aktion nur für
diesen Unterbaum (**Ordner jetzt verschlüsseln...**).

### Verschlüsselungs-Zonen

Das Zeilenmenü eines Ordners (**Verschlüsselungs-Zone: ein/aus**)
markiert ihn als Zone: neue Dateien und Speicherungen darunter verlangen
das Passwort, auch wenn das Abzeichen **Unverschlüsselt** sagt - dieser
Ordner bleibt also verschlüsselt, während der Rest des Kontos WebDAV-
kompatibel bleibt. Nur der Besitzer (oder ein Manager einer Gruppe) kann
das Flag ändern, Nachfolger erben es automatisch, und das Kopieren eines
Ordners trägt es nicht - auf der Kopie neu setzen.

### Recovery-Key: nochmal anzeigen oder neuen ausstellen

**Einstellungen > Konto** hat einen Abschnitt **Recovery-Key**: das
Speicher-Passwort eingeben und **Recovery-Key anzeigen** zeigt ihn erneut
(64 Hex-Ziffern, mit **Herunterladen**), oder **Neuen Schlüssel
ausstellen** erzeugt hinter einer Bestätigung einen frischen Schlüssel -
der alte Schlüssel hört auf zu funktionieren, sobald der neue gespeichert
ist. Ein falsches Passwort kommt nie so weit. Konten, die vor dieser
Version eingerichtet wurden, haben keine gespeicherte Kopie und antworten
"hier ausstellen"; ihre erste Neu-Ausstellung aktiviert das Anzeigen auch
für sie.

## 12. Passkeys

Ein Passkey meldet dich mit PIN oder Biometrie statt mit einem Passwort
an. fxcloud nutzt Username-first-FIDO2/WebAuthn mit ES256 und verlangt
User-Verification (eine PIN oder eine biometrische Geste, nicht nur eine
Berührung).

**Hinzufügen:** **Einstellungen** öffnen, **Passkeys**, **Passkey
hinzufügen** drücken, einen Namen geben (z.B. „Handy", „Security Key")
und mit dem Gerät bestätigen. Die Liste zeigt deine Geräte mit ihrer
letzten Nutzung; jedes kann **Umbenannt** oder **Entfernt** werden. Das
letzte zu entfernen ist erlaubt - dein Passwort funktioniert weiter, und
ein verlorenes Gerät kann sofort abgeschaltet werden.

**Anmelden:** auf der Anmeldeseite zum Tab **Passkey** wechseln, den
Benutzernamen eingeben und mit PIN oder Biometrie des Geräts bestätigen.
Ein unbekannter Benutzername und ein Konto ohne Passkeys bekommen dieselbe
Antwort, der Dialog verrät also nicht, wer ein Konto hat.

Voraussetzungen:

- Ein **sicherer Kontext**: Browser geben Passkeys nur über HTTPS oder auf
  `localhost` frei. Über reines HTTP auf einer LAN-Adresse sagt dir die
  Oberfläche, dass der Browser sie blockiert.
- Der Passkey ist an den Ursprung und den Hostnamen gebunden, unter dem er
  erstellt wurde. Wird deine Instanz unter einer URL ausgeliefert, muss
  diese URL fxcloud mit `FXCLOUD_ORIGIN` mitgeteilt werden - der nächste
  Abschnitt zeigt, wie, und wie der Fehler aussieht, wenn er fehlt.

### In einer nativen Android-App: die Mauer „Diese App unterstützt keine Passkeys"

Anmelden **im Web** funktioniert mit jedem Browser und jedem
Passwort-Manager - reines WebAuthn, davon gilt nichts unten. Anmelden
**aus der App heraus** - die fxcloud-App bietet keine Passkey-Anmeldung
mehr an (gebaut und wieder entfernt - der Grund ist genau die Fallgrube
unten); jede andere native App läuft über den Credential Manager des
Systems, und dieser Weg hat eine Fallgrube, über die die ganze Branche
seit November 2025 stolpert:

1. Die App fragt den Credential-Provider des Geräts (Bitwarden gegen
   dein eigenes Vaultwarden, Google Password Manager, ...) nach einem
   Passkey.
2. Bevor er ihn herausgibt, muss der Provider beweisen, dass *diese
   App* die Passkeys dieser Domain nutzen darf. Die Bitwarden-Android-
   App macht das über **Googles Digital-Asset-Links-API** - genau die
   Prüfung, die Googles eigene Credential-Provider-Dokumentation
   empfiehlt. Es ist eine Abfrage über eine *öffentliche* Datei: kein
   Schlüssel, kein Passwort, kein Passkey-Material verlässt dein
   Passwort-Manager, selbst gehostet oder nicht.
3. Diese API lädt `https://<host>/.well-known/assetlinks.json`
   **ohne Weiterleitungen zu folgen** und in der Praxis in der
   DNS-Wurzel-Form des Hosts (`https://<host>.`).
4. Beide Anfragen mit einer Weiterleitung oder einem 404 beantworten -
   ein Vhost, der den Namen mit Punkt schlicht nicht kennt, reicht -
   und der Provider verweigert mit einer generischen Meldung:

   > „Diese App unterstützt keine Passkeys"

Alles andere kann perfekt sein - Datei da, JSON valide, Zertifikats-
Fingerabdrücke korrekt - die Prüfung fällt trotzdem durch.

**Das ist weder dein Fehler noch der von fxcloud.** Revolut hatte
monatelang genau diesen Fehler (bitwarden/android#6164, November 2025
bis Juli 2026), Googles eigenes Tracker-Issue trägt den Fehler immer
noch (460172858), und Bitwarden hat einen Workaround ausgeliefert und
wieder zurückgenommen, weil striktes Matching eben die Spezifikation
ist. Niemand sollte seinen Nutzern einen Google-API-Fehler erklären
müssen - dieser Abschnitt existiert, damit du ihn weiterleitest, statt
ihn selbst zu schreiben.

**Für Betreiber - die Checkliste, die jeden Provider zufriedenstellt:**

- `/.well-known/assetlinks.json` antwortet **direkt** mit `200` und
  `Content-Type: application/json` - keine Weiterleitung irgendwo auf
  der **https**-URL (der DAL-API folgt keiner).
- Dieselbe URL antwortet mit **Punkt am Host**:
  `https://deine.domain./.well-known/assetlinks.json`. Bei nginx eine
  Zeile im selben Server-Block:
  `server_name deine.domain deine.domain.;` - in einem Proxy-Setup fast
  immer der Proxy vor fxcloud, nicht fxcloud selbst.
- Die Datei listet **jedes Zertifikat, das ein installiertes Build
  signieren kann**: lokaler Debug-Schlüssel, Release-APK-Schlüssel und
  unter Play App-Signierung Googles klassischen und den
  quantenresistenten. Ein Statement pro Fingerabdruck: manche Prüfer
  lesen nur den ersten Eintrag.

**Nutzer, die hierher aus der Meldung gekommen sind:** Auf deinem
Telefon ist nichts zu tun - dein Instanz-Betreiber erledigt die
Checkliste. Bis dahin meldet dich die Weboberfläche mit demselben
Passkey an. Nach dem Fix eine Weile warten (zehn Minuten bis einen Tag),
bevor du es in der App nochmal versuchst.

**Gerätegebundene Passkeys („Dieses Gerät")** werden vom Browser
angelegt und dort auch genutzt, aber vom Provider nicht immer an
native Apps weitergegeben - beobachtet mit Google Password Manager:
solche Schlüssel tauchen in der Passkey-Liste nie auf, und die App
meldet „keine verfügbare Anmeldung". Bietet das Erzeugungs-Sheet
ohnehin keine Konten-Ablage (nur „dieses Gerät", „anderes Gerät",
NFC/USB), sind native-App-Passkeys auf diesem Gerät schlicht nicht
verfügbar: nutze die Weboberfläche, die jeden Passkey bedient, den
das Gerät halten kann.

**Ohne Google zu arbeiten:** Der Bitwarden-/Vaultwarden-Weg schickt
Google nur die oben beschriebene Abfrage über die öffentliche Datei -
deine Schlüssel bleiben auf deinem eigenen Server. Provider, die die
Datei selbst laden (Google Password Manager tut das), funktionieren
auch ohne den Punkt-Host - dann liegen die Passkeys aber in dessen
Speicher. Wenn dein Grundsatz „meine Daten bleiben bei mir" lautet -
und wenn du fxcloud liest, lautet er das - reparier stattdessen die
Proxy-Zeile: eine Zeile, und alles andere bleibt deins.

## 13. HTTPS hinter einem Reverse Proxy (durchgerechnetes Beispiel)

fxcloud spricht reines HTTP, also beendet ein Reverse Proxy TLS davor.
Passkeys sind der Grund, warum hier eine Einstellung extra nötig ist:
WebAuthn bindet jeden Passkey an das exakte `scheme://host[:port]`, unter
dem er erstellt wurde, und der Browser sendet sein `Origin` bei jeder
Passkey-Anfrage. fxcloud vergleicht diesen Header mit dem Ursprung, den es
aus dem weitergeleiteten Schema und `Host` ableitet - und hinter einem
Proxy, der `Host` überschreibt oder das Schema nicht weiterleitet, sind
die beiden nicht gleich.

Das Symptom ist dieser Fehler beim Hinzufügen oder Verwenden eines
Passkeys:

```
bad request: Origin does not match this server's address - set
FXCLOUD_ORIGIN to the URL users open it under
```

Die Lösung ist eine einzige Umgebungsvariable: sage fxcloud die URL, unter
der Nutzer es tatsächlich öffnen. Durchgerechnetes Beispiel mit nginx auf
`cloud.example.com` und fxcloud auf demselben Host, Port8080:

**1. fxcloud** (systemd-Unit, oder die Shell für einen schnellen Test):

```bash
FXCLOUD_BIND=127.0.0.1 FXCLOUD_PORT=8080 \
FXCLOUD_SECURE_COOKIE=1 \
FXCLOUD_ORIGIN=https://cloud.example.com \
./fxcloud
```

In der mitgelieferten Unit-Datei (`deploy/fxcloud.service`) warten dieselben
zwei Zeilen, auskommentiert, im Environment-Abschnitt:

```ini
# Enable when serving over HTTPS behind a TLS-terminating reverse proxy:
# Environment=FXCLOUD_SECURE_COOKIE=1
# The exact URL users open fxcloud under - required for passkeys when a
# reverse proxy rewrites Host or terminates TLS (e.g. https://cloud.example.com):
# Environment=FXCLOUD_ORIGIN=https://cloud.example.com
```

**2. nginx** beendet TLS und leitet weiter:

```nginx
server {
    listen 443 ssl;
    server_name cloud.example.com;

    client_max_body_size 10G;   # keep in sync with FXCLOUD_MAX_UPLOAD_MB

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_request_buffering off;
        proxy_buffering off;
    }
}
```

**3. fxcloud neu starten** (nach Änderung der Unit:
`sudo systemctl daemon-reload && sudo systemctl restart fxcloud`).

Regeln für den Wert von `FXCLOUD_ORIGIN`:

- Er muss dem entsprechen, was die Browser-Adressleiste als Ursprung
  zeigt: Schema, Host und Port, falls nicht der Standard des Schemas (443
  für https,80 für http) - und **kein abschließender Schrägstrich**, kein
  Pfad.
- Wenn Nutzer die Instanz unter mehreren Namen erreichen, funktionieren
  Passkeys unter dem hier konfigurierten; die kanonische URL wählen.
- Er betrifft nur WebAuthn. Alles andere funktioniert weiter mit den
  Proxy-Headern aus dem obigen nginx-Block, und ohne Proxy ist das Setzen
  harmlos.

Ohne `FXCLOUD_ORIGIN` leitet fxcloud den Ursprung pro Anfrage aus
`X-Forwarded-Proto` (oder `FXCLOUD_SECURE_COOKIE`) plus `Host` ab - das
stimmt, wenn der Proxy beide unverändert durchreicht, und stimmt nicht im
Moment, in dem er es nicht tut.

## 14. WebDAV

fxcloud spricht WebDAV unter **`/dav/`** mit HTTP-Basic-Auth (dein
fxcloud-Benutzername + Passwort; Passkeys gibt es nur im Web). Der Pfad
nach `/dav/` ist relativ zu deinem Home-Ordner:

```bash
rclone config    # type: webdav, url: https://your-host/dav/, user/pass
rclone lsd remote:

# Windows "Map network drive" / macOS Finder "Connect to Server" -> /dav/
```

Deaktivierte Konten bekommen403, Kontingent-Überschreitungen507.
Verschlüsselte Dateien erscheinen als Ciphertext und können nicht von
einem Desktop-Client geschrieben werden (siehe
[Verschlüsselung](#11-verschlusselung)); die Weboberfläche ist der Weg
hinein und heraus für diese.

## 15. Fehlerbehebung

**„Diese App unterstützt keine Passkeys"** beim Anmelden aus der
Android-App: Der Credential-Provider des Geräts konnte die App nicht
gegen die assetlinks-Datei deiner Domain verifizieren (Googles
DAL-API, Weiterleitungen und Punkt-Hosts -
[Abschnitt 12](#12-passkeys) hat die Geschichte und die Checkliste für
Betreiber). Bis es behoben ist, meldet dich die Weboberfläche mit
demselben Passkey an.

**"Origin does not match this server's address - set FXCLOUD_ORIGIN ..."**
beim Hinzufügen oder Verwenden eines Passkeys: die URL, unter der Nutzer
fxcloud öffnen, weicht von dem ab, was fxcloud aus den Proxy-Headern
ableitet. `FXCLOUD_ORIGIN` wie in [Abschnitt13](#13-https-hinter-einem-reverse-proxy-durchgerechnetes-beispiel)
setzen und neu starten.

**Die Passkey-Oberfläche sagt, der Browser blockiert Passkeys**: ihr seid
auf reinem HTTP (oder einer IP-Adresse) statt HTTPS oder localhost -
Browser geben Passkeys nur in einem sicheren Kontext frei. fxcloud über
HTTPS ausliefern.

**"Account created. It has to be activated before you can sign in"**:
erwartet für jedes Konto nach dem ersten - ein Administrator aktiviert es
in der **Benutzerverwaltung**.

**"account is not activated yet - ask an administrator to activate it"**
bei der Anmeldung oder über WebDAV: dieselbe Ursache, jetzt an einem
bestehenden Konto.

**507 "storage quota exceeded: X of Y used"**: dein Kontingent ist voll -
Papierkorb leeren (er zählt weiter), Dateien löschen oder den
Administrator bitten, das Kontingent zu erhöhen.

**Verschlüsselte Dateien öffnen nicht**: das Speicher-Passwort ist in
diesem Tab nicht entsperrt (die Schlüssel leben nur im Tab-Speicher) -
die Entsperren-Leiste nutzen; wenn das Passwort vergessen ist, rettet der
Recovery-Key aus dem Setup.

**Sync-Client-Schreibvorgänge schlagen bei verschlüsselten Dateien fehl**:
Desktop-Clients verschlüsseln nicht; WebDAV liefert diese Dateien als
Ciphertext, schreibgeschützt. Für verschlüsselten Inhalt die
Weboberfläche nutzen.

**Anmeldeseite ist tot: die Tabs Passkey/Konto erstellen reagieren nicht,
die Seite zeigt Englisch, obwohl dein Browser Deutsch ist, und Abschicken
bringt nur die Maske ohne Fehler zurück**: JavaScript ist für fxcloud
abgeschaltet. Auf manchen Geräten ist das die Voreinstellung für frisch
installierte Web-Apps und der Installationsdialog bietet keinen Schalter
(berichtet auf einem Google Pixel; ein Samsung bot die Einstellung gar
nicht an) - das Seitenskript verdrahtet die Tabs und fängt das Formular
ab, ohne es fällt der Browser auf ein einfaches Neuladen zurück. Fix:
lange auf das fxcloud-Icon drücken, **Einstellungen** öffnen,
**JavaScript** aktivieren (oder Chrome > Einstellungen > Website-Einstellungen
> JavaScript), App neu öffnen. Eine andere Ursache mit teilweiser
Überschneidung: wenn die Tabs *doch* reagieren und die Seite in deiner
Sprache ist, die Anmeldung aber trotzdem zur Maske zurückläuft, wird
stattdessen das Sitzungs-Cookie verworfen - prüfen, dass die Adressleiste
`https://` zeigt, und die Daten der Seite in den Browsereinstellungen
löschen.
