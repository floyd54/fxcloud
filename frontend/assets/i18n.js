/*
 * i18n.js - the whole translation layer, no framework, no fetch.
 *
 * Every dictionary lives in this one file, so a language switch costs zero
 * round trips and the pages can never render half-translated while a second
 * asset loads. Non-ASCII letters are spelled with \uXXXX escapes (German
 * umlauts; see the cheat sheet below) so this file stays pure ASCII; the
 * browser decodes them and the UI renders proper text. See TRANSLATING.md
 * for what a new language needs.
 *
 * English stays the default: without a stored choice the UI starts on
 * English. German is the first flag in the switcher (and the first
 * language this file translates), Klingon the last - the order is CODES.
 * Anyone who wants another language picks it once and the choice sticks.
 * English is also the source text in the HTML and the safety net for a
 * key no dictionary has covered yet.
 *
 *   t(key, params)   translate; falls back to English, then to the key itself
 *   setLang(code)    switch, persist in localStorage, re-apply, notify
 *   apply(root)      re-stamp every [data-i18n*] node under root
 *   init()           detect the language, stamp the document, draw the
 *                    language dropdown (current flag opens the menu)
 *
 * Static HTML keeps its English text as the fallback (and for no-JS readers);
 * every translated element carries a data-i18n* attribute naming its key:
 *
 *   data-i18n="key"          textContent
 *   data-i18n-ph="key"       placeholder
 *   data-i18n-title="key"    title
 *   data-i18n-aria="key"     aria-label
 *
 * Dynamic strings call t() directly and re-render themselves when the
 * "fxcloud:langchange" event fires on document.
 */
(function () {
  "use strict";

  // Umlaut cheat sheet: a=\u00e4 o=\u00f6 u=\u00fc s=\u00df
  //                     A=\u00c4 O=\u00d6 U=\u00dc
  var DE = {
    // topbar
    "nav.settings": "Einstellungen",
    "nav.admin": "Benutzerverwaltung",
    "nav.signout": "Abmelden",
    "storage.title": "Belegter Speicher vom Kontingent",
    "storage.of": "{used} von {quota}",
    "lang.aria": "Sprache",

    // toolbar
    "files.new": "\uff0b Neue Datei",
    "files.newFolder": "\uff0b Neuer Ordner",
    "files.upload": "\u2b06 Datei hochladen",
    "files.uploadFolder": "\u2b06 Ordner hochladen",
    "files.trash": "Papierkorb",
    "files.emptyTrash": "Papierkorb leeren",
    "files.showHidden": "Versteckte anzeigen",
    "files.showHiddenHint":
      "Dateien und Ordner anzeigen, deren Name mit einem Punkt beginnt",
    "files.selectAll": "Alle Eintr\u00e4ge in diesem Ordner ausw\u00e4hlen",
    "files.loading": "L\u00e4dt\u2026",
    "crumb.home": "Start",

    // dropzone (three pieces around the <strong>)
    "drop.a": "Dateien",
    "drop.b": "oder ganze Ordner",
    "drop.c": "hierher ziehen zum Hochladen - oder oben die Schaltfl\u00e4chen benutzen.",

    // table headers
    "table.name": "Name",
    "table.size": "Gr\u00f6\u00dfe",
    "table.modified": "Ge\u00e4ndert",

    // bulk action bar
    "bulk.one": "1 Eintrag ausgew\u00e4hlt",
    "bulk.n": "{n} Eintr\u00e4ge ausgew\u00e4hlt",
    "bulk.download": "Herunterladen",
    "bulk.move": "Verschieben nach\u2026",
    "bulk.copy": "Kopieren nach\u2026",
    "bulk.share": "Freigeben",
    "bulk.delete": "L\u00f6schen",
    "bulk.restore": "\u267d Wiederherstellen",
    "bulk.purge": "Endg\u00fcltig l\u00f6schen",
    "bulk.clear": "Auswahl aufheben",

    // shared verbs (row menu and dialogs)
    "act.open": "\u00d6ffnen",
    "act.edit": "Bearbeiten",
    "act.preview": "Vorschau",
    "act.rename": "Umbenennen",
    "act.close": "Schlie\u00dfen",
    "act.cancel": "Abbrechen",
    "act.save": "Speichern",
    "act.remove": "Entfernen",
    "act.restore": "Wiederherstellen",
    "act.items": "{n} Eintr\u00e4ge",
    "act.itemsP": "{n} Eintr\u00e4ge",

    // rows
    "row.select": "Ausw\u00e4hlen",
    "row.actions": "Aktionen",
    "row.folder": "Ordner",
    "row.purgeOn": "Wird am {date} automatisch gel\u00f6scht",
    "row.encTitle":
      "im Browser verschl\u00fcsselt - der Server speichert nur Chiffretext",

    // empty states
    "empty.hidden1": "Hier sind nur versteckte Dateien.",
    "empty.hidden2":
      "Schalte <b>Versteckte anzeigen</b> in der Werkzeugleiste ein, um sie zu sehen.",
    "empty.trash": "Der Papierkorb ist leer.",
    "empty.folder1": "Dieser Ordner ist leer.",
    "empty.folder2": "Lade eine Datei hoch oder erstelle einen Ordner, um zu beginnen.",

    // share dialog
    "share.title1": "Freigabe f\u00fcr \"{name}\"",
    "share.titleN": "{n} Eintr\u00e4ge freigeben",
    "share.userAria": "Benutzer f\u00fcr die Freigabe",
    "share.perm.read": "Lesen",
    "share.perm.write": "Schreiben",
    "share.perm.create": "Erstellen",
    "share.perm.delete": "L\u00f6schen",
    "share.perm.share": "Weitergeben",
    "share.add": "Freigeben",
    "share.cannotLoad": "Benutzer k\u00f6nnen nicht geladen werden",
    "share.everySelected":
      "Jeder ausgew\u00e4hlte Eintrag erh\u00e4lt dieselbe Freigabe und dieselben Rechte.",
    "share.none": "Noch mit niemandem freigegeben.",
    "share.noUsers": "Noch keine weiteren Benutzer",
    "share.inactive": " \u2014 inaktiv",
    "share.fp": "Schl\u00fcsselfingerabdruck von {user}: ",
    "share.noEnc":
      "{user} hat keine Verschl\u00fcsselung eingerichtet - verschl\u00fcsselte Eintr\u00e4ge bleiben f\u00fcr sie unlesbar.",
    "share.changedShort": "Schl\u00fcssel ge\u00e4ndert: {new} (vorher {old})",
    "share.confirmChanged":
      "Der Schl\u00fcsselfingerabdruck von {user} hat sich GE\u00c4NDERT.\n\n" +
      "Vorher: {before}\nJetzt:  {now}\n\n" +
      "Eine \u00c4nderung ist nach einer Wiederherstellung oder einem neuen Ger\u00e4t normal - " +
      "und genau so w\u00fcrde ein Server in der Mitte jemandem anderen seinen eigenen " +
      "Schl\u00fcssel aush\u00e4ndigen. Vergleiche den neuen Fingerabdruck au\u00dferhalb von fxcloud, " +
      "bevor du etwas Verschl\u00fcsseltes freigibst. Fortfahren?",
    "share.confirmNew":
      "Schl\u00fcsselfingerabdruck von {user}:\n\n    {fp}\n\n" +
      "Vergleiche ihn mit dem, was die Person in ihrem eigenen fxcloud sieht " +
      "(Abzeichen, dann \"Schl\u00fcsselinfo anzeigen\"), wenn du sicher sein willst, " +
      "dass niemand dazwischen sitzt. Ab jetzt wird er gemerkt, damit eine " +
      "sp\u00e4tere \u00c4nderung auff\u00e4llt. Fortfahren?",
    "share.noKeyConfirm":
      "{user} hat keine Verschl\u00fcsselung eingerichtet, verschl\u00fcsselte Eintr\u00e4ge " +
      "k\u00f6nnen von dieser Seite nicht ge\u00f6ffnet werden.\n\nTrotzdem freigeben?",
    "share.cancelled":
      "Freigabe abgebrochen: mit gesperrten Schl\u00fcsseln kann kein Umschlag versiegelt werden.",
    "share.result": "{n} von {m} Eintr\u00e4gen mit {user} freigegeben.",
    "share.nothing": "Es wurde nichts freigegeben.",

    // move / copy dialog
    "transfer.moveTitle": "{what} verschieben nach\u2026",
    "transfer.copyTitle": "{what} kopieren nach\u2026",
    "transfer.moveHere": "Hierher verschieben",
    "transfer.copyHere": "Hierher kopieren",
    "transfer.noSub": "Keine Unterordner hier.",
    "transfer.noKeyMove":
      "Ein verschl\u00fcsselter Eintrag kann nicht verschoben werden, solange dieser Tab keine Schl\u00fcssel h\u00e4lt.",
    "transfer.noneMove": "Keiner der ausgew\u00e4hlten Eintr\u00e4ge darf verschoben werden.",
    "transfer.noneCopy": "Keiner der ausgew\u00e4hlten Eintr\u00e4ge darf kopiert werden.",
    "transfer.copyBlocked":
      "{what} kann nicht kopiert werden.\n\nEine Kopie erh\u00e4lt eine neue Zeilen-ID, " +
      "und das Neuverpacken eines Schl\u00fcsselsatzes f\u00fcr eine neue Zeile ist im Kopieren " +
      "noch nicht vorgesehen. Verschiebe die Eintr\u00e4ge stattdessen oder lade sie herunter " +
      "und wieder hoch.",
    "transfer.rollback":
      "\"{name}\" konnte nicht verschoben werden ({msg}), und sein Schl\u00fcsselsatz " +
      "konnte auch nicht zur\u00fcckgesetzt werden.\n\nSein Satz nennt jetzt den Zielordner - " +
      "verschiebe ihn dorthin, sobald die Verschiebung erlaubt ist, und er \u00f6ffnet sich wieder.",

    // prompts (client-side, one line each) and inline file creation
    "prompt.newFolder": "Name des neuen Ordners:",
    "prompt.newFile": "Name der neuen Datei:",
    "prompt.rename": "Umbenennen in:",
    "file.textOnly":
      "Hier k\u00f6nnen nur Textdateien erstellt werden (.txt, .md, .csv, Code, ...).\n" +
      "Lade andere Dateitypen stattdessen hoch.",
    "file.encFail":
      "Die neue Datei konnte nicht verschl\u00fcsselt werden und wurde deshalb entfernt: {msg}",

    // confirms and batch reports
    "confirm.purgeOne":
      "Diesen Eintrag endg\u00fcltig l\u00f6schen? Das kann nicht r\u00fcckg\u00e4ngig gemacht werden.",
    "confirm.purgeN":
      "{n} Eintr\u00e4ge endg\u00fcltig l\u00f6schen? Das kann nicht r\u00fcckg\u00e4ngig gemacht werden.",
    "confirm.emptyTrash":
      "Papierkorb leeren? Jeder darin enthaltene Eintrag wird endg\u00fcltig gel\u00f6scht.",
    "confirm.moveFolder":
      "Ordner \"{name}\" und alles darin in den Papierkorb verschieben?",
    "confirm.moveFile": "Datei \"{name}\" in den Papierkorb verschieben?",
    "confirm.discard": "Ungespeicherte \u00c4nderungen verwerfen?",
    "confirm.bulkDelete":
      "{n} von {m} ausgew\u00e4hlten Eintr\u00e4gen in den Papierkorb verschieben?",
    "batch.files": "{k} Datei(en) \u00b7 {size}",
    "batch.folders": "{k} Ordner(en) \u00b7 mit allem darin",
    "batch.skipped":
      "{missing} von {total} ausgew\u00e4hlten Eintr\u00e4gen \u00fcbersprungen \u2014 fehlende Berechtigung.",
    "batch.failed": "{failed} von {n} Eintr\u00e4gen fehlgeschlagen:",

    // upload, preview, editor
    "upload.at": "Lade {i}/{n} hoch \u2014 {path}",
    "upload.encrypted": " (verschl\u00fcsselt)",
    "upload.failed": "{n} von {m} Eintr\u00e4gen konnten nicht hochgeladen werden:",
    "upload.itemFail": "{path} \u2014 {msg}",
    "preview.failedWhy": "Vorschau fehlgeschlagen: {why} - stattdessen herunterladen.",
    "preview.failed":
      "Vorschau fehlgeschlagen - die Datei ist m\u00f6glicherweise nicht verf\u00fcgbar. Stattdessen herunterladen.",
    "preview.decrypting": "Vorschau wird entschl\u00fcsselt...",
    "preview.encHint":
      "diese Datei ist verschl\u00fcsselt - Verschl\u00fcsselung \u00fcber das Abzeichen aktivieren, um sie anzuzeigen",
    "preview.encEditHint":
      "diese Datei ist verschl\u00fcsselt - Verschl\u00fcsselung \u00fcber das Abzeichen aktivieren, um sie zu bearbeiten",
    "preview.newTab": "In neuem Tab \u00f6ffnen",
    "preview.prev": "Vorheriges",
    "preview.next": "N\u00e4chstes",
    "editor.loading": "l\u00e4dt...",
    "editor.saving": "speichert...",
    "editor.saved": "gespeichert",
    "editor.loadFailed": "Laden fehlgeschlagen: {msg}",
    "editor.saveFailed": "Speichern fehlgeschlagen: {msg}",
    "editor.unsaved": "* ungespeichert",
    "editor.meta": "{lines} Zeilen, {chars} Zeichen",
    "editor.markdown": "Markdown",

    // settings dialog
    "settings.title": "Einstellungen",
    "settings.account": "Konto",
    "settings.username": "Benutzername",
    "settings.since": "Mitglied seit",
    "settings.storage": "Speicher",
    "settings.displayName": "Anzeigename",
    "settings.theme": "Farbschema",
    "settings.light": "Hell",
    "settings.dark": "Dunkel",
    "settings.password": "Passwort",
    "settings.passCurrent": "Aktuelles Passwort",
    "settings.passNew": "Neues Passwort (mindestens 8 Zeichen)",
    "settings.passChange": "Passwort \u00e4ndern",
    "settings.passkeys": "Passkeys",
    "settings.passkeysHint":
      "Ein Passkey meldet dich mit PIN oder Biometrie statt mit einem Passwort an. " +
      "Der private Teil bleibt auf deinem Ger\u00e4t; der Server speichert nur den " +
      "\u00f6ffentlichen Schl\u00fcssel, sodass ein verlorenes Ger\u00e4t hier entfernt werden kann.",
    "settings.addPasskey": "Passkey hinzuf\u00fcgen",
    "settings.lang": "Sprache",
    "settings.langHint": "Wird sofort \u00fcbernommen und in diesem Browser gemerkt.",
    "settings.nameEmpty": "Der Anzeigename darf nicht leer sein.",
    "settings.nameSaved": "Anzeigename gespeichert.",
    "settings.themeSaved": "Farbschema gespeichert.",
    "settings.passShort":
      "Das neue Passwort muss mindestens 8 Zeichen lang sein.",
    "settings.passChanged": "Passwort ge\u00e4ndert.",

    // passkeys
    "passkey.added": "hinzugef\u00fcgt {date}",
    "passkey.lastUsed": "zuletzt verwendet {date}",
    "passkey.empty": "Noch keine Passkeys registriert.",
    "passkey.nameEmpty": "Der Passkey-Name darf nicht leer sein.",
    "passkey.renamed": "Passkey umbenannt.",
    "passkey.removed": "Passkey entfernt.",
    "passkey.cancelled": "Die Passkey-Erstellung wurde abgebrochen.",
    "passkey.addedStatus": "Passkey hinzugef\u00fcgt.",
    "passkey.https":
      "Passkeys ben\u00f6tigen HTTPS (oder localhost) - dieser Browser blockiert sie hier.",
    "passkey.namePrompt":
      "Name f\u00fcr den neuen Passkey (zum Beispiel: \"Telefon\", \"Sicherheitsschl\u00fcssel\"):",
    "passkey.renamePrompt": "Neuer Name f\u00fcr diesen Passkey:",
    "passkey.deviceRefused":
      "Die Passkey-Erstellung wurde abgebrochen oder vom Ger\u00e4t abgelehnt.",
    "passkey.removeConfirm":
      "Passkey \"{label}\" entfernen? Dieses Ger\u00e4t kann sich damit nicht mehr anmelden.",

    // admin table + reset dialog
    "admin.title": "Benutzerverwaltung",
    "admin.user": "Benutzer",
    "admin.status": "Status",
    "admin.role": "Rolle",
    "admin.quota": "Kontingent",
    "admin.active": "Aktiv",
    "admin.inactive": "Inaktiv",
    "admin.admin": "Admin",
    "admin.member": "Mitglied",
    "admin.quotaMiB": "Kontingent in MiB",
    "admin.used": "{size} belegt",
    "admin.deactivate": "Deaktivieren",
    "admin.activate": "Aktivieren",
    "admin.revoke": "Admin entziehen",
    "admin.make": "Zum Admin machen",
    "admin.resetPw": "Passwort zur\u00fccksetzen",
    "admin.quotaBad": "Das Kontingent muss eine nicht negative Zahl in MiB sein.",
    "reset.title": "Tempor\u00e4res Passwort",
    "reset.user": "F\u00fcr {user}:",
    "reset.hint":
      "Gib dieses Passwort an die Person weiter. Es gilt nur f\u00fcr die n\u00e4chste Anmeldung -- " +
      "das Passwort sollte sofort in den Einstellungen ge\u00e4ndert werden.",
    "reset.copy": "Kopieren",
    "reset.done": "Fertig",

    // encryption panes (static HTML)
    "enc.setup.title": "Dateiverschl\u00fcsselung aktivieren",
    "enc.setup.lead1": "Hochgeladene Dateien werden",
    "enc.setup.lead2": "in diesem Browser",
    "enc.setup.lead3":
      "verschl\u00fcsselt, bevor sie dein Ger\u00e4t verlassen. Der Server erh\u00e4lt Chiffretext, " +
      "einen verpackten Schl\u00fcssel und keinen lesbaren Inhalt - er kann weiterhin Dateinamen, " +
      "Gr\u00f6\u00dfe und Freigaben sehen, denn die braucht der Speicherdienst.",
    "enc.setup.useLogin": "Mein fxcloud-Anmeldepasswort verwenden",
    "enc.setup.usePass": "Eine eigene Passphrase w\u00e4hlen",
    "enc.setup.passLabel": "Dein fxcloud-Anmeldepasswort",
    "enc.passphrase": "Speicher-Passphrase",
    "enc.repeatPass": "Passphrase wiederholen",
    "enc.setup.go": "Weiter",
    "enc.setup.hintLogin":
      "Die Anmeldung l\u00e4sst den Server ohnehin einen 64-MiB-Argon2id-Hash berechnen, " +
      "sodass ein starkes Passwort f\u00fcr beides reicht. Dein Browser kann das Feld aus " +
      "deinem Anmeldepasswort ausf\u00fcllen, und es wird vor der Schl\u00fcsselerstellung " +
      "gegen dein Konto gepr\u00fcft.",
    "enc.setup.hintSep":
      "Eine eigene Passphrase wird nie irgendwohin gesendet; hier l\u00e4uft nur die " +
      "64-MiB-Argon2id-Ableitung. Es ist ein weiteres Geheimnis zum Aufbewahren: " +
      "ohne sie k\u00f6nnen deine Dateien nicht wieder ge\u00f6ffnet werden.",
    "enc.saved.title": "Wiederherstellungsschl\u00fcssel speichern",
    "enc.saved.lead":
      "Das ist der einzige Weg zur\u00fcck zu deinen verschl\u00fcsselten Dateien, falls die " +
      "Passphrase vergessen wird. Er wird einmalig angezeigt und an keinem Ort gespeichert, " +
      "an dem du ihn sp\u00e4ter wiederfinden k\u00f6nntest.",
    "enc.saved.dl": "Wiederherstellungsschl\u00fcssel herunterladen",
    "enc.saved.ack":
      "Ich habe diesen Wiederherstellungsschl\u00fcssel sicher und offline gespeichert.",
    "enc.saved.hint":
      "Wer diese Datei besitzt, kann deine Dateien entschl\u00fcsseln. Wenn du sie und die " +
      "Passphrase verlierst, kann niemand - auch wir nicht - sie wieder lesen.",
    "enc.saved.go": "Verschl\u00fcsselung aktivieren",
    "enc.unlock.title": "Dieser Tab ist unverschl\u00fcsselt",
    "enc.unlock.lead":
      "Gib deine Speicher-Passphrase ein, um die Verschl\u00fcsselung hier zu aktivieren: " +
      "neue Dateien und Uploads werden dann in diesem Browser verschl\u00fcsselt, und die " +
      "verschl\u00fcsselten Dateien dieses Kontos \u00f6ffnen sich. Die Schl\u00fcssel bleiben nur " +
      "im Speicher dieses Tabs - ein Neuladen bringt dich wieder auf Unverschl\u00fcsselt.",
    "enc.unlock.recover": "Wiederherstellungsschl\u00fcssel verwenden",
    "enc.unlock.go": "Entsperren",
    "enc.recover.title": "Mit Wiederherstellungsschl\u00fcssel wiederherstellen",
    "enc.recover.lead":
      "F\u00fcge die 64 Hex-Ziffern ein und w\u00e4hle dann eine neue Speicher-Passphrase. " +
      "Alle bestehenden verschl\u00fcsselten Dateien funktionieren weiter: Nur die " +
      "\u00e4u\u00dfere H\u00fclle wird ersetzt.",
    "enc.recover.keyLabel": "Wiederherstellungsschl\u00fcssel",
    "enc.recover.passLabel": "Neue Speicher-Passphrase",
    "enc.recover.back": "Zur\u00fcck",
    "enc.recover.go": "Wiederherstellen",
    "enc.info.title": "Verschl\u00fcsselung ist aktiv",
    "enc.info.lead":
      "Uploads werden in diesem Browser verschl\u00fcsselt. Vergleiche den Fingerabdruck " +
      "unten mit dem, was die andere Person angezeigt bekommt, bevor du einem " +
      "Schl\u00fcsseltaustausch vertraust (DECISION 6).",
    "enc.info.fpLabel": "Schl\u00fcsselfingerabdruck",
    "enc.info.lock": "F\u00fcr diesen Tab ausschalten",

    // fxenc runtime strings
    "enc.badge.setup": "Uploads verschl\u00fcsseln",
    "enc.badge.locked": "\uD83D\uDD13 Unverschl\u00fcsselt",
    "enc.badge.unlocked": "\uD83D\uDD12 Verschl\u00fcsselt",
    "enc.badge.unlocking": "Wird entsperrt\u2026",
    "enc.title.setup":
      "Die clientseitige Verschl\u00fcsselung ist noch nicht eingerichtet. Hochgeladene " +
      "Dateien werden so gespeichert, bis du sie aktivierst. Klicke, um sie einzurichten.",
    "enc.title.locked":
      "Neue Dateien und Uploads in diesem Tab werden unver\u00e4ndert gespeichert. Klicke, " +
      "um die Verschl\u00fcsselung hier zu aktivieren - dann \u00f6ffnen sich auch die " +
      "verschl\u00fcsselten Dateien dieses Kontos.",
    "enc.title.unlocked":
      "Uploads werden in diesem Browser verschl\u00fcsselt, bevor sie das Ger\u00e4t verlassen. " +
      "Klicke, um sie f\u00fcr diesen Tab abzuschalten oder den Schl\u00fcsselfingerabdruck " +
      "dieses Kontos zu sehen.",
    "enc.unsupported":
      "Dieser Browser hat kein WebCrypto, verschl\u00fcsselte Uploads sind daher nicht " +
      "verf\u00fcgbar. HTTPS (oder localhost) und ein aktueller Browser sind erforderlich.",
    "enc.checkLoginFail":
      "Das Anmeldepasswort konnte nicht gepr\u00fcft werden ({status})",
    "enc.enterLogin": "Gib dein fxcloud-Anmeldepasswort ein.",
    "enc.choosePass": "W\u00e4hle eine Speicher-Passphrase.",
    "enc.mismatch": "Die beiden Passphrasen stimmen nicht \u00fcberein.",
    "enc.checking": "Anmeldepasswort wird gepr\u00fcft\u2026",
    "enc.wrongLogin": "Das ist nicht dein fxcloud-Anmeldepasswort.",
    "enc.deriving": "Schl\u00fcssel werden abgeleitet (Argon2id, 64 MiB)\u2026",
    "enc.enterPass": "Gib deine Speicher-Passphrase ein.",
    "enc.pasteRcv":
      "F\u00fcge die 64 Hex-Ziffern deines Wiederherstellungsschl\u00fcssels ein.",
    "enc.chooseNew": "W\u00e4hle eine neue Speicher-Passphrase.",
    "enc.rcvLen": "Ein Wiederherstellungsschl\u00fcssel ist 32 Byte - 64 Hex-Ziffern.",
    "enc.openRoot": "Konten-Hauptchl\u00fcssel wird ge\u00f6ffnet\u2026",
    "enc.rewrapping": "Wird unter der neuen Passphrase neu verpackt\u2026",
    "enc.exists":
      "F\u00fcr dieses Konto gibt es bereits einen Schl\u00fcsselsatz; entsperre ihn mit seiner Passphrase.",

    // guards below surface as messages in alerts, previews and the editor
    "enc.err.open": "Verschl\u00fcsselung entsperren, um diese Datei zu \u00f6ffnen",
    "enc.err.download":
      "Verschl\u00fcsselung entsperren, um diese Datei herunterzuladen",
    "enc.err.preview":
      "Verschl\u00fcsselung entsperren, um diese Datei anzuzeigen",
    "enc.err.save": "Verschl\u00fcsselung entsperren, um diese Datei zu speichern",
    "enc.err.unkeyed":
      "Diese Datei hat keinen gespeicherten Schl\u00fcssel zum \u00d6ffnen",
    "enc.err.unwrapped":
      "Schl\u00fcssel konnte nicht entpackt werden - falsche Passphrase oder die Daten wurden ver\u00e4ndert",
    "enc.err.notFolder": "Das Ziel ist kein Ordner",
    "enc.err.uploadCancelled": "Verschl\u00fcsselter Upload abgebrochen",
    "enc.err.worker": "Krypto-Worker-Fehler",
    "enc.err.workerStopped": "Krypto-Worker wurde beendet",

    // login / register page
    "login.title": "Anmelden \u00b7 fxcloud",
    "login.tagline": "Deine Dateien, synchronisiert und an einem Ort.",
    "login.tab.signin": "Anmelden",
    "login.tab.passkey": "Passkey",
    "login.tab.register": "Konto erstellen",
    "login.username": "Benutzername",
    "login.display": "Anzeigename",
    "login.password": "Passwort",
    "login.wait": "Bitte warten\u2026",
    "login.waiting": "Warte auf dein Ger\u00e4t...",
    "login.passkeyHint":
      "Melde dich mit dem Passkey an, der f\u00fcr dieses Konto registriert ist - das " +
      "Ger\u00e4t fragt nach PIN oder Biometrie statt nach einem Passwort.",
    "login.passkeyBtn": "Mit Passkey anmelden",
    "login.err.generic": "Etwas ist schiefgelaufen.",
    "login.err.invalid": "Ung\u00fcltiger Benutzername oder ung\u00fcltiges Passwort.",
    "login.err.inactive":
      "Konto erstellt. Es muss aktiviert werden, bevor du dich anmelden kannst -- " +
      "wende dich an deinen Administrator.",
    "login.err.network": "Netzwerkfehler. L\u00e4uft der Server?",
    "login.err.https":
      "Dieser Browser kann hier keine Passkeys verwenden - \u00f6ffne die Seite " +
      "\u00fcber HTTPS (oder localhost).",
    "login.err.needUser": "Gib deinen Benutzernamen ein.",
    "login.err.startFail": "Passkey-Anmeldung konnte nicht gestartet werden.",
    "login.err.noPasskeyUsed":
      "Es wurde kein Passkey verwendet - die Abfrage wurde abgebrochen, ist abgelaufen " +
      "oder dieses Konto hat hier keinen.",
    "login.err.passkeyFail": "Passkey-Anmeldung fehlgeschlagen: {msg}",
    "login.err.noPasskey": "Es wurde kein Passkey verwendet.",
    "login.err.finishFail": "Passkey-Anmeldung fehlgeschlagen.",
    "login.err.unknown": "Unbekannter Benutzer oder kein passender Passkey.",

    // server error codes (the server sends the code, this side translates)
    "err.not_found": "Nicht gefunden.",
    "err.unauthorized": "Anmeldung erforderlich.",
    "err.forbidden": "Nicht erlaubt.",
    "err.inactive_account": "Dieses Konto ist noch nicht aktiv.",
    "err.quota_exceeded": "Kontingent erreicht: {used} von {quota} belegt.",
    "err.bad_request": "Ung\u00fcltige Anfrage.",
    "err.conflict": "Existiert bereits oder gleichzeitige \u00c4nderung.",
    "err.internal": "Interner Serverfehler.",
    "err.request_failed": "Anfrage fehlgeschlagen ({status})",

    // permission names as the server reports them in share rows
    "perm.read": "lesen",
    "perm.update": "\u00e4ndern",
    "perm.create": "erstellen",
    "perm.delete": "l\u00f6schen",
    "perm.share": "weitergeben",
  };

  var EN = {
    // topbar
    "nav.settings": "Settings",
    "nav.admin": "User administration",
    "nav.signout": "Sign out",
    "storage.title": "storage used of quota",
    "storage.of": "{used} of {quota}",
    "lang.aria": "Language",

    // toolbar
    "files.new": "\uff0b New file",
    "files.newFolder": "\uff0b New folder",
    "files.upload": "\u2b06 Upload file",
    "files.uploadFolder": "\u2b06 Upload folder",
    "files.trash": "Trash",
    "files.emptyTrash": "Empty trash",
    "files.showHidden": "Show hidden",
    "files.showHiddenHint":
      "Show files and folders whose name starts with a dot",
    "files.selectAll": "Select all items in this folder",
    "files.loading": "Loading\u2026",
    "crumb.home": "Home",

    // dropzone (three pieces around the <strong>)
    "drop.a": "Drop files",
    "drop.b": "or whole folders",
    "drop.c": "here to upload, or use the upload buttons above.",

    // table headers
    "table.name": "Name",
    "table.size": "Size",
    "table.modified": "Modified",

    // bulk action bar
    "bulk.one": "1 item selected",
    "bulk.n": "{n} items selected",
    "bulk.download": "Download",
    "bulk.move": "Move to\u2026",
    "bulk.copy": "Copy to\u2026",
    "bulk.share": "Share",
    "bulk.delete": "Delete",
    "bulk.restore": "\u267d Restore",
    "bulk.purge": "Delete permanently",
    "bulk.clear": "Clear",

    // shared verbs (row menu and dialogs)
    "act.open": "Open",
    "act.edit": "Edit",
    "act.preview": "Preview",
    "act.rename": "Rename",
    "act.close": "Close",
    "act.cancel": "Cancel",
    "act.save": "Save",
    "act.remove": "Remove",
    "act.restore": "Restore",
    "act.items": "{n} items",
    "act.itemsP": "{n} item(s)",

    // rows
    "row.select": "Select",
    "row.actions": "Actions",
    "row.folder": "Folder",
    "row.purgeOn": "Deleted automatically on {date}",
    "row.encTitle":
      "encrypted in the browser - the server only stores ciphertext",

    // empty states
    "empty.hidden1": "Only hidden files are here.",
    "empty.hidden2":
      "Turn on <b>Show hidden</b> in the toolbar to reveal them.",
    "empty.trash": "The trash is empty.",
    "empty.folder1": "This folder is empty.",
    "empty.folder2":
      "Upload a file or create a folder to get started.",

    // share dialog
    "share.title1": "Share \"{name}\"",
    "share.titleN": "Share {n} items",
    "share.userAria": "User to share with",
    "share.perm.read": "Read",
    "share.perm.write": "Write",
    "share.perm.create": "Create",
    "share.perm.delete": "Delete",
    "share.perm.share": "Share",
    "share.add": "Share",
    "share.cannotLoad": "Cannot load users",
    "share.everySelected":
      "Every selected item gets the same share and permissions.",
    "share.none": "Not shared with anyone yet.",
    "share.noUsers": "No other users yet",
    "share.inactive": " \u2014 inactive",
    "share.fp": "{user}'s key fingerprint: ",
    "share.noEnc":
      "{user} has no encryption set up - encrypted items stay unreadable for them.",
    "share.changedShort": "key changed: {new} (was {old})",
    "share.confirmChanged":
      "{user}'s key fingerprint CHANGED.\n\n" +
      "Before: {before}\nNow:    {now}\n\n" +
      "A change is normal after a recovery or a new device - and it is " +
      "also how a server in the middle would hand someone else its own " +
      "key. Compare the new fingerprint with them out of band before " +
      "sharing anything encrypted. Continue?",
    "share.confirmNew":
      "{user}'s key fingerprint:\n\n    {fp}\n\n" +
      "Compare it with what they see in their own fxcloud (badge, then " +
      "\"Show key info\") if you want to be sure nobody sits in the middle. " +
      "It is remembered from now on, so a later change will be flagged. Continue?",
    "share.noKeyConfirm":
      "{user} has no encryption set up, so encrypted items " +
      "cannot be opened from their side.\n\nShare anyway?",
    "share.cancelled":
      "Sharing was cancelled: with locked keys no envelope can be sealed.",
    "share.result": "{n} of {m} item(s) shared with {user}.",
    "share.nothing": "Nothing was shared.",

    // move / copy dialog
    "transfer.moveTitle": "Move {what} to\u2026",
    "transfer.copyTitle": "Copy {what} to\u2026",
    "transfer.moveHere": "Move here",
    "transfer.copyHere": "Copy here",
    "transfer.noSub": "No subfolders here.",
    "transfer.noKeyMove":
      "Cannot move an encrypted item while this tab holds no keys.",
    "transfer.noneMove":
      "None of the selected items may be moved.",
    "transfer.noneCopy":
      "None of the selected items may be copied.",
    "transfer.copyBlocked":
      "Cannot copy {what}.\n\n" +
      "A copy gets a new row id, and re-wrapping a key record for a " +
      "new row is not wired into copy yet. Move it instead, or " +
      "download it and upload it again.",
    "transfer.rollback":
      "\"{name}\" could not be moved ({msg}), and its key " +
      "record could not be put back either.\n\n" +
      "Its record now names the destination folder - move it there " +
      "once the move is allowed, and it opens again.",

    // prompts (client-side, one line each) and inline file creation
    "prompt.newFolder": "New folder name:",
    "prompt.newFile": "New file name:",
    "prompt.rename": "Rename to:",
    "file.textOnly":
      "Only text files can be created here (.txt, .md, .csv, code, ...).\n" +
      "Upload other file types instead.",
    "file.encFail":
      "The new file could not be encrypted, so it was removed: {msg}",

    // confirms and batch reports
    "confirm.purgeOne":
      "Delete this item permanently? This cannot be undone.",
    "confirm.purgeN":
      "Delete {n} item(s) permanently? This cannot be undone.",
    "confirm.emptyTrash":
      "Empty the trash? Every item in it is deleted permanently.",
    "confirm.moveFolder":
      "Move folder \"{name}\" and everything inside it to the trash?",
    "confirm.moveFile": "Move file \"{name}\" to the trash?",
    "confirm.discard": "Discard unsaved changes?",
    "confirm.bulkDelete":
      "Move {n} of {m} selected item(s) to the trash?",
    "batch.files": "{k} file(s) \u00b7 {size}",
    "batch.folders": "{k} folder(s) \u00b7 with everything inside them",
    "batch.skipped":
      "{missing} of {total} selected item(s) skipped \u2014 missing permission.",
    "batch.failed": "{failed} of {n} item(s) failed:",

    // upload, preview, editor
    "upload.at": "Uploading {i}/{n} \u2014 {path}",
    "upload.encrypted": " (encrypted)",
    "upload.failed": "{n} of {m} item(s) could not be uploaded:",
    "upload.itemFail": "{path} \u2014 {msg}",
    "preview.failedWhy":
      "Preview failed: {why} - use Download instead.",
    "preview.failed":
      "Preview failed - the file may be unavailable. Use Download instead.",
    "preview.decrypting": "Decrypting preview...",
    "preview.encHint":
      "this file is encrypted - turn encryption on from the badge to preview it",
    "preview.encEditHint":
      "this file is encrypted - turn encryption on from the badge to edit it",
    "preview.newTab": "Open in new tab",
    "preview.prev": "Previous",
    "preview.next": "Next",
    "editor.loading": "loading...",
    "editor.saving": "saving...",
    "editor.saved": "saved",
    "editor.loadFailed": "load failed: {msg}",
    "editor.saveFailed": "save failed: {msg}",
    "editor.unsaved": "* unsaved",
    "editor.meta": "{lines} lines, {chars} chars",
    "editor.markdown": "Markdown",

    // settings dialog
    "settings.title": "Settings",
    "settings.account": "Account",
    "settings.username": "Username",
    "settings.since": "Member since",
    "settings.storage": "Storage",
    "settings.displayName": "Display name",
    "settings.theme": "Theme",
    "settings.light": "Light",
    "settings.dark": "Dark",
    "settings.password": "Password",
    "settings.passCurrent": "Current password",
    "settings.passNew": "New password (min 8 characters)",
    "settings.passChange": "Change password",
    "settings.passkeys": "Passkeys",
    "settings.passkeysHint":
      "A passkey signs you in with a PIN or biometrics instead of a " +
      "password. The private half stays on your device; the server only " +
      "stores the public key, so a lost device can be removed here.",
    "settings.addPasskey": "Add passkey",
    "settings.lang": "Language",
    "settings.langHint":
      "Applies immediately and is remembered in this browser.",
    "settings.nameEmpty": "Display name cannot be empty.",
    "settings.nameSaved": "Display name saved.",
    "settings.themeSaved": "Theme saved.",
    "settings.passShort":
      "New password must be at least 8 characters.",
    "settings.passChanged": "Password changed.",

    // passkeys
    "passkey.added": "added {date}",
    "passkey.lastUsed": "last used {date}",
    "passkey.empty": "No passkeys registered yet.",
    "passkey.nameEmpty": "Passkey name cannot be empty.",
    "passkey.renamed": "Passkey renamed.",
    "passkey.removed": "Passkey removed.",
    "passkey.cancelled": "Passkey creation was cancelled.",
    "passkey.addedStatus": "Passkey added.",
    "passkey.https":
      "Passkeys need HTTPS (or localhost) - this browser blocks them here.",
    "passkey.namePrompt":
      "Name for the new passkey (for example: \"phone\", \"security key\"):",
    "passkey.renamePrompt": "New name for this passkey:",
    "passkey.deviceRefused":
      "Passkey creation was cancelled or refused by the device.",
    "passkey.removeConfirm":
      "Remove the passkey \"{label}\"? This device can no longer sign in with it.",

    // admin table + reset dialog
    "admin.title": "User administration",
    "admin.user": "User",
    "admin.status": "Status",
    "admin.role": "Role",
    "admin.quota": "Quota",
    "admin.active": "Active",
    "admin.inactive": "Inactive",
    "admin.admin": "Admin",
    "admin.member": "Member",
    "admin.quotaMiB": "Quota in MiB",
    "admin.used": "{size} used",
    "admin.deactivate": "Deactivate",
    "admin.activate": "Activate",
    "admin.revoke": "Revoke admin",
    "admin.make": "Make admin",
    "admin.resetPw": "Reset password",
    "admin.quotaBad":
      "Quota must be a non-negative number of MiB.",
    "reset.title": "Temporary password",
    "reset.user": "For {user}:",
    "reset.hint":
      "Give this password to the user. It works for the next sign-in only -- " +
      "the user should change it in Settings right away.",
    "reset.copy": "Copy",
    "reset.done": "Done",

    // encryption panes (static HTML)
    "enc.setup.title": "Enable file encryption",
    "enc.setup.lead1": "Files you upload are encrypted",
    "enc.setup.lead2": "in this browser",
    "enc.setup.lead3":
      "before they leave your device. The server receives ciphertext, a wrapped key " +
      "and no readable content for them - it can still see file names, " +
      "sizes and sharing, because those are what the storage service needs.",
    "enc.setup.useLogin": "Use my fxcloud login password",
    "enc.setup.usePass": "Choose a separate passphrase",
    "enc.setup.passLabel": "Your fxcloud login password",
    "enc.passphrase": "Storage passphrase",
    "enc.repeatPass": "Repeat passphrase",
    "enc.setup.go": "Continue",
    "enc.setup.hintLogin":
      "Signing in already makes the server spend a 64 MiB Argon2id hash, " +
      "so one strong password can cover both. Your browser can fill this " +
      "from the password you signed in with, and it is checked against " +
      "your account before any key is created.",
    "enc.setup.hintSep":
      "A separate passphrase is never sent anywhere; only the 64 MiB " +
      "Argon2id derivation runs here. It is one more secret to keep: " +
      "without it your files cannot be opened again.",
    "enc.saved.title": "Save your recovery key",
    "enc.saved.lead":
      "This is the only way back into your encrypted files if the " +
      "passphrase is forgotten. It is shown once and never stored anywhere " +
      "you can retrieve it later.",
    "enc.saved.dl": "Download recovery key",
    "enc.saved.ack":
      "I have saved this recovery key somewhere safe and offline.",
    "enc.saved.hint":
      "Anyone holding this file can decrypt your files. Losing both it and " +
      "the passphrase means nobody - including us - can read them again.",
    "enc.saved.go": "Enable encryption",
    "enc.unlock.title": "This tab is unencrypted",
    "enc.unlock.lead":
      "Enter your storage passphrase to turn encryption on here: new files " +
      "and uploads are then encrypted in this browser, and this account's " +
      "encrypted files open. The keys stay in this tab's memory only - a " +
      "reload puts you back to Unencrypted.",
    "enc.unlock.recover": "Use recovery key",
    "enc.unlock.go": "Unlock",
    "enc.recover.title": "Recover with your recovery key",
    "enc.recover.lead":
      "Paste the 64 hex digits, then pick a new storage passphrase. Every " +
      "existing encrypted file keeps working: only the outer wrapper " +
      "changes.",
    "enc.recover.keyLabel": "Recovery key",
    "enc.recover.passLabel": "New storage passphrase",
    "enc.recover.back": "Back",
    "enc.recover.go": "Recover",
    "enc.info.title": "Encryption is on",
    "enc.info.lead":
      "Uploads are encrypted in this browser. Compare the fingerprint below " +
      "with the one shown to the other person before you trust a key " +
      "exchange (DECISION 6).",
    "enc.info.fpLabel": "Key fingerprint",
    "enc.info.lock": "Turn off for this tab",

    // fxenc runtime strings
    "enc.badge.setup": "Encrypt uploads",
    "enc.badge.locked": "\uD83D\uDD13 Unencrypted",
    "enc.badge.unlocked": "\uD83D\uDD12 Encrypted",
    "enc.badge.unlocking": "Unlocking\u2026",
    "enc.title.setup":
      "Client-side encryption is not set up yet. Files you upload are stored " +
      "as-is until you turn it on. Click to set it up.",
    "enc.title.locked":
      "New files and uploads in this tab are stored as-is. Click to turn " +
      "encryption on here - that also opens this account's encrypted files.",
    "enc.title.unlocked":
      "Uploads are encrypted in this browser before they leave the device. " +
      "Click to turn it off for this tab or to see this account's key fingerprint.",
    "enc.unsupported":
      "This browser has no WebCrypto, so encrypted uploads are unavailable. " +
      "HTTPS (or localhost) and a current browser are required.",
    "enc.checkLoginFail":
      "Could not check the login password ({status})",
    "enc.enterLogin": "Enter your fxcloud login password.",
    "enc.choosePass": "Choose a storage passphrase.",
    "enc.mismatch": "The two passphrases do not match.",
    "enc.checking": "Checking your login password\u2026",
    "enc.wrongLogin": "That is not your fxcloud login password.",
    "enc.deriving": "Deriving keys (Argon2id, 64 MiB)\u2026",
    "enc.enterPass": "Enter your storage passphrase.",
    "enc.pasteRcv": "Paste the 64 hex digits from your recovery key.",
    "enc.chooseNew": "Choose a new storage passphrase.",
    "enc.rcvLen": "A recovery key is 32 bytes - 64 hex digits.",
    "enc.openRoot": "Opening the account root key\u2026",
    "enc.rewrapping": "Re-wrapping under the new passphrase\u2026",
    "enc.exists":
      "This account already has a key record; unlock with its passphrase instead.",

    // guards below surface as messages in alerts, previews and the editor
    "enc.err.open": "unlock encryption to open this file",
    "enc.err.download": "unlock encryption to download this file",
    "enc.err.preview": "unlock encryption to preview this file",
    "enc.err.save": "unlock encryption to save this file",
    "enc.err.unkeyed": "this file has no stored key to open it with",
    "enc.err.unwrapped":
      "could not unwrap this key - wrong passphrase, or the data was altered",
    "enc.err.notFolder": "destination is not a folder",
    "enc.err.uploadCancelled": "encrypted upload cancelled",
    "enc.err.worker": "crypto worker error",
    "enc.err.workerStopped": "crypto worker stopped",

    // login / register page
    "login.title": "Sign in \u00b7 fxcloud",
    "login.tagline": "Your files, synced and in one place.",
    "login.tab.signin": "Sign in",
    "login.tab.passkey": "Passkey",
    "login.tab.register": "Create account",
    "login.username": "Username",
    "login.display": "Display name",
    "login.password": "Password",
    "login.wait": "Please wait\u2026",
    "login.waiting": "Waiting for your device...",
    "login.passkeyHint":
      "Sign in with the passkey registered for this account - the device " +
      "asks for a PIN or biometrics instead of a password.",
    "login.passkeyBtn": "Sign in with passkey",
    "login.err.generic": "Something went wrong.",
    "login.err.invalid": "Invalid username or password.",
    "login.err.inactive":
      "Account created. It has to be activated before you can sign in \u2013 " +
      "please contact your administrator.",
    "login.err.network": "Network error. Is the server running?",
    "login.err.https":
      "This browser cannot use passkeys here - open the site over HTTPS (or on localhost).",
    "login.err.needUser": "Enter your username.",
    "login.err.startFail": "Could not start the passkey sign-in.",
    "login.err.noPasskeyUsed":
      "No passkey was used - the prompt was cancelled, timed out, or this account has none on this device.",
    "login.err.passkeyFail": "Passkey sign-in failed: {msg}",
    "login.err.noPasskey": "No passkey was used.",
    "login.err.finishFail": "Passkey sign-in failed.",
    "login.err.unknown": "Unknown user or no matching passkey.",

    // server error codes (the server sends the code, this side translates)
    "err.not_found": "Not found.",
    "err.unauthorized": "Sign in required.",
    "err.forbidden": "Not permitted.",
    "err.inactive_account": "This account is not active yet.",
    "err.quota_exceeded": "Quota exceeded: {used} of {quota} used.",
    "err.bad_request": "Invalid request.",
    "err.conflict": "Already exists or concurrent change.",
    "err.internal": "Internal server error.",
    "err.request_failed": "Request failed ({status})",

    // permission names as the server reports them in share rows
    "perm.read": "read",
    "perm.update": "update",
    "perm.create": "create",
    "perm.delete": "delete",
    "perm.share": "share",
  };

  /*
   * Klingon (tlhIngan Hol) - the third flag, and the proof that the engine
   * carries no hard-coded pair anywhere. Canonical vocabulary where the
   * language has a word (juH home, poS open, qaw forget, yuD download,
   * laD load, quj key, Sa' wait), consistent KLI-style compounds where it
   * does not (bIQroq folder, quj pon fingerprint). No umlauts to escape,
   * so this dictionary is plain ASCII like the rest of the file.
   */
  var TLH = {
    // topbar
    "nav.settings": "choH",
    "nav.admin": "lo'wI' Qap",
    "nav.signout": "nomta'",
    "storage.title": "nI' qan",
    "storage.of": "{used}/{quota} nI'",
    "lang.aria": "Hol",

    // toolbar
    "files.new": "\uff0b che' chu'",
    "files.newFolder": "\uff0b bIQroq chu'",
    "files.upload": "\u2b06 che' laD",
    "files.uploadFolder": "\u2b06 bIQroq laD",
    "files.trash": "bIQtIq",
    "files.emptyTrash": "bIQtIq yIQaw",
    "files.showHidden": "nogh yItu'",
    "files.showHiddenHint":
      "che' bIQroq nogh yItu' - pong -mo'",
    "files.selectAll": "bIQroqvam Hoch yIwIv",
    "files.loading": "laDtaH\u2026",
    "crumb.home": "juH",

    // dropzone (three pieces around the <strong>)
    "drop.a": "yIQong",
    "drop.b": "bIQroq",
    "drop.c": "chen - laDmeH qup yIlo'.",

    // table headers
    "table.name": "pong",
    "table.size": "nI'",
    "table.modified": "choH",

    // bulk action bar
    "bulk.one": "nat wa' wIv",
    "bulk.n": "{n} nat wIv",
    "bulk.download": "yuD",
    "bulk.move": "ghoS\u2026",
    "bulk.copy": "qon\u2026",
    "bulk.share": "boq",
    "bulk.delete": "qaw",
    "bulk.restore": "\u267d qa'",
    "bulk.purge": "qawmo'",
    "bulk.clear": "wIv yIchIm",

    // shared verbs (row menu and dialogs)
    "act.open": "poS",
    "act.edit": "choH",
    "act.preview": "legh",
    "act.rename": "pong chu'",
    "act.close": "rap",
    "act.cancel": "taHbe'",
    "act.save": "qan",
    "act.remove": "yu'",
    "act.restore": "qa'",
    "act.items": "{n} nat",
    "act.itemsP": "{n} nat",

    // rows
    "row.select": "wIv",
    "row.actions": "Qap",
    "row.folder": "bIQroq",
    "row.purgeOn": "{date} chIj yIQaw",
    "row.encTitle":
      "buS yIchuSQang - qanwI' chay' puS",

    // empty states
    "empty.hidden1": "nogh che' tlhIj.",
    "empty.hidden2": "che' <b>nogh yItu'</b> yIlo'.",
    "empty.trash": "bIQtIq chIm.",
    "empty.folder1": "bIQroqvam chIm.",
    "empty.folder2": "che' laD pagh bIQroq chu'.",

    // share dialog
    "share.title1": "boq \"{name}\"",
    "share.titleN": "{n} nat boq",
    "share.userAria": "boq lo'wI'",
    "share.perm.read": "legh",
    "share.perm.write": "choH",
    "share.perm.create": "chu'",
    "share.perm.delete": "qaw",
    "share.perm.share": "boq",
    "share.add": "boq",
    "share.cannotLoad": "lo'wI' laDlaHbe'",
    "share.everySelected":
      "nat wIvpu' Hoch ram boq quv.",
    "share.none": "latlh boqbe'.",
    "share.noUsers": "latlh lo'wI' wa'be'",
    "share.inactive": " \u2014 nombe'",
    "share.fp": "{user} quj pon: ",
    "share.noEnc":
      "{user} chuSQang chIm - chuS chay' yIleghbe'.",
    "share.changedShort": "quj choH: {new} ({old} chu')",
    "share.confirmChanged":
      "{user} quj pon CHOHLU'.\n\n" +
      "chu': {before}\nDaH: {now}\n\n" +
      "choH chu' yIleghbe' - chuSQang yIlo' latlh yIpar bIqab. " +
      "chuSQang boq qel quj chu' latlh qab. chIk?",
    "share.confirmNew":
      "{user} quj pon:\n\n    {fp}\n\n" +
      "latlhvaD fxcloud chIm leghbogh qel - \"quj pon\" yIlegh. " +
      "DaHjaj mon - choH chIj yIpuj. chIk?",
    "share.noKeyConfirm":
      "{user} chuSQang chIm - chuS chay' poSbe'.\n\nchIk boq?",
    "share.cancelled":
      "boq qetlu' - quj chImchugh chuSbe'.",
    "share.result": "{user}vaD {n}/{m} nat boqlu'.",
    "share.nothing": "ram boqbe'.",

    // move / copy dialog
    "transfer.moveTitle": "{what} ghoS\u2026",
    "transfer.copyTitle": "{what} qon\u2026",
    "transfer.moveHere": "ghoS",
    "transfer.copyHere": "qon",
    "transfer.noSub": "bIQroq chIm.",
    "transfer.noKeyMove":
      "quj chImchugh bIQroq vIghoSbe'.",
    "transfer.noneMove": "wIvpu' nat wa' ghoSlaHbe'.",
    "transfer.noneCopy": "wIvpu' nat wa' qonlaHbe'.",
    "transfer.copyBlocked":
      "{what} qonlaHbe'.\n\n" +
      "qon nat chu' chu' - quj yIchu' qon rIntai'be'. " +
      "ghoS pagh yuD qon laD.",
    "transfer.rollback":
      "\"{name}\" ghoSlaHbe' ({msg}), quj yIchu'be'bogh quj chImbe'.\n\n" +
      "quj DaH bIQroqvam pong - ghoS chay' poS chIj.",

    // prompts (client-side, one line each) and inline file creation
    "prompt.newFolder": "bIQroq chu' pong:",
    "prompt.newFile": "che' chu' pong:",
    "prompt.rename": "pong chu':",
    "file.textOnly":
      "che' text qonlaHbe' - vIt.\n" +
      "che' laD.",
    "file.encFail":
      "che' chu' chuSQanglaHbe' - qawlu': {msg}",

    // confirms and batch reports
    "confirm.purgeOne":
      "natvam qawmo'? cha' yIQawbe'.",
    "confirm.purgeN":
      "{n} nat qawmo'? cha' yIQawbe'.",
    "confirm.emptyTrash":
      "bIQtIq yIQaw? Hoch yIQaw.",
    "confirm.moveFolder":
      "bIQroq \"{name}\" Hoch bIQtIq ghoS?",
    "confirm.moveFile": "che' \"{name}\" bIQtIq ghoS?",
    "confirm.discard": "choH chIm?",
    "confirm.bulkDelete":
      "wIvpu' {m} nat chIm {n} bIQtIq ghoS?",
    "batch.files": "{k} che' \u00b7 {size}",
    "batch.folders": "{k} bIQroq \u00b7 chuy Hoch",
    "batch.skipped":
      "wIvpu' {total} nat chIm {missing} - qawlaHbe'.",
    "batch.failed": "{n} nat chIm {failed}:",

    // upload, preview, editor
    "upload.at": "laDtaH {i}/{n} \u2014 {path}",
    "upload.encrypted": " (chuSQang)",
    "upload.failed": "{m} nat chIm {n}:",
    "upload.itemFail": "{path} \u2014 {msg}",
    "preview.failedWhy": "leghlaHbe': {why} - yuD yIlo'.",
    "preview.failed":
      "leghlaHbe' - che' rap. yuD yIlo'.",
    "preview.decrypting": "chuSlegh...",
    "preview.encHint":
      "che'vam chuS - leghmeH chuSQang yIchu'",
    "preview.encEditHint":
      "che'vam chuS - choHmeH chuSQang yIchu'",
    "preview.newTab": "tab chu' poS",
    "preview.prev": "Qav",
    "preview.next": "wav'",
    "editor.loading": "laD...",
    "editor.saving": "qan...",
    "editor.saved": "qanlu'",
    "editor.loadFailed": "laDlaHbe': {msg}",
    "editor.saveFailed": "qanlaHbe': {msg}",
    "editor.unsaved": "* qanbe'",
    "editor.meta": "{lines} gram, {chars} nat",
    "editor.markdown": "Markdown",

    // settings dialog
    "settings.title": "choH",
    "settings.account": "yuQ",
    "settings.username": "lo'wI' pong",
    "settings.since": "nom wa'Hu'",
    "settings.storage": "qan",
    "settings.displayName": "pong",
    "settings.theme": "Dung",
    "settings.light": "wov",
    "settings.dark": "yIv",
    "settings.password": "mu'mu'",
    "settings.passCurrent": "mu'mu' DaHjaj",
    "settings.passNew": "mu'mu' chu' (8 pong puS)",
    "settings.passChange": "mu'mu' yIchoH",
    "settings.passkeys": "quj mu'mu'",
    "settings.passkeysHint":
      "quj mu'mu' PIN biometric yIlo' - mu'mu' yIlo'be'. " +
      "qan nIteb device chIm; qanwI' quj yIqan - device qawchugh yIyu'.",
    "settings.addPasskey": "quj mu'mu' chu'",
    "settings.lang": "Hol",
    "settings.langHint":
      "DaHjaj yIlo' - browser mon.",
    "settings.nameEmpty": "pong chImlaHbe'.",
    "settings.nameSaved": "pong qanlu'.",
    "settings.themeSaved": "Dung qanlu'.",
    "settings.passShort":
      "mu'mu' chu' 8 pong puS.",
    "settings.passChanged": "mu'mu' choHlu'.",

    // passkeys
    "passkey.added": "{date} chu'",
    "passkey.lastUsed": "{date} lo'",
    "passkey.empty": "quj mu'mu' wa'be'.",
    "passkey.nameEmpty": "quj mu'mu' pong chImlaHbe'.",
    "passkey.renamed": "pong choHlu'.",
    "passkey.removed": "yu'lu'.",
    "passkey.cancelled": "quj mu'mu' qetlu'be'.",
    "passkey.addedStatus": "quj mu'mu' chu'lu'.",
    "passkey.https":
      "quj mu'mu' meH HTTPS - browser yIqaw.",
    "passkey.namePrompt":
      "quj mu'mu' chu' pong (juv: \"quj\"):",
    "passkey.renamePrompt": "quj mu'mu'vam pong chu':",
    "passkey.deviceRefused":
      "quj mu'mu' device yIchu'be'.",
    "passkey.removeConfirm":
      "quj mu'mu' \"{label}\" yIyu'? devicevam nomlaHbe'.",

    // admin table + reset dialog
    "admin.title": "lo'wI' Qap",
    "admin.user": "lo'wI'",
    "admin.status": "SaH",
    "admin.role": "Qap",
    "admin.quota": "nI'",
    "admin.active": "SaH",
    "admin.inactive": "SaHbe'",
    "admin.admin": "QapwI'",
    "admin.member": "puq",
    "admin.quotaMiB": "nI' MiB",
    "admin.used": "{size} qan",
    "admin.deactivate": "SaHbe'",
    "admin.activate": "SaH",
    "admin.revoke": "QapwI' yIqaw",
    "admin.make": "QapwI' yIchoH",
    "admin.resetPw": "mu'mu' yIchoH",
    "admin.quotaBad":
      "nI' MiB ram - yIqawbe'.",
    "reset.title": "mu'mu' chu'",
    "reset.user": "{user}:",
    "reset.hint":
      "mu'mu'vam yInob - nom wa' lo'; Settings choH yIqan.",
    "reset.copy": "chel",
    "reset.done": "qawlu'",

    // encryption panes (static HTML)
    "enc.setup.title": "chuSQang yIchu'",
    "enc.setup.lead1": "che' laD chuSQanglu'",
    "enc.setup.lead2": "buS yIchuSQang",
    "enc.setup.lead3":
      "device yIchu'bogh che' chuSQanglu' buS. " +
      "qanwI' yIchu' nung yIchu'; yIchu'be'bogh che' yIlegh. " +
      "pong nI' boq je yIlegh - qanwI' meH raS.",
    "enc.setup.useLogin": "nom mu'mu' yIlo'",
    "enc.setup.usePass": "mu'mu' nIteb chu'",
    "enc.setup.passLabel": "nom mu'mu'",
    "enc.passphrase": "mu'mu' qan",
    "enc.repeatPass": "mu'mu' yIchu'",
    "enc.setup.go": "yIghoS",
    "enc.setup.hintLogin":
      "nomchugh qanwI' Argon2id 64 MiB yIlo' - mu'mu' wa' rap. " +
      "browser mu'mu' qon; nom yIchu'be'bogh yIqaw - yIchu'bogh mu'mu' " +
      "yuQ yIqel quj yIchu'be'bogh.",
    "enc.setup.hintSep":
      "mu'mu' nIteb ram yIchu'be' - buS Argon2id 64 MiB chIm. " +
      "mu'mu' chu' yIqan - qawchugh che' poSbe'.",
    "enc.saved.title": "quj yIqan",
    "enc.saved.lead":
      "mu'mu' qawchugh chuSQang che' poSmeH ram. " +
      "wa' legh yIchu'; yIchu'be'bogh.",
    "enc.saved.dl": "quj yIyuD",
    "enc.saved.ack":
      "qujvam offline qan rIntai'.",
    "enc.saved.hint":
      "qujvam tu'chugh latlh che' yIpoS. mu'mu' quj je qawchugh latlh yIleghbe'.",
    "enc.saved.go": "chuSQang yIchu'",
    "enc.unlock.title": "tabvam chuSQangbe'",
    "enc.unlock.lead":
      "mu'mu' qan yIpar - tabvam chuSQang yIchu'. che' chu' laD chuSQanglu'; " +
      "yuQ chuSQang che' poS. quj tab memo - reload chuSQangbe'.",
    "enc.unlock.recover": "quj yIlo'",
    "enc.unlock.go": "yIpar",
    "enc.recover.title": "quj yIlo'choH",
    "enc.recover.lead":
      "hex pong 64 yIpar, mu'mu' qan chu' yIwIv. chuSQang che' Hoch choHbe' - " +
      "qon ram.",
    "enc.recover.keyLabel": "quj",
    "enc.recover.passLabel": "mu'mu' qan chu'",
    "enc.recover.back": "qab",
    "enc.recover.go": "qa'",
    "enc.info.title": "chuSQang DaHjaj",
    "enc.info.lead":
      "buS chuSQang. quj ponvam latlh qab qel - boq quj chu' yIqelchugh.",
    "enc.info.fpLabel": "quj pon",
    "enc.info.lock": "tab yIrap",

    // fxenc runtime strings
    "enc.badge.setup": "chuSQang laD",
    "enc.badge.locked": "\uD83D\uDD13 chuSQangbe'",
    "enc.badge.unlocked": "\uD83D\uDD12 chuSQang",
    "enc.badge.unlocking": "par\u2026",
    "enc.title.setup":
      "buS chuSQang chIm. che' laD qanlu' - chuSQang yIchu'meH yIchu'.",
    "enc.title.locked":
      "che' chu' laD tabvam qanlu'. chuSQang yIchu' yIpoS - yuQ chuSQang che' je poS.",
    "enc.title.unlocked":
      "buS chuSQang device yIchu'bogh. tab yIrap pagh yuQ quj pon yIlegh.",
    "enc.unsupported":
      "browservam WebCrypto chIm - chuSQang laDlaHbe'. HTTPS pagh localhost 'ej browser chu'.",
    "enc.checkLoginFail":
      "nom mu'mu' qellaHbe' ({status})",
    "enc.enterLogin": "nom mu'mu' yIpar.",
    "enc.choosePass": "mu'mu' qan yIwIv.",
    "enc.mismatch": "mu'mu' ram.",
    "enc.checking": "nom mu'mu' yIqel\u2026",
    "enc.wrongLogin": "mu'mu'vam nombe'.",
    "enc.deriving": "quj Derive (Argon2id, 64 MiB)\u2026",
    "enc.enterPass": "mu'mu' qan yIpar.",
    "enc.pasteRcv": "quj hex pong 64 yIpar.",
    "enc.chooseNew": "mu'mu' qan chu' yIwIv.",
    "enc.rcvLen": "quj 32 byte - hex pong 64.",
    "enc.openRoot": "yuQ quj poS\u2026",
    "enc.rewrapping": "mu'mu' chu' yIchuSQang\u2026",
    "enc.exists":
      "yuQvam quj qan - mu'mu' yIpar.",

    // guards below surface as messages in alerts, previews and the editor
    "enc.err.open": "che'vam poSmeH chuSQang yIpar",
    "enc.err.download": "che'vam yuDmeH chuSQang yIpar",
    "enc.err.preview": "che'vam leghmeH chuSQang yIpar",
    "enc.err.save": "che'vam qanmeH chuSQang yIpar",
    "enc.err.unkeyed": "che'vam quj qanbe'",
    "enc.err.unwrapped":
      "quj chuSQanglaHbe' - mu'mu' ram pagh yIchu'",
    "enc.err.notFolder": "bIQroq ram",
    "enc.err.uploadCancelled": "chuSQang laD qetlu'be'",
    "enc.err.worker": "quj Qap ram",
    "enc.err.workerStopped": "quj Qap ta'",

    // login / register page
    "login.title": "nom \u00b7 fxcloud",
    "login.tagline": "che'pu' - wa' chIm.",
    "login.tab.signin": "nom",
    "login.tab.passkey": "quj mu'mu'",
    "login.tab.register": "yuQ chu'",
    "login.username": "lo'wI' pong",
    "login.display": "pong",
    "login.password": "mu'mu'",
    "login.wait": "Sa'\u2026",
    "login.waiting": "device yIpar...",
    "login.passkeyHint":
      "yuQvam quj mu'mu' yIlo' - device PIN biometric yIpar mu'mu' yIlo'be'.",
    "login.passkeyBtn": "quj mu'mu' yIlo'",
    "login.err.generic": "ram.",
    "login.err.invalid": "lo'wI' pong mu'mu' ram.",
    "login.err.inactive":
      "yuQ chu'lu'. nommeH SaHbe' - QapwI' yIchu'legh.",
    "login.err.network": "net ram. qanwI' SaHbe'?",
    "login.err.https":
      "browser quj mu'mu' laDlaHbe' - HTTPS localhost je yIpoS.",
    "login.err.needUser": "lo'wI' pong yIpar.",
    "login.err.startFail": "quj nom qetlaHbe'.",
    "login.err.noPasskeyUsed":
      "quj wa'be' - yIqet, pagh DIS, pagh yuQvam device quj chIm.",
    "login.err.passkeyFail": "quj nom ram: {msg}",
    "login.err.noPasskey": "quj wa'be'.",
    "login.err.finishFail": "quj nom ram.",
    "login.err.unknown": "lo'wI' DatlhIjbe' pagh quj ram.",

    // server error codes (the server sends the code, this side translates)
    "err.not_found": "Tu'lu'be'.",
    "err.unauthorized": "nom.",
    "err.forbidden": "qawlu'be'.",
    "err.inactive_account": "yuQvam SaHbe' DaHjaj.",
    "err.quota_exceeded": "nI' puS: {used}/{quota} qan.",
    "err.bad_request": "raS ram.",
    "err.conflict": "DaHjaj tu'lu' pagh choH ram.",
    "err.internal": "qanwI' ram.",
    "err.request_failed": "raS ram ({status})",

    // permission names as the server reports them in share rows
    "perm.read": "legh",
    "perm.update": "choH",
    "perm.create": "chu'",
    "perm.delete": "qaw",
    "perm.share": "boq",
  };

  // The catalogue both the UI and tests/check-i18n.js read. German is
  // first wherever the languages are ordered (switcher, this map); English
  // is the default language and the fallback dictionary in t().
  var LANGS = { de: DE, en: EN, tlh: TLH };
  var CODES = ["de", "en", "tlh"];
  var STORAGE_KEY = "fxcloud.lang";
  var currentCode = "en";

  function dict(code) {
    return LANGS[code] || EN;
  }

  function lang() {
    return currentCode;
  }

  /** Locale tag for date/number formatting, or undefined for the browser's. */
  var LOCALES = { de: "de-DE" }; // tlh has no Intl locale: browser default
  function dateLocale() {
    return LOCALES[currentCode];
  }

  function t(key, params) {
    var s = dict(currentCode)[key];
    if (s === undefined) s = EN[key];
    if (s === undefined) s = key;
    if (params) {
      for (var k in params) {
        s = s.split("{" + k + "}").join(params[k]);
      }
    }
    return s;
  }

  function apply(root) {
    if (!root || typeof root.querySelectorAll !== "function") return;
    var pairs = [
      ["[data-i18n]", "textContent", "data-i18n"],
      ["[data-i18n-ph]", "placeholder", "data-i18n-ph"],
      ["[data-i18n-title]", "title", "data-i18n-title"],
      ["[data-i18n-aria]", "aria-label", "data-i18n-aria"],
    ];
    for (var i = 0; i < pairs.length; i++) {
      var els = root.querySelectorAll(pairs[i][0]);
      for (var j = 0; j < els.length; j++) {
        els[j][pairs[i][1]] = t(els[j].getAttribute(pairs[i][2]));
      }
    }
  }

  function detect() {
    var stored = null;
    try {
      stored = window.localStorage && window.localStorage.getItem(STORAGE_KEY);
    } catch (e) {
      /* private mode, Node harness: fall through to the default */
    }
    // A stored choice wins. Without one the UI starts on English, the
    // default: no browser-language guessing, whoever wants German (or any
    // later language) sets it once and it sticks.
    if (stored && LANGS[stored]) return stored;
    return "en";
  }

  /*
   * The two flags, drawn as inline SVG: three stripes for Germany, a
   * simplified Union Jack for English. Deliberately not emoji - Windows
   * renders regional-indicator pairs as the letters "DE"/"GB" instead of a
   * flag, and the point of a flag is that it reads at a glance everywhere.
   */
  function flag(code) {
    if (code === "de") {
      return '<svg viewBox="0 0 5 3" width="18" height="11" aria-hidden="true">' +
        '<rect width="5" height="1" y="0" fill="#000000"/>' +
        '<rect width="5" height="1" y="1" fill="#DD0000"/>' +
        '<rect width="5" height="1" y="2" fill="#FFCE00"/></svg>';
    }
    if (code === "tlh") {
      // The Empire's flag: red field, the black trefoil - three notched
      // blades 120 degrees apart, one path drawn three times.
      var blade =
        'M15 2.5c2.4 3.2 3 5.4 2.5 7.2L15 8.8 12.5 9.7C12 7.9 12.6 5.7 15 2.5z';
      return '<svg viewBox="0 0 30 18" width="18" height="11" aria-hidden="true">' +
        '<rect width="30" height="18" fill="#B22222"/>' +
        '<path fill="#111111" d="' + blade + '"/>' +
        '<path fill="#111111" d="' + blade + '" transform="rotate(120 15 9)"/>' +
        '<path fill="#111111" d="' + blade + '" transform="rotate(240 15 9)"/></svg>';
    }
    return '<svg viewBox="0 0 60 30" width="18" height="11" aria-hidden="true">' +
      '<clipPath id="i18n-union"><path d="M0,0 v30 h60 v-30 z"/></clipPath>' +
      '<path d="M0,0 v30 h60 v-30 z" fill="#012169"/>' +
      '<path d="M0,0 L60,30 M60,0 L0,30" stroke="#ffffff" stroke-width="6"/>' +
      '<path d="M0,0 L60,30 M60,0 L0,30" clip-path="url(#i18n-union)" stroke="#C8102E" stroke-width="4"/>' +
      '<path d="M30,0 v30 M0,15 h60" stroke="#ffffff" stroke-width="10"/>' +
      '<path d="M30,0 v30 M0,15 h60" stroke="#C8102E" stroke-width="6"/></svg>';
  }

  // The language's own name for itself, one per flag button.
  var ENDONYMS = { de: "Deutsch", en: "English", tlh: "tlhIngan Hol" };

  function endonym(code) {
    return ENDONYMS[code] || ENDONYMS.en;
  }

  // The one open dropdown (or null): opening one closes the rest, and a
  // language switch redraws every copy closed.
  var openSwitch = null;

  function closeSwitch() {
    if (!openSwitch) return;
    var menu = openSwitch.querySelector(".lang-menu");
    var trigger = openSwitch.querySelector(".lang-current");
    if (menu) menu.hidden = true;
    if (trigger) trigger.setAttribute("aria-expanded", "false");
    openSwitch = null;
  }

  // Outside click and Escape act on whichever dropdown is open, so they
  // are wired once against the document, not per redraw.
  var switchWired = false;
  function wireSwitch() {
    if (switchWired || typeof document === "undefined") return;
    switchWired = true;
    document.addEventListener("click", function (ev) {
      if (openSwitch && !openSwitch.contains(ev.target)) closeSwitch();
    });
    document.addEventListener("keydown", function (ev) {
      if (!openSwitch) return;
      if (ev.key !== "Escape" && ev.key !== "Esc") return;
      var trigger = openSwitch.querySelector(".lang-current");
      closeSwitch();
      if (trigger && typeof trigger.focus === "function") trigger.focus();
    });
  }

  /**
   * Draw the language dropdown into every .lang-switch container (topbar,
   * settings dialog, login/register card): a button with the current flag
   * opens a menu with one row per language - its flag plus the endonym, so
   * an unfamiliar flag still says what it is. The row stays one button
   * wide however many languages exist. One class, one code path; every
   * copy repaints together on setLang().
   */
  function renderSwitch() {
    if (typeof document === "undefined" || typeof document.querySelectorAll !== "function") return;
    openSwitch = null;
    wireSwitch();
    var boxes = document.querySelectorAll(".lang-switch");
    for (var b = 0; b < boxes.length; b++) {
      var box = boxes[b];
      if (!box || typeof box.appendChild !== "function") continue;
      while (box.firstChild) box.removeChild(box.firstChild);

      var trigger = document.createElement("button");
      trigger.type = "button";
      trigger.className = "lang-current";
      trigger.setAttribute("aria-haspopup", "true");
      trigger.setAttribute("aria-expanded", "false");
      trigger.setAttribute("aria-label", t("lang.aria"));
      trigger.title = t("lang.aria");
      trigger.innerHTML = flag(currentCode);

      var menu = document.createElement("div");
      menu.className = "lang-menu";
      menu.hidden = true;
      for (var i = 0; i < CODES.length; i++) {
        var code = CODES[i];
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "lang-btn" + (code === currentCode ? " active" : "");
        btn.setAttribute("data-lang", code);
        btn.setAttribute("aria-label", endonym(code));
        btn.title = endonym(code);
        btn.innerHTML = flag(code) + "<span>" + endonym(code) + "</span>";
        menu.appendChild(btn);
      }

      /* istanbul ignore next - the handlers are what the click test drives */
      (function (box, menu, trigger) {
        trigger.addEventListener("click", function (ev) {
          ev.stopPropagation();
          var wasOpen = !menu.hidden;
          closeSwitch();
          if (!wasOpen) {
            menu.hidden = false;
            trigger.setAttribute("aria-expanded", "true");
            openSwitch = box;
          }
        });
        // A click may land on the flag or the endonym <span> inside a row.
        menu.addEventListener("click", function (ev) {
          var el = ev.target;
          while (el && el !== menu && !el.getAttribute("data-lang")) {
            el = el.parentNode;
          }
          if (!el || el === menu) return;
          setLang(el.getAttribute("data-lang"));
        });
      })(box, menu, trigger);

      box.appendChild(trigger);
      box.appendChild(menu);
    }
  }

  function setLang(code) {
    if (!LANGS[code]) code = "en";
    currentCode = code;
    try {
      window.localStorage && window.localStorage.setItem(STORAGE_KEY, code);
    } catch (e) {
      /* private mode: the choice simply does not survive the session */
    }
    if (typeof document === "undefined") return;
    if (document.documentElement) document.documentElement.lang = code;
    apply(document);
    renderSwitch();
    if (typeof document.dispatchEvent === "function" &&
        typeof CustomEvent === "function") {
      document.dispatchEvent(new CustomEvent("fxcloud:langchange", {
        detail: code,
      }));
    }
  }

  function init() {
    currentCode = detect();
    if (typeof document === "undefined") return;
    if (document.documentElement) document.documentElement.lang = currentCode;
    apply(document);
    renderSwitch();
  }

  // Only self-start in a real document: the Node crypto harness requires
  // this file for t() alone and its fake document has no readyState.
  if (typeof document !== "undefined" && document.readyState) init();

  globalThis.I18N = {
    t: t,
    lang: lang,
    setLang: setLang,
    apply: apply,
    init: init,
    dict: dict,
    flag: flag,
    dateLocale: dateLocale,
    STORAGE_KEY: STORAGE_KEY,
  };
})();
