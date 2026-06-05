# WissensDB

WissensDB ist eine lokale Desktop-Wissensdatenbank auf Basis von Python, Tkinter und SQLite.
Du organisierst Inhalte in Themen und Unterthemen, kannst Notizen schnell durchsuchen und Texte inklusive einfacher Markdown-Elemente pflegen.

## Hinweis zum Dateinamen

Das Projekt startet jetzt ueber `wissensdb.py`.

## Hauptfunktionen

- Themenverwaltung
  - Neue Themen anlegen
  - Sortierung: A-Z, Z-A, neueste zuerst, aelteste zuerst
- Unterthemenverwaltung
  - Unterthemen anlegen, umbenennen, loeschen
  - Archivieren und wiederherstellen
  - Eigene Gruppen pro Unterthema setzen
  - Sortierung: neueste, aelteste, zuletzt bearbeitet, laengst nicht bearbeitet
- Editor
  - Bearbeiten mit Autosave
  - Zeilennummern ein-/ausschaltbar
  - Kontextmenue fuer schnelles Formatieren
  - Interne und externe Links
  - Checkboxen/Checklisten, Codeblock- und Hervorhebungsfunktionen
- Markdown-Unterstuetzung
  - Ueberschriften, Fett/Kursiv, Code, Codebloecke, Listen, Zitate, Links
  - Markdown-Darstellung kann umgeschaltet werden
- Suche
  - Stichwortsuche ueber Titel, Inhalt und Felder
  - ToDo-Dialog mit Erkennung von ToDo-Texten und Checklisten-Eintraegen
  - Treffer koennen direkt geoeffnet und im Inhalt hervorgehoben werden
- Metadaten/Felder
  - Frei definierbare Key-Value-Felder pro Unterthema
- Import/Export
  - Textdateien importieren
  - Export als TXT, PDF oder frei waehlbare Datei
  - Unverschluesseltes DB-Backup exportieren
- Backup
  - Automatisches Backup in konfigurierbaren Intervallen
  - Backups landen standardmaessig im Ordner `backups/`
- Navigation
  - Verlauf (zurueck/vorwaerts) zwischen zuletzt geoeffneten Unterthemen
- Debug
  - Interner Debug-Dialog mit SQL-/Fehler-Log

## Datenbank und Verschluesselung

Beim Start kannst du:

- eine vorhandene SQLite-DB oeffnen,
- eine neue Standard-DB erstellen,
- oder eine neue verschluesselte DB anlegen.

Unterstuetzt werden:

- normale SQLite-Dateien (`.db`, `.sqlite`, `.sqlite3`)
- verschluesselte WissensDB-Dateien (aktuelles Format)

Hinweis: Das alte `WISSENSDBENC1`-Format wird nicht mehr unterstuetzt.

## Voraussetzungen

- Python 3.10+ (empfohlen)
- Standardbibliothek reicht aus (keine externen Python-Pakete notwendig)

## Start

Im Projektordner:

```powershell
python wissensdb.py
```

Optional mit expliziter Datenbank:

```powershell
python wissensdb.py --db "Pfad\\zu\\deiner.db"
```

Du kannst auch einfach den DB-Pfad als Argument uebergeben:

```powershell
python wissensdb.py "Pfad\\zu\\deiner.db"
```

## Wichtige Tastenkuerzel

- `Strg+F`: Stichwortsuche
- `Strg+N`: Schnellnotiz im Thema NOTIZEN anlegen
- `Strg+B`: Auswahl hervorheben
- `Strg+Shift+C`: Auswahl als Codeblock
- `Strg+Shift+X`: Checkbox in aktueller Zeile umschalten
- `Strg+Z` / `Strg+Y`: Undo / Redo (im Bearbeitungsmodus)
- `Esc`: Speichern und Bearbeitungsmodus verlassen
- `Alt+Links` / `Alt+Rechts`: Navigation zurueck / vor

## Projektstruktur (aktuell)

- `wissensdb.py`: Hauptanwendung (GUI, Datenzugriff, Suche, Import/Export)
- `backups/`: Zielordner fuer automatische Backups
- `*.spec`: Build-Dateien fuer PyInstaller

## Build-Hinweis (optional)

Die vorhandenen `.spec`-Dateien deuten auf einen PyInstaller-Build hin.
Falls du eine EXE bauen willst, kannst du z. B. so arbeiten:

```powershell
pyinstaller wissensdb.spec
```

oder

```powershell
pyinstaller wissensdb_v2.spec
```

(Je nachdem, welche Spec-Datei du aktiv nutzen willst.)
