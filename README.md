# ⚙️ SysMate – Dein smarter PowerShell-Begleiter für Systemverwaltung und Wartung 🧩

**SysMate** ist ein modernes PowerShell-Toolkit für Windows, das die tägliche Systemadministration automatisiert, vereinfacht und verschönert.  
Von **System- und Netzwerkchecks**, über **Druckerinstallation**, **Systembereinigung** bis hin zu **Windows- und App-Updates** –  
SysMate bündelt alles in einem interaktiven, farbigen und verständlichen Interface.

## 🚀 Hauptfunktionen

### 🧍‍♂️ Admin-Auto-Elevation
- 🔒 Erkennt automatisch, ob Administratorrechte vorhanden sind.  
- 🚀 Startet sich bei Bedarf selbst neu mit erhöhten Rechten (`RunAs`).  
- ✅ Kein manuelles "Als Administrator ausführen" nötig.

---

### 🧠 UTF-8 & Konsolenoptimierung
- 🧩 Erzwingt UTF-8 für Eingabe & Ausgabe → keine Zeichenfehler (`Ã¼`, `â–ˆ`, etc.).  
- 🎨 Nutzt konsistente Farben (Cyan, Gelb, Grün) für Status- und Erfolgsmeldungen.  
- 🧘‍♂️ Unterdrückt PowerShells Standard-Fortschrittsanzeige für klare Ausgabe.

---

### 💻 Systemcheck
- 🧾 Liest grundlegende Systeminformationen:  
  - Windows-Version, Build, Architektur  
  - Systemlaufzeit, installierter RAM, CPU-Infos  
  - Benutzername, Domänenstatus, aktive Sessions  
- ⚙️ Erkennt häufige Systemprobleme (z. B. veraltete Treiber oder niedrigen Speicherplatz).  
- 💡 Gibt übersichtliche Systemstatistiken direkt in der Konsole aus.

---

### 🌐 Netzwerkcheck
- 🔎 Testet Internetverbindung (Ping, DNS-Auflösung, Gateway-Erreichbarkeit).  
- 🌍 Prüft aktive Netzwerkschnittstellen, IP-Adressen, DNS-Server.  
- 🧠 Ermittelt Verbindungsgeschwindigkeit und Paketverlust.  
- 🧩 Erkennt häufige Netzwerkfehler wie falsche DNS-Konfigurationen oder Gateway-Ausfälle.  
- 🧰 Optional: öffnet Netzwerkdiagnose-Tools (ipconfig, netsh, nslookup, tracert) direkt aus der Konsole.

---

### 🖨️ Druckerinstallation & Verwaltung
- 🖨️ Erkennt vorhandene Drucker automatisch.  
- 🧾 Installiert Netzwerk- oder lokale Drucker anhand vordefinierter Pfade (`\\Server\Drucker`).  
- ⚙️ Prüft, ob Drucker verfügbar und korrekt installiert sind.  
- 🔄 Optional: Neustart des Spooler-Dienstes bei Fehlern.  
- 💡 Ideal für IT-Support oder Rollout-Skripte in größeren Umgebungen.

---

### 🧹 Systembereinigung
- 🧽 Leert temporäre Verzeichnisse (%TEMP%, Windows\Temp, Edge/Chrome Cache).  
- 🧾 Löscht alte Windows-Logs, Update-Caches und Fehlerberichte.  
- 🧠 Prüft freien Speicherplatz und gibt Ergebnis in MB/GB aus.  
- 🚀 Verbessert Performance und Stabilität mit einem einzigen Befehl.  

---

### 🪟 Windows-Updates (via PSWindowsUpdate)
- 📦 Prüft automatisch, ob das Modul **PSWindowsUpdate** vorhanden ist – installiert es bei Bedarf.  
- 🔍 Listet verfügbare Updates (Titel, KB, Größe, Kategorie).  
- 🙋‍♂️ Fragt interaktiv, welche installiert werden sollen.  
- ⚙️ Führt Installation ohne automatischen Neustart durch.  
- 🧠 Behandelt Fehler sauber und zeigt verständliche Warnungen.

---

### 💾 App-Updates (via Winget)
- 🔎 Nutzt den **Windows Package Manager (`winget`)**, um installierte Apps zu prüfen.  
- 📋 Listet verfügbare App-Updates übersichtlich (Name, ID, Version alt → neu).  
- 🙋‍♂️ Fragt, ob jede App aktualisiert werden soll.  
- 🧵 Führt `winget upgrade` im Hintergrundjob aus, mit:
  - 🌀 **einzeiliger Spinner-Animation**  
  - 💬 Live-Fortschritt ohne Zeilenchaos  
- ✅ Gibt Ergebnis sauber zurück („Fertig installiert!“ / „Übersprungen“).

---

### 🧰 Systemtools & Schnellzugriffe
- ⚙️ Öffnet gängige Verwaltungs-Tools direkt:
  - Task-Manager  
  - Diensteverwaltung (`services.msc`)  
  - Gerätemanager (`devmgmt.msc`)  
  - MSConfig, Ereignisanzeige, PowerShell-Terminal  
- 🧩 Ideal als zentraler Startpunkt für Admin-Wartung.

---

### 🧾 Logging & Fehlermanagement
- 📡 Jeder Block in `try/catch` abgesichert.  
- 💬 Klare Warnungen und Statusanzeigen (`Write-Warning`, `Write-Host`).  
- 🗂️ Keine kryptischen Fehlermeldungen – nur lesbare Rückgaben.  
- 🛡️ Läuft stabil, auch wenn einzelne Module nicht verfügbar sind.

---
##    ❤️ Projektidee

Dieses Toolkit entstand in der FISI Ausbildung als Idee, häufige Admin-Aufgaben einfach, übersichtlich und interaktiv zu gestalten. Für weitere Ideen was die Funktionalität betrifft, schreibt mir.

## 🧩 Nutzung

```powershell
# PowerShell als Administrator öffnen
. .\SysMate.ps1
Invoke-Updates

