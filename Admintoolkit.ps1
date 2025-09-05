# ==========================================
# Admin-Toolkit für Windows
# ==========================================

# Prüfung auf Administratorrechte
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Dieses Skript erfordert Administratorrechte. Bitte als Administrator ausfuehren."
    exit
}

# Konsolen-Encoding auf UTF-8
try { 
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 
} catch { 
    Write-Warning "Fehler beim Setzen des Encodings: $($_.Exception.Message)" 
}

# Desktop/Log-Verzeichnis
$DesktopPath = [Environment]::GetFolderPath("Desktop")
$LogRoot = Join-Path $DesktopPath "AdminLogs"
if (!(Test-Path $LogRoot)) { New-Item -ItemType Directory -Path $LogRoot | Out-Null }

# --------------------------
# Sysinternals Suite (Auto-Download & Start)
# --------------------------
$SysinternalsPath = "C:\Tools\Sysinternals"
$SysinternalsZip  = Join-Path $env:TEMP "SysinternalsSuite.zip"
$SysinternalsUrl  = "https://download.sysinternals.com/files/SysinternalsSuite.zip"

function Ensure-Sysinternals {
    if (-not (Test-Path $SysinternalsPath)) {
        Write-Host "Sysinternals Suite wird heruntergeladen..." -ForegroundColor Yellow
        try {
            Invoke-WebRequest -Uri $SysinternalsUrl -OutFile $SysinternalsZip -UseBasicParsing
            Expand-Archive -Path $SysinternalsZip -DestinationPath $SysinternalsPath -Force
            Remove-Item $SysinternalsZip -Force
            Write-Host "Sysinternals Suite installiert nach: $SysinternalsPath" -ForegroundColor Green
        } catch {
            Write-Warning "Download/Installation der Sysinternals Suite fehlgeschlagen: $($_.Exception.Message)"
        }
    }
}

function Start-SysinternalTool {
    param([Parameter(Mandatory=$true)][string]$ExeName)
    Ensure-Sysinternals
    $exe = Join-Path $SysinternalsPath $ExeName
    if (Test-Path $exe) {
        Start-Process $exe
    } else {
        Write-Warning "Tool nicht gefunden: $exe"
    }
}

# --------------------------
# Wetter (Originalfunktion)
# --------------------------
function Get-Weather {
    try {
        Write-Host "`n=== Standort und Wetter ===" -ForegroundColor Cyan
        $ipInfo = Invoke-RestMethod -Uri "https://ipinfo.io/json" -ErrorAction Stop
        if (-not $ipInfo.loc) { throw "Keine Koordinaten vorhanden." }
        $lat, $lon = $ipInfo.loc.Split(',')

        $uri = "https://api.open-meteo.com/v1/forecast?latitude=$lat&longitude=$lon&current_weather=true&hourly=precipitation_probability"
        $w = Invoke-RestMethod -Uri $uri -ErrorAction Stop

        $temp = $w.current_weather.temperature
        $wind = $w.current_weather.windspeed

        # Regenwahrscheinlichkeit zur aktuellen Stunde
        $nowIso = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:00")
        $idx = ($w.hourly.time).IndexOf($nowIso)
        if ($idx -lt 0) { $idx = 0 }
        $rain = $w.hourly.precipitation_probability[$idx]

        Write-Host ("Standort: {0}, {1}" -f $ipInfo.city, $ipInfo.country)
        Write-Host ("Temperatur: {0} °C" -f $temp)
        Write-Host ("Windgeschwindigkeit: {0} km/h" -f $wind)
        Write-Host ("Regenwahrscheinlichkeit: {0} %" -f $rain)
    }
    catch {
        Write-Warning "Wetterabfrage uebersprungen: $($_.Exception.Message)"
        Write-Host "Hinweis: Wetterinformationen sind nur bei Internetverbindung verfuegbar" -ForegroundColor Yellow
    }
}

# --------------------------
# Systeminformationen
# --------------------------
function Show-SystemInfo {
    Write-Host "`n=== Systeminformation ===" -ForegroundColor Cyan
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $cpu = (Get-CimInstance Win32_Processor | Select-Object -ExpandProperty Name) -join ", "
        $ramGB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)

        $disks = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
            Select-Object DeviceID,
                          @{n="Kapazitaet(GB)";e={[math]::Round($_.Size/1GB,2)}},
                          @{n="Frei(GB)";e={[math]::Round($_.FreeSpace/1GB,2)}}

        Write-Host ("Hostname: {0}" -f $cs.Name)
        Write-Host ("OS: {0} {1}" -f $os.Caption, $os.Version)
        Write-Host ("CPU: {0}" -f $cpu)
        Write-Host ("Arbeitsspeicher: {0} GB" -f $ramGB)
        Write-Host "Festplatten:"
        $disks | Format-Table -AutoSize
    }
    catch {
        Write-Warning "Fehler beim Auslesen der Systeminformationen: $($_.Exception.Message)"
    }
}

# --------------------------
# Netzwerk & Dienste pruefen (Originalfunktion)
# --------------------------
function Test-NetworkAndServices {
    Write-Host "`n=== Netzwerk und Dienste pruefen ===" -ForegroundColor Cyan
    try {
        Write-Host "`nFirewall-Status:"
        Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize

        Write-Host "`nAktive Netzwerkadapter:"
        Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object Name, Status, LinkSpeed | Format-Table -AutoSize

        Write-Host "`nIP-Konfiguration (IPv4):"
        Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object InterfaceAlias, IPAddress, PrefixLength | Format-Table -AutoSize

        $gw = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Sort-Object RouteMetric | Select-Object -First 1).NextHop
        if ($gw) {
            Write-Host ("`nPing Gateway {0} ..." -f $gw)
            $pingResult = Test-Connection -ComputerName $gw -Count 2 -ErrorAction SilentlyContinue
            if ($pingResult) {
                Write-Host "Gateway erreichbar" -ForegroundColor Green
            } else {
                Write-Warning "Gateway nicht erreichbar"
            }
        } else {
            Write-Warning "Kein Gateway gefunden"
        }
        
        Write-Host "`nPing Internet (8.8.8.8) ..."
        try { 
            $internetResult = Test-Connection -ComputerName 8.8.8.8 -Count 2 -ErrorAction Stop
            if ($internetResult) {
                Write-Host "Internet: OK" -ForegroundColor Green 
            }
        } catch { 
            Write-Warning "Internet: nicht erreichbar" 
        }
    }
    catch {
        Write-Warning "Fehler beim Netzwerk-Check: $($_.Exception.Message)"
    }
}

# --------------------------
# Updates (Windows + Apps) (Originalfunktion)
# --------------------------
function Run-Updates {
    Write-Host "`n=== Windows Updates ===" -ForegroundColor Cyan
    try {
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Write-Host "PSWindowsUpdate Modul wird installiert..."
            Install-Module PSWindowsUpdate -Scope CurrentUser -Force -Confirm:$false -ErrorAction Stop
        }
        Import-Module PSWindowsUpdate -Force -ErrorAction Stop
        
        Write-Host "Suche nach Windows Updates..."
        $updates = Get-WUList -ErrorAction Stop
        if ($updates) {
            Write-Host "$($updates.Count) Updates verfuegbar. Installation wird gestartet..."
            Install-WindowsUpdate -AcceptAll -AutoReboot:$false -ErrorAction Stop
            Write-Host "Updates installiert. Neustart moeglicherweise erforderlich." -ForegroundColor Green
        } else {
            Write-Host "Keine Windows Updates verfuegbar." -ForegroundColor Green
        }
    } catch {
        Write-Warning "Windows Update via Modul nicht moeglich: $($_.Exception.Message)"
    }

    Write-Host "`n=== Anwendungsupdates (winget) ===" -ForegroundColor Cyan
    try { 
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            winget upgrade --all --accept-package-agreements --accept-source-agreements
        } else {
            Write-Warning "winget nicht gefunden. Installieren Sie winget von https://github.com/microsoft/winget-cli"
        }
    }
    catch { Write-Warning "winget-Update fehlgeschlagen: $($_.Exception.Message)" }
}

# --------------------------
# Fehleranalyse (Originalfunktion)
# --------------------------
function Show-SystemErrors {
    Write-Host "`n=== Letzte Systemfehler ===" -ForegroundColor Cyan
    try {
        $errorEvents = Get-EventLog -LogName System -EntryType Error -Newest 10 -ErrorAction SilentlyContinue
        if ($errorEvents) {
            $errorEvents | Select-Object TimeGenerated, Source, EventID, Message | Format-Table -AutoSize -Wrap
        } else {
            Write-Host "Keine Fehlerereignisse in den letzten Eintraegen gefunden." -ForegroundColor Green
        }
        
        Write-Host "`n=== Letzte Warnungen ==="
        $warningEvents = Get-EventLog -LogName System -EntryType Warning -Newest 10 -ErrorAction SilentlyContinue
        if ($warningEvents) {
            $warningEvents | Select-Object TimeGenerated, Source, EventID, Message | Format-Table -AutoSize -Wrap
        } else {
            Write-Host "Keine Warnereignisse in den letzten Eintraegen gefunden." -ForegroundColor Green
        }
    }
    catch {
        Write-Warning "Eventlogs konnten nicht gelesen werden: $($_.Exception.Message)"
        Write-Host "Hinweis: Fuehren Sie das Skript als Administrator aus, um Eventlogs zu lesen." -ForegroundColor Yellow
    }
}

# --------------------------
# IP-Konfiguration setzen (Originalfunktion)
# --------------------------
function Set-NetworkConfig {
    Write-Host "`n=== IP-Konfiguration setzen ===" -ForegroundColor Cyan

    # Aktive Netzwerkadapter ermitteln
    $adapters = Get-NetAdapter | Where-Object Status -eq "Up"
    if (-not $adapters) { Write-Warning "Keine aktiven Netzwerkadapter gefunden."; return }

    # Adapter auflisten mit Name, Status, Geschwindigkeit, aktueller IPv4-Adresse und Domäne
    Write-Host "`nVerfuegbare Netzwerkadapter:"
    $i = 1
    $adapterInfoList = @()
    foreach ($a in $adapters) {
        $ip = (Get-NetIPAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
        $domain = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.InterfaceIndex -eq $a.ifIndex }).DNSDomain
        if (-not $domain) { $domain = "keine" }
        $ipDisplay = if ($ip) { $ip } else { "leer" }
        Write-Host ("{0}: {1} | Status: {2} | Speed: {3} | IP: {4} | Domäne: {5}" -f $i, $a.Name, $a.Status, $a.LinkSpeed, $ipDisplay, $domain)
        $adapterInfoList += $a
        $i++
    }

    # Adapter auswählen
    $sel = Read-Host "`n Adapterauswahl (Nummer)"
    if (-not ($sel -match '^\d+$') -or $sel -lt 1 -or $sel -gt $adapterInfoList.Count) {
        Write-Warning "Unpassende Auswahl."; return
    }
    $adapter = $adapterInfoList[$sel - 1]

    # Aktuelle IP, Gateway und DNS abrufen
    $currentIP = (Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
    $currentPrefix = (Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).PrefixLength
    $currentGW = (Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1).NextHop
    $currentDNS = (Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4).ServerAddresses

    # Neue Konfiguration abfragen, Standardwerte mit aktuellen Werten füllen
    $ip = Read-Host ("Statische IP [{0}]" -f (if ($currentIP) { $currentIP } else { "leer" }))
    $prefix = Read-Host ("PrefixLength [{0}]" -f (if ($currentPrefix) { $currentPrefix } else { "24" }))
    $gateway = Read-Host ("Standardgateway [{0}]" -f (if ($currentGW) { $currentGW } else { "leer" }))
    $dns1 = Read-Host ("Primärer DNS [{0}]" -f (if ($currentDNS[0]) { $currentDNS[0] } else { "leer" }))
    $dns2 = Read-Host ("Sekundärer DNS [{0}] (Enter zum Überspringen)" -f (if ($currentDNS[1]) { $currentDNS[1] } else { "leer" }))

    # Wenn Eingabe leer bleibt, aktuellen Wert verwenden
    if (-not $ip) { $ip = $currentIP }
    if (-not $prefix) { $prefix = $currentPrefix }
    if (-not $gateway) { $gateway = $currentGW }
    if (-not $dns1) { $dns1 = $currentDNS[0] }
    if (-not $dns2) { $dns2 = $currentDNS[1] }

    # Bestätigung einholen
    Write-Host "`nFolgende Konfiguration wird angewendet:"
    Write-Host "IP: $ip/$prefix"
    Write-Host "Gateway: $gateway"
    Write-Host "DNS: $dns1" + $(if ($dns2) { ", $dns2" } else { "" })
    $confirm = Read-Host "Fortfahren? (J/N)"
    if ($confirm -notmatch "^[jJ]") {
        Write-Host "Abgebrochen." -ForegroundColor Yellow
        return
    }

    try {
        # Alte IP-Adressen entfernen (nur wenn sich die IP ändert)
        if ($currentIP -and $currentIP -ne $ip) {
            Remove-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
        }

        # Alte Route entfernen (nur wenn sich das Gateway ändert)
        if ($currentGW -and $currentGW -ne $gateway) {
            Remove-NetRoute -InterfaceAlias $adapter.Name -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
        }

        # Neue IP-Adresse und Gateway setzen
        if ($ip -and $prefix) {
            New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $ip -PrefixLength ([int]$prefix) -ErrorAction Stop | Out-Null
        }
        
        if ($gateway) {
            New-NetRoute -InterfaceAlias $adapter.Name -AddressFamily IPv4 -NextHop $gateway -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop | Out-Null
        }

        # DNS-Server setzen
        if ($dns1) {
            $dnsServers = @($dns1)
            if ($dns2) { $dnsServers += $dns2 }
            Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $dnsServers -ErrorAction Stop
        }

        Write-Host "IP-Konfiguration erfolgreich gesetzt." -ForegroundColor Green
        
        # Neue Konfiguration anzeigen
        Write-Host "`nAktuelle Konfiguration:"
        Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 | Format-Table
        Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 | Format-Table
        
    } catch {
        Write-Warning "Fehler beim Setzen der IP-Konfiguration: $($_.Exception.Message)"
    }
}
# --------------------------
# VLAN-Konfiguration (KORRIGIERTE Funktion)
# --------------------------
function Set-VlanTag {
    Write-Host "`n=== VLAN-Konfiguration ===" -ForegroundColor Cyan

    try {
        # Aktive Netzwerkadapter ermitteln
        $adapters = Get-NetAdapter | Where-Object Status -eq "Up"
        if (-not $adapters) { 
            Write-Warning "Keine aktiven Netzwerkadapter gefunden."
            return 
        }

        # Adapter auflisten
        Write-Host "`nVerfuegbare Netzwerkadapter:"
        $i = 1
        $adapterInfoList = @()
        foreach ($a in $adapters) {
            Write-Host ("{0}: {1} | Status: {2} | Speed: {3}" -f $i, $a.Name, $a.Status, $a.LinkSpeed)
            $adapterInfoList += $a
            $i++
        }

        # Adapter auswählen
        $sel = Read-Host "`n Adapterauswahl (Nummer)"
        if (-not ($sel -match '^\d+$') -or $sel -lt 1 -or $sel -gt $adapterInfoList.Count) {
            Write-Warning "Unpassende Auswahl."
            return
        }
        $adapter = $adapterInfoList[$sel - 1]

        # VLAN-ID abfragen
        $vlanId = Read-Host "VLAN-ID (z.B. 100)"
        if (-not $vlanId -or -not ($vlanId -match '^\d+$')) {
            Write-Warning "Ungueltige VLAN-ID"
            return
        }

        # Prüfen, ob VLAN unterstützt wird
        $vlanProperty = Get-NetAdapterAdvancedProperty -Name $adapter.Name | Where-Object { $_.DisplayName -match "VLAN" }

        if (-not $vlanProperty) {
            Write-Warning "Adapter '$($adapter.Name)' unterstützt keine VLAN-Konfiguration."
            return
        }

        # VLAN setzen mit Fehlerbehandlung
        try {
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $vlanProperty.DisplayName -DisplayValue $vlanId
            Write-Host "VLAN $vlanId erfolgreich auf '$($adapter.Name)' gesetzt." -ForegroundColor Green

            # Neustart des Adapters vorschlagen
            $restart = Read-Host "Adapter neu starten für die Änderungen? (J/N)"
            if ($restart -match "^[jJ]") {
                Restart-NetAdapter -Name $adapter.Name -Confirm:$false
                Write-Host "Adapter wurde neu gestartet." -ForegroundColor Green
            }
        }
        catch {
            Write-Warning "Fehler beim Setzen des VLAN: $($_.Exception.Message)"
        }
    } catch {
        Write-Warning "Fehler in Set-VlanTag: $($_.Exception.Message)"
    }
}
# --------------------------
# Netzwerkadapter mit Details anzeigen
# --------------------------
function Show-NetworkAdapters {
    Write-Host "`n=== Netzwerkadapter mit Details ===" -ForegroundColor Cyan
    
    $adapters = Get-NetAdapter | Where-Object Status -eq "Up"
    if (-not $adapters) {
        Write-Warning "Keine aktiven Netzwerkadapter gefunden."
        return
    }

    foreach ($adapter in $adapters) {
        Write-Host "`nAdapter: $($adapter.Name)" -ForegroundColor Yellow
        Write-Host "Status: $($adapter.Status)"
        Write-Host "Geschwindigkeit: $($adapter.LinkSpeed)"
        
        # IP-Konfiguration
        $ipConfig = Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($ipConfig) {
            Write-Host "IP-Adresse: $($ipConfig.IPAddress)/$($ipConfig.PrefixLength)"
        } else {
            Write-Host "IP-Adresse: Keine IPv4-Konfiguration"
        }
        
        # Gateway
        $gateway = Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($gateway) {
            Write-Host "Gateway: $($gateway.NextHop)"
        }
        
        # DNS-Server
        $dnsServers = Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($dnsServers -and $dnsServers.ServerAddresses) {
            Write-Host "DNS-Server: $($dnsServers.ServerAddresses -join ', ')"
        }
        
        Write-Host "-" * 50
    }
}

# --------------------------
# Drucker im Netzwerk suchen und installieren
# --------------------------
function Install-PrinterByRoom {
    Write-Host "`n=== Drucker Installation ===" -ForegroundColor Cyan
    
    $roomNumber = Read-Host "Bitte geben Sie die Raumnummer ein (z.B. 190)"
    if (-not $roomNumber -or -not ($roomNumber -match '^\d+$')) {
        Write-Warning "Ungueltige Raumnummer"
        Pause
        return
    }
    
    $networkRange = "192.168.$roomNumber.*"
    Write-Host "`nSuche nach Druckern im Bereich: $networkRange" -ForegroundColor Yellow
    
    # Liste möglicher Drucker-IPs im Raum
    $possiblePrinters = @()
    for ($i = 1; $i -le 254; $i++) {
        $possiblePrinters += "192.168.$roomNumber.$i"
    }
    
    Write-Host "Scanne nach Druckern... Dies kann einen Moment dauern." -ForegroundColor Yellow
    
    $foundPrinters = @()
    $counter = 0
    
    foreach ($printerIP in $possiblePrinters) {
        $counter++
        Write-Progress -Activity "Netzwerkscan" -Status "Prüfe $printerIP" -PercentComplete (($counter / 254) * 100)
        
        # Prüfen ob Port 9100 (Druckerport) offen ist
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($printerIP, 9100, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne(100, $false)
        
        if ($wait -and $tcpClient.Connected) {
            $tcpClient.EndConnect($asyncResult)
            $tcpClient.Close()
            
            # Versuchen, Druckernamen zu ermitteln
            $printerName = "Drucker_Raum_${roomNumber}_$($printerIP.Split('.')[-1])"
            $foundPrinters += [PSCustomObject]@{
                IP = $printerIP
                Name = $printerName
                Port = 9100
            }
        }
        $tcpClient.Close()
    }
    
    Write-Progress -Activity "Netzwerkscan" -Completed
    
    if ($foundPrinters.Count -eq 0) {
        Write-Warning "Keine Drucker im Netzwerkbereich $networkRange gefunden."
        Pause
        return
    }
    
    # Gefundene Drucker anzeigen
    Write-Host "`nGefundene Drucker:" -ForegroundColor Green
    for ($i = 0; $i -lt $foundPrinters.Count; $i++) {
        Write-Host "$($i+1): $($foundPrinters[$i].IP) - $($foundPrinters[$i].Name)"
    }
    
    # Drucker auswählen
    $printerChoice = Read-Host "`nWelchen Drucker moechten Sie installieren? (Nummer)"
    if (-not ($printerChoice -match '^\d+$') -or $printerChoice -lt 1 -or $printerChoice -gt $foundPrinters.Count) {
        Write-Warning "Ungueltige Auswahl"
        Pause
        return
    }
    
    $selectedPrinter = $foundPrinters[$printerChoice - 1]
    
    Write-Host "`nDrucker wird konfiguriert:"
    Write-Host "IP-Adresse: $($selectedPrinter.IP)"
    Write-Host "Name: $($selectedPrinter.Name)"
    
    $confirm = Read-Host "Fortfahren? (J/N)"
    if ($confirm -notmatch "^[jJ]") {
        Write-Host "Abgebrochen" -ForegroundColor Yellow
        Pause
        return
    }
    
    try {
        # Druckerport erstellen
        Add-PrinterPort -Name $selectedPrinter.IP -PrinterHostAddress $selectedPrinter.IP -ErrorAction Stop
        
        # Drucker installieren (mit generischem Treiber)
        Add-Printer -Name $selectedPrinter.Name -PortName $selectedPrinter.IP -DriverName "Generic / Text Only" -ErrorAction Stop
        
        Write-Host "Drucker erfolgreich installiert: $($selectedPrinter.Name)" -ForegroundColor Green
        Write-Host "IP: $($selectedPrinter.IP)" -ForegroundColor Green
    }
    catch {
        Write-Warning "Fehler bei der Druckerinstallation: $($_.Exception.Message)"
    }
    
    Pause
}

# --------------------------
# Hilfsfunktion für Pause
# --------------------------
function Pause {
    Write-Host "`nDrücken Sie eine Taste, um fortzufahren..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# --------------------------
# Installationsfunktionen
# --------------------------
function Install-IIS {
    try {
        if (-not (Get-WindowsFeature -Name Web-Server).Installed) {
            Install-WindowsFeature -Name Web-Server -IncludeManagementTools | Out-Null
            Write-Host "IIS wurde installiert." -ForegroundColor Green
        } else {
            Write-Host "IIS ist bereits installiert." -ForegroundColor Green
        }

        $index = "C:\inetpub\wwwroot\index.html"
        if (-not (Test-Path $index)) {
            "Willkommen $(Get-Date)" | Out-File $index -Encoding utf8
            Write-Host "IIS-Startseite erstellt." -ForegroundColor Green
        } else {
            Write-Host "IIS-Startseite existiert bereits." -ForegroundColor Green
        }
    } catch {
        Write-Warning "IIS-Setup Problem: $($_.Exception.Message)"
    }
    Pause
}

function Install-RSAT {
    Write-Host "`n=== RSAT Installation ===" -ForegroundColor Cyan
    try {
        $adCap = Get-WindowsCapability -Online | Where-Object { $_.Name -like "Rsat.ActiveDirectory.DS-LDS.Tools*" } | Select-Object -First 1
        if ($adCap -and $adCap.State -ne "Installed") {
            Add-WindowsCapability -Online -Name $adCap.Name -ErrorAction Stop | Out-Null
            Write-Host "RSAT AD DS/LDAP Tools installiert." -ForegroundColor Green
        } else {
            Write-Host "RSAT AD Tools sind bereits installiert." -ForegroundColor Green
        }
        
        # Prüfen ob ActiveDirectory Modul verfügbar ist
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory -Force
            Write-Host "ActiveDirectory Modul importiert." -ForegroundColor Green
        } else {
            Write-Warning "ActiveDirectory Modul nicht verfügbar. Bitte stellen Sie sicher, dass RSAT installiert ist."
        }
    } catch {
        Write-Warning "RSAT-Installation fehlgeschlagen: $($_.Exception.Message)"
    }
    Pause
}

function Install-OpenSSH {
    Write-Host "`n=== OpenSSH-Server Installation ===" -ForegroundColor Cyan
    try {
        $cap = Get-WindowsCapability -Online | Where-Object { $_.Name -like "OpenSSH.Server*" } | Select-Object -First 1
        if ($cap -and $cap.State -ne "Installed") {
            Add-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop | Out-Null
            Write-Host "OpenSSH-Server installiert." -ForegroundColor Green
        } else {
            Write-Host "OpenSSH-Server ist bereits installiert." -ForegroundColor Green
        }
        # Dienst aktivieren und starten
        Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name sshd -ErrorAction SilentlyContinue
        Write-Host "sshd Dienst aktiviert/gestartet (falls vorhanden)." -ForegroundColor Green
    } catch {
        Write-Warning "OpenSSH-Installation fehlgeschlagen: $($_.Exception.Message)"
    }
    Pause
}

function Install-SNMP {
    Write-Host "`n=== SNMP-Client Installation ===" -ForegroundColor Cyan
    try {
        # Windows 10/11 & Server (Capabilities)
        $cap = Get-WindowsCapability -Online | Where-Object { $_.Name -like "SNMP.Client*" } | Select-Object -First 1
        if ($cap) {
            if ($cap.State -ne "Installed") {
                Add-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop | Out-Null
                Write-Host "SNMP-Client installiert." -ForegroundColor Green
            } else {
                Write-Host "SNMP-Client ist bereits installiert." -ForegroundColor Green
            }
        } else {
            # Fallback für ältere Server-Editionen
            if (-not (Get-WindowsFeature -Name SNMP-Services).Installed) {
                Install-WindowsFeature -Name SNMP-Services | Out-Null
                Write-Host "SNMP-Services installiert." -ForegroundColor Green
            } else {
                Write-Host "SNMP-Services sind bereits installiert." -ForegroundColor Green
            }
        }
    } catch {
        Write-Warning "SNMP-Installation fehlgeschlagen: $($_.Exception.Message)"
    }
    Pause
}

function Install-Requirements {
    Write-Host "`n=== Voraussetzungen installieren ===" -ForegroundColor Cyan
    try {
        # TLS 1.2 erzwingen
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # NuGet & PowerShellGet aktualisieren
        if (-not (Get-PackageProvider -ListAvailable | Where-Object Name -eq "NuGet")) {
            Install-PackageProvider -Name NuGet -Force -Scope CurrentUser -ErrorAction Stop | Out-Null
        }
        Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        Write-Host "Grundlagen aktualisiert." -ForegroundColor Green
    } catch {
        Write-Warning "Voraussetzungen konnten nicht vollständig installiert werden: $($_.Exception.Message)"
    }
    Pause
}

# --------------------------
# Active Directory – Menü-Funktionen (Basis)
# --------------------------
function New-ADUser {
    try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Warning "ActiveDirectory-Modul nicht vorhanden. Bitte RSAT installieren."
            Pause; return
        }
        Import-Module ActiveDirectory -ErrorAction Stop

        $sam = Read-Host "SAM-AccountName (z.B. m.mueller)"
        $given = Read-Host "Vorname"
        $sn = Read-Host "Nachname"
        $ou = Read-Host "OU (LDAP-Pfad, z.B. OU=Users,DC=contoso,DC=local)"
        $pwd = Read-Host "Initialpasswort" -AsSecureString

        if (-not $sam -or -not $given -or -not $sn -or -not $ou) { Write-Warning "Eingaben unvollständig."; Pause; return }

        New-ADUser -Name "$given $sn" -SamAccountName $sam -GivenName $given -Surname $sn -Path $ou -AccountPassword $pwd -Enabled $true
        Write-Host "Benutzer '$sam' angelegt." -ForegroundColor Green
    } catch {
        Write-Warning "Fehler beim Anlegen des Benutzers: $($_.Exception.Message)"
    }
    Pause
}

function New-ADGroup {
    try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Warning "ActiveDirectory-Modul nicht vorhanden. Bitte RSAT installieren."
            Pause; return
        }
        Import-Module ActiveDirectory -ErrorAction Stop

        $name = Read-Host "Gruppenname"
        $ou = Read-Host "OU (LDAP-Pfad, z.B. OU=Groups,DC=contoso,DC=local)"
        if (-not $name -or -not $ou) { Write-Warning "Eingaben unvollständig."; Pause; return }

        New-ADGroup -Name $name -GroupScope Global -GroupCategory Security -Path $ou
        Write-Host "Gruppe '$name' angelegt." -ForegroundColor Green
    } catch {
        Write-Warning "Fehler beim Anlegen der Gruppe: $($_.Exception.Message)"
    }
    Pause
}

function New-ADUserWithGroup {
    try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Warning "ActiveDirectory-Modul nicht vorhanden. Bitte RSAT installieren."
            Pause; return
        }
        Import-Module ActiveDirectory -ErrorAction Stop

        $sam = Read-Host "SAM-AccountName"
        $given = Read-Host "Vorname"
        $sn = Read-Host "Nachname"
        $ouUser = Read-Host "OU für Benutzer (LDAP-Pfad)"
        $ouGroup = Read-Host "OU für Gruppe (LDAP-Pfad)"
        $grp = Read-Host "Gruppenname"
        $pwd = Read-Host "Initialpasswort" -AsSecureString

        if (-not $sam -or -not $given -or -not $sn -or -not $ouUser -or -not $ouGroup -or -not $grp) { Write-Warning "Eingaben unvollständig."; Pause; return }

        # Gruppe sicherstellen
        if (-not (Get-ADGroup -Filter "Name -eq '$grp'" -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $grp -GroupScope Global -GroupCategory Security -Path $ouGroup | Out-Null
            Write-Host "Gruppe '$grp' angelegt." -ForegroundColor Green
        }

        # Benutzer anlegen
        New-ADUser -Name "$given $sn" -SamAccountName $sam -GivenName $given -Surname $sn -Path $ouUser -AccountPassword $pwd -Enabled $true
        Add-ADGroupMember -Identity $grp -Members $sam
        Write-Host "Benutzer '$sam' angelegt und zu '$grp' hinzugefügt." -ForegroundColor Green
    } catch {
        Write-Warning "Fehler bei Benutzer- und Gruppenerstellung: $($_.Exception.Message)"
    }
    Pause
}

# --------------------------
# Hauptmenü Funktion
# --------------------------
function Show-InstallMenu {
    do {
        Clear-Host
        Write-Host "=== Installieren und Konfigurieren ===" -ForegroundColor Cyan
        Write-Host "1: IIS Webserver installieren"
        Write-Host "2: RSAT Tools installieren"
        Write-Host "3: OpenSSH-Server installieren"
        Write-Host "4: SNMP-Client installieren"
        Write-Host "5: Sysinternals Tools starten"
        Write-Host "Q: Zurueck zum Hauptmenue"
        
        $choice = Read-Host "`nIhre Auswahl"
        
        switch ($choice) {
            "1" { Install-IIS }
            "2" { Install-RSAT }
            "3" { Install-OpenSSH }
            "4" { Install-SNMP }
            "5" { Show-SysinternalsMenu }
            "Q" { return }
            default {
                Write-Warning "Ungueltige Auswahl"
                Pause
            }
        }
    } while ($true)
}

function Show-SysinternalsMenu {
    do {
        Clear-Host
        Write-Host "=== Sysinternals Tools ===" -ForegroundColor Cyan
        Write-Host "1: Process Explorer starten"
        Write-Host "2: TCPView starten"
        Write-Host "3: Autoruns starten"
        Write-Host "4: Process Monitor starten"
        Write-Host "5: BGInfo starten"
        Write-Host "Q: Zurueck"
        
        $choice = Read-Host "`nIhre Auswahl"
        
        switch ($choice) {
            "1" { Start-SysinternalTool -ExeName "procexp.exe" }
            "2" { Start-SysinternalTool -ExeName "tcpview.exe" }
            "3" { Start-SysinternalTool -ExeName "autoruns.exe" }
            "4" { Start-SysinternalTool -ExeName "procmon.exe" }
            "5" { Start-SysinternalTool -ExeName "bginfo.exe" }
            "Q" { return }
            default {
                Write-Warning "Ungueltige Auswahl"
                Pause
            }
        }
    } while ($true)
}

function Show-NetworkMenu {
    do {
        Clear-Host
        Write-Host "=== Netzwerk Konfiguration ===" -ForegroundColor Cyan
        Write-Host "1: IP-Konfiguration setzen"
        Write-Host "2: VLAN-Konfiguration"
        Write-Host "3: Netzwerkadapter anzeigen (mit Details)"
        Write-Host "Q: Zurueck"
        
        $choice = Read-Host "`nIhre Auswahl"
        
        switch ($choice) {
            "1" { Set-NetworkConfig }
            "2" { Set-VlanTag }
            "3" { Show-NetworkAdapters; Pause }
            "Q" { return }
            default {
                Write-Warning "Ungueltige Auswahl"
                Pause
            }
        }
    } while ($true)
}

function Show-ADMenu {
    do {
        Clear-Host
        Write-Host "=== Active Directory Verwaltung ===" -ForegroundColor Cyan
        Write-Host "1: Benutzer anlegen"
        Write-Host "2: Gruppe anlegen"
        Write-Host "3: Benutzer und Gruppe anlegen"
        Write-Host "Q: Zurueck"
        
        $choice = Read-Host "`nIhre Auswahl"
        
        switch ($choice) {
            "1" { New-ADUser }
            "2" { New-ADGroup }
            "3" { New-ADUserWithGroup }
            "Q" { return }
            default {
                Write-Warning "Ungueltige Auswahl"
                Pause
            }
        }
    } while ($true)
}

function Show-MainMenu {
    do {
        Clear-Host
        Get-Weather
        Write-Host "`n==== Admin-Master 3000 ====" -ForegroundColor Magenta
        Write-Host "1: Systeminformationen anzeigen"
        Write-Host "2: Installieren und Konfigurieren"
        Write-Host "3: Netzwerk und Dienste pruefen"
        Write-Host "4: Windows und App Updates"
        Write-Host "5: Active Directory Verwaltung"
        Write-Host "6: Systemfehler anzeigen"
        Write-Host "7: Netzwerk Konfiguration"
        Write-Host "8: Drucker installieren (nach Raum)"
        Write-Host "9: Voraussetzungen installieren"
        Write-Host "Q: Beenden"
        
        $choice = Read-Host "`nIhre Auswahl"
        
        switch ($choice) {
            "1" { Show-SystemInfo; Pause }
            "2" { Show-InstallMenu }
            "3" { Test-NetworkAndServices; Pause }
            "4" { Run-Updates; Pause }
            "5" { Show-ADMenu }
            "6" { Show-SystemErrors; Pause }
            "7" { Show-NetworkMenu }
            "8" { Install-PrinterByRoom }
            "9" { Install-Requirements }
            "Q" { 
                Write-Host "Admin-Toolkit wird beendet." -ForegroundColor Cyan
                exit 
            }
            default {
                Write-Warning "Ungueltige Auswahl"
                Pause
            }
        }
    } while ($true)
}

# ----- Skriptstart -----
# Aufruf des Hauptmenüs, damit das Skript beim Start läuft
Show-MainMenu
