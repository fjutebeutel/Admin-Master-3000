# ==========================================
# Admin-Toolkit fuer Windows
# ==========================================

# Pruefung auf Administratorrechte
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

# --------------------------
# Pause-Hilfsfunktion (host-unabhaengig)
# --------------------------
function Pause-Script {
    [void](Read-Host "`nWeiter mit [Enter] ...")
}

# --------------------------
# Wetter
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
    Pause-Script
}

# --------------------------
# Netzwerk & Dienste pruefen
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
            if ($pingResult) { Write-Host "Gateway erreichbar" -ForegroundColor Green }
            else { Write-Warning "Gateway nicht erreichbar" }
        } else { Write-Warning "Kein Gateway gefunden" }
        
        Write-Host "`nPing Internet (8.8.8.8) ..."
        try { 
            $internetResult = Test-Connection -ComputerName 8.8.8.8 -Count 2 -ErrorAction Stop
            if ($internetResult) { Write-Host "Internet: OK" -ForegroundColor Green }
        } catch { Write-Warning "Internet: nicht erreichbar" }
    }
    catch {
        Write-Warning "Fehler beim Netzwerk-Check: $($_.Exception.Message)"
    }
    Pause-Script
}

# --------------------------
# Updates (Windows + Apps)
# --------------------------
function Invoke-Updates {
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
            Write-Host "$($updates.Count) Updates verfuegbar." -ForegroundColor Yellow
            foreach ($u in $updates) {
                Write-Host "`nTitel: $($u.Title)"
                if ($u.KBArticleIDs) { Write-Host "KB:    $($u.KBArticleIDs -join ', ')" }
                if ($u.Size) { Write-Host "Groesse: $($u.Size) MB" }
                $answer = Read-Host "Dieses Update installieren? (J/N)"
                if ($answer -match "^[JjYy]$") {
                    if ($u.KBArticleIDs) {
                        Install-WindowsUpdate -KBArticleID $u.KBArticleIDs -AcceptAll -AutoReboot:$false -Verbose
                    } else {
                        Install-WindowsUpdate -Title $u.Title -AcceptAll -AutoReboot:$false -Verbose
                    }
                } else { Write-Host "Uebersprungen: $($u.Title)" -ForegroundColor Yellow }
            }
        } else {
            Write-Host "Keine Windows Updates verfuegbar." -ForegroundColor Green
        }
    } catch {
        Write-Warning "Windows Update via Modul nicht moeglich: $($_.Exception.Message)"
    }

    Write-Host "`n=== Anwendungsupdates (winget) ===" -ForegroundColor Cyan
    try {
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            $list = winget upgrade --accept-source-agreements | Select-String "^\S"
            if ($list) {
                foreach ($line in $list) {
                    $text = $line.ToString().Trim()
                    $parts = $text -split "\s{2,}",2
                    $id = $null
                    if ($parts.Count -ge 2) {
                        $maybeId = ($parts[0] -split '\s+')[0]
                        $id = $maybeId
                    }
                    Write-Host "`nGefundenes App-Update: $text"
                    $ans = Read-Host "Diese App aktualisieren? (J/N)"
                    if ($ans -match "^[JjYy]$") {
                        if ($id) {
                            winget upgrade --id $id --accept-package-agreements --accept-source-agreements
                        } else {
                            Write-Host "Konnte ID nicht sicher ermitteln, versuche Upgrade-All..." -ForegroundColor Yellow
                            winget upgrade --all --accept-package-agreements --accept-source-agreements
                        }
                    } else {
                        Write-Host "Uebersprungen." -ForegroundColor Yellow
                    }
                }
            } else {
                Write-Host "Keine App-Updates verfuegbar." -ForegroundColor Green
            }
        } else {
            Write-Warning "winget nicht gefunden. Installieren Sie winget von https://github.com/microsoft/winget-cli"
        }
    } catch {
        Write-Warning "winget-Update fehlgeschlagen: $($_.Exception.Message)"
    }
    Pause-Script
}

# --------------------------
# Fehleranalyse
# --------------------------
function Show-SystemErrors {
    [CmdletBinding()]
    param(
        [switch]$IncludeWarnings,
        [switch]$ShowDetails
    )

    Write-Host "`n=== Letzte Systemfehler ===" -ForegroundColor Cyan

    try {
        $EventFixes = @{
            7     = "Disk-Fehler: chkdsk /f oder SMART pruefen."
            41    = "Kernel-Power: Unerwarteter Neustart, Netzteil/Treiber pruefen."
            1014  = "DNS-Fehler: Verbindung oder DNS-Server pruefen."
            55    = "NTFS-Fehler: Dateisystem beschaedigt – chkdsk /f."
            2019  = "Speicher-Leck: Treiber/Programme mit hoher RAM-Last pruefen."
        }

        $errorEvents = Get-EventLog -LogName System -EntryType Error -Newest 10 -ErrorAction SilentlyContinue
        if ($errorEvents) {
            foreach ($evt in $errorEvents) {
                $msg = $evt.Message -replace "`r|`n"," " -replace '\s{2,}',' '
                if (-not $ShowDetails) { if ($msg.Length -gt 100) { $msg = $msg.Substring(0,100) + "..." } }
                Write-Host "`n[!] Fehler $($evt.EventID) | $($evt.Source) | $($evt.TimeGenerated)" -ForegroundColor Red
                Write-Host "    Nachricht: $msg"
                if ($EventFixes.ContainsKey($evt.EventID)) {
                    Write-Host "    Hinweis: $($EventFixes[$evt.EventID])" -ForegroundColor Yellow
                } else {
                    Write-Host "    Mehr Infos: https://www.google.com/search?q=Windows+EventID+$($evt.EventID)" -ForegroundColor DarkGray
                }
            }
        } else {
            Write-Host "Keine Fehlerereignisse in den letzten Eintraegen gefunden." -ForegroundColor Green
        }

        if ($IncludeWarnings) {
            Write-Host "`n=== Letzte Warnungen ===" -ForegroundColor Cyan
            $warningEvents = Get-EventLog -LogName System -EntryType Warning -Newest 10 -ErrorAction SilentlyContinue
            if ($warningEvents) {
                foreach ($evt in $warningEvents) {
                    $msg = $evt.Message -replace "`r|`n"," " -replace '\s{2,}',' '
                    if (-not $ShowDetails) { if ($msg.Length -gt 100) { $msg = $msg.Substring(0,100) + "..." } }
                    Write-Host "`n[~] Warnung $($evt.EventID) | $($evt.Source) | $($evt.TimeGenerated)" -ForegroundColor DarkYellow
                    Write-Host "    Nachricht: $msg"
                }
            } else {
                Write-Host "Keine Warnereignisse in den letzten Eintraegen gefunden." -ForegroundColor Green
            }
        }
    }
    catch {
        Write-Warning "Eventlogs konnten nicht gelesen werden: $($_.Exception.Message)"
        Write-Host "Hinweis: Fuehren Sie das Skript als Administrator aus, um Eventlogs zu lesen." -ForegroundColor Yellow
    }
    Pause-Script
}

# --------------------------
# IP-Konfiguration setzen
# --------------------------
function Set-NetworkConfig {
    Write-Host "`n=== IP-Konfiguration setzen ===" -ForegroundColor Cyan

    $adapters = Get-NetAdapter | Where-Object Status -eq "Up"
    if (-not $adapters) { Write-Warning "Keine aktiven Netzwerkadapter gefunden."; return }

    Write-Host "`nVerfuegbare Netzwerkadapter:"
    $i = 1
    $adapterInfoList = @()
    foreach ($a in $adapters) {
        $ip = (Get-NetIPAddress -InterfaceAlias $a.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
        $domain = (Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.InterfaceIndex -eq $a.ifIndex }).DNSDomain
        if (-not $domain) { $domain = "keine" }
        $ipDisplay = if ($ip) { $ip } else { "leer" }
        Write-Host ("{0}: {1} | Status: {2} | Speed: {3} | IP: {4} | Domaene: {5}" -f $i, $a.Name, $a.Status, $a.LinkSpeed, $ipDisplay, $domain)
        $adapterInfoList += $a
        $i++
    }

    $sel = Read-Host "`n Adapterauswahl (Nummer)"
    if (-not ($sel -match '^\d+$') -or $sel -lt 1 -or $sel -gt $adapterInfoList.Count) {
        Write-Warning "Unpassende Auswahl."; return
    }
    $adapter = $adapterInfoList[$sel - 1]

    $currentIP = (Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
    $currentPrefix = (Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).PrefixLength
    $currentGW = (Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" | Select-Object -First 1).NextHop
    $currentDNS = (Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4).ServerAddresses

    $ip = Read-Host ("Statische IP [{0}]" -f (if ($currentIP) { $currentIP } else { "leer" }))
    $prefix = Read-Host ("PrefixLength [{0}]" -f (if ($currentPrefix) { $currentPrefix } else { "24" }))
    $gateway = Read-Host ("Standardgateway [{0}]" -f (if ($currentGW) { $currentGW } else { "leer" }))
    $dns1 = Read-Host ("Primaerer DNS [{0}]" -f (if ($currentDNS[0]) { $currentDNS[0] } else { "leer" }))
    $dns2 = Read-Host ("Sekundaerer DNS [{0}] (Enter zum Ueberspringen)" -f (if ($currentDNS[1]) { $currentDNS[1] } else { "leer" }))

    if (-not $ip) { $ip = $currentIP }
    if (-not $prefix) { $prefix = $currentPrefix }
    if (-not $gateway) { $gateway = $currentGW }
    if (-not $dns1) { $dns1 = $currentDNS[0] }
    if (-not $dns2) { $dns2 = $currentDNS[1] }

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
        if ($currentIP -and $currentIP -ne $ip) {
            Remove-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
        }

        if ($currentGW -and $currentGW -ne $gateway) {
            Remove-NetRoute -InterfaceAlias $adapter.Name -AddressFamily IPv4 -Confirm:$false -ErrorAction SilentlyContinue
        }

        if ($ip -and $prefix) {
            New-NetIPAddress -InterfaceAlias $adapter.Name -IPAddress $ip -PrefixLength ([int]$prefix) -ErrorAction Stop | Out-Null
        }
        
        if ($gateway) {
            New-NetRoute -InterfaceAlias $adapter.Name -AddressFamily IPv4 -NextHop $gateway -DestinationPrefix "0.0.0.0/0" -ErrorAction Stop | Out-Null
        }

        if ($dns1) {
            $dnsServers = @($dns1)
            if ($dns2) { $dnsServers += $dns2 }
            Set-DnsClientServerAddress -InterfaceAlias $adapter.Name -ServerAddresses $dnsServers -ErrorAction Stop
        }

        Write-Host "IP-Konfiguration erfolgreich gesetzt." -ForegroundColor Green
        
        Write-Host "`nAktuelle Konfiguration:"
        Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 | Format-Table
        Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 | Format-Table
    } catch {
        Write-Warning "Fehler beim Setzen der IP-Konfiguration: $($_.Exception.Message)"
    }
    Pause-Script
}

# --------------------------
# VLAN-Konfiguration
# --------------------------
function Set-VlanTag {
    Write-Host "`n=== VLAN-Konfiguration ===" -ForegroundColor Cyan

    try {
        $adapters = Get-NetAdapter | Where-Object Status -eq "Up"
        if (-not $adapters) {
            Write-Warning "Keine aktiven Netzwerkadapter gefunden."
            return
        }

        Write-Host "`nVerfuegbare Netzwerkadapter:"
        $i = 1
        $adapterInfoList = @()
        foreach ($a in $adapters) {
            Write-Host ("{0}: {1} | Status: {2} | Speed: {3}" -f $i, $a.Name, $a.Status, $a.LinkSpeed)
            $adapterInfoList += $a
            $i++
        }

        $sel = Read-Host "`n Adapterauswahl (Nummer)"
        if (-not ($sel -match '^\d+$') -or $sel -lt 1 -or $sel -gt $adapterInfoList.Count) {
            Write-Warning "Unpassende Auswahl."
            return
        }
        $adapter = $adapterInfoList[$sel - 1]

        $vlanId = Read-Host "VLAN-ID (z.B. 100)"
        if (-not $vlanId -or -not ($vlanId -match '^\d+$')) {
            Write-Warning "Ungueltige VLAN-ID"
            return
        }

        $vlanProperty = Get-NetAdapterAdvancedProperty -Name $adapter.Name | Where-Object { $_.DisplayName -match "VLAN" }

        if (-not $vlanProperty) {
            Write-Warning "Adapter '$($adapter.Name)' unterstuetzt keine VLAN-Konfiguration."
            return
        }

        try {
            Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName $vlanProperty.DisplayName -DisplayValue $vlanId
            Write-Host "VLAN $vlanId erfolgreich auf '$($adapter.Name)' gesetzt." -ForegroundColor Green

            $restart = Read-Host "Adapter neu starten fuer die Aenderungen? (J/N)"
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
    Pause-Script
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
        
        $ipConfig = Get-NetIPAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($ipConfig) {
            Write-Host "IP-Adresse: $($ipConfig.IPAddress)/$($ipConfig.PrefixLength)"
        } else {
            Write-Host "IP-Adresse: Keine IPv4-Konfiguration"
        }
        
        $gateway = Get-NetRoute -InterfaceIndex $adapter.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($gateway) {
            Write-Host "Gateway: $($gateway.NextHop)"
        }
        
        $dnsServers = Get-DnsClientServerAddress -InterfaceAlias $adapter.Name -AddressFamily IPv4 -ErrorAction SilentlyContinue
        if ($dnsServers -and $dnsServers.ServerAddresses) {
            Write-Host "DNS-Server: $($dnsServers.ServerAddresses -join ', ')"
        }
        
        Write-Host "-" * 50
    }
    Pause-Script
}

# -------------------------------------------------------------
# Helper: Alle Host-IP-Adressen aus lokalen Subnetzen ermitteln
# -------------------------------------------------------------
function Get-AllSubnetHosts {
    $hosts = @()
    $ipConfigs = Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -in 'Dhcp','Manual' }
    foreach ($cfg in $ipConfigs) {
        $octets = ($cfg.IPAddress -split '\.')[0..2] -join '.'
        for ($i=1; $i -le 254; $i++) { $hosts += "$octets.$i" }
    }
    return $hosts | Sort-Object -Unique
}

# -------------------------------------------------------------
# Helper: TCP-Port pruefen
# -------------------------------------------------------------
function Test-TCPPort {
    param(
        [Parameter(Mandatory)][string]$IP,
        [Parameter(Mandatory)][int]$Port,
        [int]$Timeout = 200
    )
    try {
        $client      = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $client.BeginConnect($IP, $Port, $null, $null)
        if ($asyncResult.AsyncWaitHandle.WaitOne($Timeout)) {
            $client.EndConnect($asyncResult) | Out-Null
            return $true
        }
    } catch {}
    finally { if ($client) { $client.Close() } }
    return $false
}

# -------------------------------------------------------------
# Helper: SNMP‑Name eines Druckers ermitteln (falls snmpget vorhanden)
# -------------------------------------------------------------
function Get-SNMPPrinterName {
    param([string]$IPAddress)
    $snmpCmd = Get-Command snmpget -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    if ($snmpCmd) {
        try {
            $output = & $snmpCmd -v 2c -c public "$IPAddress" .1.3.6.1.2.1.43.5.1.1.17.1
            if ($output -match 'STRING:\s*(.+)') { return $Matches[1].Trim() }
        } catch {}
    }
    return $null
}

# -------------------------------------------------------------
# Helper: Druckerinstallation
# -------------------------------------------------------------
function Install-PrinterFromSelection {
    param([PSCustomObject]$Printer)
    Write-Host "`n=== Drucker konfigurieren ===" -ForegroundColor Cyan

    $defaultPortName = $Printer.IP
    $portName = Read-Host "Portname (Default: $defaultPortName)"
    if ([string]::IsNullOrWhiteSpace($portName)) { $portName = $defaultPortName }

    $printerName = Read-Host "Druckername (Default: $($Printer.Name))"
    if ([string]::IsNullOrWhiteSpace($printerName)) { $printerName = $Printer.Name }

    $driverName = $null
    $driverDownloadedAns = Read-Host "Haben Sie einen spezifischen Druckertreiber heruntergeladen? (J/N)"
    if ($driverDownloadedAns -match '^[jJ]') {
        do {
            $driverPath = Read-Host "Pfad zum Treiberordner angeben"
            if (-not (Test-Path $driverPath)) { Write-Warning "Pfad nicht gefunden. Bitte erneut eingeben." }
        } until (Test-Path $driverPath)

        $infFiles = Get-ChildItem -Path $driverPath -Filter *.inf -Recurse -ErrorAction SilentlyContinue
        if ($infFiles.Count -gt 0) {
            $selectedInf = $infFiles[0].FullName
            try {
                Add-PrinterDriver -Name ("Custom_$($Printer.IP)") -InfPath $selectedInf -ErrorAction Stop
                $driverName = "Custom_$($Printer.IP)"
            } catch {
                Write-Warning "Fehler bei Treiberinstallation: $($_.Exception.Message)"
            }
        }
    }

    if (-not $driverName) {
        $existingDrivers = Get-PrinterDriver | Select-Object -ExpandProperty Name
        if ($existingDrivers -and $existingDrivers.Count -gt 0) {
            Write-Host "`nVorhandene Treiber:" -ForegroundColor Green
            for ($i=0;$i -lt $existingDrivers.Count;$i++) { Write-Host "$($i+1): $($existingDrivers[$i])" }
            $driverChoice = Read-Host "Treiber auswaehlen (Nummer) oder Enter fuer 'Generic / Text Only'"
            if ($driverChoice -match '^\d+$' -and [int]$driverChoice -ge 1 -and [int]$driverChoice -le $existingDrivers.Count) {
                $driverName = $existingDrivers[[int]$driverChoice-1]
            }
        }
        if (-not $driverName) { $driverName = "Generic / Text Only" }
    }

    try {
        if (-not (Get-PrinterPort -Name $portName -ErrorAction SilentlyContinue)) {
            Add-PrinterPort -Name $portName -PrinterHostAddress $Printer.IP -ErrorAction Stop
        }

        Add-Printer -Name $printerName -DriverName $driverName -PortName $portName -ErrorAction Stop
        Write-Host "`nDrucker erfolgreich installiert: $printerName" -ForegroundColor Green
    } catch {
        Write-Warning "Fehler bei Druckerinstallation: $($_.Exception.Message)"
    }
}

# -------------------------------------------------------------
# Drucker im Netzwerk suchen und installieren
# -------------------------------------------------------------
function Install-PrinterByRoom {
    Write-Host "`n=== Drucker Installation ===" -ForegroundColor Cyan

    $hasFixedIP = Read-Host "Hat der Drucker bereits eine feste IP-Adresse? (J/N)"
    if ($hasFixedIP -match '^[jJ]') {
        do {
            $printerIP = Read-Host "IP-Adresse des Druckers"
            $validIP  = $printerIP -match '^(\d{1,3}\.){3}\d{1,3}$'
            if (-not $validIP) { Write-Warning "Ungueltige IP. Bitte erneut eingeben." }
        } until ($validIP)

        $printer = [PSCustomObject]@{
            IP   = $printerIP
            Name = "Drucker_$($printerIP.Split('.')[-1])"
            Port = 9100
        }
        Install-PrinterFromSelection -Printer $printer
        Pause-Script
        return
    }

    Write-Host "`nDurchsuche lokale Subnetze nach Druckern (Port 9100)..." -ForegroundColor Yellow
    $hosts = Get-AllSubnetHosts
    if ($hosts.Count -eq 0) {
        Write-Warning "Keine IP-Adressen aus der Netzwerkkonfiguration gefunden."
        Pause-Script
        return
    }

    $foundPrinters = @()
    $counter = 0
    foreach ($ip in $hosts) {
        $counter++
        Write-Progress -Activity "Netzwerkscan" -Status "Pruefe $ip" -PercentComplete (($counter / $hosts.Count) * 100)
        if (Test-TCPPort -IP $ip -Port 9100) {
            $name = Get-SNMPPrinterName -IPAddress $ip
            if (-not $name) { $name = "Drucker_$($ip.Split('.')[-1])" }
            $foundPrinters += [PSCustomObject]@{ IP = $ip; Name = $name; Port = 9100 }
        }
    }
    Write-Progress -Activity "Netzwerkscan" -Completed

    if ($foundPrinters.Count -eq 0) {
        Write-Warning "Keine Drucker im Netzwerk gefunden."
        Pause-Script
        return
    }

    Write-Host "`nGefundene Drucker:" -ForegroundColor Green
    for ($i=0;$i -lt $foundPrinters.Count;$i++) {
        Write-Host "$($i+1): $($foundPrinters[$i].IP) – $($foundPrinters[$i].Name)"
    }

    do {
        $choice = Read-Host "`nWelche Drucker installieren? (z. B. 1,3 oder 'alle')"
        if ($choice -match '^alle$' -or $choice -match '^[0-9,\s]+$') { break }
        Write-Warning "Ungueltige Eingabe."
    } until ($true)

    $selectedPrinters = @()
    if ($choice -eq 'alle') {
        $selectedPrinters = $foundPrinters
    } else {
        $indices = ($choice -split '[,\s]+' | Where-Object { $_ -match '^\d+$' })
        foreach ($idx in $indices) {
            $n = [int]$idx
            if ($n -ge 1 -and $n -le $foundPrinters.Count) {
                $selectedPrinters += $foundPrinters[$n-1]
            }
        }
    }

    foreach ($p in $selectedPrinters) {
        Install-PrinterFromSelection -Printer $p
    }
    Pause-Script
}

# --------------------------
# Installationsfunktionen
# --------------------------
function Install-IIS {
    try {
        Clear-Host
        Write-Host "=== IIS Webserver installieren ===" -ForegroundColor Cyan
        
        if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Warning "Diese Funktion erfordert Administratorrechte!"
            Pause-Script; return
        }
        
        if (Get-WindowsFeature -Name Web-Server | Where-Object {$_.InstallState -eq 'Installed'}) {
            Write-Host "IIS ist bereits installiert" -ForegroundColor Yellow
            Pause-Script; return
        }

        Write-Host "Installiere IIS-Webserver..." -ForegroundColor Yellow
        
        $result = Install-WindowsFeature -Name Web-Server, Web-Mgmt-Tools, Web-WebServer, Web-Common-Http, Web-Default-Doc, Web-Dir-Browsing, Web-Http-Errors, Web-Static-Content, Web-Http-Logging, Web-Request-Monitor
        
        if ($result.Success) {
            Write-Host "IIS-Webserver erfolgreich installiert" -ForegroundColor Green
            Write-Host "Zugriff per: http://localhost" -ForegroundColor Gray
        } else {
            Write-Warning "IIS-Webserver konnte nicht installiert werden"
        }
        
    } catch {
        Write-Warning "Fehler bei der IIS-Installation: $($_.Exception.Message)"
    }
    Pause-Script
}

function Install-RSAT {
    try {
        Clear-Host
        Write-Host "=== RSAT Tools installieren ===" -ForegroundColor Cyan
        
        if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Warning "Diese Funktion erfordert Administratorrechte!"
            Pause-Script; return
        }
        
        Write-Host "Installiere RSAT-Tools..." -ForegroundColor Yellow
        
        $features = @(
            "RSAT.ActiveDirectory.DS-LDS.Tools",
            "RSAT.DHCP.Tools",
            "RSAT.DNS.Tools",
            "RSAT.FileServices.Tools",
            "RSAT.GroupPolicy.Management.Tools"
        )

        $successCount = 0
        foreach ($feature in $features) {
            Write-Host "Installiere $feature..." -ForegroundColor Gray
            $result = Add-WindowsCapability -Online -Name $feature -ErrorAction SilentlyContinue
            if ($result -and $result.State -eq 'Installed') {
                Write-Host "  OK: $feature" -ForegroundColor Green
                $successCount++
            } else {
                Write-Warning "  Konnte nicht installiert werden: $feature"
            }
        }

        if ($successCount -eq $features.Count) {
            Write-Host "`nAlle RSAT-Tools wurden erfolgreich installiert!" -ForegroundColor Green
        } else {
            Write-Host "`n$successCount von $($features.Count) RSAT-Tools wurden installiert." -ForegroundColor Yellow
        }
        
    } catch {
        Write-Warning "Fehler bei der RSAT-Installation: $($_.Exception.Message)"
    }
    Pause-Script
}

function Install-OpenSSH {
    try {
        Clear-Host
        Write-Host "=== OpenSSH-Server installieren ===" -ForegroundColor Cyan
        
        if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Warning "Diese Funktion erfordert Administratorrechte!"
            Pause-Script; return
        }
        
        $sshInstalled = Get-WindowsCapability -Online | Where-Object {$_.Name -like 'OpenSSH.Server*' -and $_.State -eq 'Installed'}
        if ($sshInstalled) {
            Write-Host "OpenSSH-Server ist bereits installiert" -ForegroundColor Yellow
            Pause-Script; return
        }

        Write-Host "Installiere OpenSSH-Server..." -ForegroundColor Yellow
        $result = Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
        
        if ($result.State -eq 'Installed') {
            Start-Service sshd
            Set-Service -Name sshd -StartupType 'Automatic'
            Write-Host "OpenSSH-Server erfolgreich installiert und gestartet" -ForegroundColor Green
            Write-Host "Zugriff per: ssh $env:COMPUTERNAME" -ForegroundColor Gray
        } else {
            Write-Warning "OpenSSH-Server konnte nicht installiert werden"
        }
        
    } catch {
        Write-Warning "Fehler bei der OpenSSH-Installation: $($_.Exception.Message)"
    }
    Pause-Script
}

function Install-SNMP {
    try {
        Clear-Host
        Write-Host "=== SNMP-Dienst installieren ===" -ForegroundColor Cyan
        
        if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Warning "Diese Funktion erfordert Administratorrechte!"
            Pause-Script; return
        }
        
        if (Get-WindowsFeature -Name SNMP-Service | Where-Object {$_.InstallState -eq 'Installed'}) {
            Write-Host "SNMP-Dienst ist bereits installiert" -ForegroundColor Yellow
            Pause-Script; return
        }

        Write-Host "Installiere SNMP-Dienst..." -ForegroundColor Yellow
        $result = Install-WindowsFeature -Name SNMP-Service, SNMP-WMI-Provider
        
        if ($result.Success) {
            Set-Service -Name SNMP -StartupType 'Automatic'
            Start-Service -Name SNMP
            Write-Host "SNMP-Dienst erfolgreich installiert und gestartet" -ForegroundColor Green
            Write-Host "Hinweis: SNMP-Community-Strings muessen noch konfiguriert werden" -ForegroundColor Yellow
        } else {
            Write-Warning "SNMP-Dienst konnte nicht installiert werden"
        }
        
    } catch {
        Write-Warning "Fehler bei der SNMP-Installation: $($_.Exception.Message)"
    }
    Pause-Script
}

function Show-RequirementsMenu {
    do {
        Clear-Host
        Write-Host "=== Voraussetzungen installieren ===" -ForegroundColor Cyan
        Write-Host "1: RSAT Tools installieren"
        Write-Host "2: OpenSSH-Server installieren"
        Write-Host "3: SNMP-Dienst installieren"
        Write-Host "4: IIS Webserver installieren"
        Write-Host "5: Sysinternals Tools herunterladen"
        Write-Host "6: PowerShell konfigurieren"
        Write-Host "7: ALLE Voraussetzungen installieren"
        Write-Host "8: Installationsstatus pruefen"
        Write-Host "Q: Zurueck zum Hauptmenue"
        
        $choice = Read-Host "`nIhre Auswahl"
        
        switch ($choice) {
            "1" { Install-RSAT }
            "2" { Install-OpenSSH }
            "3" { Install-SNMP }
            "4" { Install-IIS }
            "5" { Install-Sysinternals }
            "6" { Set-PowerShellConfiguration }
            "7" { Install-AllPrerequisites }
            "8" { Test-Requirements }
            "Q" { return }
            default { Write-Warning "Ungueltige Auswahl"; Pause-Script }
        }
    } while ($true)
}

function Initialize-Sysinternals {
    if (-not (Test-Path $SysinternalsPath)) {
        Write-Host "Sysinternals Suite wird heruntergeladen..." -ForegroundColor Yellow
        try {
            Invoke-WebRequest -Uri $SysinternalsUrl -OutFile $SysinternalsZip -UseBasicParsing
            if (!(Test-Path (Split-Path $SysinternalsPath))) { New-Item -ItemType Directory -Path (Split-Path $SysinternalsPath) -Force | Out-Null }
            Expand-Archive -Path $SysinternalsZip -DestinationPath $SysinternalsPath -Force
            Remove-Item $SysinternalsZip -Force
            Write-Host "Sysinternals Suite installiert nach: $SysinternalsPath" -ForegroundColor Green
        } catch {
            Write-Warning "Download/Installation der Sysinternals Suite fehlgeschlagen: $($_.Exception.Message)"
        }
    }
}

function Start-SysinternalsTool {
    param([Parameter(Mandatory=$true)][string]$ExeName)
    Initialize-Sysinternals
    $exe = Join-Path $SysinternalsPath $ExeName
    if (Test-Path $exe) { Start-Process $exe } else { Write-Warning "Tool nicht gefunden: $exe" }
}

function Install-Sysinternals {
    try {
        Clear-Host
        Write-Host "=== Sysinternals Tools herunterladen ===" -ForegroundColor Cyan
        
        $sysinternalsPath = "C:\Tools\Sysinternals"
        if (Test-Path $sysinternalsPath) {
            Write-Host "Sysinternals-Tools sind bereits vorhanden in: $sysinternalsPath" -ForegroundColor Yellow
            Pause-Script; return
        }

        Write-Host "Lade Sysinternals-Tools herunter..." -ForegroundColor Yellow
        New-Item -Path $sysinternalsPath -ItemType Directory -Force | Out-Null
        $url = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
        $zipPath = "$env:TEMP\SysinternalsSuite.zip"
        Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing
        Expand-Archive -Path $zipPath -DestinationPath $sysinternalsPath -Force
        Remove-Item -Path $zipPath -Force
        Write-Host "Sysinternals-Tools erfolgreich nach $sysinternalsPath heruntergeladen" -ForegroundColor Green
        Write-Host "Tools verfuegbar in: $sysinternalsPath" -ForegroundColor Gray
    } catch {
        Write-Warning "Fehler beim Herunterladen der Sysinternals-Tools: $($_.Exception.Message)"
    }
    Pause-Script
}

function Set-PowerShellConfiguration {
    try {
        Clear-Host
        Write-Host "=== PowerShell konfigurieren ===" -ForegroundColor Cyan
        
        if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Warning "Diese Funktion erfordert Administratorrechte!"
            Pause-Script; return
        }
        
        Write-Host "Setze Ausfuehrungsrichtlinie auf 'RemoteSigned'..." -ForegroundColor Gray
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
        
        Write-Host "Aktiviere PowerShell-Remoting..." -ForegroundColor Gray
        Enable-PSRemoting -Force
        
        Write-Host "PowerShell erfolgreich konfiguriert!" -ForegroundColor Green
        Write-Host "• ExecutionPolicy: RemoteSigned" -ForegroundColor Gray
        Write-Host "• PowerShell-Remoting: Aktiviert" -ForegroundColor Gray
    } catch {
        Write-Warning "Fehler bei der PowerShell-Konfiguration: $($_.Exception.Message)"
    }
    Pause-Script
}

function Install-AllPrerequisites {
    try {
        Clear-Host
        Write-Host "=== ALLE Voraussetzungen installieren ===" -ForegroundColor Cyan
        
        if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Warning "Diese Funktion erfordert Administratorrechte!"
            Pause-Script; return
        }
        
        Write-Host "Installiere alle Voraussetzungen..." -ForegroundColor Yellow
        Install-RSAT
        Install-OpenSSH
        Install-SNMP
        Install-IIS
        Install-Sysinternals
        Set-PowerShellConfiguration
        
        Write-Host "`n=== Alle Voraussetzungen installiert! ===" -ForegroundColor Green
    } catch {
        Write-Warning "Fehler bei der Installation: $($_.Exception.Message)"
    }
    Pause-Script
}

function Test-Requirements {
    Clear-Host
    Write-Host "=== Installationsstatus pruefen ===" -ForegroundColor Cyan
    
    Write-Host "`nPruefe installierte Komponenten...`n" -ForegroundColor Yellow
    
    $rsatInstalled = Get-WindowsCapability -Name RSAT* -Online | Where-Object {$_.State -eq 'Installed'}
    Write-Host "RSAT Tools:" -ForegroundColor Gray -NoNewline
    if ($rsatInstalled) { Write-Host " OK ($($rsatInstalled.Count) Features)" -ForegroundColor Green }
    else { Write-Host " Nicht installiert" -ForegroundColor Red }
    
    $sshInstalled = Get-WindowsCapability -Online | Where-Object {$_.Name -like 'OpenSSH.Server*' -and $_.State -eq 'Installed'}
    Write-Host "OpenSSH Server:" -ForegroundColor Gray -NoNewline
    if ($sshInstalled) { Write-Host " OK" -ForegroundColor Green }
    else { Write-Host " Nicht installiert" -ForegroundColor Red }
    
    $snmpInstalled = Get-WindowsFeature -Name SNMP-Service | Where-Object {$_.InstallState -eq 'Installed'}
    Write-Host "SNMP Dienst:" -ForegroundColor Gray -NoNewline
    if ($snmpInstalled) { Write-Host " OK" -ForegroundColor Green }
    else { Write-Host " Nicht installiert" -ForegroundColor Red }
    
    $iisInstalled = Get-WindowsFeature -Name Web-Server | Where-Object {$_.InstallState -eq 'Installed'}
    Write-Host "IIS Webserver:" -ForegroundColor Gray -NoNewline
    if ($iisInstalled) { Write-Host " OK" -ForegroundColor Green }
    else { Write-Host " Nicht installiert" -ForegroundColor Red }
    
    $sysinternalsPath = "C:\Tools\Sysinternals"
    Write-Host "Sysinternals Tools:" -ForegroundColor Gray -NoNewline
    if (Test-Path $sysinternalsPath) { Write-Host " OK" -ForegroundColor Green }
    else { Write-Host " Nicht vorhanden" -ForegroundColor Red }
    
    $executionPolicy = Get-ExecutionPolicy -Scope LocalMachine
    Write-Host "ExecutionPolicy:" -ForegroundColor Gray -NoNewline
    if ($executionPolicy -eq "RemoteSigned") { Write-Host " OK" -ForegroundColor Green }
    else { Write-Host " $executionPolicy" -ForegroundColor Yellow }
    
    Write-Host "`nPruefung abgeschlossen." -ForegroundColor Yellow
    Pause-Script
}

# --------------------------
# Active Directory – Funktionen
# --------------------------
function New-ADUser {
    try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Warning "ActiveDirectory-Modul nicht vorhanden. Bitte RSAT installieren."
            Pause-Script; return
        }
        Import-Module ActiveDirectory -ErrorAction Stop

        $sam = Read-Host "SAM-AccountName (z.B. m.mueller)"
        $given = Read-Host "Vorname"
        $sn = Read-Host "Nachname"
        $ou = Read-Host "OU (LDAP-Pfad, z.B. OU=Users,DC=contoso,DC=local)"
        $InitialPassword = Read-Host "Initialpasswort" -AsSecureString

        if (-not $sam -or -not $given -or -not $sn -or -not $ou) { Write-Warning "Eingaben unvollstaendig."; Pause-Script; return }

        New-ADUser -Name "$given $sn" -SamAccountName $sam -GivenName $given -Surname $sn -Path $ou -AccountPassword $InitialPassword -Enabled $true
        Write-Host "Benutzer '$sam' angelegt." -ForegroundColor Green
    } catch {
        Write-Warning "Fehler beim Anlegen des Benutzers: $($_.Exception.Message)"
    }
    Pause-Script
}

function New-ADGroup {
    try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Warning "ActiveDirectory-Modul nicht vorhanden. Bitte RSAT installieren."
            Pause-Script; return
        }
        Import-Module ActiveDirectory -ErrorAction Stop

        $name = Read-Host "Gruppenname"
        $ou = Read-Host "OU (LDAP-Pfad, z.B. OU=Groups,DC=contoso,DC=local)"
        if (-not $name -or -not $ou) { Write-Warning "Eingaben unvollstaendig."; Pause-Script; return }

        New-ADGroup -Name $name -GroupScope Global -GroupCategory Security -Path $ou
        Write-Host "Gruppe '$name' angelegt." -ForegroundColor Green
    } catch {
        Write-Warning "Fehler beim Anlegen der Gruppe: $($_.Exception.Message)"
    }
    Pause-Script
}

function New-ADUserWithGroup {
    try {
        if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
            Write-Warning "ActiveDirectory-Modul nicht vorhanden. Bitte RSAT installieren."
            Pause-Script; return
        }
        Import-Module ActiveDirectory -ErrorAction Stop

        $sam = Read-Host "SAM-AccountName"
        $given = Read-Host "Vorname"
        $sn = Read-Host "Nachname"
        $ouUser = Read-Host "OU fuer Benutzer (LDAP-Pfad)"
        $ouGroup = Read-Host "OU fuer Gruppe (LDAP-Pfad)"
        $grp = Read-Host "Gruppenname"
        $InitialPassword = Read-Host "Initialpasswort" -AsSecureString

        if (-not $sam -or -not $given -or -not $sn -or -not $ouUser -or -not $ouGroup -or -not $grp) { Write-Warning "Eingaben unvollstaendig."; Pause-Script; return }

        if (-not (Get-ADGroup -Filter "Name -eq '$grp'" -ErrorAction SilentlyContinue)) {
            New-ADGroup -Name $grp -GroupScope Global -GroupCategory Security -Path $ouGroup | Out-Null
            Write-Host "Gruppe '$grp' angelegt." -ForegroundColor Green
        }

        New-ADUser -Name "$given $sn" -SamAccountName $sam -GivenName $given -Surname $sn -Path $ouUser -AccountPassword $InitialPassword -Enabled $true
        Add-ADGroupMember -Identity $grp -Members $sam
        Write-Host "Benutzer '$sam' angelegt und zu '$grp' hinzugefuegt." -ForegroundColor Green
    } catch {
        Write-Warning "Fehler bei Benutzer- und Gruppenerstellung: $($_.Exception.Message)"
    }
    Pause-Script
}

# =============================
# Fehlerbehebungsfunktionen
# =============================
function Repair-SystemFiles {
    Write-Host "`n[Systemdateien pruefen & reparieren]" -ForegroundColor Cyan
    sfc /scannow
    Write-Host "`nBei Fehlern: DISM /Online /Cleanup-Image /RestoreHealth" -ForegroundColor Yellow
    Pause-Script
}

function Repair-DriversAndHardware {
    Write-Host "`n[Treiber & Hardware pruefen]" -ForegroundColor Cyan
    Write-Host " - Geraete-Manager: devmgmt.msc"
    chkdsk C: /scan
    Pause-Script
}

function Repair-Network {
    Write-Host "`n[Netzwerk & DNS reparieren]" -ForegroundColor Cyan
    netsh int ip reset
    netsh winsock reset
    ipconfig /flushdns
    Test-Connection google.com -Count 2
    Pause-Script
}

function Repair-MemoryAndPerformance {
    Write-Host "`n[Speicher & Leistung pruefen]" -ForegroundColor Cyan
    Write-Host " - Windows-Speicherdiagnose: mdsched.exe"
    Write-Host " - Performance-Monitor: perfmon"
    Get-Process | Sort-Object CPU -Descending | Select-Object -First 10
    Pause-Script
}

function Repair-EventLogAnalysis {
    Write-Host "`n[Eventlogs analysieren]" -ForegroundColor Cyan
    Get-WinEvent -LogName System | Where-Object { $_.Level -le 2 } | Select-Object TimeCreated, Id, ProviderName, Message -First 20
    Pause-Script
}

function Repair-AutomatedTroubleshooters {
    Write-Host "`n[Automatische Problembehandlung]" -ForegroundColor Cyan
    Write-Host "WindowsUpdate: msdt.exe /id WindowsUpdateDiagnostic"
    Write-Host "Netzwerk: msdt.exe /id NetworkDiagnosticsNetworkAdapter"
    Write-Host "Audio: msdt.exe /id AudioPlaybackDiagnostic"
    Write-Host "Bluescreen: msdt.exe /id BlueScreenDiagnostic"
    Pause-Script
}

function Repair-RegistryAndAdvanced {
    Write-Host "`n[Registry & erweiterte Analyse]" -ForegroundColor Cyan
    Get-WinEvent -LogName Application -MaxEvents 5 | Format-List
    Pause-Script
}

function Repair-SystemRestore {
    Write-Host "`n[Systemwiederherstellung & Backup]" -ForegroundColor Cyan
    Write-Host "Systemwiederherstellung: rstrui.exe"
    Pause-Script
}

function Show-FixMenu {
    do {
        Clear-Host
        Write-Host "`n==== Allgemeine Fehlerbehebung ====" -ForegroundColor Magenta
        Write-Host "1: Systemdateien pruefen & reparieren"
        Write-Host "2: Treiber & Hardware pruefen"
        Write-Host "3: Netzwerk & DNS zuruecksetzen"
        Write-Host "4: Speicher & Leistung pruefen"
        Write-Host "5: Eventlogs analysieren"
        Write-Host "6: Automatische Problembehandlungen"
        Write-Host "7: Registry & erweiterte Analyse"
        Write-Host "8: Systemwiederherstellung & Backup"
        Write-Host "Q: Zurueck"
        
        $choice = Read-Host "`nIhre Auswahl"
        
        switch ($choice) {
            "1" { Repair-SystemFiles }
            "2" { Repair-DriversAndHardware }
            "3" { Repair-Network }
            "4" { Repair-MemoryAndPerformance }
            "5" { Repair-EventLogAnalysis }
            "6" { Repair-AutomatedTroubleshooters }
            "7" { Repair-RegistryAndAdvanced }
            "8" { Repair-SystemRestore }
            "Q" { return }
            default { Write-Warning "Ungueltige Auswahl"; Pause-Script }
        }
    } while ($true)
}

# --------------------------
# Untermenues
# --------------------------
function Show-InstallMenu {
    do {
        Clear-Host
        Write-Host "=== Installieren und Konfigurieren ===" -ForegroundColor Cyan
        Write-Host "1: IIS Webserver installieren"
        Write-Host "2: RSAT Tools installieren"
        Write-Host "3: OpenSSH-Server installieren"
        Write-Host "4: SNMP-Dienst installieren"
        Write-Host "5: Sysinternals Tools verwalten"
        Write-Host "6: PowerShell konfigurieren"
        Write-Host "Q: Zurueck"
        
        $choice = Read-Host "`nIhre Auswahl"
        
        switch ($choice) {
            "1" { Install-IIS }
            "2" { Install-RSAT }
            "3" { Install-OpenSSH }
            "4" { Install-SNMP }
            "5" { Show-SysinternalsMenu }
            "6" { Set-PowerShellConfiguration }
            "Q" { return }
            default { Write-Warning "Ungueltige Auswahl"; Pause-Script }
        }
    } while ($true)
}

function Show-SysinternalsMenu {
    do {
        Clear-Host
        Write-Host "=== Sysinternals Tools ===" -ForegroundColor Cyan
        Write-Host "1: Process Explorer"
        Write-Host "2: TCPView"
        Write-Host "3: Autoruns"
        Write-Host "4: Process Monitor"
        Write-Host "5: BGInfo"
        Write-Host "Q: Zurueck"
        
        $choice = Read-Host "`nIhre Auswahl"
        
        switch ($choice) {
            "1" { Start-SysinternalsTool -ExeName "procexp.exe"; Pause-Script }
            "2" { Start-SysinternalsTool -ExeName "tcpview.exe"; Pause-Script }
            "3" { Start-SysinternalsTool -ExeName "autoruns.exe"; Pause-Script }
            "4" { Start-SysinternalsTool -ExeName "procmon.exe"; Pause-Script }
            "5" { Start-SysinternalsTool -ExeName "bginfo.exe"; Pause-Script }
            "Q" { return }
            default { Write-Warning "Ungueltige Auswahl"; Pause-Script }
        }
    } while ($true)
}

function Show-NetworkMenu {
    do {
        Clear-Host
        Write-Host "=== Netzwerk Konfiguration ===" -ForegroundColor Cyan
        Write-Host "1: IP-Konfiguration setzen"
        Write-Host "2: VLAN-Konfiguration"
        Write-Host "3: Netzwerkadapter anzeigen"
        Write-Host "Q: Zurueck"
        
        $choice = Read-Host "`nIhre Auswahl"
        
        switch ($choice) {
            "1" { Set-NetworkConfig }
            "2" { Set-VlanTag }
            "3" { Show-NetworkAdapters }
            "Q" { return }
            default { Write-Warning "Ungueltige Auswahl"; Pause-Script }
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
            default { Write-Warning "Ungueltige Auswahl"; Pause-Script }
        }
    } while ($true)
}

# --------------------------
# Hauptmenue
# --------------------------
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
        Write-Host "8: Drucker installieren"
        Write-Host "9: Voraussetzungen installieren"
        Write-Host "10: Allgemeine Fehlerbehebung"
        Write-Host "Q: Beenden"
        
        $choice = Read-Host "`nIhre Auswahl"
        
        switch ($choice) {
            "1"  { Show-SystemInfo }
            "2"  { Show-InstallMenu }
            "3"  { Test-NetworkAndServices }
            "4"  { Invoke-Updates }
            "5"  { Show-ADMenu }
            "6"  { Show-SystemErrors }
            "7"  { Show-NetworkMenu }
            "8"  { Install-PrinterByRoom }
            "9"  { Show-RequirementsMenu }
            "10" { Show-FixMenu }
            "Q"  {
                Write-Host "Admin-Toolkit wird beendet. Tschuess." -ForegroundColor Cyan
                exit
            }
            default {
                Write-Warning "Ungueltige Auswahl"
                Pause-Script
            }
        }
    } while ($true)
}

# ----- Skriptstart -----
Show-MainMenu
