
# defensive_script.ps1

param (
    [string]$TargetIp
)

# Define log files and alert recipient
$MONITOR_LOG = "C:\Logs\monitor.log"
$ALERT_EMAIL = "admin@example.com"
$SOUND_FILE = "C:\path\to\zombie_alert.wav"

# Function to log messages with timestamp
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[INFO] $timestamp - $message"
    Write-Host $logMessage
    Add-Content -Path $MONITOR_LOG -Value $logMessage
}

# Function to play sound alert
function Play-SoundAlert {
    if (Test-Path $SOUND_FILE) {
        [System.Media.SoundPlayer]::new($SOUND_FILE).PlaySync()
    } else {
        Log-Message "Sound file $SOUND_FILE not found!"
    }
}

# Function to send alert with color and sound
function Send-Alert {
    param (
        [string]$message
    )
    $message = "Security Alert: $message"
    Send-MailMessage -To $ALERT_EMAIL -Subject "Security Alert" -Body $message -SmtpServer "smtp.example.com"
    Write-Host -ForegroundColor Red -BackgroundColor White $message
    Play-SoundAlert
}

# Function to install dependencies
function Install-Dependencies {
    Log-Message "Checking and installing dependencies..."
    $dependencies = @("Wireshark", "Sysinternals", "Sysmon", "nmap", "OpenSSH")

    foreach ($dep in $dependencies) {
        if (-not (Get-Command $dep -ErrorAction SilentlyContinue)) {
            Log-Message "Installing $dep..."
            # Add installation command for each dependency
            # Example: Install-WindowsFeature -Name $dep
        } else {
            Log-Message "$dep is already installed."
        }
    }
}

# Function to block an IP address using Windows Firewall
function Block-IP {
    param (
        [string]$ip
    )
    Log-Message "Blocking IP address $ip..."
    New-NetFirewallRule -DisplayName "Block $ip" -Direction Inbound -RemoteAddress $ip -Action Block
    Log-Message "IP address $ip blocked."
}

# Function to monitor network traffic for port scans and anomalies
function Monitor-Network {
    Log-Message "Monitoring network traffic for port scans and anomalies on $TargetIp..."
    Start-Process -FilePath "tshark.exe" -ArgumentList "-i 1 -f 'host $TargetIp and (tcp[tcpflags] & (tcp-syn) != 0 or icmp)' -w C:\Logs\network_traffic.pcap"
}

# Function to monitor for DoS attacks
function Monitor-DosAttacks {
    Log-Message "Monitoring for DoS attacks on $TargetIp..."
    Start-Process -FilePath "tshark.exe" -ArgumentList "-i 1 -f 'host $TargetIp and tcp' -w C:\Logs\dos_attacks.pcap" | ForEach-Object {
        $counts = @{}
        foreach ($line in Get-Content -Path "C:\Logs\dos_attacks.pcap") {
            $ip = $line.Split()[1]
            if ($counts.ContainsKey($ip)) {
                $counts[$ip]++
            } else {
                $counts[$ip] = 1
            }
        }
        foreach ($ip in $counts.Keys) {
            if ($counts[$ip] -gt 1000) {
                $message = "Possible DoS attack from IP: $ip with $counts[$ip] connections to $TargetIp"
                Log-Message $message
                Send-Alert $message
                Block-IP $ip
            }
        }
    }
}

# Function to monitor ARP spoofing
function Monitor-ArpSpoofing {
    Log-Message "Monitoring ARP spoofing attempts..."
    # Implement ARP spoofing detection logic using Windows tools
}

# Function to monitor system logs for exploitation attempts
function Monitor-SystemLogs {
    Log-Message "Monitoring system logs for exploitation attempts..."
    Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4624 -or $_.Id -eq 4625 } | ForEach-Object {
        $message = "Suspicious login attempt detected: $($_.Message)"
        Log-Message $message
        Send-Alert $message
    }
}

# Function to monitor web server logs for common attacks
function Monitor-WebLogs {
    Log-Message "Monitoring web server logs for common web attacks on $TargetIp..."
    Get-Content -Path "C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log" -Tail 0 -Wait | ForEach-Object {
        if ($_ -match "$TargetIp" -and ($_ -match "sqlmap" -or $_ -match "union select" -or $_ -match "<script>")) {
            $message = "Possible web attack detected on $TargetIp: $_"
            Log-Message $message
            Send-Alert $message
        }
    }
}

# Function to monitor filesystem changes
function Monitor-Filesystem {
    Log-Message "Monitoring critical filesystem changes..."
    Register-WmiEvent -Query "SELECT * FROM __InstanceOperationEvent WITHIN 10 WHERE TargetInstance ISA 'CIM_DirectoryContainsFile' AND TargetInstance.GroupComponent = 'Win32_Directory.Name="C:\\Windows"' OR TargetInstance.GroupComponent = 'Win32_Directory.Name="C:\\Users"'" -Action {
        $message = "Filesystem change detected: $($event.SourceEventArgs.NewEvent.TargetInstance.PartComponent)"
        Log-Message $message
        Send-Alert $message
    }
}

# Function to detect and disable keyloggers
function Monitor-Keyloggers {
    Log-Message "Monitoring for keyloggers..."
    while ($true) {
        $keyloggers = @("keylogger1.exe", "keylogger2.exe", "keylogger3.exe")
        foreach ($keylogger in $keyloggers) {
            if (Get-Process -Name $keylogger -ErrorAction SilentlyContinue) {
                $message = "Keylogger detected: $keylogger"
                Log-Message $message
                Send-Alert $message
                Stop-Process -Name $keylogger
                Log-Message "Terminated keylogger process: $keylogger"
            }
        }
        Start-Sleep -Seconds 60
    }
}

# Function to perform counter-scan
function Perform-CounterScan {
    Log-Message "Performing counter-scan to detect potential scanning attempts..."
    while ($true) {
        Start-Process -FilePath "nmap.exe" -ArgumentList "-p- --unprivileged -sS -T0 --scan-delay 1s -oN C:\Logs\nmap_counter_scan.txt $TargetIp"
        $scanResults = Get-Content -Path "C:\Logs\nmap_counter_scan.txt" | Select-String -Pattern "Host is up"
        
        if ($scanResults) {
            $message = "Potential scanning detected: $scanResults"
            Log-Message $message
            Send-Alert $message
        }

        Start-Sleep -Seconds 300
    }
}

# Main script execution
function Main {
    Log-Message "Defensive script started for target IP: $TargetIp."

    Install-Dependencies

    # Start monitoring tasks in background
    Start-Job -ScriptBlock { Monitor-Network }
    Start-Job -ScriptBlock { Monitor-DosAttacks }
    Start-Job -ScriptBlock { Monitor-ArpSpoofing }
    Start-Job -ScriptBlock { Monitor-SystemLogs }
    Start-Job -ScriptBlock { Monitor-WebLogs }
    Start-Job -ScriptBlock { Monitor-Filesystem }
    Start-Job -ScriptBlock { Monitor-Keyloggers }
    Start-Job -ScriptBlock { Perform-CounterScan }

    # Wait for background jobs to complete
    Get-Job | Wait-Job
}

if ($TargetIp) {
    Main
} else {
    Write-Host "Usage: .\defensive_script.ps1 <target-ip>"
}
# defensive_script.ps1

param (
    [string]$TargetIp
)

# Define log files and alert recipient
$MONITOR_LOG = "C:\Logs\monitor.log"
$ALERT_EMAIL = "admin@example.com"
$SOUND_FILE = "C:\path\to\zombie_alert.wav"

# Function to log messages with timestamp
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[INFO] $timestamp - $message"
    Write-Host $logMessage
    Add-Content -Path $MONITOR_LOG -Value $logMessage
}

# Function to play sound alert
function Play-SoundAlert {
    if (Test-Path $SOUND_FILE) {
        [System.Media.SoundPlayer]::new($SOUND_FILE).PlaySync()
    } else {
        Log-Message "Sound file $SOUND_FILE not found!"
    }
}

# Function to send alert with color and sound
function Send-Alert {
    param (
        [string]$message
    )
    $message = "Security Alert: $message"
    Send-MailMessage -To $ALERT_EMAIL -Subject "Security Alert" -Body $message -SmtpServer "smtp.example.com"
    Write-Host -ForegroundColor Red -BackgroundColor White $message
    Play-SoundAlert
}

# Function to install dependencies
function Install-Dependencies {
    Log-Message "Checking and installing dependencies..."
    $dependencies = @("Wireshark", "Sysinternals", "Sysmon", "nmap", "OpenSSH")

    foreach ($dep in $dependencies) {
        if (-not (Get-Command $dep -ErrorAction SilentlyContinue)) {
            Log-Message "Installing $dep..."
            # Add installation command for each dependency
            # Example: Install-WindowsFeature -Name $dep
        } else {
            Log-Message "$dep is already installed."
        }
    }
}

# Function to block an IP address using Windows Firewall
function Block-IP {
    param (
        [string]$ip
    )
    Log-Message "Blocking IP address $ip..."
    New-NetFirewallRule -DisplayName "Block $ip" -Direction Inbound -RemoteAddress $ip -Action Block
    Log-Message "IP address $ip blocked."
}

# Function to monitor network traffic for port scans and anomalies
function Monitor-Network {
    Log-Message "Monitoring network traffic for port scans and anomalies on $TargetIp..."
    Start-Process -FilePath "tshark.exe" -ArgumentList "-i 1 -f 'host $TargetIp and (tcp[tcpflags] & (tcp-syn) != 0 or icmp)' -w C:\Logs\network_traffic.pcap"
}

# Function to monitor for DoS attacks
function Monitor-DosAttacks {
    Log-Message "Monitoring for DoS attacks on $TargetIp..."
    Start-Process -FilePath "tshark.exe" -ArgumentList "-i 1 -f 'host $TargetIp and tcp' -w C:\Logs\dos_attacks.pcap" | ForEach-Object {
        $counts = @{}
        foreach ($line in Get-Content -Path "C:\Logs\dos_attacks.pcap") {
            $ip = $line.Split()[1]
            if ($counts.ContainsKey($ip)) {
                $counts[$ip]++
            } else {
                $counts[$ip] = 1
            }
        }
        foreach ($ip in $counts.Keys) {
            if ($counts[$ip] -gt 1000) {
                $message = "Possible DoS attack from IP: $ip with $counts[$ip] connections to $TargetIp"
                Log-Message $message
                Send-Alert $message
                Block-IP $ip
            }
        }
    }
}

# Function to monitor ARP spoofing
function Monitor-ArpSpoofing {
    Log-Message "Monitoring ARP spoofing attempts..."
    # Implement ARP spoofing detection logic using Windows tools
}

# Function to monitor system logs for exploitation attempts
function Monitor-SystemLogs {
    Log-Message "Monitoring system logs for exploitation attempts..."
    Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4624 -or $_.Id -eq 4625 } | ForEach-Object {
        $message = "Suspicious login attempt detected: $($_.Message)"
        Log-Message $message
        Send-Alert $message
    }
}

# Function to monitor web server logs for common attacks
function Monitor-WebLogs {
    Log-Message "Monitoring web server logs for common web attacks on $TargetIp..."
    Get-Content -Path "C:\inetpub\logs\LogFiles\W3SVC1\u_ex*.log" -Tail 0 -Wait | ForEach-Object {
        if ($_ -match "$TargetIp" -and ($_ -match "sqlmap" -or $_ -match "union select" -or $_ -match "<script>")) {
            $message = "Possible web attack detected on $TargetIp: $_"
            Log-Message $message
            Send-Alert $message
        }
    }
}

# Function to monitor filesystem changes
function Monitor-Filesystem {
    Log-Message "Monitoring critical filesystem changes..."
    Register-WmiEvent -Query "SELECT * FROM __InstanceOperationEvent WITHIN 10 WHERE TargetInstance ISA 'CIM_DirectoryContainsFile' AND TargetInstance.GroupComponent = 'Win32_Directory.Name="C:\\Windows"' OR TargetInstance.GroupComponent = 'Win32_Directory.Name="C:\\Users"'" -Action {
        $message = "Filesystem change detected: $($event.SourceEventArgs.NewEvent.TargetInstance.PartComponent)"
        Log-Message $message
        Send-Alert $message
    }
}

# Function to detect and disable keyloggers
function Monitor-Keyloggers {
    Log-Message "Monitoring for keyloggers..."
    while ($true) {
        $keyloggers = @("keylogger1.exe", "keylogger2.exe", "keylogger3.exe")
        foreach ($keylogger in $keyloggers) {
            if (Get-Process -Name $keylogger -ErrorAction SilentlyContinue) {
                $message = "Keylogger detected: $keylogger"
                Log-Message $message
                Send-Alert $message
                Stop-Process -Name $keylogger
                Log-Message "Terminated keylogger process: $keylogger"
            }
        }
        Start-Sleep -Seconds 60
    }
}

# Function to perform counter-scan
function Perform-CounterScan {
    Log-Message "Performing counter-scan to detect potential scanning attempts..."
    while ($true) {
        Start-Process -FilePath "nmap.exe" -ArgumentList "-p- --unprivileged -sS -T0 --scan-delay 1s -oN C:\Logs\nmap_counter_scan.txt $TargetIp"
        $scanResults = Get-Content -Path "C:\Logs\nmap_counter_scan.txt" | Select-String -Pattern "Host is up"
        
        if ($scanResults) {
            $message = "Potential scanning detected: $scanResults"
            Log-Message $message
            Send-Alert $message
        }

        Start-Sleep -Seconds 300
    }
}

# Main script execution
function Main {
    Log-Message "Defensive script started for target IP: $TargetIp."

    Install-Dependencies

    # Start monitoring tasks in background
    Start-Job -ScriptBlock { Monitor-Network }
    Start-Job -ScriptBlock { Monitor-DosAttacks }
    Start-Job -ScriptBlock { Monitor-ArpSpoofing }
    Start-Job -ScriptBlock { Monitor-SystemLogs }
    Start-Job -ScriptBlock { Monitor-WebLogs }
    Start-Job -ScriptBlock { Monitor-Filesystem }
    Start-Job -ScriptBlock { Monitor-Keyloggers }
    Start-Job -ScriptBlock { Perform-CounterScan }

    # Wait for background jobs to complete
    Get-Job | Wait-Job
}

if ($TargetIp) {
    Main
} else {
    Write-Host "Usage: .\defensive_script.ps1 <target-ip>"
}
