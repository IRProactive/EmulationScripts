# Akira Ransomware Threat Emulation
# Gerard Johansen
# May 7, 2024
# https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a
# https://www.cisa.gov/sites/default/files/2024-04/aa24-109a-stopransomware-akira-ransomware_2.pdf

# Install Invoke Atomic Test harness and Atomic Red Team

Set-ExecutionPolicy Bypass -Force

function Test-Administrator  
{  
    [OutputType([bool])]
    param()
    process {
        [Security.Principal.WindowsPrincipal]$user = [Security.Principal.WindowsIdentity]::GetCurrent();
        return $user.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator);
    }
}

if(-not (Test-Administrator))
{
    Write-Error "This script must be executed as Administrator.";
    exit 1;
}

$Logfile = $MyInvocation.MyCommand.Path -replace '\.ps1$', '.log'
Start-Transcript -Path $Logfile

if (Test-Path "C:\AtomicRedTeam\") {
   Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
}
else {
  IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1'); Install-AtomicRedTeam -getAtomics -Force
  Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
}

# Valid Accounts - Akira threat actors obtain and abuse credentials of existing accounts as a means of gaining initial access.
Invoke-AtomicTest T1078.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1078.001 -TestNumbers 1 

# Phishing: Spearphishing Attachment - Akira threat actors use phishing emails with malicious attachments to gain access to networks.
Invoke-AtomicTest T1566.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1566.001 -TestNumbers 1

# OS Credential Dumping: LSASS Memory - Akira threat actors attempt to access credential material stored in the process memory of the LSASS.
Invoke-AtomicTest T1003.001 -TestNumbers 10 -GetPrereqs
Invoke-AtomicTest T1003.001 -TestNumbers 10

# System Network Configuration Discovery - Akira threat actors use tools to scan systems and identify services running on remote hosts and local network infrastructure.
Invoke-AtomicTest T1016 -TestNumbers 1,5 -GetPrereqs
Invoke-AtomicTest T1016 -TestNumbers 1,5

# System Information Discovery - Akira threat actors use tools like PCHunter64 to acquire detailed process and system information.
Invoke-AtomicTest T1082 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1082 -TestNumbers 1 

# Domain Trust Discovery - Akira threat actors use the net Windows command to enumerate domain information.
Invoke-AtomicTest T1482 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1482 -TestNumbers 1

# Process Discovery - Akira threat actors use the Tasklist utility to obtain details on running processes via PowerShell.
Invoke-AtomicTest T1057 -TestNumbers 2 -GetPrereqs
Invoke-AtomicTest T1057 -TestNumbers 2

# Permission Groups Discovery: Local Groups - Akira threat actors use the net localgroup /dom to find local system groups and permission settings.
Invoke-AtomicTest T1069.001 -TestNumbers 2 -GetPrereqs
Invoke-AtomicTest T1069.001 -TestNumbers 2

# Permission Groups Discovery: Domain Groups - Akira threat actors use the net group /domain command to attempt to find domain level groups and permission settings.
Invoke-AtomicTest T1069.002 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1069.002 -TestNumbers 1

# Remote System Discovery - Akira threat actors use nltest / dclist to amass a listing of other systems by IP address, hostname, or other logical identifiers on a network.
Invoke-AtomicTest T1018 -TestNumbers 3 -GetPrereqs
Invoke-AtomicTest T1018 -TestNumbers 3

# Create Account: Domain Account - Akira threat actors attempt to abuse the functions of domain controllers by creating new domain accounts to establish persistence.
Invoke-AtomicTest T1136.002 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1136.002 -TestNumbers 1

# Impair Defenses: Disable or Modify Tools - Akira threat actors use BYOVD attacks to disable antivirus software.
Invoke-AtomicTest T1562.001 -TestNumbers 29 -GetPrereqs
Invoke-AtomicTest T1562.001 -TestNumbers 29

# Remote Access Software - Akira threat actors use legitimate desktop support software like AnyDesk to obtain remote access to victim systems.
Invoke-AtomicTest T1219 -TestNumbers 2 -GetPrereqs
Invoke-AtomicTest T1219 -TestNumbers 2

# Archive Collected Data: Archive via Utility - Akira threat actors use tools like WinRAR to compress files.
Invoke-AtomicTest T1560.001 -TestNumbers 2 -GetPrereqs
Invoke-AtomicTest T1560.001 -TestNumbers 2

# Exfiltration Over Web Service: Exfiltration to Cloud Storage - Akira threat actors leveraged RClone to sync files with cloud storage services to exfiltrate data.
Invoke-AtomicTest T1567.002 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1567.002 -TestNumbers 1

# Date Encrypted for Impact - Akira threat actors encrypt data on target systems to interrupt availability to system and network resources.
Invoke-AtomicTest T1486 -TestNumbers 5 -GetPrereqs
Invoke-AtomicTest T1486 -TestNumbers 5

# Inhibit System Recovery - Akira threat actors delete volume shadow copies on Windows systems.
Invoke-AtomicTest T1490 -TestNumbers 2 -GetPrereqs
Invoke-AtomicTest T1490 -TestNumbers 2 





