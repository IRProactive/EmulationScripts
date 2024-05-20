# Ransomware Post-Exploitation Impair Defneses (Simulates disabling secuirty controls and logging)
# Gerard Johansen
# May 13, 2024

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

# System Discovery
Invoke-AtomicTest T1033 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1033 -TestNumbers 1

# Security Software Discovery AV Discovery via WMI
Invoke-AtomicTest T1518.001 -TestNumbers 7 -GetPrereqs
Invoke-AtomicTest T1518.001 -TestNumbers 7

# Tamper with Windows Defender ATP PowerShell
Invoke-AtomicTest T1562.001 -TestNumbers 16 -GetPrereqs
Invoke-AtomicTest T1562.001 -TestNumbers 16

# Disable Microsoft Defender Firewall via Registry
Invoke-AtomicTest T1562.004 -TestNumbers 2 -GetPrereqs
Invoke-AtomicTest T1562.004 -TestNumbers 2

# Disable Event Logging with Phantom
Invoke-AtomicTest T1562.002 -TestNumbers 7 -GetPrereqs
Invoke-AtomicTest T1562.002 -TestNumbers 7







