# Impacket Threat Emulation
# Gerard Johansen
# May 13, 2024
# https://redcanary.com/blog/threat-intelligence/raspberry-robin/


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

# Command Prompt reads contents from CMD file and execute.

Invoke-AtomicTest T1059.003 -TestNumbers 5 
Invoke-AtomicTest T1059.003 -TestNumbers 5

# Msiexec.exe Executes a Remote MSI File
Invoke-AtomicTest T1218.007 -TestNumbers 11
Invoke-AtomicTest T1218.007 -TestNumbers 11

# Odbcconf.exe Executes arbitrary DLL on disk
Invoke-AtomicTest T1218.008 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1218.008 -TestNumbers 1