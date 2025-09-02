# LOLBin Threat Emulation
# Selected Living off the land Binaries that are used for tool download and process execution.
# Gerard Johansen

# Install Invoke-AtomicRedTeam and tests

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

Start-Transcript -Path "C:\AtomicRedTeam.txt"

# PowerShell is used to execute Base64 encoded payload
Invoke-AtomicTest T1059.001 -TestNumbers 17 -ShowDetails
Invoke-AtomicTest T1059.001 -TestNumbers 17 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 17

# BitsAdmin used to download secondary payload
Invoke-AtomicTest T1105 -TestNumbers 9 -ShowDetails
Invoke-AtomicTest T1105 -TestNumbers 9 -GetPrereqs
Invoke-AtomicTest T1105 -TestNumbers 9

# CertUtil used to download secondary payload
Invoke-AtomicTest T1105 -TestNumbers 7 -ShowDetails
Invoke-AtomicTest T1105 -TestNumbers 7 -GetPrereqs
Invoke-AtomicTest T1105 -TestNumbers 7

# Certreq is used to download a malicious binary
Invoke-AtomicTest T1105 -TestNumbers 25 -ShowDetails
Invoke-AtomicTest T1105 -TestNumbers 25 -GetPrereqs
Invoke-AtomicTest T1105 -TestNumbers 25

# DLL Proxy using RunDLL32 
Invoke-AtomicTest T1218.011 -TestNumbers 3 -ShowDetails
Invoke-AtomicTest T1218.011 -TestNumbers 3 -GetPrereqs
Invoke-AtomicTest T1218.011 -TestNumbers 3

# RegSVR32 used to register a Non DLL file observed in the Gozi maldoc file.
Invoke-AtomicTest T1218.010 -TestNumbers 4 -ShowDetails
Invoke-AtomicTest T1218.010 -TestNumbers 4 -GetPrereqs
Invoke-AtomicTest T1218.010 -TestNumbers 4

# Execute a Local MSI file with MSIEXEC 
Invoke-AtomicTest T1218.007 -TestNumbers 4 -ShowDetails
Invoke-AtomicTest T1218.007 -TestNumbers 4 -GetPrereqs
Invoke-AtomicTest T1218.007 -TestNumbers 4

# MSHTA used to download additional payload
Invoke-AtomicTest T1059.001 -TestNumbers 8 -ShowDetails
Invoke-AtomicTest T1059.001 -TestNumbers 8 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 8

# WMIC used to execute a local process
Invoke-AtomicTest T1047 -TestNumbers 5 -ShowDetails
Invoke-AtomicTest T1047 -TestNumbers 5 -GetPrereqs
Invoke-AtomicTest T1047 -TestNumbers 5

# MSIEXEC is used to execute a local MSI file with embedded EXE
Invoke-AtomicTest T1218.007 -TestNumbers 4 -ShowDetails
Invoke-AtomicTest T1218.007 -TestNumbers 4 -GetPrereqs
Invoke-AtomicTest T1218.007 -TestNumbers 4

Stop-Transcript