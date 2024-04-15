# Sysmon Testing Emulation plan
# By Gerard Johansen
# For BSIDES Charm 
# For examining example Sysmon log files

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

# Sysmon Event ID 1: Process Creation
# T1218.011 Signed Binary Proxy Execution: RunDll32

Invoke-AtomicTest T1218.011 -TestNumbers 11 -GetPrereqs
Invoke-AtomicTest T1218.011 -TestNumbers 11

# Sysmon Event ID 2: A Process Changed A File Creation Time
# T1070.006 Indicator Removal on Host: Timestomp

Invoke-AtomicTest T1070.006 -TestNumbers 5 -GetPrereqs
Invoke-AtomicTest T1070.006 -TestNumbers 5

# Sysmon Event ID 3: Network Connection
# T1105 Ingress Tool Transfer
Invoke-AtomicTest T1105 -TestNumbers 7 -GetPrereqs
Invoke-AtomicTest T1105 -TestNumbers 7

# Sysmon Event ID 5: Process Terminated
# T1489 Service Stop

Invoke-AtomicTest -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest -TestNumbers 1 

# Sysmon Event ID 6: Driver Loaded
# T1547 Boot or Logon Autostart Execution
Invoke-AtomicTest T1547 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1547 -TestNumbers 1

# Sysmon Event ID 7: Image Loaded
# T1574.002 DLL Side-Loading

Invoke-AtomicTest T1574.002 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1574.002 -TestNumbers 1

# Sysmon Event ID 8: CreateRemoteThread
# T1055.001 Process Injection: DLL Injection
Invoke-AtomicTest T1055.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1055.001 -TestNumbers 1

# Sysmon Event ID 9: RawAccessRead
# No test identified

# Sysmon Event ID 10: ProcessAccess
# T1059.001
Invoke-AtomicTest T1059.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1

# Sysmon Event ID 11: File Creation Events
# T1197
Invoke-AtomicTest T1197 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1197 -TestNumbers 1

#Sysmon Event IDs 12, 13, 14: Registry 
# T1112 Modify Registry - BlackByte Ransomware
Invoke-AtomicTest T1112 -TestNumbers 7 -GetPrereqs
Invoke-AtomicTest T1112 -TestNumbers

# Sysmon Event ID 15: FileCreateStreamHash
# T1105 Ingress Tool Transfer
Invoke-AtomicTest T1105 -TestNumbers 29 -GetPrereqs
Invoke-AtomicTest T1105 -TestNumbers 29

# Sysmon Event ID 16: Sysmon Config Changed
# No test identified - See Sysmon Event ID 4: Sysmon Service State Changed

# Sysmon Event ID 17, 18: Pipe Events
# T1134.001 Access Token Manipulation
Invoke-AtomicTest T1134.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1134.001 -TestNumbers

# Sysmon Event ID 19, 20, 21: WMI Event Consumer
# T1546.003 Event Triggered Subscription
Invoke-AtomicTest T1546.003 -TestNumbers 2 -GetPrereqs
Invoke-AtomicTest T1546.003 -TestNumbers 2

# Sysmon Event ID 22: DNS Events
# T1566.001 Spear Phising Attachment
Invoke-AtomicTest T1566.001 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1566.001 -TestNumbers 1

#Sysmon Event ID 29: FileExecutableDetected

Invoke-WebRequest 'https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe' -OutFile C:\Sharphound.exe

# Sysmon Event ID 4: Sysmon Service State Changed

Invoke-AtomicTest T1562.001 -TestNumbers 11 -GetPrereqs
Invoke-AtomicTest T1562.001 -TestNumbers 11

