<# More information on how to use can be found here

https://overgrowncarrot1.medium.com/macchanger-ps1-b8d2a09bd35c

#>
 
 Write-Host -BackgroundColor black -ForegroundColor green 'Showing Net Adapters, please pick one'
sleep -Seconds 2

Get-NetAdapter

sleep -Seconds 2 
$mac = Read-Host -Prompt 'Adapter to change?'

$confirmation = Read-Host "Do you want a random MAC or do you have one? (Random/MyOwn):"
        if ($confirmation -eq 'Random')
	{
		$change = for($i=1; $i -le 1; $i++){([char[]]([char]'A'..[char]'F') + 0..9 | sort {Get-Random})[0..11] -join ''}

		Set-NetAdapter -Name $mac -MacAddress $change -Confirm:$false

		Write-Host -BackgroundColor black -ForegroundColor green 'Waiting 5 seconds to restart network adapter'
		sleep -Seconds 5

		Write-Host -BackgroundColor black -ForegroundColor green 'Showing Net Adapter'$mac
		Get-NetAdapter -name $mac
	}

	elseif ($confirmation -eq 'MyOwn')
	{
		$mac_address = Read-Host -Prompt 'Mac Address'
		Set-NetAdapter -Name $mac -MacAddress $mac_address -Confirm:$false

		Write-Host -BackgroundColor black -ForegroundColor green 'Waiting 5 seconds to restart network adapter'
		sleep -Seconds 5

		Write-Host -BackgroundColor black -ForegroundColor green 'Showing Net Adapter'$mac
		Get-NetAdapter -name $mac
	}

	else {}

		
