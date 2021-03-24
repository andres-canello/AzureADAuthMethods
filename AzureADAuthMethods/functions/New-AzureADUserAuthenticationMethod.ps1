function New-AzureADUserAuthenticationMethod {
	<#
	.SYNOPSIS
	    Creates a new authentication method for the user.
	.DESCRIPTION
		Creates a new authentication method for the user.
		Use to create a new method type for the user. To modify a method, use Update-AzureADUserAuthenticationMethod.
	.EXAMPLE
	    PS C:\>New-AzureADUserAuthenticationMethod user@contoso.com -Phone -PhoneNumber '+61412345678' -PhoneType mobile
		Adds a new mobile phone authentication method to the user.
	#>
	[CmdletBinding()]
	param (

		[Parameter(Mandatory = $True, ParameterSetName = 'password')]
		[switch]
		$Password,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'securityQuestion')]
		[switch]
		$SecurityQuestion,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'default')]
		[switch]
		$Default,
		
		[Alias('UserId', 'UPN', 'UserPrincipalName')]
		[Parameter(Mandatory = $True, Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$ObjectId,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'phone')]
		[string]
		$PhoneNumber,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'phone')]
		[ValidateSet("mobile", "alternateMobile", "office")]
		[string]
		$PhoneType,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'email', Position = 2)]
		[string]
		$EmailAddress,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'password')]
		[string]
		$NewPassword,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'securityQuestion')]
		[string]
		$Question,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'securityQuestion')]
		[string]
		$Answer,

		[Parameter(Mandatory = $True, ParameterSetName = 'temporaryAccessPass')]
		[switch]
		$TemporaryAccessPass,

		[Parameter(Mandatory = $False,ParameterSetName = 'temporaryAccessPass')]
		[int]$LifetimeInMinutes,

		[Parameter(Mandatory = $False,ParameterSetName = 'temporaryAccessPass')]
		[datetime]$StartDateTime,

		[Parameter(Mandatory = $False,ParameterSetName = 'temporaryAccessPass')]
		[boolean]$IsUsableOnce
		
	)
	
	begin {
		Assert-GraphConnection -Cmdlet $PSCmdlet
	}
	process {
		switch ($PSCmdlet.ParameterSetName) {
			"phone" {
				$postParams = @{
					phoneNumber = $PhoneNumber
					phoneType = $PhoneType
				}
				$json = $postparams | ConvertTo-Json -Depth 99 -Compress
				Invoke-AzureAdRequest -Method POST -Query "users/$ObjectId/authentication/phoneMethods" -Body $json -Raw
				break
			}
			"email" {
				$postParams = @{
					emailAddress = $EmailAddress
				}
				$json = $postparams | ConvertTo-Json -Depth 99 -Compress
				Invoke-AzureAdRequest -Method POST -Query "users/$ObjectId/authentication/emailMethods" -Body $json -Raw
				break
			}
			"temporaryAccessPass" {
				$postParams = @{}
				if ($True -eq $LifetimeInMinutes) {$postParams.LifetimeInMinutes = $LifetimeInMinutes}
				if ($True -eq $StartDateTime) {
					$startDateTimeUTC = $StartDateTime.ToUniversalTime()
					$startDateTimeUTCISO = Get-Date $startDateTimeUTC
					$postParams.StartDateTime = $startDateTimeUTCISO
				}
				if ($True -eq $IsUsableOnce) {$postParams.isUsableOnce = 'True'}
				$json = $postparams | ConvertTo-Json -Depth 99 -Compress
				Invoke-AzureAdRequest -Method POST -Query "users/$ObjectId/authentication/temporaryAccessPassMethods" -Body $json -Raw
				break
			}
			default {
				throw "Setting the $($PSCmdlet.ParameterSetName) method is not yet supported."
			}
		}
	}
}
