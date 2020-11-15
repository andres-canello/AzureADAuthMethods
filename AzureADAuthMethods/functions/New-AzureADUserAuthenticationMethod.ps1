function New-AzureADUserAuthenticationMethod {
	<#
	.SYNOPSIS
	    Creates a new authentication method for the user.
	.DESCRIPTION
		Creates a new authentication method for the user.
		Use to create a new method type for the user. To modify a method, use Set-AzureADUserAuthenticationMethod.
	.EXAMPLE
	    PS C:\>New-AzureADUserAuthenticationMethod user@contoso.com -Phone -PhoneNumber '+61412345678' -PhoneType mobile
		Adds a new mobile phone authentication method to the user.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True, ParameterSetName = 'pin')]
		[switch]
		$Pin,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'oath')]
		[switch]
		$Oath,
		
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
		
		[Parameter(Mandatory = $True, ParameterSetName = 'pin', Position = 2)]
		[string]
		$NewPin,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'oath')]
		[string]
		$SecretKey,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'oath')]
		[int]
		$TimeIntervalInSeconds,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'oath')]
		[string]
		$SerialNumber,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'oath')]
		[string]
		$Manufacturer,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'oath')]
		[string]
		$Model,
		
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
		$Answer
		
	)
	
	process {
		switch ($PSCmdlet.ParameterSetName) {
			"phone" {
				$postParams = @{
					phoneNumber = $PhoneNumber
					phoneType = $PhoneType
				}
				$json = $postparams | ConvertTo-Json -Depth 99 -Compress
				Invoke-AzureAdRequest -Method POST -Query "users/$ObjectId/authentication/phone" -Body $json
				break
			}
			"email" {
				$postParams = @{
					emailAddress = $EmailAddress
				}
				$json = $postparams | ConvertTo-Json -Depth 99 -Compress
				Invoke-AzureAdRequest -Method POST -Query "users/$ObjectId/authentication/email" -Body $json
				break
			}
			default {
				throw "Setting the $($PSCmdlet.ParameterSetName) method is not yet supported."
			}
		}
	}
}
