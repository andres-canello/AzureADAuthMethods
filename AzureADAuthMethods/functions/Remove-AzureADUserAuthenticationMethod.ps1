function Remove-AzureADUserAuthenticationMethod {
	<#
	.SYNOPSIS
	    Removes an authentication method from the user.
	.DESCRIPTION
		Removes an authentication method from the user.
		Use to remove an existing authentication method for the user.
	.EXAMPLE
	    PS C:\>Remove-AzureADUserAuthenticationMethod -Phone -PhoneType mobile user@contoso.com
	    Removes the mobile phone authentication method for the user.
	#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $True, ParameterSetName = 'pin')]
		[switch]
		$Pin,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'oath')]
		[switch]
		$Oath,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'phone')]
		[switch]
		$Phone,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'email')]
		[switch]
		$Email,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'password')]
		[switch]
		$Password,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'FIDO2')]
		[switch]
		$FIDO2,

		[Parameter(Mandatory = $True, ParameterSetName = 'MicrosoftAuthenticator')]
		[switch]
		$MicrosoftAuthenticator,

		[Parameter(Mandatory = $True, ParameterSetName = 'WindowsHelloForBusiness')]
		[switch]
		$WindowsHelloForBusiness,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'FIDO2')]
		[Parameter(Mandatory = $True, ParameterSetName = 'MicrosoftAuthenticator')]
		[Parameter(Mandatory = $True, ParameterSetName = 'WindowsHelloForBusiness')]
		[Parameter(Mandatory = $True, ParameterSetName = 'temporaryAccessPass')]
		[string]
		$MethodId,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'securityQuestion')]
		[switch]
		$SecurityQuestion,
		
		[Alias('UserId', 'UPN', 'UserPrincipalName')]
		[Parameter(Mandatory = $True, Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$ObjectId,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'oath')]
		[string]
		$SerialNumber,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'phone')]
		[ValidateSet("mobile", "alternateMobile", "office")]
		[string]
		$PhoneType,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'securityQuestion')]
		[string]
		$Question,

		[Parameter(Mandatory = $True,ParameterSetName = 'temporaryAccessPass')]
		[switch]$TemporaryAccessPass
		
	)
	
	begin {
		Assert-GraphConnection -Cmdlet $PSCmdlet
	}
	process {
		switch ($PSCmdlet.ParameterSetName) {
			"phone" {
				$methodId = switch ($PhoneType) {
					'alternateMobile' { 'b6332ec1-7057-4abe-9331-3d72feddfe41' }
					'mobile' { '3179e48a-750b-4051-897c-87b9720928f7' }
					'office' { 'e37fc753-ff3b-4958-9484-eaa9425c82bc' }
				}
				Invoke-AzureAdRequest -Method DELETE -Query "users/$ObjectId/authentication/phoneMethods/$methodId"
				break
			}
			"email" {
				Invoke-AzureAdRequest -Method DELETE -Query "users/$ObjectId/authentication/emailMethods/3ddfcfc8-9383-446f-83cc-3ab9be4be18f"
				break
			}
			"FIDO2" {
				Invoke-AzureAdRequest -Method DELETE -Query "users/$ObjectId/authentication/fido2Methods/$MethodId"
				break
			}
			"MicrosoftAuthenticator" {
				Invoke-AzureAdRequest -Method DELETE -Query "users/$ObjectId/authentication/MicrosoftAuthenticatorMethods/$MethodId"
				break
			}
			"WindowsHelloForBusiness" {
				Invoke-AzureAdRequest -Method DELETE -Query "users/$ObjectId/authentication/windowsHelloForBusinessMethods/$MethodId"
				break
			}
			"temporaryAccessPass" {
				Invoke-AzureAdRequest -Method DELETE -Query "users/$ObjectId/authentication/temporaryAccessPassMethods/$MethodId"
				break
			}
			default {
				throw "Removing the $($PSCmdlet.ParameterSetName) method is not yet supported."
			}
		}
	}
}
