function Get-AzureADUserAuthenticationMethod {
	<#
	.SYNOPSIS
	    Gets a user's authentication methods.
	.DESCRIPTION
		Gets a user's authentication methods.
		All methods are returned by default. Pass the required method as a switch to only get that method.
	.EXAMPLE
	    PS C:\>Get-AzureADUserAuthenticationMethod -ObjectId user@contoso.com -Phone
		Gets the phone authentication methods set for the user.
	.EXAMPLE
	    PS C:\>Get-AzureADUser -SearchString user1@contoso.com | Get-AzureADUserAuthenticationMethod
		Gets the phone authentication methods set for the user from the pipeline.
	.EXAMPLE
	    PS C:\>Get-AzureADUserAuthenticationMethod -UserPrincipalName user@contoso.com -Phone
		Gets the phone authentication methods set for the user.
	#>
	[CmdletBinding(DefaultParameterSetName = 'allMethods')]
	param (
		[Parameter(Mandatory = $True, ParameterSetName = 'pin')]
		[switch]
		$Pin,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'softwareOath')]
		[switch]
		$softwareOath,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'phone')]
		[switch]
		$Phone,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'email')]
		[switch]
		$Email,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'password')]
		[switch]
		$Password,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'securityQuestion')]
		[switch]
		$SecurityQuestion,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'FIDO2')]
		[switch]
		$FIDO2,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'passwordlessMicrosoftAuthenticator')]
		[switch]
		$PasswordlessMicrosoftAuthenticator,

		[Parameter(Mandatory = $True, ParameterSetName = 'MicrosoftAuthenticator')]
		[switch]
		$MicrosoftAuthenticator,

		[Parameter(Mandatory = $True, ParameterSetName = 'WindowsHelloForBusiness')]
		[switch]
		$WindowsHelloForBusiness,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'default')]
		[switch]
		$Default,
		
		[Alias('UserId', 'UPN', 'UserPrincipalName')]
		[Parameter(Mandatory = $True, Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$ObjectId
	)
	begin {
		$common = @{
			Method = 'GET'
			GetValues = $false
		}
	}
	process {
		$values = switch ($PSCmdlet.ParameterSetName) {
			"phone" {
				Invoke-AzureAdRequest @common -Query "users/$ObjectId/authentication/phoneMethods"
				break
			}
			"email" {
				Invoke-AzureAdRequest @common -Query "users/$ObjectId/authentication/emailMethods"
				break
			}
			"password" {
				Invoke-AzureAdRequest @common -Query "users/$ObjectId/authentication/passwordMethods"
				break
			}
			"FIDO2" {
				Invoke-AzureAdRequest @common -Query "users/$ObjectId/authentication/fido2Methods"
				break
			}
			"passwordlessMicrosoftAuthenticator" {
				Invoke-AzureAdRequest @common -Query "users/$ObjectId/authentication/passwordlessMicrosoftAuthenticatorMethods"
				break
			}
			"MicrosoftAuthenticator" {
				Invoke-AzureAdRequest @common -Query "users/$ObjectId/authentication/MicrosoftAuthenticatorMethods"
				break
			}
			"WindowsHelloForBusiness" {
				Invoke-AzureAdRequest @common -Query "users/$ObjectId/authentication/windowsHelloForBusinessMethods"
				break
			}
			"allMethods" {
				Invoke-AzureAdRequest @common -Query "users/$ObjectId/authentication/methods"
				break
			}
			default {
				throw "Getting the $($PSCmdlet.ParameterSetName) method is not yet supported."
			}
		}
		$values  | Add-Member -NotePropertyName userObjectId -NotePropertyValue $ObjectId -PassThru
	}
}
