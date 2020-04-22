<#
.SYNOPSIS
    Manage Azure AD users' authentication methods.
.DESCRIPTION
    This module helps Azure AD administrators managing authentication methods for users.
	Get the latest version and report issues here: https://github.com/andres-canello/AzureADAuthMethods
	Andres Canello https://twitter.com/andrescanello
	Version 0.82 - 22 April 2020
.EXAMPLE
    PS C:\>Get-AzureADUserAuthenticationMethod user@contoso.com
	Gets all the authentication methods set for the user.
.EXAMPLE
    PS C:\>Get-AzureADUserAuthenticationMethod -ObjectId user@contoso.com -method phone
	Gets the phone authentication methods set for the user.
.EXAMPLE
    PS C:\>Get-AzureADUserAuthenticationMethod -UserPrincipalName user@contoso.com -method phone
	Gets the phone authentication methods set for the user.
.EXAMPLE
    PS C:\>Get-AzureADUser -SearchString user1@contoso.com | Get-AzureADUserAuthenticationMethod
	Gets the phone authentication methods set for the user from the pipeline.
.EXAMPLE
    PS C:\>New-AzureADUserAuthenticationMethod user@contoso.com -phone -phoneNumber '+61412345678' -phoneType mobile
	Adds a new mobile phone authentication method to the user.
.EXAMPLE
    PS C:\>Set-AzureADUserAuthenticationMethod user@contoso.com -phone -phoneNumber '+61412345679' -phoneType mobile
	Modifies the existing mobile phone number for the user.
.EXAMPLE
    PS C:\>Remove-AzureADUserAuthenticationMethod -phone -phoneType mobile user@contoso.com
    Removes the mobile phone authentication method for the user.
.EXAMPLE
	PS C:\>Set-AzureADUserAuthenticationMethod -phone -UserPrincipalName user1@contoso.com -enableSmsSignIn
	Enables SMS sign-in for the existing mobile phone authentication method for the user.
	
.NOTES
    THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
    FITNESS FOR A PARTICULAR PURPOSE.
    This sample is not supported under any Microsoft standard support program or service. 
    The script is provided AS IS without warranty of any kind. Microsoft further disclaims all
    implied warranties including, without limitation, any implied warranties of merchantability
    or of fitness for a particular purpose. The entire risk arising out of the use or performance
    of the sample and documentation remains with you. In no event shall Microsoft, its authors,
    or anyone else involved in the creation, production, or delivery of the script be liable for 
    any damages whatsoever (including, without limitation, damages for loss of business profits, 
    business interruption, loss of business information, or other pecuniary loss) arising out of 
    the use of or inability to use the sample or documentation, even if Microsoft has been advised 
    of the possibility of such damages, rising out of the use of or inability to use the sample script, 
    even if Microsoft has been advised of the possibility of such damages.
#>



# Update this info
$tenantDomain = 'contoso.onmicrosoft.com' # REQUIRED -> Change to your tenant domain
$clientId = 'c79c106a-bdf0-475c-a6e0-2195c4b9a017' # REQUIRED -> Change to your AppID
#$certThumbprint = '1C821E0590DB1E5112323FABF451097731168F8EB'  # NOT SUPPORTED YET | OPTIONAL -> Set only if using App Permissions and a certificate to authenticate

# =====================================================================================================================================

$baseURI = 'https://graph.microsoft.com/beta/users/'
$authMethodUri = "$baseUri{0}/authentication/{1}Methods"
$script:authResult = $null
$script:authHeaders = $null


function New-Auth {

	param($aR)

	# If App Permissions, try to get the cert from the cert store
	if ($certThumbprint) {

		$clientCertificate = Get-Item Cert:\CurrentUser\My\$certThumbprint -ErrorAction SilentlyContinue

		if ($clientCertificate) {
			Write-Host "Certificate selected: " $clientCertificate.Subject
			$aR = Get-MsalToken -ClientCertificate $ClientCertificate -ClientId $clientId -TenantId $tenantDomain
		} else {
			Write-Host "Couldn't find a certificate in the local certificate store that matches the configured thumbprint ($certThumbprint)" -ForegroundColor Red
			throw
		}
	} else {
		# if we've done interactive auth, try silently getting a new token
		if ($aR) {

			$user = $aR.Account.Username
			$aR = $null
			$aR = Get-MsalToken -TenantId $tenantDomain -ClientId $clientId -RedirectUri 'urn:ietf:wg:oauth:2.0:oob' -LoginHint $user -Silent

		} else {

			# Interactive auth required
			$aR = Get-MsalToken -TenantId $tenantDomain -ClientId $clientId -RedirectUri 'urn:ietf:wg:oauth:2.0:oob' -Interactive

		}
	}

	return $aR
}

function New-AuthHeaders{

	$aH = $null
	$aH = New-Object 'System.Collections.Generic.Dictionary[[String],[String]]'
	$aH.Add('Authorization', 'Bearer ' + $authResult.AccessToken)
	$aH.Add('Content-Type','application/json')
	$aH.Add('Accept','application/json, text/plain')

	return $aH

}


function Test-TokenValidity {

	if ($authResult) {
		# We have an auth context
		if ($authResult.ExpiresOn.LocalDateTime -gt (Get-Date)) {

			# Token is still valid, nothing to do here.
			$remaining = $authResult.ExpiresOn.LocalDateTime - (Get-Date)
			Write-Host "Access Token valid for $remaining" -ForegroundColor Green

		} else {
			# Token expired, try to get a new one silently from the token cache			
			Write-Host 'Access Token expired, getting new token silently' -ForegroundColor Green
			$script:authResult = New-Auth $authResult
			$script:authHeaders = New-AuthHeaders

		}

	} else {
		# No auth context, go interactive
		Write-Host "We need to authenticate first, select a user with the appropriate permissions" -ForegroundColor Green
		$script:authResult = New-Auth
		$script:authHeaders = New-AuthHeaders
	}

}

<#
.SYNOPSIS
    Gets a user's authentication methods.
.DESCRIPTION
	Gets a user's authentication methods.
	All methods are returned by default. Pass the required method as a switch to only get that method.
.EXAMPLE
    PS C:\>Get-AzureADUserAuthenticationMethod -ObjectId user@contoso.com -method phone
	Gets the phone authentication methods set for the user.
.EXAMPLE
    PS C:\>Get-AzureADUser -SearchString user1@contoso.com | Get-AzureADUserAuthenticationMethod
	Gets the phone authentication methods set for the user from the pipeline.
.EXAMPLE
    PS C:\>Get-AzureADUserAuthenticationMethod -UserPrincipalName user@contoso.com -method phone
	Gets the phone authentication methods set for the user.
#>
function Get-AzureADUserAuthenticationMethod {

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = 'pin')]
		[switch]$pin,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[switch]$oath,

		[Parameter(Mandatory = $True,ParameterSetName = 'phone')]
		[switch]$phone,

		[Parameter(Mandatory = $True,ParameterSetName = 'email')]
		[switch]$email,

		[Parameter(Mandatory = $True,ParameterSetName = 'password')]
		[switch]$password,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[switch]$securityQuestion,

		[Parameter(Mandatory = $True,ParameterSetName = 'default')]
		[switch]$default,

		[Alias('userID','UPN','UserPrincipalName')]
		[Parameter(Mandatory = $True,ParameterSetName = 'pin',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'oath',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'phone',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'email',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'password',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'default',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'allMethods',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[string]$ObjectId
	)

	Test-TokenValidity

	switch -Wildcard ($PSCmdlet.ParameterSetName) {
		"pin" {
			Write-Host "Getting pin method is not yet supported."
			break
		}
		"oath" {
			Write-Host "Getting oath method is not yet supported."
			break
		}
		"phone" {
			$uri = $authMethodUri -f $ObjectId,'phone'
			$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Get
			$values = ConvertFrom-Json $response.Content

			if ($values.value.count -eq 0) {
				Write-Host "User $ObjectId has no phone auth methods."
				return $null
			} else { return $values.value }

			break
		}
		"email" {
			Write-Host "Getting email method is not yet supported."
			break
		}
		"password" {
			$uri = $authMethodUri -f $ObjectId,'password'
			$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Get
			$values = ConvertFrom-Json $response.Content

			if ($values.value.count -eq 0) {
				Write-Host "User $ObjectId has no password auth methods."
				return $null
			} else { return $values.value }

			break
		}
		"securityQuestion" {
			Write-Host "Getting security question method is not yet supported."
			break
		}
		"default" {
			Write-Host "Getting the default method is not yet supported."
			break
		}
		"allMethods" {
			$uri = $authMethodUri -f $ObjectId,''
			$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Get
			$values = ConvertFrom-Json $response.Content

			if ($values.value.count -eq 0) {
				Write-Host "User $ObjectId has no auth methods."
				return $null
			} else { return $values.value }

			break
		}
	}
}

<#
.SYNOPSIS
    Creates a new authentication method for the user.
.DESCRIPTION
	Creates a new authentication method for the user.
	Use to create a new method type for the user. To modify a method, use Set-AzureADUserAuthenticationMethod.
.EXAMPLE
    PS C:\>New-AzureADUserAuthenticationMethod user@contoso.com -phone -phoneNumber '+61412345678' -phoneType mobile
	Adds a new mobile phone authentication method to the user.
#>
function New-AzureADUserAuthenticationMethod {

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = 'pin')]
		[switch]$pin,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[switch]$oath,

		[Parameter(Mandatory = $True,ParameterSetName = 'phone')]
		[switch]$phone,

		[Parameter(Mandatory = $True,ParameterSetName = 'email')]
		[switch]$email,

		[Parameter(Mandatory = $True,ParameterSetName = 'password')]
		[switch]$password,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[switch]$securityQuestion,

		[Parameter(Mandatory = $True,ParameterSetName = 'default')]
		[switch]$default,

		[Alias('userID','UPN','UserPrincipalName')]
		[Parameter(Mandatory = $True,ParameterSetName = 'pin',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'oath',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'phone',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'email',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'password',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'default',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[string]$ObjectId,

		[Parameter(Mandatory = $True,ParameterSetName = 'pin',Position = 2)]
		[string]$newPin,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[string]$secretKey,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[int]$timeIntervalInSeconds,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[string]$serialNumber,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[string]$manufacturer,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[string]$model,

		[Parameter(Mandatory = $True,ParameterSetName = 'phone')]
		[string]$phoneNumber,

		[Parameter(Mandatory = $True,ParameterSetName = 'phone')]
		[ValidateSet("mobile","alternateMobile","office")] [string]$phoneType,

		[Parameter(Mandatory = $True,ParameterSetName = 'email',Position = 2)]
		[string]$emailAddress,

		[Parameter(Mandatory = $True,ParameterSetName = 'password')]
		[string]$newPassword,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[string]$question,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[string]$answer

	)

	switch -Wildcard ($PSCmdlet.ParameterSetName) {
		"pin" {
			Write-Host "Setting pin method is not yet supported."
			break
		}
		"oath" {
			Write-Host "Setting oath method is not yet supported."
			break
		}
		"phone" {
			Test-TokenValidity
			$uri = $authMethodUri -f $ObjectId,'phone'
			$postParams = @{}
			$postParams.phoneNumber = $phoneNumber
			$postParams.phoneType = $phoneType

			$json = $postparams | ConvertTo-Json -Depth 99 -Compress

			$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Post -Body $json
			$values = ConvertFrom-Json $response.Content

			return $values
			break
		}
		"email" {
			Write-Host "Setting email method is not yet supported."
			break
		}
		"password" {
			Write-Host "Setting password method is not yet supported."
			break
		}
		"securityQuestion" {
			Write-Host "Setting security question method is not yet supported."
			break
		}

	}

}

<#
.SYNOPSIS
    Modifies an authentication method for the user. Manages SMS Sign In for mobile phone method.
.DESCRIPTION
	Modifies an authentication method for the user. Manages SMS Sign In for mobile phone method.
	Use to modify an existing authentication method for the user. To create a new method, use New-AzureADUserAuthenticationMethod.
.EXAMPLE
    PS C:\>Set-AzureADUserAuthenticationMethod user@contoso.com -phone -phoneNumber '+61412345679' -phoneType mobile
	Modifies the existing mobile phone number for the user.
.EXAMPLE
	PS C:\>Set-AzureADUserAuthenticationMethod -phone -UPN user1@contoso.com -enableSmsSignIn
	Enables SMS sign-in for the existing mobile phone authentication method for the user.
#>
function Set-AzureADUserAuthenticationMethod {

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = 'pin')]
		[switch]$pin,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[switch]$oath,

		[Parameter(Mandatory = $True,ParameterSetName = 'phone')]
		[Parameter(Mandatory = $True,ParameterSetName = 'enableSmsSignIn')]
		[Parameter(Mandatory = $True,ParameterSetName = 'disableSmsSignIn')]
		[switch]$phone,

		[Parameter(Mandatory = $True,ParameterSetName = 'email')]
		[switch]$email,

		[Parameter(Mandatory = $True,ParameterSetName = 'password')]
		[switch]$password,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[switch]$securityQuestion,

		[Parameter(Mandatory = $True,ParameterSetName = 'default')]
		[switch]$default,

		[Alias('userID','UPN','UserPrincipalName')]
		[Parameter(Mandatory = $True,ParameterSetName = 'pin',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'oath',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'phone',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'email',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'password',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'default',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'enableSmsSignIn',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'disableSmsSignIn',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[string]$ObjectId,

		[Parameter(Mandatory = $True,ParameterSetName = 'pin',Position = 2)]
		[string]$newPin,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[string]$secretKey,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[int]$timeIntervalInSeconds,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[string]$serialNumber,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[string]$manufacturer,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[string]$model,

		[Parameter(Mandatory = $True,ParameterSetName = 'phone')]
		[string]$phoneNumber,

		[Parameter(Mandatory = $True,ParameterSetName = 'phone')]
		[Parameter(Mandatory = $False,ParameterSetName = 'default')]
		[ValidateSet("mobile","alternateMobile","office")] [string]$phoneType,

		[Parameter(Mandatory = $True,ParameterSetName = 'email',Position = 2)]
		[string]$emailAddress,

		[Parameter(Mandatory = $True,ParameterSetName = 'password')]
		[string]$newPassword,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[string]$question,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[string]$answer,

		[Parameter(Mandatory = $True,ParameterSetName = 'default')]
		[string]$defaultMethod,

		[Parameter(Mandatory = $True,ParameterSetName = 'enableSmsSignIn')]
		[switch]$enableSmsSignIn,

		[Parameter(Mandatory = $True,ParameterSetName = 'disableSmsSignIn')]
		[switch]$disableSmsSignIn

	)

	Test-TokenValidity

	switch -Wildcard ($PSCmdlet.ParameterSetName) {
		"pin" {
			Write-Host "Setting pin method is not yet supported."
			break
		}
		"oath" {
			Write-Host "Setting oath method is not yet supported."
			break
		}
		"phone" {
			if ($phoneType -eq "alternateMobile") { $methodId = "b6332ec1-7057-4abe-9331-3d72feddfe41" }
			elseif ($phoneType -eq "mobile") { $methodId = "3179e48a-750b-4051-897c-87b9720928f7" }
			else { $methodId = "e37fc753-ff3b-4958-9484-eaa9425c82bc" }

			$uri = $authMethodUri -f $ObjectId,'phone' + "/$methodId"
			$postParams = @{}
			$postParams.phoneNumber = $phoneNumber
			$postParams.phoneType = $phoneType

			$json = $postparams | ConvertTo-Json -Depth 99 -Compress

			$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Put -Body $json
			$values = ConvertFrom-Json $response.Content

			return $values
			break
		}
		"email" {
			Write-Host "Setting email method is not yet supported."
			break
		}
		"password" {
			Write-Host "Setting password method is not yet supported."
			break
		}
		"securityQuestion" {
			Write-Host "Setting security question method is not yet supported."
			break
		}
		"default" {
			Write-Host "Setting the default method is not yet supported."
			break
		}
		"enableSmsSignIn" {
			$uri = $authMethodUri -f $ObjectId,'phone' + "/3179e48a-750b-4051-897c-87b9720928f7/enableSmsSignIn"
			$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Post
			$values = ConvertFrom-Json $response.Content

			return $values
			break
		}
		"disableSmsSignIn" {
			$uri = $authMethodUri -f $ObjectId,'phone' + "/3179e48a-750b-4051-897c-87b9720928f7/disableSmsSignIn"
			$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Post
			$values = ConvertFrom-Json $response.Content

			return $values
			break
		}
	}


}

<#
.SYNOPSIS
    Removes an authentication method from the user.
.DESCRIPTION
	Removes an authentication method from the user.
	Use to remove an existing authentication method for the user.
.EXAMPLE
    PS C:\>Remove-AzureADUserAuthenticationMethod -phone -phoneType mobile user@contoso.com
    Removes the mobile phone authentication method for the user.
#>
function Remove-AzureADUserAuthenticationMethod {

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = 'pin')]
		[switch]$pin,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[switch]$oath,

		[Parameter(Mandatory = $True,ParameterSetName = 'phone')]
		[switch]$phone,

		[Parameter(Mandatory = $True,ParameterSetName = 'email')]
		[switch]$email,

		[Parameter(Mandatory = $True,ParameterSetName = 'password')]
		[switch]$password,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[switch]$securityQuestion,

		[Alias('userID','UPN','UserPrincipalName')]
		[Parameter(Mandatory = $True,ParameterSetName = 'pin',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'oath',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'phone',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'email',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'password',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'default',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[string]$ObjectId,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[string]$serialNumber,

		[Parameter(Mandatory = $True,ParameterSetName = 'phone')]
		[ValidateSet("mobile","alternateMobile","office")] [string]$phoneType,

		[Parameter(Mandatory = $True,ParameterSetName = 'email',Position = 2)]
		[string]$emailAddress,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[string]$question

	)

	switch -Wildcard ($PSCmdlet.ParameterSetName) {
		"pin" {
			Write-Host "Removing pin method is not yet supported."
			break
		}
		"oath" {
			Write-Host "Removing oath method is not yet supported."
			break
		}
		"phone" {
			Test-TokenValidity
			if ($phoneType -eq "alternateMobile") { $methodId = "b6332ec1-7057-4abe-9331-3d72feddfe41" }
			elseif ($phoneType -eq "mobile") { $methodId = "3179e48a-750b-4051-897c-87b9720928f7" }
			else { $methodId = "e37fc753-ff3b-4958-9484-eaa9425c82bc" }


			$uri = $authMethodUri -f $ObjectId,'phone' + "/$methodId"
			$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Delete
			$values = ConvertFrom-Json $response.Content

			return $values
			break
		}
		"email" {
			Write-Host "Deleting email method is not yet supported."
			break
		}
		"securityQuestion" {
			Write-Host "Setting security question method is not yet supported."
			break
		}

	}
}

#  Run this when the module is loaded
$MSAL = Get-Module -ListAvailable MSAL.ps -Verbose:$false -ErrorAction SilentlyContinue
if (-not $MSAL) {

	Write-Host "Please install the MSAL.ps PowerShell module (Install-Module MSAL.ps) and try again" -ForegroundColor Red
	throw
	#$authResult = New-Auth
	#$authHeaders = New-AuthHeaders $authResult
}

Export-ModuleMember -Function Get-AzureADUserAuthenticationMethod
Export-ModuleMember -Function New-AzureADUserAuthenticationMethod
Export-ModuleMember -Function Set-AzureADUserAuthenticationMethod
Export-ModuleMember -Function Remove-AzureADUserAuthenticationMethod
