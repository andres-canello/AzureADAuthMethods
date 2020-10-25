<#
.SYNOPSIS
    Manage Azure AD users' authentication methods.
.DESCRIPTION
    This module helps Azure AD administrators managing authentication methods for users.
	Get the latest version and report issues here: https://github.com/andres-canello/AzureADAuthMethods
	Andres Canello https://twitter.com/andrescanello
	Version 0.92 - 28 April 2020
.EXAMPLE
    PS C:\>Get-AzureADUserAuthenticationMethod user@contoso.com
	Gets all the authentication methods set for the user.
.EXAMPLE
    PS C:\>Get-AzureADUserAuthenticationMethod -ObjectId user@contoso.com -Phone
	Gets the phone authentication methods set for the user.
.EXAMPLE
    PS C:\>Get-AzureADUserAuthenticationMethod -UserPrincipalName user@contoso.com -Phone
	Gets the phone authentication methods set for the user.
.EXAMPLE
    PS C:\>Get-AzureADUser -SearchString user1@contoso.com | Get-AzureADUserAuthenticationMethod
	Gets the phone authentication methods set for the user from the pipeline.
.EXAMPLE
    PS C:\>New-AzureADUserAuthenticationMethod user@contoso.com -Phone -PhoneNumber '+61412345678' -PhoneType mobile
	Adds a new mobile phone authentication method to the user.
.EXAMPLE
    PS C:\>Set-AzureADUserAuthenticationMethod user@contoso.com -Phone -PhoneNumber '+61412345679' -PhoneType mobile
	Modifies the existing mobile phone number for the user.
.EXAMPLE
	PS C:\>Set-AzureADUserAuthenticationMethod -Phone -UserPrincipalName user1@contoso.com -EnableSmsSignIn
	Enables SMS sign-in for the existing mobile phone authentication method for the user.
.EXAMPLE
	PS C:\>Set-AzureADUserAuthenticationMethod user@contoso.com -Password -NewPassword "password"
	Sets "password" as a new password for the user. Doesn't return the operation result.
.EXAMPLE
	PS C:\>Set-AzureADUserAuthenticationMethod user@contoso.com -Password -NewPassword "password" -ReturnResult
	Sets "password" as a new password for the user and waits 5 seconds for the operation result.
.EXAMPLE
	PS C:\>Set-AzureADUserAuthenticationMethod clouduser@contoso.com -Password
	Sets new system generated password for the user. Not available for syncronised users.
.EXAMPLE
    PS C:\>Remove-AzureADUserAuthenticationMethod -Phone -PhoneType mobile user@contoso.com
	Removes the mobile phone authentication method for the user.
		
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
$tenantDomain = '' # REQUIRED -> Change to your tenant domain (contoso.onmicrosoft.com)
$clientId = '' # REQUIRED -> Change to your AppID / ClientId
#$certThumbprint = '1C821E0590DB1E5112323FABF451097731168F8EB'  # NOT SUPPORTED YET | OPTIONAL -> Set only if using App Permissions and a certificate to authenticate

# =====================================================================================================================================

$baseURI = 'https://graph.microsoft.com/beta/users/'
$authMethodUri = "$baseUri{0}/authentication/{1}Methods"
$script:authResult = $null
$script:authHeaders = $null


function New-Auth
{
	
	param ($aR)
	
	# If App Permissions, try to get the cert from the cert store
	if ($certThumbprint)
	{
		
		$clientCertificate = Get-Item Cert:\CurrentUser\My\$certThumbprint -ErrorAction SilentlyContinue
		
		if ($clientCertificate)
		{
			Write-Host "Certificate selected: " $clientCertificate.Subject
			$aR = Get-MsalToken -ClientCertificate $ClientCertificate -ClientId $clientId -TenantId $tenantDomain
		}
		else
		{
			Write-Host "Couldn't find a certificate in the local certificate store that matches the configured thumbprint ($certThumbprint)" -ForegroundColor Red
			throw
		}
	}
	else
	{
		# if we've done interactive auth, try silently getting a new token
		if ($aR)
		{
			
			$user = $aR.Account.Username
			$aR = $null
			$aR = Get-MsalToken -TenantId $tenantDomain -ClientId $clientId -RedirectUri 'urn:ietf:wg:oauth:2.0:oob' -LoginHint $user -Silent
			
		}
		else
		{
			
			# Interactive auth required
			$aR = Get-MsalToken -TenantId $tenantDomain -ClientId $clientId -RedirectUri 'urn:ietf:wg:oauth:2.0:oob' -Interactive
			
		}
	}
	
	return $aR
}

function New-AuthHeaders
{
	
	$aH = $null
	$aH = New-Object 'System.Collections.Generic.Dictionary[[String],[String]]'
	$aH.Add('Authorization', 'Bearer ' + $authResult.AccessToken)
	$aH.Add('Content-Type', 'application/json')
	$aH.Add('Accept', 'application/json, text/plain')
	
	return $aH
	
}


function Test-TokenValidity
{
	
	if ($authResult)
	{
		# We have an auth context
		if ($authResult.ExpiresOn.LocalDateTime -gt (Get-Date))
		{
			
			# Token is still valid, nothing to do here.
			$remaining = $authResult.ExpiresOn.LocalDateTime - (Get-Date)
			Write-Host "Access Token valid for $remaining" -ForegroundColor Green
			
		}
		else
		{
			# Token expired, try to get a new one silently from the token cache			
			Write-Host 'Access Token expired, getting new token silently' -ForegroundColor Green
			$script:authResult = New-Auth $authResult
			$script:authHeaders = New-AuthHeaders
			
		}
		
	}
	else
	{
		# No auth context, go interactive
		Write-Host "We need to authenticate first, select a user with the appropriate permissions" -ForegroundColor Green
		$script:authResult = New-Auth
		$script:authHeaders = New-AuthHeaders
	}
	
}


function Get-AzureADUserAuthenticationMethod
{
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
		
		[Parameter(Mandatory = $True, ParameterSetName = 'securityQuestion')]
		[switch]
		$SecurityQuestion,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'default')]
		[switch]
		$Default,
		
		[Alias('UserId', 'UPN', 'UserPrincipalName')]
		[Parameter(Mandatory = $True, ParameterSetName = 'pin', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'oath', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'phone', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'email', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'password', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'securityQuestion', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'default', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'allMethods', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$ObjectId
	)
	
	Test-TokenValidity
	
	switch -Wildcard ($PSCmdlet.ParameterSetName)
	{
		"pin" {
			Write-Host "Getting pin method is not yet supported."
			break
		}
		"oath" {
			Write-Host "Getting oath method is not yet supported."
			break
		}
		"phone" {
			$uri = $authMethodUri -f $ObjectId, 'phone'
			$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Get
			$values = ConvertFrom-Json $response.Content
			
			if ($values.value.count -eq 0)
			{
				Write-Host "User $ObjectId has no phone auth methods."
				return $null
			}
			else { return $values.value }
			
			break
		}
		"email" {
			Write-Host "Getting email method is not yet supported."
			break
		}
		"password" {
			$uri = $authMethodUri -f $ObjectId, 'password'
			$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Get
			$values = ConvertFrom-Json $response.Content
			
			if ($values.value.count -eq 0)
			{
				Write-Host "User $ObjectId has no password auth methods."
				return $null
			}
			else { return $values.value }
			
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
			$uri = $authMethodUri -f $ObjectId, ''
			$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Get
			$values = ConvertFrom-Json $response.Content
			
			if ($values.value.count -eq 0)
			{
				Write-Host "User $ObjectId has no auth methods."
				return $null
			}
			else { return $values.value }
			
			break
		}
	}
}


function New-AzureADUserAuthenticationMethod
{
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
		
		[Parameter(Mandatory = $True, ParameterSetName = 'default')]
		[switch]
		$Default,
		
		[Alias('UserId', 'UPN', 'UserPrincipalName')]
		[Parameter(Mandatory = $True, ParameterSetName = 'pin', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'oath', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'phone', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'email', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'password', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'securityQuestion', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'default', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
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
	
	switch -Wildcard ($PSCmdlet.ParameterSetName)
	{
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
			$uri = $authMethodUri -f $ObjectId, 'phone'
			$postParams = @{ }
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


function Set-AzureADUserAuthenticationMethod
{
	<#
.SYNOPSIS
    Modifies an authentication method for the user. Manages SMS Sign In for mobile phone method.
.DESCRIPTION
	Modifies an authentication method for the user. Manages SMS Sign In for mobile phone method.
	Use to modify an existing authentication method for the user. To create a new method, use New-AzureADUserAuthenticationMethod.
.EXAMPLE
    PS C:\>Set-AzureADUserAuthenticationMethod user@contoso.com -Phone -PhoneNumber '+61412345679' -PhoneType mobile
	Modifies the existing mobile phone number for the user.
.EXAMPLE
	PS C:\>Set-AzureADUserAuthenticationMethod -Phone -UPN user1@contoso.com -EnableSmsSignIn
	Enables SMS sign-in for the existing mobile phone authentication method for the user.
.EXAMPLE
	PS C:\>Set-AzureADUserAuthenticationMethod user@contoso.com -Password -NewPassword "password"
	Sets "password" as a new password for the user. Doesn't return the operation result.
.EXAMPLE
	PS C:\>Set-AzureADUserAuthenticationMethod user@contoso.com -Password -NewPassword "password" -ReturnResult
	Sets "password" as a new password for the user and waits 5 seconds for the operation result.
.EXAMPLE
	PS C:\>Set-AzureADUserAuthenticationMethod clouduser@contoso.com -Password
	Sets new system generated password for the user. Not available for syncronised users.
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
		[Parameter(Mandatory = $True, ParameterSetName = 'enableSmsSignIn')]
		[Parameter(Mandatory = $True, ParameterSetName = 'disableSmsSignIn')]
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
		
		[Parameter(Mandatory = $True, ParameterSetName = 'default')]
		[switch]
		$Default,
		
		[Alias('UserId', 'UPN', 'UserPrincipalName')]
		[Parameter(Mandatory = $True, ParameterSetName = 'pin', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'oath', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'phone', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'email', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'password', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'securityQuestion', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'default', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'enableSmsSignIn', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'disableSmsSignIn', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
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
		[Parameter(Mandatory = $False, ParameterSetName = 'default')]
		[ValidateSet("mobile", "alternateMobile", "office")]
		[string]
		$PhoneType,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'email', Position = 2)]
		[string]
		$EmailAddress,
		
		[Parameter(Mandatory = $False, ParameterSetName = 'password')]
		[string]
		$NewPassword,
		
		[Parameter(Mandatory = $False, ParameterSetName = 'password')]
		[switch]
		$ReturnResult,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'securityQuestion')]
		[string]
		$Question,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'securityQuestion')]
		[string]
		$Answer,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'default')]
		[string]
		$DefaultMethod,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'enableSmsSignIn')]
		[switch]
		$EnableSmsSignIn,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'disableSmsSignIn')]
		[switch]
		$DisableSmsSignIn
		
	)
	
	Test-TokenValidity
	
	switch -Wildcard ($PSCmdlet.ParameterSetName)
	{
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
			
			$uri = $authMethodUri -f $ObjectId, 'phone' + "/$methodId"
			$postParams = @{ }
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
			$uri = $authMethodUri -f $ObjectId, 'password' + "/28c10230-6103-485e-b985-444c60001490/resetPassword"
			if ($newPassword)
			{
				$postParams = @{ }
				$postParams.newPassword = $newPassword
				$json = $postparams | ConvertTo-Json -Depth 99 -Compress
				
				$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Post -Body $json
			}
			else
			{
				$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Post
			}
			$values = ConvertFrom-Json $response.Content
			
			# Check password reset result
			if (($response.StatusCode -eq "202") -and $returnResult)
			{
				Write-Host "Waiting for a response..."
				Start-Sleep -Seconds 5
				$oR = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $response.Headers.Location -Method Get
				$operationResult = ConvertFrom-Json $oR.Content
				
				$operationResult
			}
			
			return $values
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
			$uri = $authMethodUri -f $ObjectId, 'phone' + "/3179e48a-750b-4051-897c-87b9720928f7/enableSmsSignIn"
			$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Post
			$values = ConvertFrom-Json $response.Content
			
			return $values
			break
		}
		"disableSmsSignIn" {
			$uri = $authMethodUri -f $ObjectId, 'phone' + "/3179e48a-750b-4051-897c-87b9720928f7/disableSmsSignIn"
			$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Post
			$values = ConvertFrom-Json $response.Content
			
			return $values
			break
		}
	}
	
	
}


function Remove-AzureADUserAuthenticationMethod
{
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
		
		[Parameter(Mandatory = $True, ParameterSetName = 'securityQuestion')]
		[switch]
		$SecurityQuestion,
		
		[Alias('UserId', 'UPN', 'UserPrincipalName')]
		[Parameter(Mandatory = $True, ParameterSetName = 'pin', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'oath', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'phone', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'email', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'password', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'securityQuestion', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[Parameter(Mandatory = $True, ParameterSetName = 'default', Position = 1, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
		[string]
		$ObjectId,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'oath')]
		[string]
		$SerialNumber,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'phone')]
		[ValidateSet("mobile", "alternateMobile", "office")]
		[string]
		$PhoneType,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'email', Position = 2)]
		[string]
		$EmailAddress,
		
		[Parameter(Mandatory = $True, ParameterSetName = 'securityQuestion')]
		[string]
		$Question
		
	)
	
	switch -Wildcard ($PSCmdlet.ParameterSetName)
	{
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
			
			
			$uri = $authMethodUri -f $ObjectId, 'phone' + "/$methodId"
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
