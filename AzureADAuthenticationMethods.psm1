<#
.SYNOPSIS
    Manage Azure AD users' authentication methods.
.DESCRIPTION
    This module helps Azure AD administrators managing authentication methods for users.
	Get the latest version and report issues here: https://github.com/andres-canello/AzureADAuthMethods
	Andres Canello https://twitter.com/andrescanello
	
.EXAMPLE
    PS C:\>Get-AzureADUserAuthenticationMethod user@contoso.com
	Gets all the authentication methods set for the user.
.EXAMPLE
    PS C:\>Get-AzureADUserAuthenticationMethod user@contoso.com -method phone
	Gets the phone authentication methods set for the user.
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
	PS C:\>Set-AzureADUserAuthenticationMethod -phone -userID user1@contoso.com -enableSmsSignIn
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



# Update this
$tenantDomain = 'contoso.onmicrosoft.com' # REQUIRED -> Change your tenant domain
$clientId = 'c79c106a-bbf0-415c-a6e0-2195c449a017'  # REQUIRED -> Change to your AppID
#$certThumbprint = '1C821E0590DB1E5112323FABF451097731168F8EB'  # OPTIONAL -> Set and uncomment only if using App Permissions and a certificate to authenticate

# =====================================================================================================================================

$baseURI = 'https://graph.microsoft.com/beta/users/'
$authMethodUri = "$baseUri{0}/authentication/{1}Methods"


$MSAL = Get-Module -ListAvailable MSAL.ps -Verbose:$false -ErrorAction SilentlyContinue
if ($MSAL) {
			
        # If App Permissions, try to get the cert from the cert store
        if ($certThumbprint){

            $clientCertificate = Get-Item Cert:\CurrentUser\My\$certThumbprint -ErrorAction SilentlyContinue

	        if ($clientCertificate){
                Write-Host "Certificate selected: " $clientCertificate.Subject
                $authResult = Get-MsalToken -ClientCertificate $ClientCertificate -ClientId $clientId -TenantId $tenantDomain
            }else{
		        Write-Host "Couldn't find a certificate in the local certificate store that matches the configured thumbprint ($certThumbprint)" -ForegroundColor Red
				throw
		        }
        }else{
				$authResult = Get-MsalToken -TenantId $tenantDomain -ClientId $clientId -RedirectUri 'urn:ietf:wg:oauth:2.0:oob' -Interactive
			}
     
$authHeaders = New-Object 'System.Collections.Generic.Dictionary[[String],[String]]'
$authHeaders.Add('Authorization', 'Bearer ' + $authResult.AccessToken)
$authHeaders.Add('Content-Type','application/json')
$authHeaders.Add('Accept','application/json, text/plain')
}  else {
	Write-Host "Please install the MSAL.ps PowerShell module (Install-Module MSAL.ps) and try again" -ForegroundColor Red
	throw
	}


function Check-Token{

	if ($authResult){
	
		if ($authResult.ExpiresOn.LocalDateTime -gt (get-date)){
			$remaining = $authResult.ExpiresOn.LocalDateTime - (get-date)
			Write-Host "Authentication valid for $remaining" -ForegroundColor Green
			} else {
				Write-Host 'Authentication expired' -ForegroundColor Red
				throw
				}
	
	} else {
		Write-Host 'Authentication failed' -ForegroundColor Red
		throw
		}

}


 function Get-AzureADUserAuthenticationMethod{
      
	[CmdletBinding()]
	Param(
		[parameter(Mandatory=$True, ParameterSetName='pin')]
		[switch]$pin,
		
		[parameter(Mandatory=$True, ParameterSetName='oath')]
		[switch]$oath,
		
		[parameter(Mandatory=$True, ParameterSetName='phone')]
		[switch]$phone,
		
		[parameter(Mandatory=$True, ParameterSetName='email')]
		[switch]$email,
		
		[parameter(Mandatory=$True, ParameterSetName='password')]
		[switch]$password,
		
		[parameter(Mandatory=$True, ParameterSetName='securityQuestion')]
		[switch]$securityQuestion,
		
		[parameter(Mandatory=$True, ParameterSetName='default')]
		[switch]$default,
										
		[parameter(Mandatory=$True, ParameterSetName='pin', Position=1)]
		[parameter(Mandatory=$True, ParameterSetName='oath', Position=1)]
		[parameter(Mandatory=$True, ParameterSetName='phone', Position=1)]
		[parameter(Mandatory=$True, ParameterSetName='email', Position=1)]
		[parameter(Mandatory=$True, ParameterSetName='password', Position=1)]
		[parameter(Mandatory=$True, ParameterSetName='securityQuestion', Position=1)]
		[parameter(Mandatory=$True, ParameterSetName='default', Position=1)]
		[parameter(Mandatory=$True, ParameterSetName='allMethods', Position=1)]
		[string]$userID
	)

	Check-Token
		
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
			$uri = $authMethodUri -f $userId,'phone'
			$response = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $uri -Method Get
			$values = ConvertFrom-Json $response.Content
			
			if ($values.value.count -eq 0) {
				Write-Host "User $userId has no phone auth methods."
				return $null
			} else {Return $values.value}
		
			break
		}
		"email" {
			Write-Host "Getting email method is not yet supported."
			break
		}
		"password" {
			$uri = $authMethodUri -f $userId,'password'
			$response = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $uri -Method Get
			$values = ConvertFrom-Json $response.Content
			
			if ($values.value.count -eq 0) {
				Write-Host "User $userId has no password auth methods."
				return $null
			} else {Return $values.value}
		
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
			$uri = $authMethodUri -f $userId,''
			$response = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $uri -Method Get
			$values = ConvertFrom-Json $response.Content
			
			if ($values.value.count -eq 0) {
				Write-Host "User $userId has no auth methods."
				return $null
			} else {Return $values.value}
		
			break
		}
	}
} 

function New-AzureADUserAuthenticationMethod{
            
			[CmdletBinding()]
			Param(
                [parameter(Mandatory=$True, ParameterSetName='pin')]
				[switch]$pin,
				
				[parameter(Mandatory=$True, ParameterSetName='oath')]
				[switch]$oath,
				
				[parameter(Mandatory=$True, ParameterSetName='phone')]
				[switch]$phone,
				
				[parameter(Mandatory=$True, ParameterSetName='email')]
				[switch]$email,
				
				[parameter(Mandatory=$True, ParameterSetName='password')]
				[switch]$password,
				
				[parameter(Mandatory=$True, ParameterSetName='securityQuestion')]
				[switch]$securityQuestion,
				
				[parameter(Mandatory=$True, ParameterSetName='default')]
				[switch]$default,
												
				[parameter(Mandatory=$True, ParameterSetName='pin', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='oath', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='phone', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='email', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='password', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='securityQuestion', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='default', Position=1)]
				[string]$userID,

				[parameter(Mandatory=$True, ParameterSetName='pin', Position=2)]
				[string]$newPin,

				[parameter(Mandatory=$True, ParameterSetName='oath')]
				[string]$secretKey,

				[parameter(Mandatory=$True, ParameterSetName='oath')]
				[int]$timeIntervalInSeconds,
				
				[parameter(Mandatory=$True, ParameterSetName='oath')]
				[string]$serialNumber,

				[parameter(Mandatory=$True, ParameterSetName='oath')]
				[string]$manufacturer,

				[parameter(Mandatory=$True, ParameterSetName='oath')]
				[string]$model,
	
				[parameter(Mandatory=$True, ParameterSetName='phone')]
                [string]$phoneNumber,
				
				[parameter(Mandatory=$True, ParameterSetName='phone')]
                [ValidateSet("mobile","alternateMobile","office")][String]$phoneType,
            
				[parameter(Mandatory=$True, ParameterSetName='email', Position=2)]
                [string]$emailAddress,
			
				[parameter(Mandatory=$True, ParameterSetName='password')]
                [string]$newPassword,
			
				[parameter(Mandatory=$True, ParameterSetName='securityQuestion')]
                [string]$question,
			
				[parameter(Mandatory=$True, ParameterSetName='securityQuestion')]
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
                Check-Token
				$uri = $authMethodUri -f $userId,'phone'
				$postParams = @{}
				$postParams.phoneNumber = $phoneNumber
				$postParams.phoneType = $phoneType

				$json = $postparams | ConvertTo-Json -depth 99 -Compress
  
				$response = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $uri -Method Post -Body $json
				$values = ConvertFrom-Json $response.Content

				Return $values
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

function Set-AzureADUserAuthenticationMethod{
            
			[CmdletBinding()]
			Param(
                [parameter(Mandatory=$True, ParameterSetName='pin')]
				[switch]$pin,
				
				[parameter(Mandatory=$True, ParameterSetName='oath')]
				[switch]$oath,
				
				[parameter(Mandatory=$True, ParameterSetName='phone')]
				[parameter(Mandatory=$True, ParameterSetName='enableSmsSignIn')]
				[parameter(Mandatory=$True, ParameterSetName='disableSmsSignIn')]
				[switch]$phone,
				
				[parameter(Mandatory=$True, ParameterSetName='email')]
				[switch]$email,
				
				[parameter(Mandatory=$True, ParameterSetName='password')]
				[switch]$password,
				
				[parameter(Mandatory=$True, ParameterSetName='securityQuestion')]
				[switch]$securityQuestion,
				
				[parameter(Mandatory=$True, ParameterSetName='default')]
				[switch]$default,
				
				[parameter(Mandatory=$True, ParameterSetName='pin', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='oath', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='phone', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='email', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='password', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='securityQuestion', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='default', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='enableSmsSignIn', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='disableSmsSignIn', Position=1)]
				[string]$userID,

				[parameter(Mandatory=$True, ParameterSetName='pin', Position=2)]
				[string]$newPin,

				[parameter(Mandatory=$True, ParameterSetName='oath')]
				[string]$secretKey,

				[parameter(Mandatory=$True, ParameterSetName='oath')]
				[int]$timeIntervalInSeconds,
				
				[parameter(Mandatory=$True, ParameterSetName='oath')]
				[string]$serialNumber,

				[parameter(Mandatory=$True, ParameterSetName='oath')]
				[string]$manufacturer,

				[parameter(Mandatory=$True, ParameterSetName='oath')]
				[string]$model,
	
				[parameter(Mandatory=$True, ParameterSetName='phone')]
                [string]$phoneNumber,
				
				[parameter(Mandatory=$True, ParameterSetName='phone')]
				[parameter(Mandatory=$False, ParameterSetName='default')]
                [ValidateSet("mobile","alternateMobile","office")][String]$phoneType,
            
				[parameter(Mandatory=$True, ParameterSetName='email', Position=2)]
                [string]$emailAddress,
			
				[parameter(Mandatory=$True, ParameterSetName='password')]
                [string]$newPassword,
			
				[parameter(Mandatory=$True, ParameterSetName='securityQuestion')]
                [string]$question,
			
				[parameter(Mandatory=$True, ParameterSetName='securityQuestion')]
                [string]$answer,

				[parameter(Mandatory=$True, ParameterSetName='default')]
                [string]$defaultMethod,
				
				[parameter(Mandatory=$True, ParameterSetName='enableSmsSignIn')]
                [switch]$enableSmsSignIn,
				
				[parameter(Mandatory=$True, ParameterSetName='disableSmsSignIn')]
                [switch]$disableSmsSignIn
			
			)
		
		Check-Token
		
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
				if 		($phoneType -eq "alternateMobile"){$methodId = "b6332ec1-7057-4abe-9331-3d72feddfe41"}
				elseif 	($phoneType -eq "mobile"){$methodId = "3179e48a-750b-4051-897c-87b9720928f7"}
				else 	{$methodId = "e37fc753-ff3b-4958-9484-eaa9425c82bc"}

				$uri = $authMethodUri -f $userId,'phone' + "/$methodId"
				$postParams = @{}
				$postParams.phoneNumber = $phoneNumber
				$postParams.phoneType = $phoneType

				$json = $postparams | ConvertTo-Json -depth 99 -Compress

				$response = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $uri -Method Put -Body $json
				$values = ConvertFrom-Json $response.Content

				Return $values
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
				$uri = $authMethodUri -f $userId,'phone' + "/3179e48a-750b-4051-897c-87b9720928f7/enableSmsSignIn"
				$response = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $uri -Method Post
				$values = ConvertFrom-Json $response.Content

				Return $values
                break
            }
            "disableSmsSignIn" {
				$uri = $authMethodUri -f $userId,'phone' + "/3179e48a-750b-4051-897c-87b9720928f7/disableSmsSignIn"
				$response = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $uri -Method Post
				$values = ConvertFrom-Json $response.Content

				Return $values
                break
            }
        }

              
}


function Remove-AzureADUserAuthenticationMethod{
            
			[CmdletBinding()]
			Param(
                [parameter(Mandatory=$True, ParameterSetName='pin')]
				[switch]$pin,
				
				[parameter(Mandatory=$True, ParameterSetName='oath')]
				[switch]$oath,
				
				[parameter(Mandatory=$True, ParameterSetName='phone')]
				[switch]$phone,
				
				[parameter(Mandatory=$True, ParameterSetName='email')]
				[switch]$email,
				
				[parameter(Mandatory=$True, ParameterSetName='password')]
				[switch]$password,
				
				[parameter(Mandatory=$True, ParameterSetName='securityQuestion')]
				[switch]$securityQuestion,
											
				[parameter(Mandatory=$True, ParameterSetName='pin', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='oath', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='phone', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='email', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='password', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='securityQuestion', Position=1)]
				[parameter(Mandatory=$True, ParameterSetName='default', Position=1)]
				[string]$userID,
				
				[parameter(Mandatory=$True, ParameterSetName='oath')]
				[string]$serialNumber,
				
				[parameter(Mandatory=$True, ParameterSetName='phone')]
                [ValidateSet("mobile","alternateMobile","office")][String]$phoneType,
            
				[parameter(Mandatory=$True, ParameterSetName='email', Position=2)]
                [string]$emailAddress,
			
				[parameter(Mandatory=$True, ParameterSetName='securityQuestion')]
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
				Check-Token
				if 		($phoneType -eq "alternateMobile"){$methodId = "b6332ec1-7057-4abe-9331-3d72feddfe41"}
				elseif 	($phoneType -eq "mobile"){$methodId = "3179e48a-750b-4051-897c-87b9720928f7"}
				else 	{$methodId = "e37fc753-ff3b-4958-9484-eaa9425c82bc"}
						
				
				$uri = $authMethodUri -f $userId,'phone' + "/$methodId"
				$response = Invoke-WebRequest -UseBasicParsing -headers $authHeaders -Uri $uri -Method Delete 
				$values = ConvertFrom-Json $response.Content

				Return $values
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


Export-ModuleMember -Function Get-AzureADUserAuthenticationMethod
Export-ModuleMember -Function New-AzureADUserAuthenticationMethod
Export-ModuleMember -Function Set-AzureADUserAuthenticationMethod
Export-ModuleMember -Function Remove-AzureADUserAuthenticationMethod