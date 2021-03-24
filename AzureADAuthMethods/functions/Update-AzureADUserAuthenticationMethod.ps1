function Update-AzureADUserAuthenticationMethod {
	<#
.SYNOPSIS
    Modifies an authentication method for the user. Manages SMS Sign In for mobile phone method.
.DESCRIPTION
	Modifies an authentication method for the user. Manages SMS Sign In for mobile phone method.
	Use to modify an existing authentication method for the user. To create a new method, use New-AzureADUserAuthenticationMethod.
.EXAMPLE
    PS C:\>Update-AzureADUserAuthenticationMethod user@contoso.com -Phone -PhoneNumber '+61412345679' -PhoneType mobile
	Modifies the existing mobile phone number for the user.
.EXAMPLE
	PS C:\>Update-AzureADUserAuthenticationMethod -Phone -UPN user1@contoso.com -EnableSmsSignIn
	Enables SMS sign-in for the existing mobile phone authentication method for the user.
.EXAMPLE
	PS C:\>Update-AzureADUserAuthenticationMethod user@contoso.com -Password -NewPassword "password"
	Sets "password" as a new password for the user. Doesn't return the operation result.
.EXAMPLE
	PS C:\>Update-AzureADUserAuthenticationMethod user@contoso.com -Password -NewPassword "password" -ReturnResult
	Sets "password" as a new password for the user and waits 5 seconds for the operation result.
.EXAMPLE
	PS C:\>Update-AzureADUserAuthenticationMethod clouduser@contoso.com -Password
	Sets new system generated password for the user. Not available for syncronised users.
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
				
				$postParams = @{
					phoneNumber = $PhoneNumber
					phoneType   = $PhoneType
				}
				$json = $postparams | ConvertTo-Json -Depth 99 -Compress
				Invoke-AzureAdRequest -Method PUT -Query "users/$ObjectId/authentication/phoneMethods/$methodId" -Body $json
				break
			}
			"email" {
				$postParams = @{
					emailAddress = $EmailAddress
				}
				$json = $postparams | ConvertTo-Json -Depth 99 -Compress
				Invoke-AzureAdRequest -Method PUT -Query "users/$ObjectId/authentication/emailMethods/3ddfcfc8-9383-446f-83cc-3ab9be4be18f" -Body $json
				break
			}
			"password" {
				$parameters = @{
					Method = 'POST'
					Query = "users/$ObjectId/authentication/passwordMethods/28c10230-6103-485e-b985-444c60001490/resetPassword"
				}
				if ($NewPassword) {
					$parameters.Body = @{
						newPassword = $NewPassword
					} | ConvertTo-Json -Depth 99 -Compress
				}
				$response = Invoke-AzureAdRequest @parameters -Raw
				if (-not $ReturnResult) { return $response }
				
				# TODO: If RAW, use invoke-webrequest to get response headers.
				# Check password reset result
				if ($response.StatusCode -eq "202") {
					Write-Host "Waiting for a response..."
					Start-Sleep -Seconds 5
					(Invoke-WebRequest -UseBasicParsing -Headers (Get-Token | ConvertTo-AuthHeader) -Uri $response.Headers.Location -Method Get).Content
				}
				
				return $response.Content
			}
			"enableSmsSignIn" {
				Invoke-AzureAdRequest -Method PUT -Query "users/$ObjectId/authentication/phoneMethods/3179e48a-750b-4051-897c-87b9720928f7/enableSmsSignIn" -Body $json
				break
			}
			"disableSmsSignIn" {
				Invoke-AzureAdRequest -Method PUT -Query "users/$ObjectId/authentication/phoneMethods/3179e48a-750b-4051-897c-87b9720928f7/disableSmsSignIn" -Body $json
				break
			}
			default {
				throw "Setting the $($PSCmdlet.ParameterSetName) method is not yet supported."
			}
		}
	}
}
