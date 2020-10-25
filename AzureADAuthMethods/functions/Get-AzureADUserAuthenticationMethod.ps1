function Get-AzureADUserAuthenticationMethod {

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = 'pin')]
		[switch]$Pin,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[switch]$Oath,

		[Parameter(Mandatory = $True,ParameterSetName = 'phone')]
		[switch]$Phone,

		[Parameter(Mandatory = $True,ParameterSetName = 'email')]
		[switch]$Email,

		[Parameter(Mandatory = $True,ParameterSetName = 'password')]
		[switch]$Password,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[switch]$SecurityQuestion,

		[Parameter(Mandatory = $True,ParameterSetName = 'FIDO2')]
		[switch]$FIDO2,

		[Parameter(Mandatory = $True,ParameterSetName = 'passwordlessMicrosoftAuthenticator')]
		[switch]$PasswordlessMicrosoftAuthenticator,

		[Parameter(Mandatory = $True,ParameterSetName = 'default')]
		[switch]$Default,

		[Alias('UserId','UPN','UserPrincipalName')]
		[Parameter(Mandatory = $True,ParameterSetName = 'pin',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'oath',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'phone',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'email',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'password',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'FIDO2',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'passwordlessMicrosoftAuthenticator',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'default',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'allMethods',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[string]$ObjectId
	)

	Process {

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
				} else {
					$Methods = Add-UserToMethods -Methods $values.value -ObjectId $ObjectId
					return $Methods
				}
				break
			}
			"email" {
				$uri = $authMethodUri -f $ObjectId,'email'
				$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Get
				$values = ConvertFrom-Json $response.Content

				if ($values.value.count -eq 0) {
					Write-Host "User $ObjectId has no email auth method."
				} else {
					$Methods = Add-UserToMethods -Methods $values.value -ObjectId $ObjectId
					return $Methods
				}
				break
			}
			"password" {
				$uri = $authMethodUri -f $ObjectId,'password'
				$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Get
				$values = ConvertFrom-Json $response.Content

				if ($values.value.count -eq 0) {
					Write-Host "User $ObjectId has no password auth methods."
				} else {
					$Methods = Add-UserToMethods -Methods $values.value -ObjectId $ObjectId
					return $Methods
				}
				break
			}
			"FIDO2" {
				$uri = $authMethodUri -f $ObjectId,'fido2'
				$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Get
				$values = ConvertFrom-Json $response.Content

				if ($values.value.count -eq 0) {
					Write-Host "User $ObjectId has no FIDO2 Security Keys."
				} else {
					$Methods = Add-UserToMethods -Methods $values.value -ObjectId $ObjectId
					return $Methods
				}
				break
			}
			"passwordlessMicrosoftAuthenticator" {
				$uri = $authMethodUri -f $ObjectId,'passwordlessMicrosoftAuthenticator'
				$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Get
				$values = ConvertFrom-Json $response.Content

				if ($values.value.count -eq 0) {
					Write-Host "User $ObjectId has no devices configured for Microsoft Authenticator Phone Sign-in."
				} else {
					$Methods = Add-UserToMethods -Methods $values.value -ObjectId $ObjectId
					return $Methods
				}
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
				} else {
					$Methods = Add-UserToMethods -Methods $values.value -ObjectId $ObjectId
					return $Methods
				}
				break
			}
		}
	}
}
