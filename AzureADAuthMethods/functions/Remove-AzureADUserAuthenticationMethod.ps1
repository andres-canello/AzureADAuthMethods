function Remove-AzureADUserAuthenticationMethod {

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

		[Parameter(Mandatory = $True,ParameterSetName = 'FIDO2')]
		[switch]$FIDO2,

		[Parameter(Mandatory = $True,ParameterSetName = 'passwordlessMicrosoftAuthenticator')]
		[switch]$PasswordlessMicrosoftAuthenticator,

		[Parameter(Mandatory = $True,ParameterSetName = 'FIDO2')]
		[Parameter(Mandatory = $True,ParameterSetName = 'passwordlessMicrosoftAuthenticator')]
		[string]$MethodId,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[switch]$SecurityQuestion,

		[Alias('UserId','UPN','UserPrincipalName')]
		[Parameter(Mandatory = $True,ParameterSetName = 'pin',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'oath',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'phone',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'email',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'FIDO2',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'passwordlessMicrosoftAuthenticator',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'password',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'default',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[string]$ObjectId,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[string]$SerialNumber,

		[Parameter(Mandatory = $True,ParameterSetName = 'phone')]
		[ValidateSet("mobile","alternateMobile","office")] [string]$PhoneType,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[string]$Question

	)
	
	Process {
	
		Test-TokenValidity

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
				$uri = $authMethodUri -f $ObjectId,'email' + "/3ddfcfc8-9383-446f-83cc-3ab9be4be18f"
				$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Delete
				$values = ConvertFrom-Json $response.Content

				return $values
				break
			}
			"securityQuestion" {
				Write-Host "Setting security question method is not yet supported."
				break
			}
			"FIDO2" {
				$uri = $authMethodUri -f $ObjectId,'fido2' + "/$MethodId"
				$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Delete
				$values = ConvertFrom-Json $response.Content

				return $values
				break
			}
			"passwordlessMicrosoftAuthenticator" {
				$uri = $authMethodUri -f $ObjectId,'passwordlessMicrosoftAuthenticator' + "/$MethodId"
				$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Delete
				$values = ConvertFrom-Json $response.Content

				return $values
				break
			}

		}
	}
}
