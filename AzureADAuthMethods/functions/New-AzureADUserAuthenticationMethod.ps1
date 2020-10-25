function New-AzureADUserAuthenticationMethod {

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

		[Parameter(Mandatory = $True,ParameterSetName = 'default')]
		[switch]$Default,

		[Alias('UserId','UPN','UserPrincipalName')]
		[Parameter(Mandatory = $True,ParameterSetName = 'pin',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'oath',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'phone',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'email',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'password',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'default',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[string]$ObjectId,

		[Parameter(Mandatory = $True,ParameterSetName = 'pin',Position = 2)]
		[string]$NewPin,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[string]$SecretKey,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[int]$TimeIntervalInSeconds,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[string]$SerialNumber,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[string]$Manufacturer,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[string]$Model,

		[Parameter(Mandatory = $True,ParameterSetName = 'phone')]
		[string]$PhoneNumber,

		[Parameter(Mandatory = $True,ParameterSetName = 'phone')]
		[ValidateSet("mobile","alternateMobile","office")] [string]$PhoneType,

		[Parameter(Mandatory = $True,ParameterSetName = 'email',Position = 2)]
		[string]$EmailAddress,

		[Parameter(Mandatory = $True,ParameterSetName = 'password')]
		[string]$NewPassword,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[string]$Question,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[string]$Answer

	)

	begin {
		Test-TokenValidity
	}

	Process {
		switch ($PSCmdlet.ParameterSetName) {
			"pin" {
				Write-Host "Setting pin method is not yet supported."
				break
			}
			"oath" {
				Write-Host "Setting oath method is not yet supported."
				break
			}
			"phone" {
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
				$uri = $authMethodUri -f $ObjectId,'email'
				$postParams = @{}
				$postParams.emailAddress = $EmailAddress

				$json = $postparams | ConvertTo-Json -Depth 99 -Compress

				$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Post -Body $json
				$values = ConvertFrom-Json $response.Content

				return $values
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
}
