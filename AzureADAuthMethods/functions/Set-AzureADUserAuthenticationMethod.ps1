function Set-AzureADUserAuthenticationMethod {

	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True,ParameterSetName = 'pin')]
		[switch]$Pin,

		[Parameter(Mandatory = $True,ParameterSetName = 'oath')]
		[switch]$Oath,

		[Parameter(Mandatory = $True,ParameterSetName = 'phone')]
		[Parameter(Mandatory = $True,ParameterSetName = 'enableSmsSignIn')]
		[Parameter(Mandatory = $True,ParameterSetName = 'disableSmsSignIn')]
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
		[Parameter(Mandatory = $True,ParameterSetName = 'enableSmsSignIn',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
		[Parameter(Mandatory = $True,ParameterSetName = 'disableSmsSignIn',Position = 1,ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
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
		[Parameter(Mandatory = $False,ParameterSetName = 'default')]
		[ValidateSet("mobile","alternateMobile","office")] [string]$PhoneType,

		[Parameter(Mandatory = $True,ParameterSetName = 'email',Position = 2)]
		[string]$EmailAddress,

		[Parameter(Mandatory = $False,ParameterSetName = 'password')]
		[string]$NewPassword,

		[Parameter(Mandatory = $False,ParameterSetName = 'password')]
		[switch]$ReturnResult,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[string]$Question,

		[Parameter(Mandatory = $True,ParameterSetName = 'securityQuestion')]
		[string]$Answer,

		[Parameter(Mandatory = $True,ParameterSetName = 'default')]
		[string]$DefaultMethod,

		[Parameter(Mandatory = $True,ParameterSetName = 'enableSmsSignIn')]
		[switch]$EnableSmsSignIn,

		[Parameter(Mandatory = $True,ParameterSetName = 'disableSmsSignIn')]
		[switch]$DisableSmsSignIn

	)

	Process {

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
				$postParams = @{
					phoneNumber = $phoneNumber
					phoneType = $phoneType
				}

				$json = $postparams | ConvertTo-Json -Depth 99 -Compress

				$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Put -Body $json
				$values = ConvertFrom-Json $response.Content

				return $values
				break
			}
			"email" {
				$uri = $authMethodUri -f $ObjectId,'email' + "/3ddfcfc8-9383-446f-83cc-3ab9be4be18f"
				$postParams = @{}
				$postParams.emailAddress = $EmailAddress

				$json = $postparams | ConvertTo-Json -Depth 99 -Compress

				$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Put -Body $json
				$values = ConvertFrom-Json $response.Content

				return $values
				break
			}
			"password" {
				$uri = $authMethodUri -f $ObjectId,'password' + "/28c10230-6103-485e-b985-444c60001490/resetPassword"
				if ($newPassword){
					$postParams = @{}
					$postParams.newPassword = $newPassword
					$json = $postparams | ConvertTo-Json -Depth 99 -Compress
		
					$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Post -Body $json
				}else{
					$response = Invoke-WebRequest -UseBasicParsing -Headers $authHeaders -Uri $uri -Method Post
				}
				$values = ConvertFrom-Json $response.Content

				# Check password reset result
				if (($response.StatusCode -eq "202") -and $returnResult){
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
}
