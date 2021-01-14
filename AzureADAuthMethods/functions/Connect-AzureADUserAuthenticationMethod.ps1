function Connect-AzureADUserAuthenticationMethod {
	[CmdletBinding(DefaultParameterSetName = 'Interactive')]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$TenantId,
		
		[Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
		[System.Security.Cryptography.X509Certificates.X509Certificate2]
		$Certificate,
		
		[Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
		[string]
		$Thumbprint,
		
		[Parameter(ParameterSetName = 'Thumbprint')]
		[string]
		$CertificateStore = 'Cert:\CurrentUser\My',
		
		[Parameter(ParameterSetName = 'Interactive')]
		[switch]
		$Interactive,

		[Parameter(ParameterSetName = 'Interactive')]
		[switch]
		$DeviceCode,
		
		[string]
		$ClientID = "",
		
		[string]
		$RedirectUri = "urn:ietf:wg:oauth:2.0:oob",
		
		[string]
		$BaseUri = 'https://graph.microsoft.com/beta/',
		
		[switch]
		$PassThru
	)
	
	process {
		if ($Thumbprint) {
			try { $Certificate = Get-Item -Path (Join-Path -Path $CertificateStore -ChildPath $Thumbprint) }
			catch { throw "Unable to find certificate $Thumbprint in certificate store $CertificateStore !" }
		}
		switch ($PSCmdlet.ParameterSetName) {
			'Interactive' {
				try { $token = Get-MsalToken -TenantId $TenantId -ClientId $ClientID -RedirectUri $RedirectUri -Interactive -DeviceCode:$DeviceCode }
				catch {
					Write-Warning "Failed to authenticate to tenant $TenantID : $_"
					throw
				}
			}
			default {
				try { $token = Get-MsalToken -TenantId $TenantId -ClientId $ClientID -ClientCertificate $Certificate }
				catch {
					Write-Warning "Failed to authenticate to tenant $TenantID : $_"
					throw
				}
			}
		}
		
		$script:msgraphToken = $token
		$script:baseUri = $BaseUri
		$script:tenantID = $TenantId
		$script:clientID = $ClientID
		$script:redirectUri = $RedirectUri
		$script:clientCertificate = $Certificate
		
		if ($PassThru) { $token }
	}
}
