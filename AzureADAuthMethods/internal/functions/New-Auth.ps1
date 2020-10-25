function New-Auth {
	[CmdletBinding()]
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
