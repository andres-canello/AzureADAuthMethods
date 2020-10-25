function Test-TokenValidity {
	[CmdletBinding()]
	param ()

	if ($script:authResult) {
		# We have an auth context
		if ($script:authResult.ExpiresOn.LocalDateTime -gt (Get-Date)) {

			# Token is still valid, nothing to do here.
			$remaining = $script:authResult.ExpiresOn.LocalDateTime - (Get-Date)
			Write-Host "Access Token valid for $remaining" -ForegroundColor Green

		} else {
			# Token expired, try to get a new one silently from the token cache			
			Write-Host 'Access Token expired, getting new token silently' -ForegroundColor Green
			$script:authResult = New-Auth $script:authResult
			$script:authHeaders = New-AuthHeaders

		}

	} else {
		# No auth context, go interactive
		Write-Host "We need to authenticate first, select a user with the appropriate permissions" -ForegroundColor Green
		$script:authResult = New-Auth
		$script:authHeaders = New-AuthHeaders
	}
}