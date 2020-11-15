function Get-Token
{
<#
	.SYNOPSIS
		Returns the token to use for authentication to MSGraph.
	
	.DESCRIPTION
		Returns the token to use for authentication to MSGraph.
		Automatically refreshes it if it is close to expiration.
	
	.EXAMPLE
		PS C:\> Get-Token
	
		Returns the token to use for authentication to MSGraph.
#>
	[CmdletBinding()]
	Param (
	
	)
	
	process
	{
		if ($script:msgraphToken -and $script:msgraphToken.ExpiresOn.LocalDateTime -gt (Get-Date).AddMinutes(3)) {
			return $script:msgraphToken
		}
		
		$parameters = @{
			TenantId = $script:tenantID
			ClientId = $script:clientID
			ErrorAction = 'Stop'
		}
		if ($script:clientCertificate) {
			$parameters.ClientCertificate = $script:clientCertificate
		}
		else {
			$parameters.RedirectUri = $script:redirectUri
			$parameters.LoginHint = $script:msgraphToken.Account.Username
			$parameters.Silent = $true
		}
		
		try { $token = Get-MsalToken @parameters }
		catch {
			Write-Warning "Failed to re-authenticate to tenant $script:tenantID : $_"
			throw
		}
		$script:msgraphToken = $token
		return $token
	}
}