function Connect-AzureADUserAuthentication
{
	[CmdletBinding()]
    param (
        [string]
		$TenantId,
		
        [string]
		$ClientID = "1b730954-1685-4b74-9bfd-dac224a7b894",
		
        [string]
		$RedirectUri = "urn:ietf:wg:oauth:2.0:oob",
		
        [string]
		$Scopes = "https://graph.microsoft.com/.default",
		
        [switch]
		$Interactive,
		
		[string]
		$BaseUri = 'https://graph.microsoft.com/beta/users/'
    )
    
    $token = Get-MSCloudIdAccessToken -TenantId $TenantId -ClientID $ClientID -RedirectUri $RedirectUri -Scopes $Scopes -Interactive:$Interactive
    $Header = @{ }
    $Header.Authorization = "Bearer {0}" -f $token.AccessToken
    $Header.'Content-type' = "application/json"
    
    $script:msgraphToken = $token
    $script:authHeader = $Header
}
