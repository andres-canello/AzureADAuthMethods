function Invoke-AzureAdRequest
{
<#
	.SYNOPSIS
		Execute an arbitrary graph call against AzureAD endpoints.
	
	.DESCRIPTION
		Execute an arbitrary graph call against AzureAD endpoints.
		Handles authentication & token refresh transparently.
	
	.PARAMETER Query
		The actual query to execute.
	
	.PARAMETER Method
		The REST method to apply
	
	.PARAMETER Body
		Any body data to pass along as part of the request
	
	.PARAMETER GetValues
		Get the content of the .Value property, rather than the raw response content
	
	.PARAMETER Raw
		Get raw response
	
	.EXAMPLE
		PS C:\> Invoke-AzureAdRequest -Query 'users/3ec9f2ec-aeec-4ad9-ad18-b456288fdb32/authentication/phone' -Method GET
		
		Retrieve the phone authentication settings for the specified user.
#>
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $true)]
		[string]
		$Query,
		
		[Parameter(Mandatory = $true)]
		[string]
		$Method,
		
		$Body,
		
		[switch]
		$GetValues,
		
		[switch]
		$Raw
	)
	
	begin
	{
		try { $authHeader = Get-Token | ConvertTo-AuthHeader }
		catch { throw }
		
		$parameters = @{
			Method = $Method
			Uri    = "$($script:baseUri.Trim("/"))/$($Query.TrimStart("/"))"
			Headers = $authHeader
		}
		if ($Body) { $parameters.Body = $Body }
	}
	process
	{
		try { $response = Invoke-RestMethod @parameters -ErrorAction Stop }
		catch { throw }
		
		if ($Raw) { return $response }
		if ($GetValues) { return $response.Content.Value }
		$response.Content
	}
}
