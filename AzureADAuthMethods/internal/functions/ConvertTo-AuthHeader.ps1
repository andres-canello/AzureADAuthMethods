function ConvertTo-AuthHeader {
<#
	.SYNOPSIS
		Generates an authentication header from a graph token.
	
	.DESCRIPTION
		Generates an authentication header from a graph token.
	
	.PARAMETER Token
		The token from which to build the authentication header.
	
	.EXAMPLE
		PS C:\> Get-Token | ConvertTo-AuthHeader
	
		Generates an authentication header from a graph token.
#>
	[CmdletBinding()]
	param (
		[Parameter(ValueFromPipeline = $true)]
		$Token
	)
	
	process {
		foreach ($tokenObject in $Token) {
			@{
				Authorization = "Bearer $($tokenObject.AccessToken)"
				'Content-Type' = 'application/json'
				'Accept'	  = 'application/json, text/plain'
			}
		}
	}
}