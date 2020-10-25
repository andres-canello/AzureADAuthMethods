function New-AuthHeaders{
	[CmdletBinding()]
	param ()
	
	$aH = $null
	$aH = New-Object 'System.Collections.Generic.Dictionary[[String],[String]]'
	$aH.Add('Authorization', 'Bearer ' + $authResult.AccessToken)
	$aH.Add('Content-Type','application/json')
	$aH.Add('Accept','application/json, text/plain')

	return $aH

}
