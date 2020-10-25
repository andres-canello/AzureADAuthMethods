function Invoke-AzureAdRequest
{
	[CmdletBinding()]
	Param (
		$Uri,
		$Method,
		$Body
	)
	
	begin
	{
		$token = Get-Token
	}
	process
	{
	
	}
	end
	{
	
	}
}
