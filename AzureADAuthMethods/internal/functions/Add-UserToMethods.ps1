function Add-UserToMethods{
	[CmdletBinding()]
	param(
		[Parameter(Mandatory = $True)]
		$Methods,

		[Parameter(Mandatory = $True)]
		$ObjectId
	)
	if ($Methods.count -gt 0){
		foreach ($method in $Methods){
			$method | Add-Member -NotePropertyName userObjectId -NotePropertyValue $ObjectId
		}
	}
	return $Methods
}
