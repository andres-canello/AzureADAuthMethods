function Convert-Object {
    <#
    .SYNOPSIS
        Modifies an object by adding, renaming or removing properties.
    
    .DESCRIPTION
        Modifies an object by adding, renaming or removing properties.
    
    .PARAMETER Remove
        Properties to remove.
        Offer an explicit list of properties to remove.
        Properties that do not exist on the input-object will be ignored.
    
    .PARAMETER Add
        Add properties.
        Supports three notations:
        
        Example 1) String, reference to input object
        Device.DisplayName as DeviceDisplayName
        Example 2) String, absolute code
        DisplayName = $name
        Example 3) Hashtable
        @{ Name = 'Foo'; Expression = { $args[0].Bar }}
    
    .PARAMETER Rename
        Rename a property. Notation is SQL style: "OldName as NewName"
        Example: "Name as DisplayName"
    
    .PARAMETER InputObject
        The object to convert.
    #>
    [CmdletBinding()]
    param (
        [string[]]
        $Remove,
        [object[]]
        $Add,
        [string[]]
        $Rename,
        [Parameter(ValueFromPipeline = $true)]
        $InputObject
    )
    begin {
        $renames = @{ }
        foreach ($renameString in $Rename) {
            $currentName, $newName = $renameString -split " as "
            $renames[$currentName] = $newName
        }
        $additions = @{ }
        foreach ($addition in $Add) {
            if ($null -eq $addition) { continue }
            switch ($addition.GetType().Name) {
                string {
                    if ($addition -like "* as *") {
                        $expression, $name = $addition -split " as "
                        if ($expression -like '*$_*' -or $expression -like '*$args[0]*') { $additions[$name] = [scriptblock]::Create(($expression -replace '\$_', '$args[0]')) }
                        else { $additions[$name] = [scriptblock]::Create("`$args[0].$expression") }
                    }
                    if ($addition -like "* = *") {
                        $name, $expression = $addition -split " = "
                        $additions[$name] = [scriptblock]::Create($expression)
                    }
                }
                hashtable {
                    $additions[$addition.Name] = $addition.Expression
                }
            }
        }
    }
    process {
        foreach ($item in $InputObject) {
            $hash = @{ }
            foreach ($property in $item.PSObject.Properties) {
                if ($property.Name -in $Remove) { continue }
                if ($property.Name -in $renames.Keys) { $name = $renames[$property.Name] }
                else { $name = $property.Name }
                $hash[$name] = $property.Value
            }
            foreach ($addKey in $additions.Keys) {
                try { $hash[$addKey] = $additions[$addKey].Invoke($item) | Write-Output }
                catch { $hash[$addKey] = $null }
            }
            [pscustomobject]$hash
        }
    }
}