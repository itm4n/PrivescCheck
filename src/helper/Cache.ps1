
function Test-CachedData {

    [OutputType([Bool])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $Name
    )

    $CacheEntryFound = $false

    foreach ($CacheEntryName in $script:GlobalCache.Keys) {
        if ($CacheEntryName -eq $Name) {
            return $null -ne $script:GlobalCache[$CacheEntryName]
        }
    }

    if (-not $CacheEntryFound) {
        throw "No cache entry with key '$($Name)' found."
    }
}

function Get-CachedData {

    [OutputType([Object[]])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $Name
    )

    $CacheEntryFound = $false

    foreach ($CacheEntryName in $script:GlobalCache.Keys) {
        if ($CacheEntryName -eq $Name) {
            $script:GlobalCache[$CacheEntryName]
            $CacheEntryFound = $true
            break
        }
    }

    if (-not $CacheEntryFound) {
        throw "No cache entry with key '$($Name)' found."
    }
}

function Set-CachedData {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $Name,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [Object[]] $Data
    )

    $CacheEntryFound = $false

    foreach ($CacheEntryName in $script:GlobalCache.Keys) {
        if ($CacheEntryName -eq $Name) {
            Write-Verbose "Setting cache data: $($Name)"
            $script:GlobalCache[$CacheEntryName] = $Data
            $CacheEntryFound = $true
            break
        }
    }

    if (-not $CacheEntryFound) {
        throw "No cache entry with key '$($Name)' found."
    }
}

function Clear-CachedData {

    [CmdletBinding()]
    param ()

    foreach ($CacheEntryName in $($script:GlobalCache.Keys)) {
        $script:GlobalCache[$CacheEntryName] = $null
    }
}
