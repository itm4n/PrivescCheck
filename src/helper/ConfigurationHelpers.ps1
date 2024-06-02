function Get-SccmCacheFoldersFromRegistry {
    <#
    .SYNOPSIS
    Helper - Enumerate SCCM cache folders using the registry.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function lists the values of the registry key 'HKLM\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution', checks if their data contains the path of an SCCM cache folder, and finally returns all valid paths
    #>

    [CmdletBinding()]
    param ()

    begin {
        $SoftwareDistributionKey = "HKLM\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution"
    }

    process {
        $SoftwareDistributionKeyItem = Get-Item -Path "Registry::$($SoftwareDistributionKey)" -ErrorAction SilentlyContinue
        if ($null -eq $SoftwareDistributionKeyItem) { return }

        foreach ($Value in $($SoftwareDistributionKeyItem | Select-Object -ExpandProperty Property)) {

            # Filer out values that don't contain an SCCM cache folder path.
            $Data = (Get-ItemProperty -Path "Registry::$($SoftwareDistributionKey)" -Name $Value).$Value
            if ($Data -notlike "*ccmcache*") { continue }

            # Only return folders that exist.
            $FolderItem = Get-Item -Path "$($Data)" -ErrorAction SilentlyContinue
            if ($null -eq $FolderItem) { continue }

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $Value
            $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Data
            $Result
        }
    }
}

function Get-SccmCacheFiles {
    <#
    .SYNOPSIS
    Helper - Enumerate application files in SCCM cache folders.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function first retrieves a list of SCCM cache folders, and, for each path, lists files recursively. It then returns all paths corresponding to a script or executable.
    #>

    [CmdletBinding()]
    param (
        [string] $Path
    )

    begin {
        $ScriptFileExtensions = @( "bat", "cmd", "ps1", "vbe", "vbs", "wsf", "wsh" )
        $ScriptPathRegex = ".*\.($($ScriptFileExtensions -join '|'))$"

        $BinFileExtensions = @( "exe", "dll", "msi" )
        $BinFilePathRegex = ".*\.($($BinFileExtensions -join '|'))$"

        $TextFileExtensions = @( "reg", "cfg", "txt" )
        $TextFilePathRegex = ".*\.($($TextFileExtensions -join '|'))$"
    }

    process {

        $SearchPath = [string[]] @()
        $SearchPath += Join-Path -Path $Path -ChildPath "\*"
        $SearchPath += Join-Path -Path $Path -ChildPath "\*\*"
        $SearchPath += Join-Path -Path $Path -ChildPath "\*\*\*"

        foreach ($FileItem in $(Get-ChildItem -Path $SearchPath -ErrorAction SilentlyContinue)) {

            if ($FileItem -is [System.IO.DirectoryInfo]) { continue }

            if ($FileItem.FullName -match $ScriptPathRegex) {
                $FileType = "Script"
            }
            elseif ($FileItem.FullName -match $BinFilePathRegex) {
                $FileType = "Binary"
            }
            elseif ($FileItem.FullName -match $TextFilePathRegex) {
                $FileType = "Text"
            }
            else {
                continue
            }

            try {
                # Determine file path relative to the cache folder path.
                Push-Location -Path $Path
                $RelativePath = Resolve-Path -Path $FileItem.FullName -Relative
            }
            catch {
                # Nothing to do
            }
            finally {
                Pop-Location
            }

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $FileType
            $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $FileItem.FullName
            $Result | Add-Member -MemberType "NoteProperty" -Name "RelativePath" -Value $RelativePath
            $Result
        }
    }
}

function Get-ProxyAutoConfigURl {

    [CmdletBinding()]
    param (

    )

    begin {
        $RegKeys = @(
            "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        )
    }

    process {

        foreach ($RegKey in $RegKeys) {

            $RegValue = "ProxyEnable"
            $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
            if ($null -eq $RegData) { continue }

            $ProxyEnable = [UInt32] $RegData

            $RegValue = "AutoConfigURL"
            $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

            $ProxyAutoConfigUrl = $RegData

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
            $Result | Add-Member -MemberType "NoteProperty" -Name "ProxyEnable" -Value $ProxyEnable
            $Result | Add-Member -MemberType "NoteProperty" -Name "AutoConfigURL" -Value $ProxyAutoConfigUrl
            $Result
        }
    }
}