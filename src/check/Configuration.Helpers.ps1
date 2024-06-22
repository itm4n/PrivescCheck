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

function Get-SccmCacheFile {
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

        foreach ($FileItem in $(Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue)) {

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
            catch [Exception] {
                Write-Warning $_.Exception.Message
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

function Get-WindowsDefenderExclusion {
    <#
    .SYNOPSIS
    Helper - Enumerate Windows Defender exclusions from various locations

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet attempts to find Windows Defender exclusions from various locations, such as the Registry, or the Event Logs.

    .PARAMETER Source
    The location to search for exclusions.

    .NOTES
    Source 1 - Registry: This technique is based on a tweet by @splinter_code, mentioning that exclusions can be listed as an unpriv user through the registry. This was fixed my Microsoft.
    Source 2 - EventLog: This technique is based in a tweet by @VakninHai, mentioning that exclusions can be extracted from the message of event logs with the ID 5007.

    .LINK
    https://twitter.com/splinter_code/status/1481073265380581381
    https://x.com/VakninHai/status/1796628601535652289
    #>

    [CmdletBinding()]
    param (
        [ValidateSet("Registry", "EventLog")]
        [string] $Source = "Registry"
    )

    begin {
        $ExclusionsRegKeys = @(
            "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions",
            "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions"
        )

        $LogName = "Microsoft-Windows-Windows Defender/Operational"
        $EventId = 5007

        $ExclusionNames = @{
            "Paths" = "Path"
            "Extensions" = "Extension"
            "Processes" = "Process"
        }
    }

    process {

        switch ($Source) {

            "Registry" {

                foreach ($ExclusionsRegKey in $ExclusionsRegKeys) {

                    Get-ChildItem -Path "Registry::$($ExclusionsRegKey)" -ErrorAction SilentlyContinue | ForEach-Object {

                        $Type = $ExclusionNames[$_.PSChildName]
                        $_ | Get-Item | Select-Object -ExpandProperty property | ForEach-Object {

                            $Exclusion = New-Object -TypeName PSObject
                            $Exclusion | Add-Member -MemberType "NoteProperty" -Name "Source" -Value $Source
                            $Exclusion | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $Type
                            $Exclusion | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $_
                            $Exclusion
                        }
                    }
                }
            }

            "EventLog" {

                $RegKeyExclusionPattern = "HKLM\\SOFTWARE\\(Policies\\)?Microsoft\\Windows Defender\\Exclusions\\(Processes|Extensions|Paths)\\(.+)"
                $Events = Get-WinEvent -LogName $LogName | Where-Object { $_.Id -eq $EventId }

                foreach ($Event in $Events) {

                    if ($Event.Message -match $RegKeyExclusionPattern) {
                        $Type = $ExclusionNames[$Matches[2]]
                        $Value = $Matches[3] -replace ' = .*'

                        $Exclusion = New-Object -TypeName PSObject
                        $Exclusion | Add-Member -MemberType "NoteProperty" -Name "Source" -Value $Source
                        $Exclusion | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $Type
                        $Exclusion | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $Value
                        $Exclusion
                    }
                }
            }

            default {
                throw "Unhandled source: $($Source)"
            }
        }
    }
}

function Get-SmbConfiguration {
    <#
    .SYNOPSIS
    Helper - Get the SMB server or client configuration

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet retrieves the SMB server or client configuration using the WMI/CIM classes MSFT_SmbServerConfiguration and MSFT_SmbClientConfiguration.

    .PARAMETER Role
    Either "Server" or "Client".

    .EXAMPLE
    PS C:\Temp> Get-SmbConfiguration -Role "Server"

    AnnounceComment                        :
    AnnounceServer                         : False
    AsynchronousCredits                    : 64
    AuditClientCertificateAccess           : False
    AuditSmb1Access                        : False
    AutoDisconnectTimeout                  : 15
    AutoShareServer                        : True
    AutoShareWorkstation                   : True
    CachedOpenLimit                        : 10
    DisableCompression                     : False
    DisableSmbEncryptionOnSecureConnection : True
    DurableHandleV2TimeoutInSeconds        : 180
    EnableAuthenticateUserSharing          : False
    EnableDirectoryHandleLeasing           : True
    EnableDownlevelTimewarp                : False
    EnableForcedLogoff                     : True
    EnableLeasing                          : True
    EnableMultiChannel                     : True
    EnableOplocks                          : True
    EnableSecuritySignature                : False
    EnableSMB1Protocol                     : False
    ...

    .LINK
    https://techcommunity.microsoft.com/t5/storage-at-microsoft/smb-signing-required-by-default-in-windows-insider/ba-p/3831704
    https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbserverconfiguration?view=windowsserver2022-ps
    https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbclientconfiguration?view=windowsserver2022-ps
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Server", "Client")]
        [string] $Role
    )

    begin {
        $Namespace = "ROOT/Microsoft/Windows/SMB"

        switch ($Role) {
            "Server" { $ClassName = "MSFT_SmbServerConfiguration" }
            "Client" { $ClassName = "MSFT_SmbClientConfiguration" }
            default  { throw "Unknown role: $($Role)" }
        }
    }

    process {
        try {
            if ($PSVersionTable.PSVersion.Major -gt 2) {
                $CimClass = Get-CimClass -ClassName $ClassName -Namespace $Namespace
                $Invocation = Invoke-CimMethod -CimClass $CimClass -MethodName "GetConfiguration"
                $Invocation.Output | Select-Object -Property * -ExcludeProperty "CimClass","CimInstanceProperties","CimSystemProperties","PSComputerName"
            }
            else {
                $WmiObject = Get-WmiObject -Class $ClassName -Namespace $Namespace -List
                $Invocation = $WmiObject.GetConfiguration()
                $Invocation.Output | Select-Object -Property * -ExcludeProperty "__Genus","__Class","__Superclass","__Dynasty","__Relpath","__Property_Count","__Derivation","__Server","__Namespace","__Path","Properties","SystemProperties","Qualifiers","ClassPath","Site","Container"
            }
        }
        catch {
            Write-Warning "$($_.Exception)"
        }
    }
}