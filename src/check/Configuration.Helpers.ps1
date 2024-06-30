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
    param()

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
    param(
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

            $RelativePath = Resolve-PathRelativeTo -From $Path -To $FileItem.FullName

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
    param()

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
    Source 1 - Registry: This technique is based on a tweet by @splinter_code, mentioning that exclusions can be listed as a low-privileged user through the registry. This was fixed my Microsoft.
    Source 2 - EventLog: This technique is based in a tweet by @VakninHai, mentioning that exclusions can be extracted from the message of event logs with the ID 5007.

    .LINK
    https://twitter.com/splinter_code/status/1481073265380581381
    https://x.com/VakninHai/status/1796628601535652289
    #>

    [CmdletBinding()]
    param(
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

function Get-PointAndPrintConfiguration {
    <#
    .SYNOPSIS
    Get the Point and Print configuration.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet retrieves information about the Point and Print configuration, and checks whether each setting is considered as compliant depending on its value.
    #>

    [CmdletBinding()]
    param()

    begin {
        $NoWarningNoElevationOnInstallDescriptions = @(
            "Show warning and elevation prompt (default).",
            "Do not show warning or elevation prompt. Note: this setting reintroduces the PrintNightmare LPE vulnerability, even if the settings 'InForest' and/or 'TrustedServers' are configured."
        )

        $UpdatePromptSettingsDescriptions = @(
            "Show warning and elevation prompt (default).",
            "Show warning only.",
            "Do not show warning or elevation prompt."
        )

        $TrustedServersDescriptions = @(
            "Users can point and print to any server (default).",
            "Users can only point and print to a predefined list of servers. Note: this setting has no effect if elevation prompts are disabled."
        )

        $InForestDescriptions = @(
            "Users can point and print to any machine (default).",
            "Users can only point and print to machines in their forest. Note: this setting has no effect if elevation prompts are disabled."
        )

        $RestrictDriverInstallationToAdministratorsDescriptions = @(
            "Installing printer drivers does not require administrator privileges.",
            "Installing printer drivers when using Point and Print requires administrator privileges (default). Note: this setting supersedes any other (Package) Point and Print setting."
        )

        $PackagePointAndPrintOnlyDescriptions = @(
            "Users will not be restricted to package-aware point and print only (default).",
            "Users will only be able to point and print to printers that use package-aware drivers."
        )

        $PackagePointAndPrintServerListDescriptions = @(
            "Package point and print will not be restricted to specific print servers (default).",
            "Users will only be able to package point and print to print servers approved by the network administrator."
        )
    }

    process {
        $Result = New-Object -TypeName PSObject

        # Policy: Computer Configuration > Administrative Templates > Printers > Point and Print Restrictions
        # https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PointAndPrint_Restrictions
        # - 0 = Show warning and elevation prompt (default)
        # - 1 = Do not show warning or elevation prompt
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "NoWarningNoElevationOnInstall"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $RegDataDefault = 0
        $DescriptionIndex = $(if ($null -eq $RegData) { $RegDataDefault } else { $RegData })

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Point and Print Restrictions > NoWarningNoElevationOnInstall"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "<null|0>"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $NoWarningNoElevationOnInstallDescriptions[$DescriptionIndex]
        $Result | Add-Member -MemberType "NoteProperty" -Name "NoWarningNoElevationOnInstall" -Value $Item

        # Policy: Computer Configuration > Administrative Templates > Printers > Point and Print Restrictions
        # https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PointAndPrint_Restrictions
        # - 0 = Show warning and elevation prompt (default)
        # - 1 = Show warning only
        # - 2 = Do not show warning or elevation prompt
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "UpdatePromptSettings"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $RegDataDefault = 0
        $DescriptionIndex = $(if ($null -eq $RegData) { $RegDataDefault } else { $RegData })

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Point and Print Restrictions > UpdatePromptSettings"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "<null|0>"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $UpdatePromptSettingsDescriptions[$DescriptionIndex]
        $Result | Add-Member -MemberType "NoteProperty" -Name "UpdatePromptSettings" -Value $Item

        # Policy: Computer Configuration > Administrative Templates > Printers > Point and Print Restrictions
        # https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PointAndPrint_Restrictions
        # - 0 = Users can point and print to any server (default)
        # - 1 = Users can only point and print to a predefined list of servers
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "TrustedServers"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $RegDataDefault = 0
        $DescriptionIndex = $(if ($null -eq $RegData) { $RegDataDefault } else { $RegData })

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Point and Print Restrictions > TrustedServers"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "N/A"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $TrustedServersDescriptions[$DescriptionIndex]
        $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedServers" -Value $Item

        # Policy: Computer Configuration > Administrative Templates > Printers > Point and Print Restrictions
        # https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PointAndPrint_Restrictions
        # - 0 = Users can point and print to any machine (default)
        # - 1 = Users can only point and print to machines in their forest
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "InForest"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $RegDataDefault = 0
        $DescriptionIndex = $(if ($null -eq $RegData) { $RegDataDefault } else { $RegData })

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Point and Print Restrictions > InForest"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "N/A"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $InForestDescriptions[$DescriptionIndex]
        $Result | Add-Member -MemberType "NoteProperty" -Name "InForest" -Value $Item

        # Policy: Computer Configuration > Administrative Templates > Printers > Point and Print Restrictions
        # https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PointAndPrint_Restrictions
        # - "" = Empty or undefined (default)
        # - "foo;bar" = List of servers
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "ServerList"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Point and Print Restrictions > ServerList"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value "(null)"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "N/A"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ([string]::IsNullOrEmpty($RegData)) { "A list of approved Point and Print servers is not defined." } else { "A list of approved Point and Print servers is defined." })
        $Result | Add-Member -MemberType "NoteProperty" -Name "ServerList" -Value $Item

        # Policy: Limits print driver installation to Administrators
        # https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::RestrictDriverInstallationToAdministrators
        # - 0 - Installing printer drivers does not require administrator privileges.
        # - 1 = Installing printer drivers when using Point and Print requires administrator privileges (default).
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "RestrictDriverInstallationToAdministrators"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $RegDataDefault = 1
        $DescriptionIndex = $(if ($null -eq $RegData) { $RegDataDefault } else { $RegData })

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Limits print driver installation to Administrators"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "<null|1>"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $RestrictDriverInstallationToAdministratorsDescriptions[$DescriptionIndex]
        $Result | Add-Member -MemberType "NoteProperty" -Name "RestrictDriverInstallationToAdministrators" -Value $Item

        # Policy: Only use Package Point and Print
        # https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PackagePointAndPrintOnly
        # - 0 = "Users will not be restricted to package-aware point and print only (default)."
        # - 1 = "Users will only be able to point and print to printers that use package-aware drivers."
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint"
        $RegValue = "PackagePointAndPrintOnly"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $RegDataDefault = 0
        $DescriptionIndex = $(if ($null -eq $RegData) { $RegDataDefault } else { $RegData })

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Package Point and print - Only use Package Point and Print"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "<null|1>"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $PackagePointAndPrintOnlyDescriptions[$DescriptionIndex]
        $Result | Add-Member -MemberType "NoteProperty" -Name "PackagePointAndPrintOnly" -Value $Item

        # Policy: Package Point and print - Approved servers
        # https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PackagePointAndPrintServerList
        # - 0 = Package point and print will not be restricted to specific print servers (default).
        # - 1 = Users will only be able to package point and print to print servers approved by the network administrator.
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint"
        $RegValue = "PackagePointAndPrintServerList"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $RegDataDefault = 0
        $DescriptionIndex = $(if ($null -eq $RegData) { $RegDataDefault } else { $RegData })

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Package Point and print - Approved servers > PackagePointAndPrintServerList"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "<null|1>"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $PackagePointAndPrintServerListDescriptions[$DescriptionIndex]
        $Result | Add-Member -MemberType "NoteProperty" -Name "PackagePointAndPrintServerListEnabled" -Value $Item

        # Policy: Package Point and print - Approved servers
        # https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PackagePointAndPrintServerList
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint\ListOfServers"
        $RegData = Get-Item -Path ($RegKey -replace "HKLM\\","HKLM:\") -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Package Point and print - Approved servers > PackagePointAndPrintServerList"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value "N/A"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if (-not [string]::IsNullOrEmpty($RegData)) { $RegData -join "; " })
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value "(null)"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "<null|SERVER_LIST>"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ([string]::IsNullOrEmpty($RegData)) { "A list of approved Package Point and Print servers is not defined." } else { "A list of approved Package Point and Print servers is defined." })
        $Result | Add-Member -MemberType "NoteProperty" -Name "PackagePointAndPrintServerList" -Value $Item

        $Result
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
    ...
    EnableSecuritySignature                : False
    EnableSMB1Protocol                     : False
    ...

    .LINK
    https://techcommunity.microsoft.com/t5/storage-at-microsoft/smb-signing-required-by-default-in-windows-insider/ba-p/3831704
    https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbserverconfiguration?view=windowsserver2022-ps
    https://learn.microsoft.com/en-us/powershell/module/smbshare/get-smbclientconfiguration?view=windowsserver2022-ps
    #>

    [CmdletBinding()]
    param(
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

function Get-RegisteredComFromRegistry {
    <#
    .SYNOPSIS
    Helper - Enumerate registered COM classes through the registry

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet enumerates the registry keys under HKLM\SOFTWARE\Classes\CLSID to list registered COM classes.

    .EXAMPLE
    PS C:\> Get-RegisteredComFromRegistry

    ...

    Id       : {046AEAD9-5A27-4D3C-8A67-F82552E0A91B}
    Path     : HKLM\SOFTWARE\Classes\CLSID\{046AEAD9-5A27-4D3C-8A67-F82552E0A91B}
    Value    : LocalServer32
    Data     : C:\Windows\System32\rundll32.exe shell32.dll,SHCreateLocalServerRunDll {046AEAD9-5A27-4D3C-8A67-F82552E0A91B}
    DataType : CommandLine

    Id       : {04731B67-D933-450a-90E6-4ACD2E9408FE}
    Path     : HKLM\SOFTWARE\Classes\CLSID\{04731B67-D933-450a-90E6-4ACD2E9408FE}
    Value    : InProcServer32
    Data     : C:\Windows\system32\Windows.Storage.Search.dll
    DataType : FilePath

    ...

    .LINK
    https://learn.microsoft.com/en-us/windows/win32/com/component-object-model--com--portal
    #>

    [CmdletBinding()]
    param ()

    begin {
        $RootKey = "HKLM\SOFTWARE\Classes\CLSID"
        $ComTypes = @( "InprocHandler", "InprocHandler32", "InprocServer", "InprocServer32", "LocalServer", "LocalServer32" )
    }

    process {

        if ($script:CachedRegisteredComList.Count -eq 0) {

            $ClassIds = Get-ChildItem -Path "Registry::$($RootKey)" -ErrorAction SilentlyContinue
            Write-Verbose "CLSID count: $($ClassIds.Count)"

            foreach ($ClassId in $ClassIds) {
                $ServerProperties = Get-ChildItem -Path "Registry::$($ClassId.Name)" -ErrorAction SilentlyContinue | Where-Object { $ComTypes -contains $_.PSChildName }
                if ($null -eq $ServerProperties) { continue }

                foreach ($ServerProperty in $ServerProperties) {

                    $ServerData = $ServerProperty.GetValue($null, $null, "DoNotExpandEnvironmentNames")
                    $ServerDataType = $null

                    if ($ServerProperty.PSChildName -like "Inproc*") {
                        # The data contains the name or path of a DLL.
                        # $PathToAnalyze = $ServerData
                        $PathToAnalyze = [System.Environment]::ExpandEnvironmentVariables($ServerData)
                        # The following regex matches any string surrounded by double quotes, but not
                        # containing double quotes within it. This should match quoted paths such as
                        # "C:\windows\system32\combase.dll"
                        if ($ServerData -match "^`"[^`"]+`"`$") {
                            $PathToAnalyze = $PathToAnalyze.Trim('"')
                        }
                        if ([System.IO.Path]::IsPathRooted($PathToAnalyze)) {
                            $ServerDataType = "FilePath"
                        }
                        else {
                            $ServerDataType = "FileName"
                        }
                    }
                    elseif ($ServerProperty.PSChildName -like "Local*") {
                        # The data contains the path of an executable or a command line.
                        $ServerDataType = "CommandLine"
                    }

                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $ClassId.PSChildName
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $($ClassId.Name -replace "HKEY_LOCAL_MACHINE","HKLM")
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $ServerProperty.PSChildName
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $ServerData
                    $Result | Add-Member -MemberType "NoteProperty" -Name "DataType" -Value $ServerDataType
                    [void] $script:CachedRegisteredComList.Add($Result)
                }
            }
        }

        $script:CachedRegisteredComList
    }
}