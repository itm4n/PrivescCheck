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
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ([string]::IsNullOrEmpty($RegData)) { "A list of approved Point and Print servers is not defined (default)." } else { "A list of approved Point and Print servers is defined." })
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
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "N/A"
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
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "N/A"
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
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "N/A"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ([string]::IsNullOrEmpty($RegData)) { "A list of approved Package Point and Print servers is not defined (default)." } else { "A list of approved Package Point and Print servers is defined." })
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

function Get-BitLockerConfiguration {
    <#
    .SYNOPSIS
    Get the BitLocker startup authentication configuration.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet retrieves information about the authentication mode used by the BitLocker configuration from the 'HKLM\Software\Policies\Microsoft\FVE' key (e.g. 'TPM only', 'TPM+PIN', etc.).

    .EXAMPLE
    PS C:\> Get-BitLockerConfiguration

    Status             : @{Value=1; Description=BitLocker is enabled}
    UseTPM             : @{Value=1; Description=Require TPM (default)}
    UseAdvancedStartup : @{Value=0; Description=Do not require additional authentication at startup (default)}
    EnableBDEWithNoTPM : @{Value=0; Description=Do not allow BitLocker without a compatible TPM (default)}
    UseTPMPIN          : @{Value=0; Description=Do not allow startup PIN with TPM (default)}
    UseTPMKey          : @{Value=0; Description=Do not allow startup key with TPM (default)}
    UseTPMKeyPIN       : @{Value=0; Description=Do not allow startup key and PIN with TPM (default)}

    .LINK
    https://www.geoffchappell.com/studies/windows/win32/fveapi/policy/index.htm
    #>

    [CmdletBinding()]
    param()

    begin {
        # Default values for FVE parameters in HKLM\Software\Policies\Microsoft\FVE
        $FveConfig = @{
            UseAdvancedStartup = 0
            EnableBDEWithNoTPM = 0
            UseTPM = 1
            UseTPMPIN = 0
            UseTPMKey = 0
            UseTPMKeyPIN = 0
        }

        $FveUseAdvancedStartup = @(
            "Do not require additional authentication at startup (default)",
            "Require additional authentication at startup."
        )

        $FveEnableBDEWithNoTPM = @(
            "Do not allow BitLocker without a compatible TPM (default)",
            "Allow BitLocker without a compatible TPM"
        )

        $FveUseTPM = @(
            "Do not allow TPM",
            "Require TPM (default)",
            "Allow TPM"
        )

        $FveUseTPMPIN = @(
            "Do not allow startup PIN with TPM (default)",
            "Require startup PIN with TPM",
            "Allow startup PIN with TPM"
        )

        $FveUseTPMKey = @(
            "Do not allow startup key with TPM (default)",
            "Require startup key with TPM",
            "Allow startup key with TPM"
        )

        $FveUseTPMKeyPIN = @(
            "Do not allow startup key and PIN with TPM (default)",
            "Require startup key and PIN with TPM",
            "Allow startup key and PIN with TPM"
        )

        $FveConfigValues = @{
            UseAdvancedStartup = $FveUseAdvancedStartup
            EnableBDEWithNoTPM = $FveEnableBDEWithNoTPM
            UseTPM = $FveUseTPM
            UseTPMPIN = $FveUseTPMPIN
            UseTPMKey = $FveUseTPMKey
            UseTPMKeyPIN = $FveUseTPMKeyPIN
        }
    }

    process {

        $Result = New-Object -TypeName PSObject

        $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus"
        $RegValue = "BootStatus"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $BitLockerEnabled = $false

        if ($null -eq $RegData) {
            $StatusDescription = "BitLocker is not configured."
        }
        else {
            if ($RegData -ge 1) {
                $BitLockerEnabled = $true
                $StatusDescription = "BitLocker is enabled."
            }
            else {
                $StatusDescription = "BitLocker is not enabled."
            }
        }

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $StatusDescription
        $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Item

        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\FVE"

        $FveConfig.Clone().GetEnumerator() | ForEach-Object {
            $RegValue = $_.name
            $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
            if ($null -ne $RegData) {
                $FveConfig[$_.name] = $RegData
            }
        }

        if ($BitLockerEnabled) {
            foreach ($FveConfigItem in $FveConfig.GetEnumerator()) {

                $FveConfigValue = $FveConfigItem.name
                $FveConfigValueDescriptions = $FveConfigValues[$FveConfigValue]
                $IsValid = $true

                if (($FveConfigValue -eq "UseAdvancedStartup") -or ($FveConfigValue -eq "EnableBDEWithNoTPM")) {
                    if (($FveConfig[$FveConfigValue] -ne 0) -and ($FveConfig[$FveConfigValue] -ne 1)) {
                        $IsValid = $false
                    }
                }
                elseif (($FveConfigValue -eq "UseTPM") -or ($FveConfigValue -eq "UseTPMPIN") -or ($FveConfigValue -eq "UseTPMKey") -or ($FveConfigValue -eq "UseTPMKeyPIN")) {
                    if (($FveConfig[$FveConfigValue] -lt 0) -or ($FveConfig[$FveConfigValue] -gt 2)) {
                        $IsValid = $false
                    }
                }

                if (-not $IsValid) {
                    Write-Warning "Unexpected value for $($FveConfigValue): $($FveConfig[$FveConfigValue])"
                    continue
                }

                $Item = New-Object -TypeName PSObject
                $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $($FveConfig[$FveConfigValue])
                $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $($FveConfigValueDescriptions[$FveConfig[$FveConfigValue]])

                $Result | Add-Member -MemberType "NoteProperty" -Name $FveConfigValue -Value $Item
            }
        }

        $Result
    }
}

function Get-AppLockerRuleFromRegistry {
    <#
    .SYNOPSIS
    Get the AppLocker policy from the registry, as an XML document.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet is an alternative for the official "Get-AppLockerPolicy" (PSv4+) that works in PSv2. It reads the registry and builds an XML representation of the AppLocker policy, similar to the output of "Get-AppLockerPolicy".
    #>

    [CmdletBinding()]
    param()

    begin {
        function Convert-EnforcementModeToString {
            param([UInt32] $EnforcementMode = 0)
            switch ($EnforcementMode) {
                0 { "NotConfigured" }
                1 { "Enabled" }
                2 { "ServicesOnly" }
            }
        }

        $RuleCollectionTypes = @( "Appx", "Dll", "Exe", "Msi", "Script" )
        $XmlWriterSettings = New-Object System.Xml.XmlWriterSettings
        $XmlWriterSettings.IndentChars = "  "
        $XmlWriterSettings.Indent = $true
        $XmlWriterSettings.OmitXmlDeclaration = $true
        $StringWriter = New-Object System.IO.StringWriter
        $XmlWriter = [System.Xml.XmlWriter]::Create($StringWriter, $XmlWriterSettings)
        $XmlWriter.WriteStartElement("AppLockerPolicy")
        $XmlWriter.WriteAttributeString("Version", "1")
    }

    process {
        foreach ($RuleCollectionType in $RuleCollectionTypes) {

            $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$($RuleCollectionType)"
            $Item = Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue
            if ($null -eq $Item) { continue }

            $EnforcementMode = Convert-EnforcementModeToString -EnforcementMode $Item.EnforcementMode

            $XmlWriter.WriteStartElement("RuleCollection")
            $XmlWriter.WriteAttributeString("Type", $RuleCollectionType)
            $XmlWriter.WriteAttributeString("EnforcementMode", $EnforcementMode)

            foreach ($ChildItem in $(Get-ChildItem -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue)) {

                $SubKeyName = $ChildItem.PSChildName

                $RegValue = "Value"
                $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)\$($SubKeyName)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
                $RuleXml = [System.Xml.XmlDocument] $RegData

                $RuleXml.WriteTo($XmlWriter)
            }

            $XmlWriter.WriteEndElement()
        }
    }

    end {
        $XmlWriter.WriteEndElement()
        $XmlWriter.Flush()
        $StringWriter.ToString()
        $XmlWriter.Close()
        $StringWriter.Close()
    }
}

function Get-AppLockerRule {
    <#
    .SYNOPSIS
    Identify vulnerable AppLocker rules

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet parses the AppLocker configuration to identify rules that can be exploited to execute arbitrary files.

    .PARAMETER FilterLevel
    Filter rules based on their likelihood of exploitation (0 = all / no filter, 1 = low to high, 2 = medium and high, 3 = high only).
    #>

    [CmdletBinding()]
    param(
        [ValidateSet(0, 1, 2, 3)]
        [UInt32] $FilterLevel = 0
    )

    begin {
        $CurrentUserSids = Get-CurrentUserSid
        $Levels = @( "None", "Low", "Moderate", "High" )

        function Convert-AppLockerPath {
            param(
                [string] $Path
            )

            # AppLocker path variables
            # https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/understanding-the-path-rule-condition-in-applocker
            $VariableHashmap = @{
                "%WINDIR%"          = @( "%SystemRoot%" )
                "%SYSTEM32%"        = @( "%SystemDirectory%" )
                "%OSDRIVE%"         = @( "%SystemDrive%" )
                "%PROGRAMFILES%"    = @( "%ProgramFiles%", "%ProgramFiles(x86)%" )
            }

            $VariableFound = $false
            foreach ($Variable in $VariableHashmap.Keys) {
                if ($Path -like "$($Variable)*") {
                    $VariableFound = $true
                    foreach ($TranslatedVariable in $VariableHashmap[$Variable]) {
                        $Path -replace $Variable,$TranslatedVariable
                    }
                    break
                }
            }
            if (-not $VariableFound) { $Path }
        }

        function Convert-AppLockerConditionToString {
            param([object] $Condition, [string] $Type)
            switch ($Type) {
                "FilePublisher" {
                    $ConditionString = "Publisher='$($Condition.PublisherName)', Product='$($Condition.ProductName)', Binary='$($Condition.BinaryName)'"
                }
                "FilePath" {
                    $ConditionString = "Path='$($Condition.Path)'"
                }
                "FileHash" {
                    $ConditionString = "Alg='$($Condition.Type)', Hash='$($Condition.Data)', File='$($Condition.SourceFileName)', Length='$($Condition.SourceFileLength)'"
                }
                default {
                    Write-Warning "Unhandled condition type: $Type"
                }
            }
            $ConditionString
        }
    }

    process {

        if (([UInt32[]] $PSVersionTable.PSCompatibleVersions.Major) -contains 4) {
            $AppLockerPolicyXml = [xml] (Get-AppLockerPolicy -Effective -Xml)
        }
        else {
            Write-Warning "Incompatible PowerShell version detected, retrieving AppLocker policy from registry instead of using 'Get-AppLockerPolicy'..."
            $AppLockerPolicyXml = [xml] (Get-AppLockerRuleFromRegistry)
        }

        foreach ($RuleCollection in $AppLockerPolicyXml.AppLockerPolicy.GetElementsByTagName("RuleCollection")) {

            # Type: Appx / Dll / Exe / Msi / Script
            # EnforcementMode: NotConfigured / Enabled / ServicesOnly

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "RuleCollectionType" -Value $RuleCollection.Type
            $Result | Add-Member -MemberType "NoteProperty" -Name "RuleCollectionEnforcementMode" -Value $RuleCollection.EnforcementMode

            if ($RuleCollection.EnforcementMode -eq "NotConfigured") {
                $Description = "No restriction is enforced for files of type '$($RuleCollection.Type)'."
                $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                $Result | Add-Member -MemberType "NoteProperty" -Name "Impact" -Value "High"
                $Result
                continue
            }

            $RuleTypes = @( "FilePublisher", "FilePath", "FileHash" )

            foreach ($RuleType in $RuleTypes) {

                $Rules = $RuleCollection.GetElementsByTagName("$($RuleType)Rule")

                foreach ($Rule in $Rules) {

                    if ($Rule.Action -eq "Deny") {
                        Write-Warning "Deny rule encountered and ignored: $($Rule.Name)"
                        continue
                    }

                    if ($CurrentUserSids -notcontains $Rule.UserOrGroupSid) {
                        Write-Verbose "This rule applies to a SID that is not ours ($($Rule.UserOrGroupSid)): $($Rule.Name)"
                        continue
                    }

                    $ResultRule = $Result.PsObject.Copy()
                    $ResultRule | Add-Member -MemberType "NoteProperty" -Name "RuleName" -Value $Rule.Name
                    $ResultRule | Add-Member -MemberType "NoteProperty" -Name "RuleDescription" -Value $Rule.Description
                    $ResultRule | Add-Member -MemberType "NoteProperty" -Name "RuleUserOrGroupSid" -Value $Rule.UserOrGroupSid
                    $ResultRule | Add-Member -MemberType "NoteProperty" -Name "RuleAction" -Value $Rule.Action

                    if ($Rule.Conditions) {
                        $Conditions = $Rule.Conditions.GetElementsByTagName("$($RuleType)Condition")
                    }

                    if ($Rule.Exceptions) {
                        $Exceptions = $Rule.Exceptions.GetElementsByTagName("$($RuleType)Condition")
                        $ExceptionListString = ($Exceptions | ForEach-Object { "$(Convert-AppLockerConditionToString -Condition $_ -Type $RuleType)" }) -join "; "
                    }
                    else {
                        $ExceptionListString = $null
                    }

                    foreach ($Condition in $Conditions) {

                        $ConditionString = Convert-AppLockerConditionToString -Condition $Condition -Type $RuleType
                        $Level = 0

                        switch ($RuleType) {

                            "FilePublisher" {
                                if (($Rule.Action -eq "Allow") -and ($Condition.PublisherName -eq "*")) {
                                    $Level = 1
                                    $Description = "This rule allows files from any publisher."
                                }
                                elseif (($Rule.Action -eq "Allow") -and (($Condition.ProductName -eq "*") -or ($Condition.BinaryName -eq "*"))) {
                                    $Level = 1
                                    $Description = "This rule allows any product or file from the publisher '$($Condition.PublisherName)'."
                                }
                            }

                            "FilePath" {
                                # Path is simply a wildcard?
                                if ($Condition.Path -eq "*") {
                                    $Level = 3
                                    $Description = "This rule allows any file."
                                }
                                # Path is a removable media?
                                elseif ($Condition.Path.StartsWith("%REMOVABLE%")) {
                                    $Level = 1
                                    $Description = "This rule allows files to be executed from a removable media (e.g., CD/DVD)."
                                }
                                # Path is a removable storage device?
                                elseif ($Condition.Path.StartsWith("%HOT%")) {
                                    $Level = 1
                                    $Description = "This rule allows files to be executed from a removable storage device (e.g., USB flash drive)."
                                }
                                # UNC path containing wildcards?
                                elseif ($Condition.Path.StartsWith("\\")) {
                                    # The following regex catches occurrences of "\\(foo)*(bar)\..."
                                    if ($Condition.Path -match "\\\\[^\\]*\*[^\\]*\\.*") {
                                        $Level = 1
                                        $Description = "This rule allows files to be executed from a network path with a hostname containing a wildcard."
                                    }
                                    elseif ($Condition.Path -match ".*\*.*") {
                                        $Level = 1
                                        $Description = "This rule allows files to be executed from a network path containing a wildcard, manual analysis is required."
                                    }
                                }
                                else {
                                    $CandidatePaths = [string[]] (Convert-AppLockerPath -Path $Condition.Path)
                                    foreach ($CandidatePath in $CandidatePaths) {
                                        if ([String]::IsNullOrEmpty($CandidatePath)) { continue }
                                        $CandidatePath = $([System.Environment]::ExpandEnvironmentVariables($CandidatePath))
                                        if ($CandidatePath.StartsWith("*")) {
                                            $Level = 3
                                            $Description = "This rule allows files to be executed from any location."
                                        }
                                        elseif ($CandidatePath.EndsWith("*")) {
                                            if (Test-IsSystemFolder -Path $CandidatePath.Trim("*")) {
                                                $Level = 2
                                                $Description = "This rule allows files to be executed from a system folder, and could therefore be vulnerable."
                                            }
                                            else {
                                                $ModifiablePaths = Get-ModifiablePath -Path $CandidatePath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                                                if ($ModifiablePaths) {
                                                    $Level = 3
                                                    $Description = "This rule allows files to be executed from a location where the current user has write access."
                                                }
                                            }
                                        }
                                        else {
                                            $ModifiablePaths = Get-ModifiablePath -Path $CandidatePath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                                            if ($ModifiablePaths) {
                                                $Level = 3
                                                $Description = "This rule allows files to be executed from a location where the current user has write access."
                                            }
                                        }
                                    }
                                }
                            }

                            "FileHash" {
                                # Nothing to do here, secure by design???
                            }
                        }

                        if ($Level -ge $FilterLevel) {
                            if ($Rule.Exceptions) {
                                $Description = "$($Description) However, exceptions should be manually reviewed."
                            }
                            $ResultCondition = $ResultRule.PsObject.Copy()
                            $ResultCondition | Add-Member -MemberType "NoteProperty" -Name "RuleCondition" -Value $ConditionString
                            $ResultCondition | Add-Member -MemberType "NoteProperty" -Name "RuleExceptions" -Value $(if ($ExceptionListString) { $ExceptionListString } else { "(null)" })
                            $ResultCondition | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                            $ResultCondition | Add-Member -MemberType "NoteProperty" -Name "Level" -Value $Level
                            $ResultCondition | Add-Member -MemberType "NoteProperty" -Name "Risk" -Value $Levels[$Level]
                            $ResultCondition
                        }
                    }
                }
            }
        }
    }
}

function Get-AttackSurfaceReductionRuleFromRegistry {
    <#
    .SYNOPSIS
    Helper - Get the ASR rules and their values

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet returns a list of all existing ASR rules, along with their values in the registry. If a rule is not defined, the 'Data' value is null.

    .EXAMPLE
    PS C:\> Get-AttackSurfaceReductionRuleFromRegistry

    Rule        : Block executable files from running unless they meet a prevalence, age, or trusted list criterion
    Id          : 01443614-cd74-433a-b99e-2ecdc07bfc25
    State       :
    Description : Not configured (disabled)

    Rule        : Block Office applications from creating executable content
    Id          : 3b576869-a4ec-4529-8536-b80a7769e899
    State       : 2
    Description : Audit

    Rule        : Block Webshell creation for Servers
    Id          : a8f5898e-1dc8-49a9-9878-85004b8a61e6
    State       :
    Description : Not configured (disabled)

    .NOTES
    Computer Configuration > Policies > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction > Configure Attack Surface Reduction rules

    .LINK
    https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
    #>

    [CmdletBinding()]
    param()

    begin {
        $RuleIds = @{
            [Guid] "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
            [Guid] "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
            [Guid] "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
            [Guid] "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
            [Guid] "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
            [Guid] "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
            [Guid] "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
            [Guid] "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
            [Guid] "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
            [Guid] "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes"
            [Guid] "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
            [Guid] "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
            [Guid] "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
            [Guid] "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block rebooting machine in Safe Mode (preview)"
            [Guid] "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
            [Guid] "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied or impersonated system tools (preview)"
            [Guid] "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for Servers"
            [Guid] "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
            [Guid] "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
        }

        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
    }

    process {

        foreach ($RuleId in $RuleIds.GetEnumerator()) {

            $RegValue = $RuleId.Name.ToString()
            $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

            switch ($RegData) {
                $null { $Description = "Not configured (disabled)" }
                0 { $Description = "Disabled" }
                1 { $Description = "Block" }
                2 { $Description = "Audit" }
                6 { $Description = "Warn" }
                Default {
                    $Description = $null
                    Write-Warning "Unexpected value for ASR rule '$($RegValue)': $($RegData)"
                }
            }

            $Rule = New-Object -TypeName PSObject
            $Rule | Add-Member -MemberType "NoteProperty" -Name "Rule" -Value $RuleId.Value
            $Rule | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $RuleId.Name
            $Rule | Add-Member -MemberType "NoteProperty" -Name "State" -Value $RegData
            $Rule | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
            $Rule
        }
    }
}

function Get-NetworkFirewallActiveProfile {
    <#
    .SYNOPSIS
    Helper - Query firewall profile information in the active store

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet is a wrapper for the firewall API. It first opens the currently active firewall profile, and then queries the profile information thanks to the function FWGetConfig2. The information returned is similar to the output of Get-NetFirewallProfile. The reason this cmdlet was implemented, instead of using Get-NetFirewallProfile, is because the latter is not compatible with PowerShell version 2.

    .PARAMETER Profile
    Name of the firewall profile to query. This must be 'Domain', 'Private', or 'Public'.

    .EXAMPLE
    PS C:\> Get-NetworkFirewallActiveProfile

    Name                            : Public
    Enabled                         : True
    DefaultInboundAction            : Block
    DefaultOutboundAction           : Allow
    AllowInboundRules               : True
    AllowLocalFirewallRules         : True
    AllowLocalIPsecRules            : True
    AllowUserApps                   : True
    AllowUserPorts                  : True
    AllowUnicastResponseToMulticast : False
    NotifyOnListen                  : True
    LogFileName                     : %systemroot%\system32\LogFiles\Firewall\pfirewall.log
    LogMaxSizeKilobytes             : 4096
    LogAllowed                      : False
    LogBlocked                      : False
    LogIgnored                      : False
    DisabledInterfaceAliases        : {Ethernet Instance 0}

    .NOTES
    This cmdlet was built mainly be reverse engineering firewallapi.dll, and therefore might not be 100% accurate.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Domain","Private","Public")]
        $Profile
    )

    begin {
        $Attributes = @("Enabled","DefaultInboundAction","DefaultOutboundAction","AllowInboundRules","AllowLocalFirewallRules","AllowLocalIPsecRules","AllowUserApps","AllowUserPorts","AllowUnicastResponseToMulticast","NotifyOnListen","LogFileName","LogMaxSizeKilobytes","LogAllowed","LogBlocked","LogIgnored","DisabledInterfaceAliases")
        $ActionList = @("Allow","Block")
        $NetworkAdapters = Get-NetworkAdapter

        $PolicyStoreType = $script:FW_STORE_TYPE::DYNAMIC
        $PolicyStoreAccessRight = $script:FW_POLICY_ACCESS_RIGHT::READ
        $PolicyStoreHandle = [IntPtr]::Zero
        $script:FirewallApi::FWOpenPolicyStore(0x200, [IntPtr]::Zero, $PolicyStoreType, $PolicyStoreAccessRight, 0, [ref] $PolicyStoreHandle)
        if ($PolicyStoreHandle -eq [IntPtr]::Zero) {
            Write-Warning "FWOpenPolicyStore failed."
            return
        }
    }

    process {
        if ($PolicyStoreHandle -eq [IntPtr]::Zero) { return }

        $ProfileType = $Profile -as $script:FW_PROFILE_TYPE

        foreach ($Attribute in $Attributes) {

            switch ($Attribute) {
                "Enabled"   { $ProfileConfig = $script:FW_PROFILE_CONFIG::ENABLE_FW }
                "DefaultInboundAction" { $ProfileConfig = $script:FW_PROFILE_CONFIG::DEFAULT_INBOUND_ACTION }
                "DefaultOutboundAction" { $ProfileConfig = $script:FW_PROFILE_CONFIG::DEFAULT_OUTBOUND_ACTION }
                "AllowInboundRules" { $ProfileConfig = $script:FW_PROFILE_CONFIG::SHIELDED }
                "AllowLocalFirewallRules" { $ProfileConfig = $script:FW_PROFILE_CONFIG::ALLOW_LOCAL_POLICY_MERGE }
                "AllowLocalIPsecRules" { $ProfileConfig = $script:FW_PROFILE_CONFIG::ALLOW_LOCAL_IPSEC_POLICY_MERGE }
                "AllowUserApps" { $ProfileConfig = $script:FW_PROFILE_CONFIG::AUTH_APPS_ALLOW_USER_PREF_MERGE }
                "AllowUserPorts" { $ProfileConfig = $script:FW_PROFILE_CONFIG::GLOBAL_PORTS_ALLOW_USER_PREF_MERGE }
                "AllowUnicastResponseToMulticast" { $ProfileConfig = $script:FW_PROFILE_CONFIG::DISABLE_UNICAST_RESPONSES_TO_MULTICAST_BROADCAST }
                "NotifyOnListen" { $ProfileConfig = $script:FW_PROFILE_CONFIG::DISABLE_INBOUND_NOTIFICATIONS }
                # "EnableStealthModeForIPsec" { $ProfileConfig = $script:FW_PROFILE_CONFIG::DISABLE_STEALTH_MODE_IPSEC_SECURED_PACKET_EXEMPTION }
                "LogFileName" { $ProfileConfig = $script:FW_PROFILE_CONFIG::LOG_FILE_PATH }
                "LogMaxSizeKilobytes" { $ProfileConfig = $script:FW_PROFILE_CONFIG::LOG_MAX_FILE_SIZE }
                "LogAllowed" { $ProfileConfig = $script:FW_PROFILE_CONFIG::LOG_SUCCESS_CONNECTIONS }
                "LogBlocked" { $ProfileConfig = $script:FW_PROFILE_CONFIG::LOG_DROPPED_PACKETS }
                "LogIgnored" { $ProfileConfig = $script:FW_PROFILE_CONFIG::LOG_IGNORED_RULES }
                "DisabledInterfaceAliases" { $ProfileConfig = $script:FW_PROFILE_CONFIG::DISABLED_INTERFACES }
                default     { $ProfileConfig = $script:Invalid }
            }

            $BufferSize = 0
            $RuleOrigin = $script:FW_RULE_ORIGIN_TYPE::INVALID
            $script:FirewallApi::FWGetConfig2($PolicyStoreHandle, $ProfileConfig, $ProfileType, 0, [IntPtr]::Zero, [ref] $BufferSize, [ref] $RuleOrigin)

            if ($BufferSize -eq 0) {
                Write-Warning "FWGetConfig2 failed."
                continue
            }

            $BufferPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufferSize)
            $script:FirewallApi::FWGetConfig2($PolicyStoreHandle, $ProfileConfig, $ProfileType, 0, $BufferPtr, [ref] $BufferSize, [ref] $RuleOrigin)

            switch ($Attribute) {
                "Enabled" {
                    $FirewallEnabled = [Bool] [Runtime.InteropServices.Marshal]::ReadInt32($BufferPtr)
                }
                "DefaultInboundAction" {
                    $DefaultInboundActionValue = [Runtime.InteropServices.Marshal]::ReadInt32($BufferPtr)
                    $DefaultInboundAction = $ActionList[$DefaultInboundActionValue]
                }
                "DefaultOutboundAction" {
                    $DefaultOutboundActionValue = [Runtime.InteropServices.Marshal]::ReadInt32($BufferPtr)
                    $DefaultOutboundAction = $ActionList[$DefaultOutboundActionValue]
                }
                "AllowInboundRules" {
                    $AllowInboundRules = -not ([Bool] [Runtime.InteropServices.Marshal]::ReadInt32($BufferPtr))
                }
                "AllowLocalFirewallRules" {
                    $AllowLocalFirewallRules = [Bool] [Runtime.InteropServices.Marshal]::ReadInt32($BufferPtr)
                }
                "AllowLocalIPsecRules" {
                    $AllowLocalIPsecRules = [Bool] [Runtime.InteropServices.Marshal]::ReadInt32($BufferPtr)
                }
                "AllowUserApps" {
                    $AllowUserApps = [Bool] [Runtime.InteropServices.Marshal]::ReadInt32($BufferPtr)
                }
                "AllowUserPorts" {
                    $AllowUserPorts = [Bool] [Runtime.InteropServices.Marshal]::ReadInt32($BufferPtr)
                }
                "AllowUnicastResponseToMulticast" {
                    $AllowUnicastResponseToMulticast = -not ([Bool] [Runtime.InteropServices.Marshal]::ReadInt32($BufferPtr))
                }
                "NotifyOnListen" {
                    $NotifyOnListen = -not ([Bool] [Runtime.InteropServices.Marshal]::ReadInt32($BufferPtr))
                }
                # "EnableStealthModeForIPsec" {
                #     $EnableStealthModeForIPsec = -not ([Bool] [Runtime.InteropServices.Marshal]::ReadInt32($BufferPtr))
                # }
                "LogFileName" {
                    $LogFileName = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BufferPtr)
                }
                "LogMaxSizeKilobytes" {
                    $LogMaxSizeKilobytes = [Runtime.InteropServices.Marshal]::ReadInt32($BufferPtr)
                }
                "LogAllowed" {
                    $LogAllowed = [Bool] [Runtime.InteropServices.Marshal]::ReadInt32($BufferPtr)
                }
                "LogBlocked" {
                    $LogBlocked = [Bool] [Runtime.InteropServices.Marshal]::ReadInt32($BufferPtr)
                }
                "LogIgnored" {
                    $LogIgnored = [Bool] [Runtime.InteropServices.Marshal]::ReadInt32($BufferPtr)
                }
                "DisabledInterfaceAliases" {
                    $DisabledInterfaceAliases = @()
                    $InterfaceIds = [Runtime.InteropServices.Marshal]::PtrToStructure($BufferPtr, [type] $script:FW_INTERFACE_LUIDS)
                    if ($InterfaceIds.NumLUIDs -gt 0) {
                        for ($InterfaceIdIndex = 0; $InterfaceIdIndex -lt $InterfaceIds.NumLUIDs; $InterfaceIdIndex++) {
                            $InterfaceIdPtr = [IntPtr] ($InterfaceIds.LUIDs.ToInt64() + $InterfaceIdIndex * [Runtime.InteropServices.Marshal]::SizeOf([type] [Guid]))
                            $InterfaceId = [Runtime.InteropServices.Marshal]::PtrToStructure($InterfaceIdPtr, [type] [Guid])
                            $InterfaceAlias = $NetworkAdapters | Where-Object { $_.Name -like "*$($InterfaceId.ToString())*" } | Select-Object -ExpandProperty "FriendlyName"
                            $DisabledInterfaceAliases += $InterfaceAlias
                        }
                    }
                }
                default {
                    Write-Error "Unsupported attributes: $Attribute"
                }
            }

            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($BufferPtr)
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Profile
        $Result | Add-Member -MemberType "NoteProperty" -Name "Enabled" -Value $FirewallEnabled
        $Result | Add-Member -MemberType "NoteProperty" -Name "DefaultInboundAction" -Value $DefaultInboundAction
        $Result | Add-Member -MemberType "NoteProperty" -Name "DefaultOutboundAction" -Value $DefaultOutboundAction
        $Result | Add-Member -MemberType "NoteProperty" -Name "AllowInboundRules" -Value $AllowInboundRules
        $Result | Add-Member -MemberType "NoteProperty" -Name "AllowLocalFirewallRules" -Value $AllowLocalFirewallRules
        $Result | Add-Member -MemberType "NoteProperty" -Name "AllowLocalIPsecRules" -Value $AllowLocalIPsecRules
        $Result | Add-Member -MemberType "NoteProperty" -Name "AllowUserApps" -Value $AllowUserApps
        $Result | Add-Member -MemberType "NoteProperty" -Name "AllowUserPorts" -Value $AllowUserPorts
        $Result | Add-Member -MemberType "NoteProperty" -Name "AllowUnicastResponseToMulticast" -Value $AllowUnicastResponseToMulticast
        $Result | Add-Member -MemberType "NoteProperty" -Name "NotifyOnListen" -Value $NotifyOnListen
        # $Result | Add-Member -MemberType "NoteProperty" -Name "EnableStealthModeForIPsec" -Value $EnableStealthModeForIPsec
        $Result | Add-Member -MemberType "NoteProperty" -Name "LogFileName" -Value $LogFileName
        $Result | Add-Member -MemberType "NoteProperty" -Name "LogMaxSizeKilobytes" -Value $LogMaxSizeKilobytes
        $Result | Add-Member -MemberType "NoteProperty" -Name "LogAllowed" -Value $LogAllowed
        $Result | Add-Member -MemberType "NoteProperty" -Name "LogBlocked" -Value $LogBlocked
        $Result | Add-Member -MemberType "NoteProperty" -Name "LogIgnored" -Value $LogIgnored
        $Result | Add-Member -MemberType "NoteProperty" -Name "DisabledInterfaceAliases" -Value $DisabledInterfaceAliases
        $Result
    }

    end {
        if ($PolicyStoreHandle -ne [IntPtr]::Zero) {
            $null = $script:FirewallApi::FWClosePolicyStore($PolicyStoreHandle)
        }
    }
}

function Get-NameResolutionProtocolConfiguration {
    <#
    .SYNOPSIS
    Helper - Get the configuration of name resolution protocols

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet queries the registry to obtain the configuration of name resolution protocols.

    .PARAMETER Protocol
    Name of the protocol to query. This must be 'LLMNR', 'NetBIOS', or 'mDNS'.

    .EXAMPLE
    PS C:\> Get-NameResolutionProtocolConfiguration -Protocol "LLMNR"

    RegKey      : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
    RegValue    : EnableMulticast
    RegData     :
    Description : Multicast name resolution (LLMNR) is enabled (default).
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("LLMNR","NetBIOS","mDNS")]
        [String] $Protocol
    )

    begin {
        $LlmnrDescriptions = @(
            "Multicast name resolution (LLMNR) is disabled.",
            "Multicast name resolution (LLMNR) is enabled (default)."
        )
        $NodeTypeDescriptions = @(
            "",
            "The NetBIOS node type is B-node (default) - Broadcast.", # 1
            "The NetBIOS node type is P-node - Peer-to-peer (WINS servers only).", # 2
            "",
            "The NetBIOS node type is M-node - Mixed (broadcast, then WINS servers).", # 4
            "", "", "",
            "The NetBIOS node type is H-node - Hybrid (WINS servers, then broadcast)." # 8
        )
        $MdnsDescriptions = @(
            "Multicast DNS (mDNS) is disabled.",
            "Multicast DNS (mDNS) is enabled (default)."
        )
    }

    process {

        switch ($Protocol) {
            "LLMNR" {
                $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
                $RegValue = "EnableMulticast"
            }
            "NetBIOS" {
                $RegKey = "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
                $RegValue = "NodeType"
            }
            "mDNS" {
                $RegKey = "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
                $RegValue = "EnableMDNS"
            }
            default {
                Write-Error "Unsupported protocol: $Protocol"
            }
        }

        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        switch ($Protocol) {
            "LLMNR" {
                $LlmnrDescriptionIndex = $(if ($null -eq $RegData) { 1 } else { $RegData })
                $Description = $LlmnrDescriptions[$LlmnrDescriptionIndex]
            }
            "NetBIOS" {
                $NodeTypeDescriptionIndex = $(if ($null -eq $RegData) { 1 } else { $RegData })
                $Description = $NodeTypeDescriptions[$NodeTypeDescriptionIndex]
            }
            "mDNS" {
                $MdnsDescriptionIndex = $(if ($null -eq $RegData) { 1 } else { $RegData })
                $Description = $MdnsDescriptions[$MdnsDescriptionIndex]
            }
            default {
                Write-Error "Unsupported protocol: $Protocol"
            }
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
        $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
        $Result
    }
}

function Get-IPv6GlobalConfiguration {
    <#
    .SYNOPSIS
    Helper - Get the global status of the IPv6 configuration.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet determines whether IPv6 is disabled globally, or more precisely, it reads the value 'DisabledComponents' in the registry, and determines the state of each configurable feature. This function is entirely based on the information provided in the official documentation (see reference in the LINK section).

    .EXAMPLE
    PS C:\> Get-IPv6GlobalConfiguration

    Key                                 : HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters
    Value                               : DisabledComponents
    Data                                : (null)
    Default                             : 0
    PreferIPv4OverIPv6                  : False
    DisableIPv6OnAllTunnelInterfaces    : False
    DisableIPv6OnAllNonTunnelInterfaces : False
    Description                         : IPv6 is preferred over IPv4 (default). IPv6 is enabled on all tunnel interfaces
                                          (default). IPv6 is enabled on all non-tunnel interfaces (default).

    .LINK
    https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows
    #>

    [CmdletBinding()]
    param ()

    begin {
        $ValueDescriptions = @{
            "PreferIPv4OverIPv6" = @(
                "IPv6 is preferred over IPv4 (default).",
                "IPv4 is preferred over IPv6."
            )
            "DisableIPv6OnAllTunnelInterfaces" = @(
                "IPv6 is enabled on all tunnel interfaces (default).",
                "IPv6 is disabled on all tunnel interfaces."
            )
            "DisableIPv6OnAllNonTunnelInterfaces" = @(
                "IPv6 is enabled on all non-tunnel interfaces (default)."
                "IPv6 is disabled on all non-tunnel interfaces."
            )
        }
    }

    process {
        $RegKey = "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
        $RegValue = "DisabledComponents"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        if ($null -eq $RegData) { $TargetValue = 0 } else { $TargetValue = $RegData }

        $ValueDescription = ""

        $PreferIPv4OverIPv6 = 0
        if (($TargetValue -band 0x20) -eq 0x20) { $PreferIPv4OverIPv6 = 1 }
        $ValueDescription = "$($ValueDescription)$($ValueDescriptions["PreferIPv4OverIPv6"][$PreferIPv4OverIPv6]) "

        $DisableIPv6OnAllTunnelInterfaces = 0
        if (($TargetValue -band 0x01) -eq 0x01) { $DisableIPv6OnAllTunnelInterfaces = 1 }
        $ValueDescription = "$($ValueDescription)$($ValueDescriptions["DisableIPv6OnAllTunnelInterfaces"][$DisableIPv6OnAllTunnelInterfaces]) "

        $DisableIPv6OnAllNonTunnelInterfaces = 0
        if (($TargetValue -band 0x10) -eq 0x10) { $DisableIPv6OnAllNonTunnelInterfaces = 1 }
        $ValueDescription = "$($ValueDescription)$($ValueDescriptions["DisableIPv6OnAllNonTunnelInterfaces"][$DisableIPv6OnAllNonTunnelInterfaces]) "

        if ($TargetValue -eq 0xff) {
            $ValueDescription = "IPv6 is disabled."
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
        $Result | Add-Member -MemberType "NoteProperty" -Name "Default" -Value 0
        $Result | Add-Member -MemberType "NoteProperty" -Name "PreferIPv4OverIPv6" -Value ([Bool] $PreferIPv4OverIPv6)
        $Result | Add-Member -MemberType "NoteProperty" -Name "DisableIPv6OnAllTunnelInterfaces" -Value ([Bool] $DisableIPv6OnAllTunnelInterfaces)
        $Result | Add-Member -MemberType "NoteProperty" -Name "DisableIPv6OnAllNonTunnelInterfaces" -Value ([Bool] $DisableIPv6OnAllNonTunnelInterfaces)
        $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $ValueDescription
        $Result
    }
}

function Get-PowerShellSecurityFeature {
    <#
    .SYNOPSIS
    Helper - Get the configuration of PowerShell security features.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet collects information about the status of PowerShell security features, such as the execution policy enforcement, or script block logging.

    .PARAMETER Scope
    A mandatory parameter representing the scope of the information to collect ("Machine" -> "HKLM", "User" -> "HKCU")

    .EXAMPLE
    PS C:\> Get-PowerShellSecurityFeature -Scope Machine

    Name  : ScriptsEnabled
    Path  : HKLM\Software\Policies\Microsoft\Windows\PowerShell
    Value : EnableScripts
    Type  : REG_DWORD
    Data  : 1

    Name  : ExecutionPolicy
    Path  : HKLM\Software\Policies\Microsoft\Windows\PowerShell
    Value : ExecutionPolicy
    Type  : REG_SZ
    Data  : AllSigned

    ...
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet("Machine", "User")]
        [string] $Scope
    )

    begin {
        switch ($Scope) {
            "Machine" { $RootKey = "HKLM" }
            "User" { $RootKey = "HKCU" }
            default { throw "Unhandled scope: $($Scope)" }
        }

        # Note: The use of a list, instead of a hash table, is intentional here because
        # the keys of a hash table can get mixed up, except if the keyword "[ordered]"
        # is used. However, this keyword does not exist in PowerShell version 2.
        $RegistryKeys = @(
            @(
                "EnableScripts",
                "Software\Policies\Microsoft\Windows\PowerShell",
                "EnableScripts",
                "REG_DWORD"
            ),
            @(
                "ExecutionPolicy",
                "Software\Policies\Microsoft\Windows\PowerShell",
                "ExecutionPolicy",
                "REG_SZ"
            ),
            @(
                "ScriptBlockLoggingEnabled",
                "Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
                "EnableScriptBlockLogging",
                "REG_DWORD"
            ),
            @(
                "ModuleLoggingEnabled",
                "Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
                "EnableModuleLogging",
                "REG_DWORD"
            ),
            @(
                "ModuleLoggingModuleList",
                "Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames",
                $null,
                "REG_MULTI_SZ"
            ),
            @(
                "TranscriptionEnabled",
                "Software\Policies\Microsoft\Windows\PowerShell\Transcription",
                "EnableTranscripting",
                "REG_DWORD"
            ),
            @(
                "TranscriptionDirectory",
                "Software\Policies\Microsoft\Windows\PowerShell\Transcription",
                "OutputDirectory",
                "REG_SZ"
            )
        )
    }

    process {
        foreach ($Property in $RegistryKeys) {

            $PropertyName = $Property[0]
            $RegistryKeyPath = "$($RootKey)\$($Property[1])"
            $PropertyType = $Property[3]
            $RegistryKeyValue = $Property[2]

            if ($null -ne $RegistryKeyValue) {
                $RegistryKeyData = (Get-ItemProperty -Path "Registry::$($RegistryKeyPath)" -Name $RegistryKeyValue -ErrorAction SilentlyContinue).$RegistryKeyValue
            }
            else {
                $RegistryKeyData = (Get-Item -Path "Registry::$($RegistryKeyPath)" -ErrorAction SilentlyContinue).Property
            }

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $PropertyName
            $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $RegistryKeyPath
            $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegistryKeyValue
            $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $PropertyType
            $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegistryKeyData
            $Result
        }
    }
}