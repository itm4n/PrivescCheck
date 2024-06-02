function Get-SccmCacheFolder {
    <#
    .SYNOPSIS
    Helper - Get the SCCM cache folder as a PowerShell object if it exists.

    Author: @itm4n
    License: BSD 3-Clause
    #>

    [CmdletBinding()] Param()

    $CcmCachePath = Join-Path -Path $env:windir -ChildPath "CCMCache"
    Get-Item -Path $CcmCachePath -ErrorAction SilentlyContinue | Select-Object -Property FullName,Attributes,Exists
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

    [CmdletBinding()] param()

    begin {
        $NoWarningNoElevationOnInstallDescriptions = @(
            "Show warning and elevation prompt (default).",
            "Do not show warning or elevation prompt."
        )

        $UpdatePromptSettingsDescriptions = @(
            "Show warning and elevation prompt (default).",
            "Show warning only.",
            "Do not show warning or elevation prompt."
        )

        $TrustedServersDescriptions = @(
            "Users can point and print to any server (default).",
            "Users can only point and print to a predefined list of servers."
        )

        $InForestDescriptions = @(
            "Users can point and print to any machine (default).",
            "Users can only point and print to machines in their forest."
        )

        $RestrictDriverInstallationToAdministratorsDescriptions = @(
            "Installing printer drivers does not require administrator privileges.",
            "Installing printer drivers when using Point and Print requires administrator privileges (default)."
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
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value 0
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
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
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value 0
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
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
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value 1
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
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
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value 0
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
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
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value "(null)"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "<SERVER_LIST>"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
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
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value 1
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
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
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value 1
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
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
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value 1
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
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
        $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value "(null)"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "<SERVER_LIST>"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if (-not [string]::IsNullOrEmpty($RegData)) { $RegData -join ';' })
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ([string]::IsNullOrEmpty($RegData)) { "A list of approved Package Point and Print servers is not defined." } else { "A list of approved Package Point and Print servers is defined." })
        $Result | Add-Member -MemberType "NoteProperty" -Name "PackagePointAndPrintServerList" -Value $Item

        $Result
    }
}

function Invoke-RegistryAlwaysInstallElevatedCheck {
    <#
    .SYNOPSIS
    Checks whether the AlwaysInstallElevated key is set in the registry.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    AlwaysInstallElevated can be configured in both HKLM and HKCU. "If the AlwaysInstallElevated value is not set to "1" under both of the preceding registry keys, the installer uses elevated privileges to install managed applications and uses the current user's privilege level for unmanaged applications."

    .EXAMPLE
    PS C:\> Invoke-RegistryAlwaysInstallElevatedCheck

    LocalMachineKey   : HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
    LocalMachineValue : AlwaysInstallElevated
    LocalMachineData  : 1
    CurrentUserKey    : HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
    CurrentUserValue  : AlwaysInstallElevated
    CurrentUserData   : 1
    Description       : AlwaysInstallElevated is enabled in both HKLM and HKCU.
    #>

    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )

    $Vulnerable = $false
    $Config = New-Object -TypeName PSObject

    # Check AlwaysInstallElevated in HKLM
    $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $RegValue = "AlwaysInstallElevated"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

    $Config | Add-Member -MemberType "NoteProperty" -Name "LocalMachineKey" -Value $RegKey
    $Config | Add-Member -MemberType "NoteProperty" -Name "LocalMachineValue" -Value $RegValue
    $Config | Add-Member -MemberType "NoteProperty" -Name "LocalMachineData" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })

    # If the setting is not enabled in HKLM, it is not exploitable.
    if (($null -eq $RegData) -or ($RegData -eq 0)) {
        $Description = "AlwaysInstallElevated is not enabled in HKLM."
    }
    else {
        # Check AlwaysInstallElevated in HKCU
        $RegKey = "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer"
        $RegValue = "AlwaysInstallElevated"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $Config | Add-Member -MemberType "NoteProperty" -Name "CurrentUserKey" -Value $RegKey
        $Config | Add-Member -MemberType "NoteProperty" -Name "CurrentUserValue" -Value $RegValue
        $Config | Add-Member -MemberType "NoteProperty" -Name "CurrentUserData" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })

        if (($null -eq $RegData) -or ($RegData -eq 0)) {
            $Description = "AlwaysInstallElevated is enabled in HKLM but not in HKCU."
        }
        else {
            $Description = "AlwaysInstallElevated is enabled in both HKLM and HKCU."
            $Vulnerable = $true
        }
    }

    $Config | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
    $Result
}

function Invoke-WsusConfigCheck {
    <#
    .SYNOPSIS
    Checks whether the WSUS is enabled and vulnerable to MitM attacks.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    A system can be compromised if the updates are not requested using HTTPS but HTTP. If the URL of the update server (WUServer) starts with HTTP and UseWUServer=1, then the update requests are vulnerable to MITM attacks.

    .EXAMPLE
    PS C:\> Invoke-WsusConfigCheck

    WUServer                           : http://acme-upd01.corp.internal.com:8535
    UseWUServer                        : 1
    SetProxyBehaviorForUpdateDetection : 1
    DisableWindowsUpdateAccess         : (null)

    .NOTES
    "Beginning with the September 2020 cumulative update, HTTP-based intranet servers will be secure by default. [...] we are no longer allowing HTTP-based intranet servers to leverage user proxy by default to detect updates." The SetProxyBehaviorForUpdateDetection value determines whether this default behavior can be overriden. The default value is 0. If it is set to 1, WSUS can use user proxy settings as a fallback if detection using system proxy fails. See links 1 and 2 below for more details.

    .LINK
    https://techcommunity.microsoft.com/t5/windows-it-pro-blog/changes-to-improve-security-for-windows-devices-scanning-wsus/ba-p/1645547
    https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#update-setproxybehaviorforupdatedetection
    https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus
    https://github.com/pimps/wsuxploit
    https://github.com/GoSecure/pywsus
    https://github.com/GoSecure/wsuspicious
    #>

    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )

    $Vulnerable = $true
    $ArrayOfResults = @()

    $RegKey = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
    $RegValue = "WUServer"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

    $Item = New-Object -TypeName PSObject
    $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ([string]::IsNullOrEmpty($RegData)) { "(null)" } else { $RegData })
    $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ([string]::IsNullOrEmpty($RegData)) { "No WSUS server is configured (default)." } else { "A WSUS server is configured." })
    $ArrayOfResults += $Item

    if ([string]::IsNullOrEmpty($RegData)) { $Vulnerable = $false }
    if ($RegData -like "https://*") { $Vulnerable = $false }

    $RegKey = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $RegValue = "UseWUServer"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

    $Item = New-Object -TypeName PSObject
    $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ($RegData -ge 1) { "WSUS server enabled." } else { "WSUS server not enabled (default)." })
    $ArrayOfResults += $Item

    if (($null -eq $RegData) -or ($RegData -lt 1)) { $Vulnerable = $false }

    $RegKey = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
    $RegValue = "SetProxyBehaviorForUpdateDetection"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

    $Item = New-Object -TypeName PSObject
    $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ($RegData -ge 1) { "Fallback to user proxy is enabled." } else { "Proxy fallback not configured (default)." })
    $ArrayOfResults += $Item

    $RegKey = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
    $RegValue = "DisableWindowsUpdateAccess"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

    $Item = New-Object -TypeName PSObject
    $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $regData) { "(null)" } else { $RegData })
    $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ($RegData -ge 1) { "Windows Update features are disabled." } else { "Windows Update features are enabled (default)." })
    $ArrayOfResults += $Item

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
    $Result
}

function Invoke-HardenedUNCPathCheck {
    <#
    .SYNOPSIS
    Check whether hardened UNC paths are properly configured.

    Author: Adrian Vollmer - SySS GmbH (@mr_mitm), @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    If a UNC path to a file share is not hardened, Windows does not check the SMB server's identity when establishing the connection. This allows privilege escalation if the path to SYSVOL is not hardened, because a man-in-the-middle can inject malicious GPOs when group policies are updated.

    A group policy update can be triggered with 'gpupdate /force'. Exploits exist; check Impacket's karmaSMB server. A legit DC must be available at the same time.

    On Windows >= 10, UNC paths are hardened by default for SYSVOL and NETLOGON so, in this case, we just ensure that mutual authentication and integrity mode were not disabled. On Windows < 10 on the other hand, SYSVOL and NETLOGON UNC paths must be explicitely hardened. Note that this only applies to domain-joined machines.

    .EXAMPLE
    PS C:\> Invoke-HardenedUNCPathCheck

    Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths
    Value       : \\*\SYSVOL
    Data        : RequireMutualAuthentication=0, RequireIntegrity=1
    Description : Mutual authentication is disabled.

    .EXAMPLE
    PS C:\> Invoke-HardenedUNCPathCheck

    Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths
    Value       : \\*\SYSVOL
    Data        : RequireMutualAuthentication=0, RequireIntegrity=1
    Description : Mutual authentication is not enabled.

    Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths
    Value       : \\*\NETLOGON
    Data        :
    Description : Hardened UNC path is not configured.

    .NOTES
    Hardened UNC paths ensure that the communication between a client and a Domain Controller cannot be tampered with, so this setting only applies to domain-joined machines. If the current machine is not domain-joined, return immediately.

    References:
      * https://support.microsoft.com/en-us/topic/ms15-011-vulnerability-in-group-policy-could-allow-remote-code-execution-february-10-2015-91b4bda2-945d-455b-ebbb-01d1ec191328
      * https://github.com/SecureAuthCorp/impacket/blob/master/examples/karmaSMB.py
      * https://www.coresecurity.com/core-labs/articles/ms15-011-microsoft-windows-group-policy-real-exploitation-via-a-smb-mitm-attack
      * https://beyondsecurity.com/scan-pentest-network-vulnerabilities-in-group-policy-allows-code-execution-ms15-011.html
    #>

    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )

    $Vulnerable = $false
    $ArrayOfResults = @()

    if (-not (Test-IsDomainJoined)) {
        $Description = "The machine is not domain-joined, this check is irrelevant."
        $Results = New-Object -TypeName PSObject
        $Results | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    }
    else {
        $OsVersionMajor = (Get-WindowsVersion).Major

        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"

        if ($OsVersionMajor -ge 10) {

            # If Windows >= 10, paths are "hardened" by default. Therefore, the "HardenedPaths" registry
            # key should not contain any value. If it contain values, ensure that protections were not
            # explicitely disabled.

            Get-Item -Path "Registry::$RegKey" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty property | ForEach-Object {

                $RegValue = $_
                $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
                Write-Verbose "Value: $($RegValue) - Data: $($RegData)"

                $Description = ""

                if ($RegData -like "*RequireMutualAuthentication=0*") {
                    $Vulnerable = $true
                    $Description = "$($Description)Mutual authentication is disabled. "
                }

                if ($RegData -like "*RequireIntegrity=0*") {
                    $Vulnerable = $true
                    $Description = "$($Description)Integrity mode is disabled. "
                }

                if ($RegData -like "*RequirePrivacy=0*") {
                    $Vulnerable = $true
                    $Description = "$($Description)Privacy mode is disabled. "
                }

                if ($Vulnerable) {
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                    $ArrayOfResults += $Result
                }
            }
        }
        else {

            # If Windows < 10, paths are not hardened by default. Therefore, the "HardenedPaths" registry
            # should contain at least two entries, as per Microsoft recommendations. One for SYSVOL and one
            # for NETLOGON: '\\*\SYSVOL' and '\\*\NETLOGON'. However, a list of server would be valid as
            # as well. Here, we will only ensure that both '\\*\SYSVOL' and '\\*\NETLOGON' are properly
            # configured though.

            $RegValues = @("\\*\SYSVOL", "\\*\NETLOGON")
            foreach ($RegValue in $RegValues) {

                $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
                $Description = ""

                if ($null -eq $RegData) {
                    $Vulnerable = $true
                    $Description = "Hardened UNC path is not configured."
                }
                else {
                    if (-not ($RegData -like "*RequireMutualAuthentication=1*")) {
                        $Vulnerable = $true
                        $Description = "$($Description)Mutual authentication is not enabled. "
                    }

                    if ((-not ($RegData -like "*RequireIntegrity=1*")) -and (-not ($RegData -like "*RequirePrivacy=1*"))) {
                        $Vulnerable = $true
                        $Description = "$($Description)Integrity/privacy mode is not enabled. "
                    }
                }

                if ($Vulnerable) {
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                    $ArrayOfResults += $Result
                }
            }
        }
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
    $Result
}

function Invoke-DllHijackingCheck {
    <#
    .SYNOPSIS
    Checks whether any of the system path folders is modifiable

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    First, it reads the system environment PATH from the registry. Then, for each entry, it checks whether the current user has write permissions.
    #>

    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )

    begin {
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        $RegValue = "Path"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue).$RegValue
        $Paths = $RegData.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { -not [String]::IsNullOrEmpty($_) }
        $ArrayOfResults = @()

        foreach ($Path in $Paths) {
            $Path | Get-ModifiablePath -LiteralPaths | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) } | Foreach-Object {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Path
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $_.Permissions
                $ArrayOfResults += $Result
            }
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $Result
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Invoke-PointAndPrintConfigCheck {
    <#
    .SYNOPSIS
    Checks for configurations that are vulnerable to the PrintNightmare LPE exploit(s).

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Fully up-to-date machines are still vulnerable to the PrintNightmare LPE exploit if the "Point and Print Restrictions" Group policy is configured to allow users to install printer drivers or add print servers without administrator privileges. More precisely, if "NoWarningNoElevationOnInstall" or "UpdatePromptSettings" is set to a value greater or equal to 1, and the installation of printer drivers is not restricted to administrators only, the system is vulnerable.

    .EXAMPLE
    PS C:\> Invoke-PointAndPrintConfigCheck

    Policy      : Limits print driver installation to Administrators
    Default     : 1
    Expected    : 1
    Value       : (null)
    Description : Installing printer drivers when using Point and Print requires administrator privileges (default).

    Policy      : Point and Print Restrictions > NoWarningNoElevationOnInstall
    Default     : 0
    Expected    : 0
    Value       : (null)
    Description : Show warning and elevation prompt (default).

    Policy      : Point and Print Restrictions > UpdatePromptSettings
    Default     : 0
    Expected    : 0
    Value       : (null)
    Description : Show warning and elevation prompt (default).

    Policy      : Point and Print Restrictions > InForest
    Default     : 0
    Expected    : 0
    Value       : (null)
    Description : Users can point and print to any machine (default).

    Policy      : Point and Print Restrictions > TrustedServers
    Default     : 0
    Expected    : 1
    Value       : (null)
    Description : Users can point and print to any server (default).

    Policy      : Point and Print Restrictions > ServerList
    Default     : (null)
    Expected    : <SERVER_LIST>
    Value       : (null)
    Description : A list of approved Point and Print servers is not defined.

    Policy      : Package Point and print - Only use Package Point and Print
    Default     : 0
    Expected    : 1
    Value       : (null)
    Description : Users will not be restricted to package-aware point and print only (default).

    Policy      : Package Point and print - Approved servers > PackagePointAndPrintServerList
    Default     : 0
    Expected    : 1
    Value       : (null)
    Description : Package point and print will not be restricted to specific print servers (default).

    Policy      : Package Point and print - Approved servers > PackagePointAndPrintServerList
    Default     : (null)
    Expected    : <SERVER_LIST>
    Value       : (null)
    Description : A list of approved Package Point and Print servers is not defined.
    #>

    [CmdletBinding()] param (
        [UInt32] $BaseSeverity
    )

    begin {
        $ConfigVulnerable = $false
        $Severity = $BaseSeverity
    }

    process {
        # If the Print Spooler is not installed or is disabled, return immediately
        $Service = Get-ServiceList -FilterLevel 2 | Where-Object { $_.Name -eq "Spooler" }
        if (-not $Service -or ($Service.StartMode -eq "Disabled")) {
            Write-Verbose "The Print Spooler service is not installed or is disabled."

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "The Print Spooler service is disabled."

            $ArrayOfResults = @($Result)
        }
        else {
            $Config = Get-PointAndPrintConfiguration

            if ($Config.RestrictDriverInstallationToAdministrators.Data -eq 0) {

                # Printer driver installation is not restricted to administrators, the system
                # could therefore be vulnerable.

                # From the KB article KB5005652:
                # "Setting the value to 0 allows non-administrators to install signed and
                # unsigned drivers to a print server but does not override the Point and Print
                # Group Policy settings.
                # Consequently, the Point and Print Restrictions Group Policy settings can
                # override this registry key setting to prevent non-administrators from
                # installing signed and unsigned print drivers from a print server. Some
                # administrators might set the value to 0 to allow non-admins to install and
                # update drivers after adding additional restrictions, including adding a policy
                # setting that constrains where drivers can be installed from."

                # If the policy "Package Point and Print Only" is enabled (not the default), the
                # "Point and Print" configuration is irrelevant, so check this first, and skip if
                # necessary.
                if ($Config.PackagePointAndPrintOnly.Data -ne 1) {

                    # If the settings "NoWarningNoElevationOnInstall" and "UpdatePromptSettings" have
                    # non-zero values, the device is vulnerable to CVE-2021-34527 (PrintNightmare), even
                    # if the setting "TrustedServers" is set or "InForest" is enabled.
                    if (($Config.NoWarningNoElevationOnInstall.Data -gt 0) -or ($Config.UpdatePromptSettings.Data -gt 0)) {

                        $ConfigVulnerable = $true
                        $Severity = [Math]::Max([UInt32] $Severity, [UInt32] $script:SeverityLevelEnum::High) -as $script:SeverityLevelEnum
                    }
                }

                # If a list of approved "Package Point and Print" servers is not defined (default),
                # the configuration is vulnerable. The exploitation requires the use of a fake
                # printer server with a vulnerable signed printer driver though.
                if ($Config.PackagePointAndPrintServerListEnabled.Data -ne 1) {
                    $ConfigVulnerable = $true
                    $Severity = [Math]::Max([UInt32] $Severity, [UInt32] $script:SeverityLevelEnum::Medium) -as $script:SeverityLevelEnum
                }
            }

            $ArrayOfResults = @(
                $Config.RestrictDriverInstallationToAdministrators,
                $Config.NoWarningNoElevationOnInstall,
                $Config.UpdatePromptSettings,
                $Config.InForest,
                $Config.TrustedServers,
                $Config.ServerList,
                $Config.PackagePointAndPrintOnly,
                $Config.PackagePointAndPrintServerListEnabled,
                $Config.PackagePointAndPrintServerList
            )

            foreach ($Result in $ArrayOfResults) {
                if ($null -eq $Result.Data) { $Result.Data = "(null)"}
            }
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ConfigVulnerable) { $Severity } else { $script:SeverityLevelEnum::None })
        $Result
    }
}

function Invoke-DriverCoInstallersCheck {
    <#
    .SYNOPSIS
    Checks whether the DisableCoInstallers key is set in the registry.

    Author: @itm4n, @SAERXCIT
    License: BSD 3-Clause

    .DESCRIPTION
    The automatic installation as SYSTEM of additional software alongside device drivers can be a vector for privesc, if this software can be manipulated into executing arbitrary code. This can be prevented by setting the DisableCoInstallers key in HKLM. Credit to @wdormann https://twitter.com/wdormann/status/1432703702079508480.

    .EXAMPLE
    Ps C:\> Invoke-DriverCoInstallersCheck

    Key         : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer
    Value       : DisableCoInstallers
    Data        : (null)
    Description : CoInstallers are not disabled (default).
    #>

    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )

    $RegKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer"
    $RegValue = "DisableCoInstallers"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

    $Vulnerable = $false
    $Description = $(if ($RegData -ge 1) { "Driver Co-installers are disabled." } else { "Driver Co-installers are enabled (default)."; $Vulnerable = $true })

    $Config = New-Object -TypeName PSObject
    $Config | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Config | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Config | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Config | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
    $Result
}

function Invoke-SccmCacheFoldersCheck {
    <#
    .SYNOPSIS
    Get information about SCCM cache folders (incl. number and list of binary, script, and text files).

    Author: @itm4n, @SAERXCIT
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet retrieves a list of SCCM cache folders. For each folder, it also enumerates interesting files (such as binaries, scripts, or various text files).
    #>

    [CmdletBinding()]
    param ()

    process {
        $SccmCacheFolders = [object[]] (Get-SccmCacheFoldersFromRegistry)

        foreach ($SccmCacheFolder in $SccmCacheFolders) {

            if ([string]::IsNullOrEmpty($SccmCacheFolder.Path)) { continue }

            $SccmCacheFiles = [object[]] (Get-SccmCacheFile -Path $SccmCacheFolder.Path)

            $BinaryFiles = [object[]] ($SccmCacheFiles | Where-Object { $_.Type -eq "Binary" })
            $ScriptFiles = [object[]] ($SccmCacheFiles | Where-Object { $_.Type -eq "Script" })
            $TextFiles = [object[]] ($SccmCacheFiles | Where-Object { $_.Type -eq "Text" })

            $BinaryFileRelativePaths = $BinaryFiles | Select-Object -ExpandProperty "RelativePath"
            $ScriptFileRelativePaths = $ScriptFiles | Select-Object -ExpandProperty "RelativePath"
            $TextFileRelativePaths = $TextFiles | Select-Object -ExpandProperty "RelativePath"

            $SccmCacheFolderItem = $SccmCacheFolder.PSObject.Copy()
            $SccmCacheFolderItem | Add-Member -MemberType "NoteProperty" -Name "BinaryFileCount" -Value $BinaryFiles.Count
            $SccmCacheFolderItem | Add-Member -MemberType "NoteProperty" -Name "BinaryFiles" -Value ($BinaryFileRelativePaths -join "; ")
            $SccmCacheFolderItem | Add-Member -MemberType "NoteProperty" -Name "ScriptFileCount" -Value $ScriptFiles.Count
            $SccmCacheFolderItem | Add-Member -MemberType "NoteProperty" -Name "ScriptFiles" -Value ($ScriptFileRelativePaths -join "; ")
            $SccmCacheFolderItem | Add-Member -MemberType "NoteProperty" -Name "TextFileCount" -Value $TextFiles.Count
            $SccmCacheFolderItem | Add-Member -MemberType "NoteProperty" -Name "TextFiles" -Value ($TextFileRelativePaths -join "; ")
            $SccmCacheFolderItem
        }
    }
}

function Invoke-ProxyAutoConfigUrlCheck {

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $Result = New-Object -TypeName PSObject
        $AllResults = @()
    }

    process {
        $AllResults = Get-ProxyAutoConfigURl | Where-Object { $_.ProxyEnable -ne 0 }
        $Vulnerable = $null -ne ($AllResults | Where-Object { $_.AutoConfigURL -like "http://*" })

        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
    }

    end {
        $Result
    }
}