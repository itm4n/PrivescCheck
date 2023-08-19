function Get-SccmCacheFolder {
    <#
    .SYNOPSIS
    Helper - Get the SCCM cache folder as a PowerShell object if it exists.

    Author: @itm4n
    License: BSD 3-Clause
    #>

    [CmdletBinding()] param()

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
    
    .EXAMPLE
    PS C:\> Get-PointAndPrintConfiguration

    NoWarningNoElevationOnInstall              : @{Policy=Point and Print Restrictions > NoWarningNoElevationOnInstall; Value=0; Description=Show warning and elevation prompt (default).; Vulnerable=False}
    UpdatePromptSettings                       : @{Policy=Point and Print Restrictions > UpdatePromptSettings; Value=0; Description=Show warning and elevation prompt (default).; Vulnerable=False}
    TrustedServers                             : @{Policy=Point and Print Restrictions > TrustedServers; Value=0; Description=Users can point and print to any server (default).; Vulnerable=True}
    ServerList                                 : @{Policy=Point and Print Restrictions > ServerList; Value=; Description=List of authorized Point and Print servers; Vulnerable=True}
    RestrictDriverInstallationToAdministrators : @{Policy=Limits print driver installation to Administrators; Value=1; Description=Installing printer drivers when using Point and Print requires administrator privileges (default).; Vulnerable=False}
    PackagePointAndPrintServerList             : @{Policy=Package Point and print - Approved servers > PackagePointAndPrintServerList; Value=0; Description=Package point and print will not be restricted to specific print servers (default).; Vulnerable=True}

    .LINK
    https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872
    https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PointAndPrint_Restrictions_Win7
    https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::RestrictDriverInstallationToAdministrators
    https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PackagePointAndPrintServerList_Win7
    https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PackagePointAndPrintOnly
    #>

    [CmdletBinding()] param ()

    BEGIN {
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

        $RestrictDriverInstallationToAdministratorsDescriptions = @(
            "Installing printer drivers does not require administrator privileges.",
            "Installing printer drivers when using Point and Print requires administrator privileges (default)."
        )

        $PackagePointAndPrintServerListDescriptions = @(
            "Package point and print will not be restricted to specific print servers (default).",
            "Users will only be able to package point and print to print servers approved by the network administrator."
        )
    }

    PROCESS {
        $Result = New-Object -TypeName PSObject

        # Policy: Computer Configuration > Administrative Templates > Printers > Point and Print Restrictions
        # ADMX: https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PointAndPrint_Restrictions_Win7
        # Value: NoWarningNoElevationOnInstall
        # - 0 = Show warning and elevation prompt (default)
        # - 1 = Do not show warning or elevation prompt
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "NoWarningNoElevationOnInstall"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        if ($null -eq $RegData) { $RegData = 0 }

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Point and Print Restrictions > NoWarningNoElevationOnInstall"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $NoWarningNoElevationOnInstallDescriptions[$RegData]
        $Item | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value $($RegData -ne 0)
        $Result | Add-Member -MemberType "NoteProperty" -Name "NoWarningNoElevationOnInstall" -Value $Item

        # Policy: Computer Configuration > Administrative Templates > Printers > Point and Print Restrictions
        # ADMX: https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PointAndPrint_Restrictions_Win7
        # Value: UpdatePromptSettings
        # - 0 = Show warning and elevation prompt (default)
        # - 1 = Show warning only
        # - 2 = Do not show warning or elevation prompt
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "UpdatePromptSettings"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        if ($null -eq $RegData) { $RegData = 0 }

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Point and Print Restrictions > UpdatePromptSettings"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $UpdatePromptSettingsDescriptions[$RegData]
        $Item | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value $($RegData -ne 0)
        $Result | Add-Member -MemberType "NoteProperty" -Name "UpdatePromptSettings" -Value $Item

        # Policy: Computer Configuration > Administrative Templates > Printers > Point and Print Restrictions
        # ADMX: https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PointAndPrint_Restrictions_Win7
        # Value: TrustedServers
        # - 0 = Users can point and print to any server (default)
        # - 1 = Users can only point and print to a predefined list of servers
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "TrustedServers"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        if ($null -eq $RegData) { $RegData = 0 }

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Point and Print Restrictions > TrustedServers"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $TrustedServersDescriptions[$RegData]
        $Item | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value $($RegData -ne 1)
        $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedServers" -Value $Item

        # Policy: Computer Configuration > Administrative Templates > Printers > Point and Print Restrictions
        # ADMX: https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PointAndPrint_Restrictions_Win7
        # Value: ServerList
        # - "" = Empty or undefined (default)
        # - "foo;bar" = List of servers
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "ServerList"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Point and Print Restrictions > ServerList"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "List of authorized Point and Print servers"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value $([String]::IsNullOrEmpty($RegData))
        $Result | Add-Member -MemberType "NoteProperty" -Name "ServerList" -Value $Item

        # Policy: Limits print driver installation to Administrators
        # ADMX: https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::RestrictDriverInstallationToAdministrators
        # Value: RestrictDriverInstallationToAdministrators
        # - 0 - Installing printer drivers does not require administrator privileges.
        # - 1 = Installing printer drivers when using Point and Print requires administrator privileges (default).
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
        $RegValue = "RestrictDriverInstallationToAdministrators"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        if ($null -eq $RegData) { $RegData = 1 }

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Limits print driver installation to Administrators"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $RestrictDriverInstallationToAdministratorsDescriptions[$RegData]
        $Item | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value $($RegData -ne 1)
        $Result | Add-Member -MemberType "NoteProperty" -Name "RestrictDriverInstallationToAdministrators" -Value $Item

        # Policy: Package Point and print - Approved servers
        # ADMX: https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PackagePointAndPrintServerList_Win7
        # Value: PackagePointAndPrintServerList
        # - 0 = Package point and print will not be restricted to specific print servers (default).
        # - 1 = Users will only be able to package point and print to print servers approved by the network administrator.
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PackagePointAndPrint"
        $RegValue = "PackagePointAndPrintServerList"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        if ($null -eq $RegData) { $RegData = 0 }

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Package Point and print - Approved servers > PackagePointAndPrintServerList"
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $PackagePointAndPrintServerListDescriptions[$RegData]
        $Item | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value $($RegData -ne 1)
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

    [CmdletBinding()] param()

    $Result = New-Object -TypeName PSObject

    # Check AlwaysInstallElevated in HKLM
    $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $RegValue = "AlwaysInstallElevated"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    
    # If the setting is not enabled in HKLM, it is not exploitable.
    if (($null -eq $RegData) -or ($RegData -eq 0)) { return }

    $Result | Add-Member -MemberType "NoteProperty" -Name "LocalMachineKey" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "LocalMachineValue" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "LocalMachineData" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })

    # Check AlwaysInstallElevated in HKCU
    $RegKey = "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $RegValue = "AlwaysInstallElevated"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

    # If the setting is not enabled in HKCU, it is not exploitable.
    if (($null -eq $RegData) -or ($RegData -eq 0)) { return }

    $Result | Add-Member -MemberType "NoteProperty" -Name "CurrentUserKey" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "CurrentUserValue" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "CurrentUserData" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })

    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "AlwaysInstallElevated is enabled in both HKLM and HKCU."
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

    $RegKey = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
    $RegValue = "WUServer"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    if ($null -eq $RegData) { return }

    $WusUrl = $RegData

    $RegKey = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $RegValue = "UseWUServer"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    if ($null -eq $RegData) { return }

    $WusEnabled = $RegData

    $RegKey = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
    $RegValue = "SetProxyBehaviorForUpdateDetection"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

    $WsusProxybehavior = $RegData

    $RegKey = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
    $RegValue = "DisableWindowsUpdateAccess"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

    $DisableWindowsUpdateAccess = $RegData

    if (($WusUrl -like "http://*") -and ($WusEnabled -eq 1)) {

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "WUServer" -Value $WusUrl
        $Result | Add-Member -MemberType "NoteProperty" -Name "UseWUServer" -Value $WusEnabled
        $Result | Add-Member -MemberType "NoteProperty" -Name "SetProxyBehaviorForUpdateDetection" -Value $(if ($null -eq $WsusProxybehavior) { "(null)" } else { $WsusProxybehavior })
        $Result | Add-Member -MemberType "NoteProperty" -Name "DisableWindowsUpdateAccess" -Value $(if ($null -eq $DisableWindowsUpdateAccess) { "(null)" } else { $DisableWindowsUpdateAccess })
        $Result
    }
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
    References:
      * https://support.microsoft.com/en-us/topic/ms15-011-vulnerability-in-group-policy-could-allow-remote-code-execution-february-10-2015-91b4bda2-945d-455b-ebbb-01d1ec191328
      * https://github.com/SecureAuthCorp/impacket/blob/master/examples/karmaSMB.py
      * https://www.coresecurity.com/core-labs/articles/ms15-011-microsoft-windows-group-policy-real-exploitation-via-a-smb-mitm-attack
      * https://beyondsecurity.com/scan-pentest-network-vulnerabilities-in-group-policy-allows-code-execution-ms15-011.html
    #>

    [CmdletBinding()] Param()

    # Hardened UNC paths ensure that the communication between a client and a Domain Controller
    # cannot be tampered with, so this setting only applies to domain-joined machines. If the
    # current machine is not domain-joined, return immediately.

    if (-not (Test-IsDomainJoined)) {
        return
    }

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

            $Vulnerable = $false
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
                $Result
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
            $Vulnerable = $false
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
                $Result
            }
        }
    }
}

function Invoke-SccmCacheFolderCheck {
    <#
    .SYNOPSIS
    Gets some information about the SCCM cache folder if it exists.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    If the SCCM cache folder exists ('C:\Windows\CCMCache'), this check will return some information about the item, such as the ACL. This allows for further manual analysis.

    .PARAMETER Info
    Report if the folder exists without checking if it is accessible.
    #>

    [CmdletBinding()] param (
        [switch]$Info = $false
    )

    Get-SccmCacheFolder | ForEach-Object {

        if ($Info) { $_; continue } # If Info, report the item directly

        Get-ChildItem -Path $_.FullName -ErrorAction SilentlyContinue -ErrorVariable ErrorGetChildItem | Out-Null
        if (-not $ErrorGetChildItem) {
            $_
        }
    }
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

    [CmdletBinding()] Param()

    $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    $RegValue = "Path"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue).$RegValue
    $Paths = $RegData.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { -not [String]::IsNullOrEmpty($_) }

    foreach ($Path in $Paths) {
        $Path | Get-ModifiablePath -LiteralPaths | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) } | Foreach-Object {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Path
            $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
            $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
            $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $_.Permissions
            $Result
        }
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
    Value       : 0
    Description : Installing printer drivers does not require administrator privileges.
    Vulnerable  : True

    Policy      : Point and Print Restrictions > NoWarningNoElevationOnInstall
    Value       : 1
    Description : Do not show warning or elevation prompt.
    Vulnerable  : True

    Policy      : Point and Print Restrictions > UpdatePromptSettings
    Value       : 2
    Description : Do not show warning or elevation prompt.
    Vulnerable  : True

    Policy      : Point and Print Restrictions > TrustedServers
    Value       : 1
    Description : Users can only point and print to a predefined list of servers.
    Vulnerable  : Fase

    Policy      : Package Point and print - Approved servers > PackagePointAndPrintServerList
    Value       : 1
    Description : Users will only be able to package point and print to print servers approved by the network administrator.
    Vulnerable  : False

    Policy      : Point and Print Restrictions > ServerList
    Value       : printer.domain.local
    Description : List of authorized Point and Print servers
    Vulnerable  : False
    #>

    [CmdletBinding()] param()

    # If the Print Spooler is not installed or is disabled, return immediately
    $Service = Get-ServiceList -FilterLevel 2 | Where-Object { $_.Name -eq "Spooler" }
    if (-not $Service -or ($Service.StartMode -eq "Disabled")) {
        Write-Verbose "The Print Spooler service is not installed or is disabled."
        return
    }

    $Config = Get-PointAndPrintConfiguration
    $ConfigVulnerable = $false

    if ($Config.RestrictDriverInstallationToAdministrators.Value -eq 0) {

        # Printer driver installation is not restricted to administrators, the system
        # could be vulnerable.

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

        if (($Config.NoWarningNoElevationOnInstall.Value -eq 1) -or ($Config.UpdatePromptSettings.Value -ge 1)) {
            
            # Elevation prompts on install or update are disabled, so the system is vulnerable
            # to CVE-2021-34527.

            $ConfigVulnerable = $true
        }
        else {

            # Elevation prompts are enabled both on install and update, but we still need
            # to make sure that users can only connect to specific print servers.

            if (($Config.TrustedServers.Value -eq 0) -or ($Config.PackagePointAndPrintServerList.Value -eq 0)) {

                # At least one server list is not explictly defined, so the system could be
                # vulnerable.

                $ConfigVulnerable = $true
            }
        }
    }

    if ($ConfigVulnerable) {
        $Config.RestrictDriverInstallationToAdministrators
        $Config.NoWarningNoElevationOnInstall
        $Config.UpdatePromptSettings
        $Config.TrustedServers
        $Config.PackagePointAndPrintServerList
        $Config.ServerList
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

    [CmdletBinding()] param()

    $RegKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer"
    $RegValue = "DisableCoInstallers"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

    # Driver Co-Installers are disabled
    if ($RegData -ge 1) {
        Write-Verbose "Driver Co-installers are disabled."
        return
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "Driver Co-installers are not disabled (default)."
    $Result
}