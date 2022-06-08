function Invoke-RegistryAlwaysInstallElevatedCheck {
    <#
    .SYNOPSIS
    Checks whether the AlwaysInstallElevated key is set in the registry.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    AlwaysInstallElevated can be configured in both HKLM and HKCU. "If the AlwaysInstallElevated value is not set to "1" under both of the preceding registry keys, the installer uses elevated privileges to install managed applications and uses the current user's privilege level for unmanaged applications."
    #>

    [CmdletBinding()] Param()

    $Results = @()

    $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $RegValue = "AlwaysInstallElevated"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    $Description = $(if ($RegData -ge 1) { "AlwaysInstallElevated is enabled" } else { "AlwaysInstallElevated is disabled (default)" })
    Write-Verbose "HKLM > $($RegValue): $($Description)"
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $($null -eq $RegData -or $RegData -eq 0)
    [object[]]$Results += $Result

    $RegKey = "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer"
    $RegValue = "AlwaysInstallElevated"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    $Description = $(if ($RegData -ge 1) { "AlwaysInstallElevated is enabled" } else { "AlwaysInstallElevated is disabled (default)" })
    Write-Verbose "HKCU > $($RegValue): $($Description)"
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $($null -eq $RegData -or $RegData -eq 0)
    [object[]]$Results += $Result

    foreach ($Result in $Results) {
        if ($Result.Compliance -eq $true) {
            return
        }
    }

    $Results | Select-Object -ExcludeProperty Compliance
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

function Invoke-PrintNightmareCheck {
    <#
    .SYNOPSIS
    Checks for configurations that are vulnerable to the PrintNightmare exploit.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Fully up-to-date machines are still vulnerable to the PrintNightmare exploit if the "Point and Print Restrictions" Group policy is configured to allow users to install printer drivers or add print servers without administrator privileges. More precisely, if "NoWarningNoElevationOnInstall" or "UpdatePromptSettings" is set to 1, the machine is vulnerable. There is one exception though. If the patch for CVE-2021-34527 was installed, the "RestrictDriverInstallationToAdministrators" parameter can be set to 1 (or a value greater than 1) to override the "Point and Print" settings. In this case, only administrators can install printer drivers or print servers, regardless of the two other values. The "PackagePointAndPrintServerList" setting can also be set to 1 to only allow drivers to be downloaded and installed from a predefined list of print servers.

    .EXAMPLE
    PS C:\> Invoke-PrintNightmareCheck

    Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
    Value       : NoWarningNoElevationOnInstall
    Data        : 1
    Description : Do not show warning or elevation prompt

    Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
    Value       : UpdatePromptSettings
    Data        : 2
    Description : Do not show warning or elevation prompt

    Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
    Value       : RestrictDriverInstallationToAdministrators
    Data        : 0
    Description : Non-administrators can install print drivers

    Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
    Value       : PackagePointAndPrintOnly
    Data        : (null)
    Description : Users are not restricted to package-aware point and print only

    Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
    Value       : PackagePointAndPrintServerList
    Data        : (null)
    Description : Package point and print is not restricted to specific print servers

    .LINK
    https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
    https://support.microsoft.com/en-us/topic/kb5005010-restricting-installation-of-new-printer-drivers-after-applying-the-july-6-2021-updates-31b91c02-05bc-4ada-a7ea-183b129578a7
    https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PointAndPrint_Restrictions_Win7
    https://admx.help/?Category=PrintNightmare&Policy=PrintNightmare::POL_0F5609EA_BBB4_43FB_839A_231E44CEDD71
    https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PackagePointAndPrintOnly
    https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.Printing::PackagePointAndPrintServerList
    #>

    [CmdletBinding()] Param()

    # If the Print Spooler is not installed or is disabled, return immediately
    $Service = Get-ServiceList -FilterLevel 2 | Where-Object { $_.Name -eq "Spooler" }
    if (-not $Service -or ($Service.StartMode -eq "Disabled")) {
        Write-Verbose "The Print Spooler service is not installed or is disabled."
        return
    }

    $Results = @()

    # If "NoWarningNoElevationOnInstall" is not set, the default value is 0, which means "Show warning
    # and elevation prompt" (i.e. not vulnerable).
    $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
    $RegValue = "NoWarningNoElevationOnInstall"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    if ($null -eq $RegData -or $RegData -eq 0) {
        $Description = "Show warning and elevation prompt"
    }
    else {
        $Description = "Do not show warning or elevation prompt"
    }
    Write-Verbose "$($RegValue): $($Description)"
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $($null -eq $RegData -or $RegData -eq 0)
    [object[]]$Results += $Result

    # If "UpdatePromptSettings" is not set, the default value is 0, which means "Show warning and
    # elevation prompt" (i.e. not vulnerable).
    $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
    $RegValue = "UpdatePromptSettings"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    if ($null -eq $RegData -or $RegData -eq 0) {
        $Description = "Show warning and elevation prompt"
    }
    elseif ($RegData -eq 1) {
        $Description = "Show warning only"
    }
    elseif ($RegData -eq 2) {
        $Description = "Do not show warning or elevation prompt"
    }
    Write-Verbose "$($RegValue): $($Description)"
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $($null -eq $RegData -or $RegData -eq 0)
    [object[]]$Results += $Result

    # With the patch for CVE-2021-34527, MS added the "RestrictDriverInstallationToAdministrators"
    # setting. If this is set to 1 or any non-zero value then the Point and Print Restrictions Group
    # policy settings (i.e. the two previous registry values) are overridden and only administrators
    # can install printer drivers on a print server. "Updates released August 10, 2021 or later have
    # a default of 1 (enabled)."
    $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
    $RegValue = "RestrictDriverInstallationToAdministrators"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    if ($null -eq $RegData -or $RegData -eq 1) {
        $Description = "Only administrators can install print drivers"
    }
    else {
        $Description = "Non-administrators can install print drivers"
    }
    Write-Verbose "$($RegValue): $($Description)"
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $($null -eq $RegData -or $RegData -eq 1)
    [object[]]$Results += $Result

    # If "PackagePointAndPrintOnly" is enabled, users will only be able to point and print to
    # printers that use package-aware drivers predefined list of print servers.
    $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
    $RegValue = "PackagePointAndPrintOnly"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    if ($null -eq $RegValue -or $RegValue -eq 0) {
        $Description = "Users are not restricted to package-aware point and print only"
    }
    else {
        $Description = "Users can only point and print to printers that use package-aware drivers"
    }
    Write-Verbose "$($RegValue): $($Description)"
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $($RegValue -eq 1)
    [object[]]$Results += $Result

    # If "PackagePointAndPrintServerList" is enabled, clients can only install signed drivers from
    # a predefined list of print servers. This list is defined in thrhough the "ListofServers"
    # subkey. The content of the regisry key should be checked manually.
    $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
    $RegValue = "PackagePointAndPrintServerList"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    if ($null -eq $RegData -or $RegData -eq 0) {
        $Description = "Package point and print is not restricted to specific print servers"
    }
    else {
        $Description = "Package point and print is restricted to specific print servers (check 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint\ListofServers')"
    }
    Write-Verbose "$($RegValue): $($Description)"
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $($RegData -eq 1)
    [object[]]$Results += $Result

    # The system is vulnerable only if none of the checked items are compliant. So loop through all
    # the results and return as soon as one of them is marked as compliant. Note: we could also
    # immediately return after one item is seen as compliant, but this method allows us to have the
    # whole picture, in case we were to transform this into an 'Info' check.
    foreach ($Result in $Results) {
        if ($Result.Compliance -eq $true) {
            return
        }
    }

    $Results | Select-Object -ExcludeProperty Compliance
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
    Description : CoInstallers are enabled (default)
    Compliance  : False
    #>

    [CmdletBinding()] Param()

    $RegKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer"
    $RegValue = "DisableCoInstallers"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
    $Description = $(if ($RegData -ge 1) { "CoInstallers are disabled" } else { "CoInstallers are enabled (default)" })

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $($RegData -ge 1)
    $Result
}