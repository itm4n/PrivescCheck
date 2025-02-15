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

    [CmdletBinding()]
    param(
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

    $CheckResult = New-Object -TypeName PSObject
    $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
    $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevel::None })
    $CheckResult
}

function Invoke-WsusConfigurationCheck {
    <#
    .SYNOPSIS
    Checks whether the WSUS is enabled and vulnerable to MitM attacks.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    A system can be compromised if the updates are not requested using HTTPS but HTTP. If the URL of the update server (WUServer) starts with HTTP and UseWUServer=1, then the update requests are vulnerable to MITM attacks.

    .EXAMPLE
    PS C:\> Invoke-WsusConfigurationCheck

    WUServer                           : http://acme-upd01.corp.internal.com:8535
    UseWUServer                        : 1
    SetProxyBehaviorForUpdateDetection : 1
    DisableWindowsUpdateAccess         : (null)

    .NOTES
    "Beginning with the September 2020 cumulative update, HTTP-based intranet servers will be secure by default. [...] we are no longer allowing HTTP-based intranet servers to leverage user proxy by default to detect updates." The SetProxyBehaviorForUpdateDetection value determines whether this default behavior can be overridden. The default value is 0. If it is set to 1, WSUS can use user proxy settings as a fallback if detection using system proxy fails. See links 1 and 2 below for more details.

    .LINK
    https://techcommunity.microsoft.com/t5/windows-it-pro-blog/changes-to-improve-security-for-windows-devices-scanning-wsus/ba-p/1645547
    https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update#update-setproxybehaviorforupdatedetection
    https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus
    https://github.com/pimps/wsuxploit
    https://github.com/GoSecure/pywsus
    https://github.com/GoSecure/wsuspicious
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $Vulnerable = $true
        $AllResults = @()
    }

    process {
        $RegKey = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
        $RegValue = "WUServer"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ([string]::IsNullOrEmpty($RegData)) { "(null)" } else { $RegData })
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ([string]::IsNullOrEmpty($RegData)) { "No WSUS server is configured (default)." } else { "A WSUS server is configured." })
        $AllResults += $Item

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
        $AllResults += $Item

        if (($null -eq $RegData) -or ($RegData -lt 1)) { $Vulnerable = $false }

        $RegKey = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
        $RegValue = "SetProxyBehaviorForUpdateDetection"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ($RegData -ge 1) { "Fallback to user proxy is enabled." } else { "Proxy fallback not configured (default)." })
        $AllResults += $Item

        $RegKey = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
        $RegValue = "DisableWindowsUpdateAccess"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Item | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $regData) { "(null)" } else { $RegData })
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ($RegData -ge 1) { "Windows Update features are disabled." } else { "Windows Update features are enabled (default)." })
        $AllResults += $Item

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
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

    A group policy update can be triggered with 'gpupdate /force'. Exploits exist; check Impacket karmaSMB server. A legit DC must be available at the same time.

    On Windows >= 10, UNC paths are hardened by default for SYSVOL and NETLOGON so, in this case, we just ensure that mutual authentication and integrity mode were not disabled. On Windows < 10 on the other hand, SYSVOL and NETLOGON UNC paths must be explicitly hardened. Note that this only applies to domain-joined machines.

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

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $Vulnerable = $false
        $AllResults = @()
    }

    process {
        if (-not (Test-IsDomainJoined)) {
            $Description = "The machine is not domain-joined, this check is irrelevant."
            $Results = New-Object -TypeName PSObject
            $Results | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
        }
        else {
            $OsVersionMajor = (Get-WindowsVersionFromRegistry).Major

            $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"

            if ($OsVersionMajor -ge 10) {

                # If Windows >= 10, paths are "hardened" by default. Therefore, the "HardenedPaths" registry
                # key should not contain any value. If it contain values, ensure that protections were not
                # explicitly disabled.

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
                        $AllResults += $Result
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
                        $AllResults += $Result
                    }
                }
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
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

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
        $RegValue = "Path"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue).$RegValue
        $Paths = $RegData.Split(';') | ForEach-Object { $_.Trim() } | Where-Object { -not [String]::IsNullOrEmpty($_) }

        foreach ($Path in $Paths) {
            $ModifiablePaths = Get-ModifiablePath -Path $Path | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
            if ($null -eq $ModifiablePaths) { continue }
            foreach ($ModifiablePath in $ModifiablePaths) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Path
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $ModifiablePath.ModifiablePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $ModifiablePath.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($ModifiablePath.Permissions -join ", ")
                $AllResults += $Result
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Invoke-PointAndPrintConfigurationCheck {
    <#
    .SYNOPSIS
    Checks for configurations that are vulnerable to the PrintNightmare LPE exploit(s).

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Fully up-to-date machines are still vulnerable to the PrintNightmare LPE exploit if the "Point and Print Restrictions" Group policy is configured to allow users to install printer drivers or add print servers without administrator privileges. More precisely, if "NoWarningNoElevationOnInstall" or "UpdatePromptSettings" is set to a value greater or equal to 1, and the installation of printer drivers is not restricted to administrators only, the system is vulnerable.

    .EXAMPLE
    PS C:\> Invoke-PointAndPrintConfigurationCheck

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

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $ConfigVulnerable = $false
        $AllResults = @()
        $Severity = $BaseSeverity
    }

    process {
        # If the Print Spooler is not installed or is disabled, return immediately
        $Service = Get-ServiceFromRegistry -FilterLevel 2 | Where-Object { $_.Name -eq "Spooler" }
        if (($null -eq $Service) -or ($Service.StartMode -eq "Disabled")) {
            Write-Verbose "The Print Spooler service is not installed or is disabled."

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "The Print Spooler service is disabled."
            $AllResults += $Result
        }
        else {
            $Config = Get-PointAndPrintConfiguration

            if ($Config.RestrictDriverInstallationToAdministrators.Data -eq 0) {

                # Printer driver installation is not restricted to administrators, the system
                # is therefore vulnerable. We have yet to determine the severity level though.
                # Indeed, the exploitation technique and complexity depend on the other Point
                # and Print parameters. We can already mark the configuration as vulnerable.

                $ConfigVulnerable = $true
                $Severity = $script:SeverityLevel::Low

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

                # ATTACK: Install a printer driver using an arbitrary DLL
                if (($null -eq $Config.PackagePointAndPrintOnly.Data) -or ($Config.PackagePointAndPrintOnly.Data -eq 0)) {
                    # Non-package aware printer drivers can be installed, we should check the configuration
                    # of the install and update warning prompts.
                    if (($Config.NoWarningNoElevationOnInstall.Data -gt 0) -or ($Config.UpdatePromptSettings.Data -gt 0)) {
                        # At least one of the warning prompts is disabled, the device is vulnerable to CVE-2021-34527
                        # (PrintNightmare), even if the setting "TrustedServers" is set or "InForest" is enabled.
                        $Severity = [Math]::Max([UInt32] $Severity, [UInt32] $script:SeverityLevel::High) -as $script:SeverityLevel
                    }
                }

                # ATTACK: Install and exploit a known vulnerable printer driver
                if (($null -eq $Config.PackagePointAndPrintServerListEnabled.Data) -or ($Config.PackagePointAndPrintServerListEnabled.Data -eq 0)) {
                    # A list of approved servers is not configured, we can exploit the configuration by
                    # setting up a print server hosting a known vulnerable printer driver.
                    $Severity = [Math]::Max([UInt32] $Severity, [UInt32] $script:SeverityLevel::Medium) -as $script:SeverityLevel
                }

                # ATTACK: Install and exploit a known vulnerable printer driver + DNS spoofing
                if ($Config.PackagePointAndPrintServerListEnabled.Data -ge 1) {
                    # A list of approved servers is configured, we can exploit the configuration by setting
                    # up a print server hosting a known vulnerable printer driver, but we will also have to
                    # spoof the name of one of those approved servers.
                    # Note that setting the severity to 'low' here is redundant because we already set it
                    # to 'low' as a "base severity level" when we found that the installation of printer
                    # drivers was not restricted to administrators.
                    $Severity = [Math]::Max([UInt32] $Severity, [UInt32] $script:SeverityLevel::Low) -as $script:SeverityLevel
                }
            }

            $AllResults = @(
                $Config.RestrictDriverInstallationToAdministrators,
                $Config.NoWarningNoElevationOnInstall,
                $Config.UpdatePromptSettings,
                $Config.TrustedServers,
                $Config.InForest,
                $Config.ServerList,
                $Config.PackagePointAndPrintOnly,
                $Config.PackagePointAndPrintServerListEnabled,
                $Config.PackagePointAndPrintServerList
            )

            foreach ($Result in $AllResults) {
                if ($null -eq $Result.Data) { $Result.Data = "(null)" }
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ConfigVulnerable) { $Severity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}

function Invoke-DriverCoInstallerCheck {
    <#
    .SYNOPSIS
    Checks whether the DisableCoInstallers key is set in the registry.

    Author: @itm4n, @SAERXCIT
    License: BSD 3-Clause

    .DESCRIPTION
    The automatic installation as SYSTEM of additional software alongside device drivers can be a vector for privesc, if this software can be manipulated into executing arbitrary code. This can be prevented by setting the DisableCoInstallers key in HKLM. Credit to @wdormann https://twitter.com/wdormann/status/1432703702079508480.

    .EXAMPLE
    Ps C:\> Invoke-DriverCoInstallerCheck

    Key         : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer
    Value       : DisableCoInstallers
    Data        : (null)
    Description : CoInstallers are not disabled (default).
    #>

    [CmdletBinding()]
    param(
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

    $CheckResult = New-Object -TypeName PSObject
    $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
    $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevel::None })
    $CheckResult
}

function Invoke-SccmCacheFolderCheck {
    <#
    .SYNOPSIS
    Get information about SCCM cache folders (incl. number and list of binary, script, and text files).

    Author: @itm4n, @SAERXCIT
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet retrieves a list of SCCM cache folders. For each folder, it also enumerates interesting files (such as binaries, scripts, or various text files).
    #>

    [CmdletBinding()]
    param()

    process {
        $SccmCacheFolders = Get-SccmCacheFolderFromRegistry

        foreach ($SccmCacheFolder in $SccmCacheFolders) {

            if ([string]::IsNullOrEmpty($SccmCacheFolder.Path)) { continue }

            $SccmCacheFiles = Get-SccmCacheFile -Path $SccmCacheFolder.Path

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

function Invoke-ProxyAutoConfigurationCheck {
    <#
    .SYNOPSIS
    Check whether Web Proxy Auto-Discovery (WPAD) is enabled, and whether a Proxy Auto-Configuration (PAC) file is distributed over HTTPS.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet checks various mitigation measures that allow the disabling of WPAD. It also enumerates PAC URLs to check whether they use the HTTPS protocol.

    .LINK
    https://projectblack.io/blog/disable-wpad-via-gpo/
    https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-http-proxy-auth-features#how-to-disable-wpad
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $HostFilePath = Join-Path -Path $env:windir -ChildPath "System32\drivers\etc\hosts"

        $WinHttpAutoProxyServiceEnabledDescriptions = @(
            "The WinHTTP Web Proxy Auto-Discovery service is disabled.",
            "The WinHTTP Web Proxy Auto-Discovery service is not disabled."
        )

        $WpadHostEntryExistsDescriptions = @(
            "No 'wpad' entry was found in the 'hosts' file.",
            "A 'wpad' entry was found in the 'hosts' file."
        )

        $DisableWpadDescriptions = @(
            "WPAD is not disabled in the registry (HKLM).",
            "WPAD is disabled in the registry (HKLM)."
        )

        $AutoDetectDisabledDescriptions = @(
            "Proxy auto detection is not disabled in the registry (HKCU).",
            "Proxy auto detection is disabled in the registry (HKCU)."
        )
    }

    process {
        # Assume the configuration is vulnerable. We will check the different
        # remediation measures, and mark the configuration as "not vulnerable" as soon
        # as we find one implemented.
        $WpadVulnerable = $true
        $PacUrlVulnerable = $false

        # Is the service 'WinHttpAutoProxySvc' disabled?
        $WinHttpAutoProxyService = Get-ServiceFromRegistry -FilterLevel 2 | Where-Object { $_.Name -eq "WinHttpAutoProxySvc" }
        $WinHttpAutoProxyServiceEnabled = $WinHttpAutoProxyService.StartMode -ne "Disabled"
        if ($WpadVulnerable -and (-not $WinHttpAutoProxyServiceEnabled)) { $WpadVulnerable = $false }

        # Is there a "WPAD" entry in the "hosts" file, we don't care about the value,
        # but we should ensure the entry is not commented if one exists.
        $WpadHostEntries = Select-String -Pattern "wpad" -Path $HostFilePath | Where-Object { $_.Line -notmatch "^\s*#.*$" }
        $WpadHostEntryExists = $null -ne $WpadHostEntries
        if ($WpadVulnerable -and ($WpadHostEntryExists)) { $WpadVulnerable = $false }

        # Check if the following registry values are configured.
        $DisableWpadRegKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
        $DisableWpadRegValue = "DisableWpad"
        $DisableWpadRegData = (Get-ItemProperty -Path "Registry::$($DisableWpadRegKey)" -Name $DisableWpadRegValue -ErrorAction SilentlyContinue).$DisableWpadRegValue
        $WpadDisabled = $DisableWpadRegData -eq 1

        $AutoDetectRegKey = "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
        $AutoDetectRegValue = "AutoDetect"
        $AutoDetectRegData = (Get-ItemProperty -Path "Registry::$($AutoDetectRegKey)" -Name $AutoDetectRegValue -ErrorAction SilentlyContinue).$AutoDetectRegValue
        $AutoDetectDisabled = $AutoDetectRegData -eq 0
        if ($WpadVulnerable -and ($WpadDisabled -and $AutoDetectDisabled)) { $WpadVulnerable = $false }

        # Check if an PAC URL is configure in the machine
        $MachineAutoConfigUrlRegKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
        $MachineAutoConfigUrlRegValue = "AutoConfigURL"
        $MachineAutoConfigUrlRegData = (Get-ItemProperty -Path "Registry::$($MachineAutoConfigUrlRegKey)" -Name $MachineAutoConfigUrlRegValue -ErrorAction SilentlyContinue).$MachineAutoConfigUrlRegValue
        if ((-not $PacUrlVulnerable) -and ($MachineAutoConfigUrlRegData -like "http://*")) { $PacUrlVulnerable = $true }

        $UserAutoConfigUrlRegKey = "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings"
        $UserAutoConfigUrlRegValue = "AutoConfigURL"
        $UserAutoConfigUrlRegData = (Get-ItemProperty -Path "Registry::$($UserAutoConfigUrlRegKey)" -Name $UserAutoConfigUrlRegValue -ErrorAction SilentlyContinue).$UserAutoConfigUrlRegValue
        if ((-not $PacUrlVulnerable) -and ($UserAutoConfigUrlRegData -like "http://*")) { $PacUrlVulnerable = $true }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "WinHttpAutoProxyServiceStartMode" -Value $WinHttpAutoProxyService.StartMode
        $Result | Add-Member -MemberType "NoteProperty" -Name "WinHttpAutoProxyServiceEnabled" -Value $WinHttpAutoProxyServiceEnabled
        $Result | Add-Member -MemberType "NoteProperty" -Name "WinHttpAutoProxyServiceDescription" -Value $WinHttpAutoProxyServiceEnabledDescriptions[[UInt32]$WinHttpAutoProxyServiceEnabled]

        $Result | Add-Member -MemberType "NoteProperty" -Name "WpadHostEntry" -Value $(if ($WpadHostEntryExists) { $WpadHostEntries[0].Line } else { "(null)" })
        $Result | Add-Member -MemberType "NoteProperty" -Name "WpadHostEntryExists" -Value $WpadHostEntryExists
        $Result | Add-Member -MemberType "NoteProperty" -Name "WpadHostEntryDescription" -Value $WpadHostEntryExistsDescriptions[[UInt32]$WpadHostEntryExists]

        $Result | Add-Member -MemberType "NoteProperty" -Name "DisableWpadKey" -Value $DisableWpadRegKey
        $Result | Add-Member -MemberType "NoteProperty" -Name "DisableWpadValue" -Value $DisableWpadRegValue
        $Result | Add-Member -MemberType "NoteProperty" -Name "DisableWpadData" -Value $(if ($null -ne $DisableWpadRegData) { $DisableWpadRegData } else { "(null)" })
        $Result | Add-Member -MemberType "NoteProperty" -Name "DisableWpadDescription" -Value $DisableWpadDescriptions[[UInt32]$WpadDisabled]

        $Result | Add-Member -MemberType "NoteProperty" -Name "AutoDetectKey" -Value $AutoDetectRegKey
        $Result | Add-Member -MemberType "NoteProperty" -Name "AutoDetectValue" -Value $AutoDetectRegValue
        $Result | Add-Member -MemberType "NoteProperty" -Name "AutoDetectData" -Value $(if ($null -ne $AutoDetectRegData) { $AutoDetectRegData } else { "(null)" })
        $Result | Add-Member -MemberType "NoteProperty" -Name "AutoDetectDescription" -Value $AutoDetectDisabledDescriptions[[UInt32]$AutoDetectDisabled]

        $Result | Add-Member -MemberType "NoteProperty" -Name "AutoConfigUrlMachineKey" -Value $MachineAutoConfigUrlRegKey
        $Result | Add-Member -MemberType "NoteProperty" -Name "AutoConfigUrlMachineValue" -Value $MachineAutoConfigUrlRegValue
        $Result | Add-Member -MemberType "NoteProperty" -Name "AutoConfigUrlMachineData" -Value $(if ($null -ne $MachineAutoConfigUrlRegData) { $MachineAutoConfigUrlRegData } else { "(null)" })

        $Result | Add-Member -MemberType "NoteProperty" -Name "AutoConfigUrlUserKey" -Value $UserAutoConfigUrlRegKey
        $Result | Add-Member -MemberType "NoteProperty" -Name "AutoConfigUrlUserValue" -Value $UserAutoConfigUrlRegValue
        $Result | Add-Member -MemberType "NoteProperty" -Name "AutoConfigUrlUserData" -Value $(if ($null -ne $UserAutoConfigUrlRegData) { $UserAutoConfigUrlRegData } else { "(null)" })

        $Vulnerable = $WpadVulnerable -or $PacUrlVulnerable

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Result
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}

function Invoke-DefenderExclusionCheck {
    <#
    .SYNOPSIS
    List Microsoft Defender exclusions.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This check was inspired by a tweet from @splinter_code (see notes), mentioning the fact that Defender's exclusions can be listed as a low privileged user through the registry. This information is indeed stored in two registry keys (local and GPO) that are configured with a DACL that allows "Everyone" to read them. However, in some versions of Windows 10/11, the DACL is reportedly configured differently and would thus not grant read access for low-priv users. This check was then extended with a technique from @VakninHai, which consists in reading event log messages (with ID 5007) to identify modifications in the exclusions.

    .EXAMPLE
    PS C:\> Invoke-DefenderExclusionCheck

    Source   Type      Value
    ------   ----      -----
    EventLog Path      C:\Program Files\7-Zip\7zFM.exe
    EventLog Process   evil.exe
    EventLog Extension scr
    EventLog Path      C:\tools\OleViewDotNet\OleViewDotNet.exe
    EventLog Path      C:\tools
    #>

    [CmdletBinding()]
    param()

    process {
        $Exclusions = @()
        $Exclusions += Get-WindowsDefenderExclusion -Source Registry
        $Exclusions += Get-WindowsDefenderExclusion -Source EventLog
        $Exclusions
    }
}

function Invoke-SmbConfigurationCheck {
    <#
    .SYNOPSIS
    Check the SMB server and client configurations.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet checks whether SMBv1 is enabled on server side, and whether signing is required on both server and client sides.

    .LINK
    https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing
    https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3?tabs=server
    https://medium.com/tenable-techblog/smb-access-is-denied-caused-by-anti-ntlm-relay-protection-659c60089895
    https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/microsoft-network-server-server-spn-target-name-validation-level
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()

        $EnableSMB1ProtocolDescriptions = @(
            "The SMB1 protocol is disabled.",
            "The SMB1 protocol is enabled."
        )

        $RequireSecuritySignatureDescriptions = @(
            "Security signature (SMB signing) is not required.",
            "Security signature (SMB signing) is required."
        )

        $SmbServerNameHardeningLevelDescriptions = @(
            "Off (default). An SPN does not need to be sent by the SMB client. It is not required or validated by the SMB server.",
            "Accept if provided by client. If an SPN name is sent by the SMB client, it must match the SMB server's list of SPNs, otherwise the access is denied."
            "Required from client. An SPN must be sent by the SMB client in session setup, and it must match the SMB server's list of SPNs, otherwise the access is denied."
        )

        $ServerConfiguration = Get-SmbConfiguration -Role "Server"
        $ClientConfiguration = Get-SmbConfiguration -Role "Client"
    }

    process {

        $Vulnerable = $false

        # Server - SMBv1 should not be enabled

        if ($ServerConfiguration.EnableSMB1Protocol -ne $false) { $Vulnerable = $true }

        $ServerVersion = New-Object -TypeName PSObject
        $ServerVersion | Add-Member -MemberType "NoteProperty" -Name "Role" -Value "Server"
        $ServerVersion | Add-Member -MemberType "NoteProperty" -Name "Parameter" -Value "EnableSMB1Protocol"
        $ServerVersion | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $ServerConfiguration.EnableSMB1Protocol
        $ServerVersion | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "<False>"
        $ServerVersion | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $($EnableSMB1ProtocolDescriptions[$($ServerConfiguration.EnableSMB1Protocol -as [UInt32])])
        $AllResults += $ServerVersion

        # Server - SMB signing should be set to 'required'

        if ($ServerConfiguration.RequireSecuritySignature -ne $true) { $Vulnerable = $true }

        $ServerSigning = New-Object -TypeName PSObject
        $ServerSigning | Add-Member -MemberType "NoteProperty" -Name "Role" -Value "Server"
        $ServerSigning | Add-Member -MemberType "NoteProperty" -Name "Parameter" -Value "RequireSecuritySignature"
        $ServerSigning | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $ServerConfiguration.RequireSecuritySignature
        $ServerSigning | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "<True>"
        $ServerSigning | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $($RequireSecuritySignatureDescriptions[$($ServerConfiguration.RequireSecuritySignature -as [UInt32])])
        $AllResults += $ServerSigning

        # Server - Server SPN target name validation should be enabled
        # This setting is recommended only as a workaround for cases where SMB signing
        # cannot be enforced. If SMB signing in enforced, this setting is irrelevant.

        if (($ServerConfiguration.SmbServerNameHardeningLevel -eq 0) -and ($ServerConfiguration.RequireSecuritySignature -ne $true)) { $Vulnerable = $true }

        $ServerNameHardeningLevel = New-Object -TypeName PSObject
        $ServerNameHardeningLevel | Add-Member -MemberType "NoteProperty" -Name "Role" -Value "Server"
        $ServerNameHardeningLevel | Add-Member -MemberType "NoteProperty" -Name "Parameter" -Value "SmbServerNameHardeningLevel"
        $ServerNameHardeningLevel | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $ServerConfiguration.SmbServerNameHardeningLevel
        $ServerNameHardeningLevel | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "<1|2>"
        $ServerNameHardeningLevel | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $SmbServerNameHardeningLevelDescriptions[$ServerConfiguration.SmbServerNameHardeningLevel]
        $AllResults += $ServerNameHardeningLevel

        # Client - SMB signing should be set to 'required'

        if ($ClientConfiguration.RequireSecuritySignature -ne $true) { $Vulnerable = $true }

        $ClientSigning = New-Object -TypeName PSObject
        $ClientSigning | Add-Member -MemberType "NoteProperty" -Name "Role" -Value "Client"
        $ClientSigning | Add-Member -MemberType "NoteProperty" -Name "Parameter" -Value "RequireSecuritySignature"
        $ClientSigning | Add-Member -MemberType "NoteProperty" -Name "Value" -Value  $ClientConfiguration.RequireSecuritySignature
        $ClientSigning | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value "<True>"
        $ClientSigning | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $($RequireSecuritySignatureDescriptions[$($ClientConfiguration.RequireSecuritySignature -as [UInt32])])
        $AllResults += $ClientSigning

        # Final result

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}

function Invoke-ComServerRegistryPermissionCheck {
    <#
    .SYNOPSIS
    Check whether the current user has any modification rights on a COM class in the registry.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet checks the permissions of each registered COM class in the registry to determine if the current user can modify them. It should be noted that, if so, this may not necessarily result in a privilege escalation because the COM class could be instantiated in a process running as the current user instead of SYSTEM, or any other privileged account. This check is inspired from a writeup about CVE-2023-51715 (see LINK section).

    .LINK
    https://herolab.usd.de/security-advisories/usd-2023-0029/
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
    }

    process {
        Get-ComClassFromRegistry |
            Where-Object { ($_.Value -like "*server*") -and ($null -ne $_.Path) } |
                Invoke-CommandMultithread -InitialSessionState $(Get-InitialSessionState) -Command "Get-ModifiableComClassEntryRegistryPath" -InputParameter "ComClassEntry" |
                    ForEach-Object { $AllResults += $_ }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults.Count -gt 0) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}

function Invoke-ComServerImagePermissionCheck {
    <#
    .SYNOPSIS
    Check whether the current user has any modification rights on a COM server module file.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet checks the file permissions of each COM class module, and determines whether the current user has any modification rights. It should be noted that, if so, this may not necessarily result in a privilege escalation because the COM class could be instantiated in a process running as the current user instead of SYSTEM, or any other privileged account.
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
        # Create a synchronized list that we will use to store file paths which were
        # tested and are not vulnerable. This list will be populated by the threads,
        # hence why we need to use thread-safe collection object.
        $AlreadyCheckedPaths = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    }

    process {
        Get-ComClassFromRegistry |
            Where-Object { ($_.Value -like "*server*") -and ($null -ne $_.Path) -and ($null -ne $_.Data) } |
                Invoke-CommandMultithread -InitialSessionState $(Get-InitialSessionState) -Command "Get-ModifiableComClassEntryImagePath" -InputParameter "ComClassEntry" -OptionalParameter @{ "CheckedPaths" = $AlreadyCheckedPaths } |
                    ForEach-Object { $AllResults += $_ }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults.Count -gt 0) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}

function Invoke-ComServerGhostDllHijackingCheck {
    <#
    .SYNOPSIS
    Check whether there are COM servers registered with a non-existent module using a relative path.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet checks registered COM servers to identify modules using a relative path to a non-existent file. This could result in ghost DLL hijacking.
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
        $AlreadyChecked = @()
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        $RegisteredClasses = Get-ComClassFromRegistry | Where-Object { ($_.Value -like "*server*") -and ($null -ne $_.Data) }

        foreach ($RegisteredClass in $RegisteredClasses) {

            $CandidatePaths = @()

            switch ($RegisteredClass.DataType) {
                "FileName" {
                    $CandidatePaths += [System.Environment]::ExpandEnvironmentVariables($RegisteredClass.Data).Trim('"')
                }
                "CommandLine" {
                    $CommandLineResolved = [string[]] (Resolve-CommandLine -CommandLine $RegisteredClass.Data)
                    if ($null -eq $CommandLineResolved) { continue }

                    $CandidatePaths += $CommandLineResolved[0]

                    if (($CommandLineResolved[0] -match ".*rundll32(\.exe)?`$") -and ($CommandLineResolved.Count -gt 1) -and ($CommandLineResolved[1] -like "*.dll,*")) {
                        $PathToAnalyze = $CommandLineResolved[1].Split(',')[0]
                        if ([System.IO.Path]::IsPathRooted($PathToAnalyze)) {
                            $CandidatePaths += $PathToAnalyze
                        }
                        else {
                            Resolve-ModulePath -Name $PathToAnalyze | ForEach-Object { $CandidatePaths += $_ }
                        }
                    }
                }
            }

            foreach ($CandidatePath in $CandidatePaths) {

                if ($AlreadyChecked -contains $CandidatePath) { continue }
                if ([System.IO.Path]::IsPathRooted($CandidatePath)) { $AlreadyChecked += $CandidatePath; continue }

                $ResolvedPath = Resolve-ModulePath -Name $CandidatePath

                if ($null -ne $ResolvedPath) { $AlreadyChecked += $CandidatePath; continue }

                $AllResults += $RegisteredClass
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults.Count -gt 0) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Invoke-ComServerMissingModuleFileCheck {
    <#
    .SYNOPSIS
    Check whether there are leftover COM servers registered with non-existent modules.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet enumerates registered COM servers and checks whether their module file path points to an existing file. It should be noted that it does not check for file permissions. Such issue is already reported by 'Invoke-ComServerImagePermissionCheck', which checks the permissions of parent folders in case the target file doesn't exist.
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
        $AlreadyChecked = @()
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        $RegisteredClasses = Get-ComClassFromRegistry | Where-Object { ($_.Value -like "*server*") -and ($null -ne $_.Path) -and ($null -ne $_.Data) }

        foreach ($RegisteredClass in $RegisteredClasses) {

            $CandidatePaths = @()

            switch ($RegisteredClass.DataType) {
                "FilePath" {
                    $CandidatePaths += [System.Environment]::ExpandEnvironmentVariables($RegisteredClass.Data).Trim('"')
                }
                "CommandLine" {
                    $CommandLineResolved = [string[]] (Resolve-CommandLine -CommandLine $RegisteredClass.Data)
                    if ($null -eq $CommandLineResolved) { continue }

                    $CandidatePaths += $CommandLineResolved[0]

                    if (($CommandLineResolved[0] -match ".*rundll32(\.exe)?`$") -and ($CommandLineResolved.Count -gt 1) -and ($CommandLineResolved[1] -like "*.dll,*")) {
                        $PathToAnalyze = $CommandLineResolved[1].Split(',')[0]
                        if ([System.IO.Path]::IsPathRooted($PathToAnalyze)) {
                            $CandidatePaths += $PathToAnalyze
                        }
                        else {
                            Resolve-ModulePath -Name $PathToAnalyze | ForEach-Object { $CandidatePaths += $_ }
                        }
                    }
                }
            }

            $MissingFiles = @()

            foreach ($CandidatePath in $CandidatePaths) {

                if ($AlreadyChecked -contains $CandidatePath) { continue }

                if ([System.IO.Path]::IsPathRooted($CandidatePath)) {
                    if (Test-Path -LiteralPath $CandidatePath -ErrorAction SilentlyContinue) {
                        $AlreadyChecked += $CandidatePath
                        continue
                    }
                    $MissingFiles += $CandidatePath
                }
                else {
                    $ResolvedPath = Resolve-ModulePath -Name $CandidatePath
                    if ($null -ne $ResolvedPath) {
                        $AlreadyChecked += $CandidatePath
                        continue
                    }
                    $MissingFiles += $CandidatePath
                }
            }

            if ($MissingFiles.Count -gt 0) {
                $AllResults += $RegisteredClass
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults.Count -gt 0) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Invoke-MsiAutomaticRepairUacPromptCheck {
    <#
    .SYNOPSIS
    Check whether the UAC prompt displayed when attempting an application repair through the Windows Installer was disabled.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Starting from September, 2024, Windows Installer prompts for elevation when attempting a repair of an application by default. This behavior can be disabled by setting the registry value 'DisableLUAInRepair', under 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer' to '1', in which case the legacy behavior would be restored, and the system potentially made vulnerable to local privilege escalation because of unsafe MSI Custom Actions for instance.

    .LINK
    https://support.microsoft.com/en-au/topic/september-10-2024-kb5043080-os-build-26100-1742-407666c8-6b6d-4561-a982-abce4e7c2efb
    https://sec-consult.com/blog/detail/msi-installer-repair-to-system-a-detailed-journey/
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer"
        $RegValue = "DisableLUAInRepair"

        $DisableLUAInRepairDescriptions = @(
            "The User Account Control (UAC) prompts for credentials before initiating an application repair.",
            "The User Account Control (UAC) does not prompt for credentials before initiating an application repair."
        )
    }

    process {
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        $Vulnerable = $RegData -ge 1

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
        $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $DisableLUAInRepairDescriptions[[UInt32]$Vulnerable]

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Result
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}

function Invoke-CredentialDelegationCheck {
    <#
    .SYNOPSIS
    Check whether Credential Delegation is enabled. If so, passwords are very likely to be stored in clear-text in memory.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet retrieves information relative to Credential Delegation from the registry. If one of the "Allow" policies was enabled, the configuration is considered vulnerable. Indeed, if credential delegation is enabled, LSASS stores a clear-text version of a user's password so that it can automatically sends it to a remote server, which means that it is stored in memory. More information about this configuration can be found in the references (see LINK section).

    .EXAMPLE
    PS C:\> Invoke-CredentialDelegationCheck

    Policy              : Allow delegating default credentials with NTLM-only server authentication
    Setting             : AllowDefCredentialsWhenNTLMOnly
    Enabled             : True
    ConcatenateDefaults : True
    Services            : TERMSRV/*

    Policy              : Allow delegating default credentials
    Setting             : AllowDefaultCredentials
    Enabled             : False
    ConcatenateDefaults : False
    Services            : (null)

    Policy              : Deny delegating default credentials
    Setting             : DenyDefaultCredentials
    Enabled             : False
    ConcatenateDefaults : False
    Services            : (null)

    .LINK
    https://clement.notin.org/blog/2019/07/03/credential-theft-without-admin-or-touching-lsass-with-kekeo-by-abusing-credssp-tspkg-rdp-sso/
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $RootKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
        $CredentialDelegationSettings = @(
            @(
                "Allow delegating default credentials with NTLM-only server authentication",
                "AllowDefCredentialsWhenNTLMOnly",
                "ConcatenateDefaults_AllowDefNTLMOnly"
            ),
            @(
                "Allow delegating default credentials",
                "AllowDefaultCredentials",
                "ConcatenateDefaults_AllowDefault"
            ),
            @(
                "Deny delegating default credentials",
                "DenyDefaultCredentials",
                "ConcatenateDefaults_DenyDefault"
            )
        )
    }

    process {
        $AllResults = @()

        foreach ($Setting in $CredentialDelegationSettings) {

            $Policy = $Setting[0]
            $SettingName = $Setting[1]
            $SettingDefaultName = $Setting[2]

            $SettingEnabled = (Get-ItemProperty -Path "Registry::$($RootKey)" -Name $SettingName -ErrorAction SilentlyContinue).$SettingName
            $ConcatenateDefaults = (Get-ItemProperty -Path "Registry::$($RootKey)" -Name $SettingDefaultName -ErrorAction SilentlyContinue).$SettingDefaultName

            $ServiceKey = Join-Path -Path $RootKey -ChildPath $SettingName
            $ServiceData = (Get-Item -Path "Registry::$($ServiceKey)" -ErrorAction SilentlyContinue).Property | ForEach-Object {
                (Get-ItemProperty -Path "Registry::$($ServiceKey)" -Name $_ -ErrorAction SilentlyContinue).$_
            }

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value $Policy
            $Result | Add-Member -MemberType "NoteProperty" -Name "Setting" -Value $SettingName
            $Result | Add-Member -MemberType "NoteProperty" -Name "Enabled" -Value ([Bool] $SettingEnabled)
            $Result | Add-Member -MemberType "NoteProperty" -Name "ConcatenateDefaults" -Value ([Bool] $ConcatenateDefaults)
            $Result | Add-Member -MemberType "NoteProperty" -Name "Services" -Value $(if ($null -ne $ServiceData) { $ServiceData -join ", " } else { "(null)" })
            $AllResults += $Result
        }

        $Vulnerable = $null -ne ($AllResults | Where-Object { $_.Enabled -and ($_.Setting -like "Allow*") })

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}