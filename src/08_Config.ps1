function Invoke-RegistryAlwaysInstallElevatedCheck {
    <#
    .SYNOPSIS
    Checks whether the AlwaysInstallElevated key is set in the registry.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    AlwaysInstallElevated can be configured in both HKLM and HKCU. "If the AlwaysInstallElevated value is not set to "1" under both of the preceding registry keys, the installer uses elevated privileges to install managed applications and uses the current user's privilege level for unmanaged applications."
    #>
    
    [CmdletBinding()]Param()

    $Result = New-Object -TypeName System.Collections.ArrayList

    $RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer"

    if (Test-Path -Path "Registry::$RegPath" -ErrorAction SilentlyContinue) {

        $HKLMval = Get-ItemProperty -Path "Registry::$RegPath" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
        if ($HKLMval.AlwaysInstallElevated -and ($HKLMval.AlwaysInstallElevated -ne 0)){
            $Item = New-Object -TypeName PSObject -Property @{
                Name                    = $RegPath
                AlwaysInstallElevated   = $HKLMval.AlwaysInstallElevated 
                Enabled                 = $true
            }
            [void]$Result.Add($Item)
        }

        $RegPath = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer"

        if (Test-Path -Path "Registry::$RegPath" -ErrorAction SilentlyContinue) {

            $HKCUval = (Get-ItemProperty -Path "Registry::$RegPath" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
            if ($HKCUval.AlwaysInstallElevated -and ($HKCUval.AlwaysInstallElevated -ne 0)){
                $Item = New-Object -TypeName PSObject -Property @{
                    Name                    = $RegPath
                    AlwaysInstallElevated   = $HKLMval.AlwaysInstallElevated
                    Enabled                 = $true
                }
                [void]$Result.Add($Item)

                $Result
            }
        } 
    }
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

    $WindowsUpdateRegPath = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
    $WindowsUpdateAURegPath = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"

    $WsusKeyServerValue = Get-ItemProperty -Path "Registry::$($WindowsUpdateRegPath)" -Name "WUServer" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItemProperty
    if ($ErrorGetItemProperty) { return }

    $UseWUServerValue = Get-ItemProperty -Path "Registry::$($WindowsUpdateAURegPath)" -Name "UseWUServer" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItemProperty
    if ($ErrorGetItemProperty) { return }

    $SetProxybehaviorForUpdateDetection = Get-ItemProperty -Path "Registry::$($WindowsUpdateRegPath)" -Name "SetProxyBehaviorForUpdateDetection" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItemProperty

    $WusUrl = $WsusKeyServerValue.WUServer
    $WusEnabled = $UseWUServerValue.UseWUServer
    $WsusProxybehavior = $SetProxybehaviorForUpdateDetection.SetProxyBehaviorForUpdateDetection

    if (($WusUrl -like "http://*") -and ($WusEnabled -eq 1)) {

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "WUServer" -Value $WusUrl
        $Result | Add-Member -MemberType "NoteProperty" -Name "UseWUServer" -Value $WusEnabled
        $Result | Add-Member -MemberType "NoteProperty" -Name "SetProxyBehaviorForUpdateDetection" -Value $WsusProxybehavior
        $Result
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
        [switch]
        $Info = $false
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
    
    $SystemPath = (Get-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "Path").Path 
    $Paths = $SystemPath.Split(';')

    foreach ($Path in $Paths) {
        if (-not [String]::IsNullOrEmpty($Path)) {
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
}

function Invoke-PrintNightmareCheck {
    <#
    .SYNOPSIS
    Checks for configurations that are vulnerable to the PrintNightmare exploit.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Fully up-to-date machines are still vulnerable to the PrintNightmare exploit if the "Point and Print Restrictions" Group policy is configured to allow users to install printer drivers or add print servers without administrator privileges. More precisely, if "NoWarningNoElevationOnInstall" or "UpdatePromptSettings" is set to 1, the machine is vulnerable. There is one exception though. If the patch for CVE-2021-34527 was installed, the "RestrictDriverInstallationToAdministrators" parameter can be set to 1 (or a value greater than 1) to override the "Point and Print" settings. In this case, only administrators can install printer drivers or print servers, regardless of the two other values.
    
    .PARAMETER Info
    Use this parameter to report any information about the "Point and Print" configuration, regardless of the vulnerability status.
    
    .EXAMPLE
    PS C:\> Invoke-PrintNightmareCheck

    Path  : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
    Value : NoWarningNoElevationOnInstall
    Data  : 1

    Path  : HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint
    Value : RestrictDriverInstallationToAdministrators
    Data  : 0

    .LINK
    https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
    https://support.microsoft.com/en-us/topic/kb5005010-restricting-installation-of-new-printer-drivers-after-applying-the-july-6-2021-updates-31b91c02-05bc-4ada-a7ea-183b129578a7
    #>

    [CmdletBinding()] Param(
        [switch]
        $Info = $false
    )

    # If the Print Spooler is not installed or is disabled, return immediately
    $Service = Get-ServiceList -FilterLevel 2 | Where-Object { $_.Name -eq "Spooler" }
    if (-not $Service -or ($Service.StartMode -eq "Disabled")) {
        Write-Verbose "The Print Spooler service is not installed or is disabled."
        return
    }

    $Results = @()
    $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"

    # If "NoWarningNoElevationOnInstall" is not set, the default value is 0 (i.e. not vulnerable).
    $Value = "NoWarningNoElevationOnInstall"
    $ItemProptery = Get-ItemProperty -Path "Registry::$($RegKey)" -Name $Value -ErrorAction SilentlyContinue -ErrorVariable GetItemProperty
    if (-not $GetItemProperty) {
        $WarningInstall = New-Object -TypeName PSObject
        $WarningInstall | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $RegKey
        $WarningInstall | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $Value
        $WarningInstall | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $ItemProptery.NoWarningNoElevationOnInstall
        $WarningInstall | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value ($ItemProptery.NoWarningNoElevationOnInstall -ne 0)
        [object[]]$Results += $WarningInstall
    }

    # If "UpdatePromptSettings" is not set, the default value is 0 (i.e. not vulnerable).
    $Value = "UpdatePromptSettings"
    $ItemProptery = Get-ItemProperty -Path "Registry::$($RegKey)" -Name $Value -ErrorAction SilentlyContinue -ErrorVariable GetItemProperty
    if (-not $GetItemProperty) {
        $WarningUpdate = New-Object -TypeName PSObject
        $WarningUpdate | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $RegKey
        $WarningUpdate | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $Value
        $WarningUpdate | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $ItemProptery.UpdatePromptSettings
        $WarningUpdate | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value ($ItemProptery.UpdatePromptSettings -ne 0)
        [object[]]$Results += $WarningUpdate
    }

    # With the patch for CVE-2021-34527, MS added the "RestrictDriverInstallationToAdministrators"
    # setting. If this is set to 1 or any non-zero value then the Point and Print Restrictions Group
    # policy settings (i.e. the two previous registry values) are overridden and only administrators 
    # can install printer drivers on a print server.
    $Value = "RestrictDriverInstallationToAdministrators"
    $ItemProptery = Get-ItemProperty -Path "Registry::$($RegKey)" -Name $Value -ErrorAction SilentlyContinue -ErrorVariable GetItemProperty
    if (-not $GetItemProperty) {
        $RestrictInstall = New-Object -TypeName PSObject
        $RestrictInstall | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $RegKey
        $RestrictInstall | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $Value
        $RestrictInstall | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $ItemProptery.RestrictDriverInstallationToAdministrators
        $RestrictInstall | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value ($ItemProptery.RestrictDriverInstallationToAdministrators -eq 0)
        [object[]]$Results += $RestrictInstall
    }

    if ($Info) { $Results; return }

    # Not vulnerable if:
    #  - RestrictDriverInstallationToAdministrators is set to 1
    #  - NoWarningNoElevationOnInstall or UpdatePromptSettings are not set
    #  - NoWarningNoElevationOnInstall is set to 0
    #  - UpdatePromptSettings is set to 0
    if ($RestrictInstall -and (-not $RestrictInstall.Vulnerable)) { return }
    if (-not $WarningInstall) { return }
    if (-not $WarningUpdate) { return }
    if ((-not $WarningInstall.Vulnerable) -or (-not $WarningUpdate.Vulnerable)) { return }

    $Results | Select-Object -Property Path,Value,Data
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

    [CmdletBinding()]Param()

    $RegPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer"
    $Value = "DisableCoInstallers"

    $Item = Get-ItemProperty -Path "Registry::$RegPath" -Name $Value -ErrorAction SilentlyContinue
    $Description = $(if ($Item.$Value -ge 1) { "CoInstallers are disabled" } else { "CoInstallers are enabled (default)" })

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegPath
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $Value
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $Item.$Value) { "(null)" } else { $Item.$Value })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $($Item.$Value -ge 1)
    $Result
}

function Invoke-HardenedUNCPathCheck {
    <#
    .SYNOPSIS
    Checks whether SYSVOL is a hardened UNC path.

    Author: Adrian Vollmer, SySS GmbH (@mr_mitm)
    License: BSD 3-Clause

    .DESCRIPTION
    If a UNC path to a file share is not hardened, Windows does not check the SMB server's identity when establishing the connection. This allows privilege escalation if the path to SYSVOL is not hardened, because a man-in-the-middle can inject malicious GPOs when group policies are updated.

    A group policy update can be triggered with 'gpupdate /force'. Exploits exist; check Impacket's karmaSMB server. A legit DC must be available at the same time.

    References:
      * https://support.microsoft.com/en-us/topic/ms15-011-vulnerability-in-group-policy-could-allow-remote-code-execution-february-10-2015-91b4bda2-945d-455b-ebbb-01d1ec191328
      * https://github.com/SecureAuthCorp/impacket/blob/master/examples/karmaSMB.py
      * https://www.coresecurity.com/core-labs/articles/ms15-011-microsoft-windows-group-policy-real-exploitation-via-a-smb-mitm-attack
      * https://beyondsecurity.com/scan-pentest-network-vulnerabilities-in-group-policy-allows-code-execution-ms15-011.html

    .EXAMPLE
    Ps C:\> Invoke-HardenedUNCPathCheck

    Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\
    Value       : \\*\SYSVOL
    Data        : RequireMutualAuthentication=0, RequireIntegrity=1
    Description : UNC Path to SYSVOL is NOT hardened
    Compliance  : False
    #>

    [CmdletBinding()]Param()

    $RegPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\"
    $Value = "\\*\SYSVOL"
    $WinOS =  [System.Environment]::OSVersion.Version.Major

    $Item = Get-ItemProperty -Path "Registry::$RegPath" -Name $Value -ErrorAction SilentlyContinue

    if ($WinOS -ge 10) {
        $Compliance = ((-not $Item.$Value -contains "RequireMutualAuthentication=0") -or (-not $Item.$Value -contains "RequireIntegrity=0"))
    } else {
        $Compliance = (($Item.$Value -contains "RequireMutualAuthentication=1") -and ($Item.$Value -contains "RequireIntegrity=1"))
    }

    $Description = $(if ($Compliance) { "UNC Path to SYSVOL is hardened" } else { "UNC Path to SYSVOL is NOT hardened" })

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegPath
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $Value
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $Item.$Value) { "(null)" } else { $Item.$Value })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $Compliance
    $Result
}
