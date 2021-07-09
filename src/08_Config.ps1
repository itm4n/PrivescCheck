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