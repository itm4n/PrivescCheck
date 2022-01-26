function Invoke-UacCheck {
    <#
    .SYNOPSIS
    Checks whether UAC (User Access Control) is enabled

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    The state of UAC can be determined based on the value of the parameter "EnableLUA" in the following registry key:
    HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System
    0 = Disabled
    1 = Enabled 
    
    .EXAMPLE
    PS C:\> Invoke-UacCheck | fl

    Key         : HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System
    Value       : EnableLUA
    Data        : 1
    Description : UAC is enabled
    Compliance  : True
    
    .NOTES
    "UAC was formerly known as Limited User Account (LUA)."

    .LINK
    https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-lua-settings-enablelua
    #>
    
    [CmdletBinding()]Param()

    $RegPath = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $Value = "EnableLUA"

    $Item = Get-ItemProperty -Path "Registry::$RegPath" -Name $Value -ErrorAction SilentlyContinue
    $Description = $(if ($Item.$Value -ge 1) { "UAC is enabled" } else { "UAC is disabled" })

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegPath
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $Value
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $Item.$Value) { "(null)" } else { $Item.$Value })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $($Item.$Value -ge 1)
    $Result
}

function Invoke-LapsCheck {
    <#
    .SYNOPSIS
    Checks whether LAPS (Local Admin Password Solution) is enabled

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    The status of LAPS can be check using the following registry key: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd

    .EXAMPLE
    PS C:\> Invoke-LapsCheck

    Key         : HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd
    Value       : AdmPwdEnabled
    Data        : (null)
    Description : LAPS is not configured
    Compliance  : False
    #>
    
    [CmdletBinding()]Param()

    $RegPath = "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd"
    $Value = "AdmPwdEnabled"

    $Item = Get-ItemProperty -Path "Registry::$RegPath" -Name $Value -ErrorAction SilentlyContinue

    if ($null -eq $Item) {
        $Description = "LAPS is not configured"
    }
    else {
        $Description = $(if ($Item.$Value -ge 1) { "LAPS is enabled" } else { "LAPS is disabled" })
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegPath
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $Value
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $Item.$Value) { "(null)" } else { $Item.$Value })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $($Item.$Value -ge 1)
    $Result
}

function Invoke-PowershellTranscriptionCheck {
    <#
    .SYNOPSIS
    Checks whether PowerShell Transcription is configured/enabled

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Powershell Transcription is used to log PowerShell scripts execution. It can be configured thanks to the Group Policy Editor. The settings are stored in the following registry key: HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
    
    .EXAMPLE
    PS C:\> Invoke-PowershellTranscriptionCheck | fl

    EnableTranscripting    : 1
    EnableInvocationHeader : 1
    OutputDirectory        : C:\Transcripts
    
    .NOTES
    If PowerShell Transcription is configured, the settings can be found here:

    C:\>reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription

    HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
        EnableTranscripting    REG_DWORD    0x1
        OutputDirectory    REG_SZ    C:\Transcripts
        EnableInvocationHeader    REG_DWORD    0x1
    
    To enable PowerShell Transcription:
    Group Policy Editor > Administrative Templates > Windows Components > Windows PowerShell > PowerShell Transcription
    Set an output directory and set the policy as Enabled
    #>
    
    [CmdletBinding()]Param()

    $RegPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"

    $Item = Get-ItemProperty -Path "Registry::$RegPath" -ErrorAction SilentlyContinue
    
    if ($Item) {
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "EnableTranscripting" -Value $(if ($null -eq $Item.EnableTranscripting) { "(null)" } else { $Item.EnableTranscripting })
        $Result | Add-Member -MemberType "NoteProperty" -Name "EnableInvocationHeader" -Value $(if ($null -eq $Item.EnableInvocationHeader) { "(null)" } else { $Item.EnableInvocationHeader })
        $Result | Add-Member -MemberType "NoteProperty" -Name "OutputDirectory" -Value $(if ($null -eq $Item.OutputDirectory) { "(null)" } else { $Item.OutputDirectory })
        $Result
    }
}

function Invoke-BitlockerCheck {
    <#
    .SYNOPSIS
    Checks whether BitLocker is enabled.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    When BitLocker is enabled on the system drive, the value "BootStatus" is set to 1 in the following registry key: 'HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus'.
    
    .EXAMPLE
    PS C:\> Invoke-BitlockerCheck

    Description : Enable BitLocker drive encryption
    Key         : HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus
    Value       : BootStatus
    Data        : 0
    Result      : BitLocker is not enabled
    #>

    [CmdletBinding()]Param()

    $MachineRole = Invoke-MachineRoleCheck
    if ($MachineRole.Name -notlike "WinNT") { continue }

    $RegPath = "HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus"
    $Value = "BootStatus"

    $Item = Get-ItemProperty -Path "Registry::$($Key)" -Name $Value -ErrorAction SilentlyContinue

    if ($null -eq $Item) {
        $Description = "BitLocker is not configured"
    }
    else {
        $Description = $(if ($Item.$Value -ge 1) { "BitLocker is enabled" } else { "BitLocker is disabled" })
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegPath
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $Value
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $Item.$Value) { "(null)" } else { $Item.$Value })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $($Item.$Value -ge 1)
    $Result
}

function Invoke-LsaProtectionCheck {
    <#
    .SYNOPSIS
    Checks whether LSA protection is supported and enabled

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Invokes the helper function Get-LsaRunAsPPLStatus
    
    .EXAMPLE
    PS C:\> Invoke-LsaProtectionCheck

    Path        : HKLM\SYSTEM\CurrentControlSet\Control\Lsa
    Value       : RunAsPPL
    Data        : (null)
    Description : RunAsPPL is either not configured or disabled
    Compliance  : False
    #>

    [CmdletBinding()] Param()

    $OsVersion = Get-WindowsVersion

    $RegPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    $Value = "RunAsPPL"
    $Item = Get-ItemProperty -Path "Registry::$($RegPath)" -Name $Value -ErrorAction SilentlyContinue

    $Description = $(if ($Item.$Value -ge 1) { "RunAsPPL is enabled" } else { "RunAsPPL is not enabled" })

    # If < Windows 8.1 / 2012 R2
    if (-not ($OsVersion.Major -ge 10 -or (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 3)))) {
        $Description = "RunAsPPL is not supported on this OS"
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegPath
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $Value
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $Item.$Value) { "(null)" } else { $Item.$Value })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $($Item.$Value -ge 1)
    $Result
}

function Invoke-CredentialGuardCheck {
    <#
    .SYNOPSIS
    Checks whether Credential Guard is supported and enabled

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Invokes the helper function Get-CredentialGuardStatus

    .EXAMPLE
    PS C:\> Invoke-CredentialGuardCheck

    Name                                  : Credential Guard
    DeviceGuardSecurityServicesConfigured : (null)
    DeviceGuardSecurityServicesRunning    : (null)
    Description                           : Credential Guard is not configured
    Compliance                            : False
    #>

    [CmdletBinding()]Param()

    $OsVersion = Get-WindowsVersion

    if ($OsVersion.Major -ge 10) {

        if ((($PSVersionTable.PSVersion.Major -eq 5) -and ($PSVersionTable.PSVersion.Minor -ge 1)) -or ($PSVersionTable.PSVersion.Major -gt 5)) {

            $DeviceGuardSecurityServicesConfigured = (Get-ComputerInfo).DeviceGuardSecurityServicesConfigured
            if ($DeviceGuardSecurityServicesConfigured -match 'CredentialGuard') {

                $Compliance = $false
                $Description = "Credential Guard is configured but is not running"
    
                $DeviceGuardSecurityServicesRunning = (Get-ComputerInfo).DeviceGuardSecurityServicesRunning
                if ($DeviceGuardSecurityServicesRunning -match 'CredentialGuard') {
                    $Compliance = $true
                    $Description = "Credential Guard is configured and running"
                }
            }
            else {
                $Compliance = $false
                $Description = "Credential Guard is not configured"
            }
        }
        else {
            $Compliance = $false
            $Description = "Check failed: Incompatible PS version"
        }
    }
    else {
        $Compliance = $false
        $Description = "Credential Guard is not supported on this OS"
    }
    
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "Credential Guard"
    $Result | Add-Member -MemberType "NoteProperty" -Name "DeviceGuardSecurityServicesConfigured" -Value $(if ($null -eq $DeviceGuardSecurityServicesConfigured) { "(null)" } else { $DeviceGuardSecurityServicesConfigured })
    $Result | Add-Member -MemberType "NoteProperty" -Name "DeviceGuardSecurityServicesRunning" -Value $(if ($null -eq $DeviceGuardSecurityServicesRunning) { "(null)" } else { $DeviceGuardSecurityServicesConfigured })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $Compliance
    $Result
}

function Invoke-BiosModeCheck {
    <#
    .SYNOPSIS
    Checks whether UEFI and Secure are supported and enabled

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Invokes the helper functions Get-UEFIStatus and Get-SecureBootStatus
    
    .EXAMPLE
    PS C:\> Invoke-BiosModeCheck

    Name        Status Description
    ----        ------ -----------
    UEFI          True BIOS mode is UEFI
    Secure Boot  False Secure Boot is disabled
    #>

    Get-UEFIStatus
    Get-SecureBootStatus
}