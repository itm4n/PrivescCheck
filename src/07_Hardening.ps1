function Invoke-UacCheck {
    <#
    .SYNOPSIS
    Checks whether UAC (User Access Control) is enabled

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    The state of UAC can be determined based on the value of the parameter "EnableLUA" in the following registry key:
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    0 = Disabled
    1 = Enabled 
    
    .EXAMPLE
    PS C:\> Invoke-UacCheck | fl

    Path      : Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA : 1
    Enabled   : True
    
    .NOTES
    "UAC was formerly known as Limited User Account (LUA)."

    .LINK
    https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-lua-settings-enablelua
    #>
    
    [CmdletBinding()]Param()

    $RegPath = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System"

    $Item = Get-ItemProperty -Path "Registry::$RegPath" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
    if (-not $GetItemPropertyError) {
        $UacResult = New-Object -TypeName PSObject
        $UacResult | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $RegPath
        $UacResult | Add-Member -MemberType "NoteProperty" -Name "EnableLUA" -Value $Item.EnableLUA
        $UacResult | Add-Member -MemberType "NoteProperty" -Name "Enabled" -Value $($Item.EnableLUA -eq 1)
        $UacResult
    }
    else {
        Write-Verbose -Message "Error while querying '$RegPath'"
    }
}

function Invoke-LapsCheck {
    <#
    .SYNOPSIS
    Checks whether LAPS (Local Admin Password Solution) is enabled

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    The status of LAPS can be check using the following registry key: HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd

    .PARAMETER Info
    Report all start-up applications, whether or not the application path is vulnerable.

    .EXAMPLE
    PS C:\> Invoke-LapsCheck

    Key         : HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd
    Value       : AdmPwdEnabled
    Data        :
    Status      : False
    Description : LAPS is not configured
    #>
    
    [CmdletBinding()]Param(
        [switch]
        $Info = $false
    )
    
    $RegPath = "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd"

    $Item = Get-ItemProperty -Path "Registry::$RegPath" -ErrorAction SilentlyContinue

    if ($null -ne $Item) {
        if ($Item.AdmPwdEnabled -eq 1) { $Description = "LAPS is enabled" } else { $Description = "LAPS is disabled" }
    }
    else {
        $Description = "LAPS is not configured"
    }

    $Result = New-Object -TypeName PSObject 
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegPath
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value "AdmPwdEnabled"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $Item.AdmPwdEnabled
    $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value ($Item.AdmPwdEnabled -eq 1)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description

    if ($Info) { $Result; return }

    if ($Result.Status -eq $false) { $Result }
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

    $RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"

    $Item = Get-ItemProperty -Path "Registry::$RegPath" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError 
    if (-not $GetItemPropertyError) {
        # PowerShell Transcription is configured 
        $PowershellTranscriptionResult = New-Object -TypeName PSObject 
        $PowershellTranscriptionResult | Add-Member -MemberType "NoteProperty" -Name "EnableTranscripting" -Value $Item.EnableTranscripting
        $PowershellTranscriptionResult | Add-Member -MemberType "NoteProperty" -Name "EnableInvocationHeader" -Value $Item.EnableInvocationHeader
        $PowershellTranscriptionResult | Add-Member -MemberType "NoteProperty" -Name "OutputDirectory" -Value $Item.OutputDirectory
        $PowershellTranscriptionResult
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

    $Key = "HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus"
    $Value = "BootStatus"
    $Item = Get-ItemProperty -Path "Registry::$($Key)" -Name $Value -ErrorAction SilentlyContinue

    if ($Item -and $Item.$Value -eq 1) { $Description = "BitLocker is enabled" } else { $Description = "BitLocker is not enabled" }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "BitLocker status"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $Key
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $Value
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $Item.$Value
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Description
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

    Name     Status Description
    ----     ------ -----------
    RunAsPPL   True RunAsPPL is enabled
    #>

    [CmdletBinding()] Param(
        [switch]
        $Info = $false
    )

    $LsaProtection = Get-LsaRunAsPPLStatus

    if ($Info) { $LsaProtection; return }

    if ($LsaProtection.Status -eq $false) { $LsaProtection }
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

    Name             Status Description
    ----             ------ -----------
    Credential Guard  False Credential Guard is not configured
    #>

    Get-CredentialGuardStatus
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