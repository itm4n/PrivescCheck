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
    #>
    
    [CmdletBinding()]Param()
    
    $RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd"

    $Item = Get-ItemProperty -Path "Registry::$RegPath" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError 
    if (-not $GetItemPropertyError) {
        $LapsResult = New-Object -TypeName PSObject 
        $LapsResult | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $RegPath
        $LapsResult | Add-Member -MemberType "NoteProperty" -Name "AdmPwdEnabled" -Value $Item.AdmPwdEnabled
        $LapsResult | Add-Member -MemberType "NoteProperty" -Name "Enabled" -Value $($Item.AdmPwdEnabled -eq 1)
        $LapsResult
    }
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
    Checks whether BitLocker is enabled (workstations only).
    
    .DESCRIPTION
    When BitLocker is enabled on the system drive, the value "BootStatus" is set to 1 in the following registry key: 'HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus'.
    
    .EXAMPLE
    PS C:\> Invoke-BitlockerCheck

    Name        : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BitLockerStatus
    BootStatus  : 0
    Description : BitLocker isn't enabled.
    #>

    [CmdletBinding()]Param()

    $MachineRole = Invoke-MachineRoleCheck

    if ($MachineRole.Name -Like "WinNT") {

        $RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\BitLockerStatus"

        $Item = Get-ItemProperty -Path "Registry::$RegPath" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError 
        if (-not $GetItemPropertyError) {

            if (-not ($Item.BootStatus -eq 1)) {

                $BitlockerResult = New-Object -TypeName PSObject 
                $BitlockerResult | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegPath
                $BitlockerResult | Add-Member -MemberType "NoteProperty" -Name "BootStatus" -Value $Item.BootStatus
                $BitlockerResult | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "BitLocker isn't enabled."
                $BitlockerResult
            }
            else {
                $BitlockerResult = New-Object -TypeName PSObject 
                $BitlockerResult | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegPath
                $BitlockerResult | Add-Member -MemberType "NoteProperty" -Name "BootStatus" -Value $Item.BootStatus
                $BitlockerResult | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "BitLocker is enabled."
                $BitlockerResult
            }

        }
        else {

            $BitlockerResult = New-Object -TypeName PSObject 
            $BitlockerResult | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegPath
            $BitlockerResult | Add-Member -MemberType "NoteProperty" -Name "BootStatus" -Value ""
            $BitlockerResult | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "BitLocker isn't configured."
            $BitlockerResult
        }
    }
}

function Invoke-LsaProtectionCheck {
    <#
    .SYNOPSIS
    Checks whether LSA protection is supported and enabled
    
    .DESCRIPTION
    Invokes the helper function Get-LsaRunAsPPLStatus
    
    .EXAMPLE
    PS C:\> Invoke-LsaProtectionCheck

    Name     Status Description
    ----     ------ -----------
    RunAsPPL   True RunAsPPL is enabled
    #>

    Get-LsaRunAsPPLStatus
}

function Invoke-CredentialGuardCheck {
    <#
    .SYNOPSIS
    Checks whether Credential Guard is supported and enabled
    
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