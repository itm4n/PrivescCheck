function Get-UEFIStatus {
    <#
    .SYNOPSIS
    Helper - Gets the BIOS mode of the machine (Legacy / UEFI)

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Invokes the "GetFirmwareEnvironmentVariable()" function from the Windows API with dummy parameters. Indeed, the queried value doesn't matter, what matters is the last error code, which you can get by invoking "GetLastError()". If the return code is ERROR_INVALID_FUNCTION, this means that the function is not supported by the BIOS so it's LEGACY. Otherwise, the error code will indicate that it cannot find the requested variable, which means that the function is supported by the BIOS so it's UEFI.

    .EXAMPLE
    PS C:\> Get-UEFIStatus

    Name Status Description
    ---- ------ -----------
    UEFI   True BIOS mode is UEFI

    .NOTES
    https://github.com/xcat2/xcat-core/blob/master/xCAT-server/share/xcat/netboot/windows/detectefi.cpp
    https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariablea
    https://github.com/ChrisWarwick/GetUEFI/blob/master/GetFirmwareBIOSorUEFI.psm1
    #>

    [CmdletBinding()] Param()

    $OsVersion = Get-WindowsVersion

    # Windows >= 8/2012
    if (($OsVersion.Major -ge 10) -or (($OsVersion.Major -ge 6) -and ($OsVersion.Minor -ge 2))) {

        [UInt32]$FirmwareType = 0
        $Result = $Kernel32::GetFirmwareType([ref]$FirmwareType)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if ($Result -gt 0) {
            if ($FirmwareType -eq 1) {
                # FirmwareTypeBios = 1
                $Status = $false
                $Description = "BIOS mode is Legacy."
            }
            elseif ($FirmwareType -eq 2) {
                # FirmwareTypeUefi = 2
                $Status = $true
                $Description = "BIOS mode is UEFI."
            }
            else {
                $Description = "BIOS mode is unknown."
            }
        }
        else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }

    # Windows = 7/2008 R2
    }
    elseif (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -eq 1)) {

        $null = $Kernel32::GetFirmwareEnvironmentVariable("", "{00000000-0000-0000-0000-000000000000}", [IntPtr]::Zero, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        $ERROR_INVALID_FUNCTION = 1
        if ($LastError -eq $ERROR_INVALID_FUNCTION) {
            $Status = $false
            $Description = "BIOS mode is Legacy."
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }
        else {
            $Status = $true
            $Description = "BIOS mode is UEFI."
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }

    }
    else {
        $Description = "Cannot check BIOS mode."
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "UEFI"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result
}

function Get-SecureBootStatus {
    <#
    .SYNOPSIS
    Helper - Get the status of Secure Boot (enabled/disabled/unsupported)

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    In case of a UEFI BIOS, you can check whether 'Secure Boot' is enabled by looking at the 'UEFISecureBootEnabled' value of the following registry key: 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State'.

    .EXAMPLE
    PS C:\> Get-SecureBootStatus

    Key         : HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State
    Value       : UEFISecureBootEnabled
    Data        : 0
    Description : Secure Boot is disabled
    #>

    [CmdletBinding()] Param()

    $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
    $RegValue = "UEFISecureBootEnabled"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

    if ($null -ne $RegData) {
        if ($null -eq $RegData) {
            $Description = "Secure Boot is not supported."
        }
        else {
            $Description = "Secure Boot is $(if ($RegData -ne 1) { "not "})enabled."
        }
    }

    Write-Verbose "$($RegValue): $($Description)"

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result
}

function Get-MachineRole {

    [CmdletBinding()] Param()

    BEGIN {
        $FriendlyNames = @{
            "WinNT"     = "Workstation";
            "LanmanNT"  = "Domain Controller";
            "ServerNT"  = "Server";
        }
    }

    PROCESS {
        $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions"
        $RegValue = "ProductType"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue).$RegValue

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegData
        $Result | Add-Member -MemberType "NoteProperty" -Name "Role" -Value $(try { $FriendlyNames[$RegData] } catch { "" })
        $Result
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

    [CmdletBinding()] Param ()

    BEGIN {
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

    PROCESS {

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
    Description : UAC is enabled.

    Key         : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    Value       : LocalAccountTokenFilterPolicy
    Data        : (null)
    Description : Only the built-in Administrator account (RID 500) can be granted a high integrity token when authenticating remotely (default).

    Key         : HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
    Value       : FilterAdministratorToken
    Data        : (null)
    Description : The built-in administrator account (RID 500) is granted a high integrity token when authenticating remotely (default).

    .NOTES
    "UAC was formerly known as Limited User Account (LUA)."
    IF EnableLUA = 0
        -> UAC is completely disabled, no other restriction can apply.
    ELSE
        -> UAC is enabled (default).
        IF LocalAccountTokenFilterPolicy = 1
            -> Every member of the local Administrators group is granted a high integrity token for remote connections.
        ELSE
            -> Only the default local Administrator account (with RID 500) is granted a high integrity token for remote connections (default).
            IF FilterAdministratorToken = 0
                -> The default local Administrator account (with RID 500) is granted a high integrity token for remote connections (default).
            ELSE
                -> The access token of the default local Administrator account (with RID 500) is filtered.

    .LINK
    https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-lua-settings-enablelua
    https://labs.f-secure.com/blog/enumerating-remote-access-policies-through-gpo/
    #>

    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )

    $ArrayOfResults = @()
    $Vulnerable = $false

    # Check whether UAC is enabled.
    $RegKey = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    $RegValue = "EnableLUA"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

    if ($RegData -ge 1) {
        $Description = "UAC is enabled."
    } else {
        $Description = "UAC is not enabled."
        $Vulnerable = $true
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value "$(if ($null -eq $RegData) { "(null)" } else { $RegData })"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value $(($null -eq $RegData) -or ($RegData -eq 0))
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $ArrayOfResults += $Result

    # If UAC is enabled, check LocalAccountTokenFilterPolicy to determine if only the built-in
    # administrator can get a high integrity token remotely or if any local user that is a
    # member of the Administrators group can also get one.
    $RegKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $RegValue = "LocalAccountTokenFilterPolicy"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

    if ($RegData -ge 1) {
        $Description = "Local users that are members of the Administrators group are granted a high integrity token when authenticating remotely."
        $Vulnerable = $true
    }
    else {
        $Description = "Only the built-in Administrator account (RID 500) can be granted a high integrity token when authenticating remotely (default)."
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value "$(if ($null -eq $RegData) { "(null)" } else { $RegData })"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value $($RegData -ge 1)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $ArrayOfResults += $Result

    # If LocalAccountTokenFilterPolicy != 1, i.e. local admins other than RID 500 are not granted a
    # high integrity token. However, we need to check if other restrictions apply to the built-in
    # administrator as well.
    $RegKey = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $RegValue = "FilterAdministratorToken"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

    if ($RegData -ge 1) {
        $Description = "The built-in Administrator account (RID 500) is only granted a medium integrity token when authenticating remotely."
    }
    else {
        $Description = "The built-in administrator account (RID 500) is granted a high integrity token when authenticating remotely (default)."
        $Vulnerable = $true
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value "$(if ($null -eq $RegData) { "(null)" } else { $RegData })"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value $(($null -eq $RegData) -or ($RegData -eq 0))
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $ArrayOfResults += $Result

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $SeverityLevelEnum::None })
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
    #>

    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )

    BEGIN {
        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd"
        $RegValue = "AdmPwdEnabled"
        $IsDomainJoined = Test-IsDomainJoined
    }

    PROCESS {
        $Vulnerable = $false

        # If the machine is not domain-joined, LAPS cannot be configured.
        if (-not $IsDomainJoined) {
            $Description = "The machine is not domain-joined, this check is irrelevant."
        }
        else {
            $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
            
            if ($null -eq $RegData) {
                $Description = "LAPS is not configured."
                $Vulnerable = $true
            }
            else {
                if ($RegData -ge 1) {
                    $Description = "LAPS is enabled."
                }
                else {
                    $Description = "LAPS is not enabled."
                    $Vulnerable = $true
                }
            }
        }

        $Config = New-Object -TypeName PSObject
        $Config | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Config | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Config | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
        $Config | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
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

    [CmdletBinding()] Param()

    $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
    $RegItem = Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue

    if ($RegItem) {
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "EnableTranscripting" -Value $(if ($null -eq $RegItem.EnableTranscripting) { "(null)" } else { $RegItem.EnableTranscripting })
        $Result | Add-Member -MemberType "NoteProperty" -Name "EnableInvocationHeader" -Value $(if ($null -eq $RegItem.EnableInvocationHeader) { "(null)" } else { $RegItem.EnableInvocationHeader })
        $Result | Add-Member -MemberType "NoteProperty" -Name "OutputDirectory" -Value $(if ($null -eq $RegItem.OutputDirectory) { "(null)" } else { $RegItem.OutputDirectory })
        $Result
    }
}

function Invoke-BitLockerCheck {
    <#
    .SYNOPSIS
    Checks whether BitLocker is enabled.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    When BitLocker is enabled on the system drive, the value "BootStatus" is set to 1 in the following registry key: 'HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus'.

    .EXAMPLE
    PS C:\> Invoke-BitlockerCheck

    MachineRole        : Workstation
    UseAdvancedStartup : 0 - Do not require additional authentication at startup (default)
    EnableBDEWithNoTPM : 0 - Do not allow BitLocker without a compatible TPM (default)
    UseTPM             : 1 - Require TPM (default)
    UseTPMPIN          : 0 - Do not allow startup PIN with TPM (default)
    UseTPMKey          : 0 - Do not allow startup key with TPM (default)
    UseTPMKeyPIN       : 0 - Do not allow startup key and PIN with TPM (default)
    Description        : BitLocker is enabled. Additional authentication is not required at startup. Authentication mode
                        is 'TPM only'.
    #>

    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )

    begin {
        $MachineRole = Get-MachineRole
        $Config = New-Object -TypeName PSObject
        $Config | Add-Member -MemberType "NoteProperty" -Name "MachineRole" -Value $MachineRole.Role
    
        $Vulnerable = $false
        $Severity = $BaseSeverity
    }

    process {
        # The machine is not a workstation, no need to check BitLocker configuration.
        if ($MachineRole.Name -ne "WinNT") {
            $Description = "Not a workstation, BitLocker configuration is irrelevant."
        }
        else {
            $BitLockerConfig = Get-BitLockerConfiguration
            $Description = "$($BitLockerConfig.Status.Description)"
        
            if ($BitLockerConfig.Status.Value -ne 1) {
                # BitLocker is not enabled.
                $Description = "BitLocker is not enabled."
                $Vulnerable = $true
                # Increase the severity level.
                $Severity = $SeverityLevelEnum::High
            }
            else {
                $Config | Add-Member -MemberType "NoteProperty" -Name "UseAdvancedStartup" -Value "$($BitLockerConfig.UseAdvancedStartup.Value) - $($BitLockerConfig.UseAdvancedStartup.Description)"
                $Config | Add-Member -MemberType "NoteProperty" -Name "EnableBDEWithNoTPM" -Value "$($BitLockerConfig.EnableBDEWithNoTPM.Value) - $($BitLockerConfig.EnableBDEWithNoTPM.Description)"
                $Config | Add-Member -MemberType "NoteProperty" -Name "UseTPM" -Value "$($BitLockerConfig.UseTPM.Value) - $($BitLockerConfig.UseTPM.Description)"
                $Config | Add-Member -MemberType "NoteProperty" -Name "UseTPMPIN" -Value "$($BitLockerConfig.UseTPMPIN.Value) - $($BitLockerConfig.UseTPMPIN.Description)"
                $Config | Add-Member -MemberType "NoteProperty" -Name "UseTPMKey" -Value "$($BitLockerConfig.UseTPMKey.Value) - $($BitLockerConfig.UseTPMKey.Description)"
                $Config | Add-Member -MemberType "NoteProperty" -Name "UseTPMKeyPIN" -Value "$($BitLockerConfig.UseTPMKeyPIN.Value) - $($BitLockerConfig.UseTPMKeyPIN.Description)"
            
                if ($BitLockerConfig.UseAdvancedStartup.Value -ne 1) {
                    # Advanced startup is not enabled. This means that a second factor of authentication
                    # cannot be configured. We can report this and return.
                    $Description = "$($Description) Additional authentication is not required at startup."
                    if ($BitLockerConfig.UseTPM.Value -eq 1) {
                        $Description = "$($Description) Authentication mode is 'TPM only'."
                    }
                    $Vulnerable = $true
                }
                else {
                    # Advanced startup is enabled, but is a second factor of authentication enforced?
                    if (($BitLockerConfig.UseTPMPIN.Value -ne 1) -and ($BitLockerConfig.UseTPMKey.Value -ne 1) -and ($BitLockerConfig.UseTPMKeyPIN -ne 1)) {
                        # A second factor of authentication is not explicitly enforced.
                        $Description = "$($Description) A second factor of authentication (PIN, startup key) is not explicitly required."
                        if ($BitLockerConfig.EnableBDEWithNoTPM.Value -eq 1) {
                            $Description = "$($Description) BitLocker without a compatible TPM is allowed."
                        }
                        $Vulnerable = $true
                    }
                }
            }
        }
    
        $Config | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $Severity } else { $SeverityLevelEnum::None })
        $Result
    }
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

    Key         : HKLM\SYSTEM\CurrentControlSet\Control\Lsa
    Value       : RunAsPPL
    Data        : (null)
    Description : LSA protection is not enabled.
    #>

    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )

    BEGIN {
        $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        $RegValue = "RunAsPPL"
        $OsVersion = Get-WindowsVersion
    }
    
    PROCESS {
        $Vulnerable = $false

        if (-not ($OsVersion.Major -ge 10 -or (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 3)))) {
            $Description = "LSA protection is not supported on this version of Windows."
            $Vulnerable = $true
        }
        else {
            $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

            if ($RegData -ge 1) {
                $Description = "LSA protection is enabled."
            }
            else {
                $Description = "LSA protection is not enabled."
                $Vulnerable = $true
            }
        }
    
        $Config = New-Object -TypeName PSObject
        $Config | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Config | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Config | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
        $Config | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
        
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
}

function Invoke-CredentialGuardCheck {
    <#
    .SYNOPSIS
    Checks whether Credential Guard is supported and enabled

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet checks WMI and registry information to determine whether Credential Guard is configured and running.

    .EXAMPLE
    PS C:\> Invoke-CredentialGuardCheck

    SecurityServicesConfigured  : 0
    SecurityServicesRunning     : 0
    SecurityServicesDescription : Credential Guard is not configured. Credential Guard is not running.
    LsaCfgFlagsPolicyKey        : HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard
    LsaCfgFlagsPolicyValue      : LsaCfgFlags
    LsaCfgFlagsPolicyData       : (null)
    LsaCfgFlagsKey              : HKLM\SYSTEM\CurrentControlSet\Control\LSA
    LsaCfgFlagsValue            : LsaCfgFlags
    LsaCfgFlagsData             : (null)
    LsaCfgFlagsDescription      : Credential Guard is not configured.

    .NOTES
    Starting with Windows 11 22H2 (Enterprise / Education), Credential Guard is enabled by default if the machine follows all the hardware and software requirements.
    https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage
    #>

    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )

    begin {
        $LsaCfgFlagsDescriptions = @(
            "Credential Guard is disabled.",
            "Credential Guard is enabled with UEFI persistence.",
            "Credential Guard is enabled without UEFI persistence."
        )
    
        $Vulnerable = $false
    }

    process {
        # Check WMI information first
        $WmiObject = Get-WmiObject -Namespace "root\Microsoft\Windows\DeviceGuard" -Class "Win32_DeviceGuard" -ErrorAction SilentlyContinue
        
        if ($WmiObject) {

            $SecurityServicesConfigured = [UInt32[]] $WmiObject.SecurityServicesConfigured
            $SecurityServicesRunning = [UInt32[]] $WmiObject.SecurityServicesRunning

            Write-Verbose "SecurityServicesConfigured: $SecurityServicesConfigured"
            Write-Verbose "SecurityServicesRunning: $SecurityServicesRunning"

            # https://learn.microsoft.com/en-us/dotnet/api/microsoft.powershell.commands.deviceguardsoftwaresecure?view=powershellsdk-1.1.0
            # 1: Credential Guard
            # 2: Hypervisor enforced Code Integrity
            
            if ($SecurityServicesConfigured -contains ([UInt32] 1)) {
                $SecurityServicesDescription = "Credential Guard is configured."
            }
            else {
                $SecurityServicesDescription = "Credential Guard is not configured."
            }

            if ($SecurityServicesRunning -contains ([UInt32] 1)) {
                $SecurityServicesDescription = "$($SecurityServicesDescription) Credential Guard is running."
            }
            else {
                $SecurityServicesDescription = "$($SecurityServicesDescription) Credential Guard is not running."
                $Vulnerable = $true
            }
        }
        else {
            $SecurityServicesDescription = "Credential Guard is not supported."
        }

        # Check registry configuration
        $LsaCfgFlagsPolicyKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard"
        $LsaCfgFlagsPolicyValue = "LsaCfgFlags"
        $LsaCfgFlagsPolicyData = (Get-ItemProperty -Path "Registry::$($LsaCfgFlagsPolicyKey)" -Name $LsaCfgFlagsPolicyValue -ErrorAction SilentlyContinue).$LsaCfgFlagsPolicyValue

        if ($null -ne $LsaCfgFlagsPolicyData) {
            $LsaCfgFlagsDescription = $LsaCfgFlagsDescriptions[$LsaCfgFlagsPolicyData]
        }

        $LsaCfgFlagsKey = "HKLM\SYSTEM\CurrentControlSet\Control\LSA"
        $LsaCfgFlagsValue = "LsaCfgFlags"
        $LsaCfgFlagsData = (Get-ItemProperty -Path "Registry::$($LsaCfgFlagsKey)" -Name $LsaCfgFlagsValue -ErrorAction SilentlyContinue).$LsaCfgFlagsValue

        if ($null -ne $LsaCfgFlagsData) {
            $LsaCfgFlagsDescription = $LsaCfgFlagsDescriptions[$LsaCfgFlagsData]
        }

        if (($null -ne $LsaCfgFlagsPolicyData) -and ($null -ne $LsaCfgFlagsData) -and ($LsaCfgFlagsPolicyData -ne $LsaCfgFlagsData)) {
            Write-Warning "The value of 'LsaCfgFlags' set by policy is different from the one set on the LSA registry key."
        }

        if (($null -eq $LsaCfgFlagsPolicyData) -and ($null -eq $LsaCfgFlagsData)) {
            $LsaCfgFlagsDescription = "Credential Guard is not configured."
        }

        # Aggregate results
        $Config = New-Object -TypeName PSObject
        $Config | Add-Member -MemberType "NoteProperty" -Name "SecurityServicesConfigured" -Value $(if ($null -eq $SecurityServicesConfigured) { "(null)" } else { $SecurityServicesConfigured })
        $Config | Add-Member -MemberType "NoteProperty" -Name "SecurityServicesRunning" -Value $(if ($null -eq $SecurityServicesRunning) { "(null)" } else { $SecurityServicesRunning })
        $Config | Add-Member -MemberType "NoteProperty" -Name "SecurityServicesDescription" -Value $(if ([string]::IsNullOrEmpty($SecurityServicesDescription)) { "(null)" } else { $SecurityServicesDescription })
        $Config | Add-Member -MemberType "NoteProperty" -Name "LsaCfgFlagsPolicyKey" -Value $LsaCfgFlagsPolicyKey
        $Config | Add-Member -MemberType "NoteProperty" -Name "LsaCfgFlagsPolicyValue" -Value $LsaCfgFlagsPolicyValue
        $Config | Add-Member -MemberType "NoteProperty" -Name "LsaCfgFlagsPolicyData" -Value $(if ($null -eq $LsaCfgFlagsPolicyData) { "(null)" } else { $LsaCfgFlagsPolicyData })
        $Config | Add-Member -MemberType "NoteProperty" -Name "LsaCfgFlagsKey" -Value $LsaCfgFlagsKey
        $Config | Add-Member -MemberType "NoteProperty" -Name "LsaCfgFlagsValue" -Value $LsaCfgFlagsValue
        $Config | Add-Member -MemberType "NoteProperty" -Name "LsaCfgFlagsData" -Value $(if ($null -eq $LsaCfgFlagsData) { "(null)" } else { $LsaCfgFlagsData })
        $Config | Add-Member -MemberType "NoteProperty" -Name "LsaCfgFlagsDescription" -Value $(if ($null -eq $LsaCfgFlagsDescription) { "(null)" } else { $LsaCfgFlagsDescription })

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
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

    Name        Vulnerable Description
    ----        ---------- -----------
    UEFI             False BIOS mode is UEFI.
    Secure Boot       True Secure Boot is not enabled.
    #>

    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )

    $Vulnerable = $false

    $Uefi = Get-UEFIStatus
    $SecureBoot = Get-SecureBootStatus
    
    # If BIOS mode is not set to UEFI or if Secure Boot is not enabled, consider
    # the machine is vulnerable.
    if (($Uefi.Status -eq $false) -or ($SecureBoot.Data -eq 0)) {
        $Vulnerable = $true
    }

    $ArrayOfResults = @()

    $ConfigItem = New-Object -TypeName PSObject
    $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Uefi.Name
    $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value ($Uefi.Status -eq $false)
    $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Uefi.Description
    $ArrayOfResults += $ConfigItem

    $ConfigItem = New-Object -TypeName PSObject
    $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "Secure Boot"
    $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value ($SecureBoot.Data -eq 0)
    $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $SecureBoot.Description
    $ArrayOfResults += $ConfigItem

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $SeverityLevelEnum::None })
    $Result
}