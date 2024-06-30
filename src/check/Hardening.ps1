function Invoke-UserAccountControlCheck {
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
    PS C:\> Invoke-UserAccountControlCheck | fl

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

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
        $Vulnerable = $false
    }

    process {
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
        $AllResults += $Result

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
        $AllResults += $Result

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
        $AllResults += $Result

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }
}

function Invoke-LapsCheck {
    <#
    .SYNOPSIS
    Checks whether LAPS (Local Admin Password Solution) is enabled

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet checks whether LAPS legacy or LAPSv2 is configured and enforced. If so, LAPS settings are returned along with a description.

    .LINK
    https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        function New-LapsSettingObject {
            param($Name, $Policy, $Default, $Description)
            $Item = New-Object -TypeName PSObject
            $Item | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Name
            $Item | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "LAPS > $($Policy)"
            $Item | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $Default
            $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
            $Item
        }

        $Vulnerable = $false
        $LapsEnforced = $false
        $LapsResult = @()

        $RootKeys = @(
            "HKLM\Software\Microsoft\Policies\LAPS",
            "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS",
            "HKLM\Software\Microsoft\Windows\CurrentVersion\LAPS\Config"
        )

        $BackupDirectoryDescriptions = @(
            "The local administrator password is not backed up (default).",
            "The local administrator password is backed up to Azure Active Directory.",
            "The local administrator password is backed up to Active Directory."
        )

        $PasswordComplexityDescriptions = @(
            "NOT_USED",
            "Password complexity: large letters.",
            "Password complexity: large letters + small letters.",
            "Password complexity: large letters + small letters + numbers.",
            "Password complexity: large letters + small letters + numbers + specials."
        )

        $ADPasswordEncryptionEnabledDescriptions = @(
            "The managed password is not encrypted before being sent to Active Directory.",
            "The managed password is encrypted before being sent to Active Directory (default)."
        )

        $PostAuthenticationActionsDescriptions = @(
            # 0000 = Disabled
            "Disabled - take no actions",
            # 0001 = Reset password
            "Reset the password",
            # 0010 = Logoff
            "NOT_USED",
            # 0011 = Reset password + logoff
            "Reset the password and logoff the managed account.",
            # 0100 = Reboot the device
            "NOT_USED",
            # 0101 = Reset the password + reboot the device
            "Reset the password and reboot the device"
        )

        $ADBackupDSRMPasswordDescriptions = @(
            "The DSRM administrator account password is not managed and backed up to Active Directory (default)."
            "The DSRM administrator account password is managed and backed up to Active Directory."
        )

        $PasswordExpirationProtectionEnabledDescriptions = @(
            "Password expiration time may be longer than required by `"Password Settings`" policy.",
            "Password expiration time may not be longer than required by `"Password Settings`" policy (default)."
        )

        $AdmPwdEnabledDescriptions = @(
            "The local administrator password is not managed (default).",
            "The local administrator password is managed."
        )

        $LapsSettings = @(
            (New-LapsSettingObject -Name "BackupDirectory" -Policy "Configure password backup directory" -Default 0 -Description $BackupDirectoryDescriptions),
            (New-LapsSettingObject -Name "AdministratorAccountName" -Policy "Name of administrator account to manage" -Default "Well known Administrator account" -Description "This policy setting specifies a custom Administrator account name to manage the password for."),
            (New-LapsSettingObject -Name "PasswordAgeDays" -Policy "Password Settings" -Default 30 -Description "Password age in days (min: 1; max: 365; default:30)."),
            (New-LapsSettingObject -Name "PasswordLength" -Policy "Password Settings" -Default 14 -Description "Password length (min: 8; max: 64; default: 14)."),
            (New-LapsSettingObject -Name "PasswordComplexity" -Policy "Password Settings" -Default 4 -Description $PasswordComplexityDescriptions),
            (New-LapsSettingObject -Name "PostAuthenticationResetDelay" -Policy "Post-authentication actions" 24 -Description "Amount of time (in hours) to wait after an authentication before executing the specified post-authentication actions."),
            (New-LapsSettingObject -Name "PostAuthenticationActions" -Policy "Post-authentication actions" -Default 3 -Description $PostAuthenticationActionsDescriptions),
            (New-LapsSettingObject -Name "ADPasswordEncryptionEnabled" -Policy "Enable password encryption" -Default 1 -Description $ADPasswordEncryptionEnabledDescriptions),
            (New-LapsSettingObject -Name "ADPasswordEncryptionPrincipal" -Policy "Configure authorized password decryptors" -Default "Domain Admins" -Description "Group who is authorized to decrypt encrypted passwords (default: Domain Admins)."),
            (New-LapsSettingObject -Name "ADEncryptedPasswordHistorySize" -Policy "Configure size of encrypted password history" -Default 0 -Description "Number of encrypted passwords stored in Active Directory (min: 0; max: 12; default: 0)."),
            (New-LapsSettingObject -Name "ADBackupDSRMPassword" -Policy "Enable password backup for DSRM accounts" -Default 0 -Description $ADBackupDSRMPasswordDescriptions),
            (New-LapsSettingObject -Name "PasswordExpirationProtectionEnabled" -Policy "Do not allow password expiration time longer than required by policy" -Default 1 -Description $PasswordExpirationProtectionEnabledDescriptions)
        )
    }

    process {

        if (-not (Test-IsDomainJoined)) {
            $LapsResult = New-Object -TypeName PSObject
            $LapsResult | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "The machine is not domain-joined, this check is irrelevant."
        }
        else {
            $LapsItem = New-LapsSettingObject -Name "BackupDirectory" -Policy "Configure password backup directory" -Default 0 -Description $BackupDirectoryDescriptions
            $LapsItem | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RootKeys[0]
            $LapsItem | Add-Member -MemberType "NoteProperty" -Name "Value" -Value "(null)"
            $LapsItem.Description = $LapsItem.Description[0]

            foreach ($RootKey in $RootKeys) {

                $Settings = Get-ItemProperty -Path "Registry::$($RootKey)" -ErrorAction SilentlyContinue
                $ConfigFound = $false

                foreach ($LapsSetting in $LapsSettings) {
                    $SettingValue = $Settings.$($LapsSetting.Name)

                    if (($LapsSetting.Name -eq "BackupDirectory") -and ($null -eq $SettingValue)) { $ConfigFound = $true }
                    if ($ConfigFound) { continue }

                    $LapsSetting | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RootKey
                    $LapsSetting | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $(if ($null -ne $SettingValue) { $SettingValue } else { "(null)" })
                    if ($LapsSetting.Description -is [object[]]) {
                        if ($null -eq $SettingValue) { $SettingValue = $LapsSetting.Default }
                        $SettingDescription = $LapsSetting.Description[$SettingValue]
                    }
                    else {
                        $SettingDescription = $LapsSetting.Description
                    }
                    $LapsSetting.Description = $SettingDescription
                    $LapsResult += $LapsSetting | Select-Object "Policy","Key","Default","Value","Description"

                    if ($LapsSetting.Name -eq "BackupDirectory") {
                        $LapsItem = $LapsSetting
                        if ($SettingValue -gt 0) { $LapsEnforced = $true}
                    }
                }

                # If a configuration was found in a root key, we must stop the loop.
                if ($LapsResult.Count -ne 0) { break }
            }

            # If LAPS configuration was not found, or if it is not enabled, fall back to
            # checking LAPS legacy.
            if (-not $LapsEnforced) {
                $RegKey = "HKLM\Software\Policies\Microsoft Services\AdmPwd"
                $RegValue = "AdmPwdEnabled"
                $RegDataDefault = 0

                $Settings = Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue
                $RegData = $Settings.$RegValue

                $LapsLegacyItem = New-Object -TypeName PSObject
                $LapsLegacyItem | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Enable local admin password management (LAPS legacy)"
                $LapsLegacyItem | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
                $LapsLegacyItem | Add-Member -MemberType "NoteProperty" -Name "Default" -Value $RegDataDefault
                $LapsLegacyItem | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })

                if ($RegData -eq 1) { $LapsEnforced = $true }
                if ($null -eq $RegData) { $RegData = $RegDataDefault }

                $LapsLegacyItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $AdmPwdEnabledDescriptions[$RegData]
                $LapsResult += $LapsLegacyItem
            }

            # If LAPS configuration was still not found (legacy or newer), we may return
            # an object representing the default LAPS configuration.
            if (-not $LapsEnforced) {
                $Vulnerable = $true
                $LapsResult += $LapsItem | Select-Object "Policy","Key","Default","Value","Description"
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $LapsResult
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
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

    [CmdletBinding()]
    param()

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
    PS C:\> Invoke-BitLockerCheck

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

    [CmdletBinding()]
    param(
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
                $Severity = $script:SeverityLevelEnum::High
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

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $Severity } else { $script:SeverityLevelEnum::None })
        $CheckResult
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

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
        $RegValue = "RunAsPPL"
        $OsVersion = Get-WindowsVersion
    }

    process {
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

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
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

    [CmdletBinding()]
    param(
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

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
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

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
        $Vulnerable = $false
    }

    process {
        $Uefi = Get-UEFIStatus
        $SecureBoot = Get-SecureBootStatus

        # If BIOS mode is not set to UEFI or if Secure Boot is not enabled, consider
        # the machine is vulnerable.
        if (($Uefi.Status -eq $false) -or ($SecureBoot.Data -eq 0)) {
            $Vulnerable = $true
        }

        $ConfigItem = New-Object -TypeName PSObject
        $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Uefi.Name
        $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value ($Uefi.Status -eq $false)
        $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Uefi.Description
        $AllResults += $ConfigItem

        $ConfigItem = New-Object -TypeName PSObject
        $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "Secure Boot"
        $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value ($SecureBoot.Data -eq 0)
        $ConfigItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $SecureBoot.Description
        $AllResults += $ConfigItem

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }
}

function Invoke-AppLockerCheck {
    <#
    .SYNOPSIS
    Short description

    .DESCRIPTION
    Long description

    .PARAMETER BaseSeverity
    Parameter description

    .EXAMPLE
    An example

    .NOTES
    General notes
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    process {
        $AppLockerPolicy = Get-AppLockerPolicyInternal -FilterLevel 0

        if ($null -eq $AppLockerPolicy) {
            $RuleCount = 0
            $Description = "AppLocker does not seem to be configured."
            $Vulnerable = $True
        }
        else {
            $RuleCount = $AppLockerPolicy.Count
            $Description = "AppLocker seems to be configured with $($RuleCount) 'allow' rules."
            $Vulnerable = $False
        }

        $AppLockerConfigured = New-Object -TypeName PSObject
        $AppLockerConfigured | Add-Member -MemberType "NoteProperty" -Name "RuleCount" -Value $RuleCount
        $AppLockerConfigured | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AppLockerConfigured
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }
}

function Invoke-AppLockerPolicyCheck {
    <#
    .SYNOPSIS
    Check whether an AppLocker policy is defined and, if so, whether it contains rules that can be bypassed in the context of the current user.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet first retrieves potentially vulnerable AppLocker rules thanks to the cmdlet "Get-AppLockerPolicyInternal". It then sorts them by their likelihood of exploitation, and excludes this information from the output. Only the human-readable "risk" level is returned for each item.

    .EXAMPLE
    PS C:\> Invoke-AppLockerPolicyCheck

    [snip]

    RuleCollectionType            : Exe
    RuleCollectionEnforcementMode : Enabled
    RuleName                      : APPLOCKER_EXE_DUMMY_ALLOW
    RuleDescription               : C:\DUMMY\*
    RuleUserOrGroupSid            : S-1-5-11
    RuleAction                    : Allow
    RuleCondition                 : Path='C:\DUMMY\*'
    RuleExceptions                : (null)
    Description                   : This rule allows files to be executed from a location where the current user has write access.
    Level                         : High

    [snip]
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    process {
        # Find AppLocker rules that can be bypassed, with a likelihood of
        # exploitation from low to high.
        $AppLockerPolicy = Get-AppLockerPolicyInternal -FilterLevel 1 | Sort-Object -Property "Level" -Descending | Select-Object -Property "*" -ExcludeProperty "Level"

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AppLockerPolicy
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AppLockerPolicy) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }
}

function Invoke-FileExtensionAssociationCheck {
    <#
    .SYNOPSIS
    Check whether dangerous default file extensions such as '.bat' or '.wsh' are associated to a text editor such as 'notepad.exe'.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet aims at listing default file associations that could be abused by an attacker to gain initial access to a user's computer by tricking them into double clicking a file.

    .EXAMPLE
    PS C:\> Invoke-FileExtensionAssociationCheck

    Extension           Command
    ---------           -------
    .bat                "%1" %*
    .chm                "C:\Windows\hh.exe" %1
    .cmd                "%1" %*
    .com                "%1" %*
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $TextEditors = @("Notepad.exe", "Wordpad.exe", "Notepad++.exe")
        $DefaultAssociations = $script:DangerousDefaultFileExtensionAssociations | ConvertFrom-Csv -Header "Extension","Executable"
        $VulnerableAssociations = @()
    }

    process {
        foreach ($DefaultAssociation in $DefaultAssociations) {

            $CurrentExecutable = Get-FileExtensionAssociation -Extension $DefaultAssociation.Extension -Type "Executable"
            if ($null -eq $CurrentExecutable -or $CurrentExecutable -like "*OpenWith.exe*") { continue }

            $CurrentCommand = Get-FileExtensionAssociation -Extension $DefaultAssociation.Extension -Type "Command"

            if (($CurrentExecutable -eq $DefaultAssociation.Executable) -or ($TextEditors -NotContains [System.IO.Path]::GetFileName($CurrentExecutable))) {
                $VulnerableAssociation = New-Object -TypeName PSObject
                $VulnerableAssociation | Add-Member -MemberType "NoteProperty" -Name "Extension" -Value $DefaultAssociation.Extension
                # $VulnerableAssociation | Add-Member -MemberType "NoteProperty" -Name "Executable" -Value $CurrentExecutable
                $VulnerableAssociation | Add-Member -MemberType "NoteProperty" -Name "Command" -Value $CurrentCommand
                $VulnerableAssociations += $VulnerableAssociation
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $VulnerableAssociations
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($VulnerableAssociations.Count) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }
}

function Invoke-HiddenFilenameExtensionCheck {
    <#
    .SYNOPSIS
    Check whether extensions of known file types are shown in the Explorer.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet checks whether the Explorer is configured to hide the file name extension of known file types.

    .EXAMPLE
    An example
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $RegKey = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        $RegValue = "HideFileExt"
    }

    process {
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
        if (($null -eq $RegData) -or ($RegData -ge 1)) {
            $IsVulnerable = $true
            $Description = "File name extensions of known file types are hidden in the Explorer."
        }
        else {
            $IsVulnerable = $false
            $Description = "File name extensions of known file types are shown in the Explorer."
        }

        $Config = New-Object -TypeName PSObject
        $Config | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
        $Config | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
        $Config | Add-Member -MemberType "NoteProperty" -Name "Expected" -Value 0
        $Config | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
        $Config | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($IsVulnerable) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }
}

function Invoke-PowerShellExecutionPolicyCheck {
    <#
    .SYNOPSIS
    Check whether a PowerShell execution policy is enforced

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet checks whether a PowerShell execution policy is enforced, and, if so, ensures that the setting is set to 'AllSigned' or 'RemoteSigned'.
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $Vulnerable = $false
    }

    process {

        if (-not (Test-IsDomainJoined)) {
            $PolicyResult = New-Object -TypeName PSObject
            $PolicyResult | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "The machine is not domain-joined, this check is irrelevant."
        }
        else {
            $PolicyResult = Get-EnforcedPowerShellExecutionPolicy

            if ($null -eq $PolicyResult) {
                $Vulnerable = $true
                $PolicyResult = New-Object -TypeName PSObject
                $PolicyResult | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "No PowerShell execution policy is enforced."
            }
            else {
                if ($PolicyResult.ExecutionPolicy -eq "Unrestricted") {
                    $Vulnerable = $true
                }
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $PolicyResult
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }
}

function Invoke-AttackSurfaceReductionRuleCheck {
    <#
    .SYNOPSIS
    Get information about configured Windows Defender Exploit Guard Attack Surface Reduction (ASR) rules.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet returns a list of enabled ASR rules.

    .EXAMPLE
    PS C:\> Invoke-AttackSurfaceReductionRuleCheck

    Rule        : Block Office applications from creating executable content
    Id          : 3b576869-a4ec-4529-8536-b80a7769e899
    State       : 2
    Description : Audit

    Rule        : Block Win32 API calls from Office macros
    Id          : 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b
    State       : 1
    Description : Block
    #>

    [CmdletBinding()]
    param()

    process {
        Get-AttackSurfaceReductionRule | Where-Object { ($null -ne $_.State) -and ($_.State -ne 0) }
    }
}