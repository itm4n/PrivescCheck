function Get-ProcessTokenHandle {
    <#
    .SYNOPSIS
    Open a Process Token handle

    .DESCRIPTION
    This helper function returns a Process Token handle.

    .PARAMETER ProcessId
    The ID of a Process. By default, the value is zero, which means open the current Process.

    .PARAMETER ProcessAccess
    The access flags used to open the Process.

    .PARAMETER TokenAccess
    The access flags used to open the Token.
    #>

    [OutputType([IntPtr])]
    [CmdletBinding()]
    param(
        [UInt32] $ProcessId = 0,
        [UInt32] $ProcessAccess = $script:ProcessAccessRightEnum::QUERY_INFORMATION,
        [UInt32] $TokenAccess = $script:TokenAccessRightEnum::Query
    )

    if ($ProcessId -eq 0) {
        $ProcessHandle = $script:Kernel32::GetCurrentProcess()
    }
    else {
        $ProcessHandle = $script:Kernel32::OpenProcess($ProcessAccess, $false, $ProcessId)

        if ($ProcessHandle -eq [IntPtr]::Zero) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "OpenProcess($($ProcessId), 0x$('{0:x8}' -f $ProcessAccess))) - $([ComponentModel.Win32Exception] $LastError)"
            return
        }
    }

    [IntPtr] $TokenHandle = [IntPtr]::Zero
    $Success = $script:Advapi32::OpenProcessToken($ProcessHandle, $TokenAccess, [ref] $TokenHandle)
    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "OpenProcessToken - $([ComponentModel.Win32Exception] $LastError)"
        $script:Kernel32::CloseHandle($ProcessHandle) | Out-Null
        return
    }

    $script:Kernel32::CloseHandle($ProcessHandle) | Out-Null

    $TokenHandle
}

function Get-TokenInformationData {
    <#
    .SYNOPSIS
    Get information about a Token.

    .DESCRIPTION
    This helper function leverages the Windows API (GetTokenInformation) to get various information about a Token. It takes a Token handle and an information class as the input parameter and returns a pointer to a buffer that contains the result data. The returned buffer must be freed with a call to FreeHGlobal.

    .PARAMETER TokenHandle
    A Token handle.

    .PARAMETER InformationClass
    The type of information to retrieve from the Token.
    #>

    [OutputType([IntPtr])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [IntPtr] $TokenHandle,
        [Parameter(Mandatory=$true)]
        [UInt32] $InformationClass
    )

    $DataSize = 0
    $Success = $script:Advapi32::GetTokenInformation($TokenHandle, $InformationClass, 0, $null, [ref] $DataSize)
    if ($DataSize -eq 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "GetTokenInformation - $([ComponentModel.Win32Exception] $LastError)"
        return
    }

    [IntPtr] $DataPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($DataSize)

    $Success = $script:Advapi32::GetTokenInformation($TokenHandle, $InformationClass, $DataPtr, $DataSize, [ref] $DataSize)
    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "GetTokenInformation - $([ComponentModel.Win32Exception] $LastError)"
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($DataPtr)
        return
    }

    $DataPtr
}

function Get-TokenInformationGroup {
    <#
    .SYNOPSIS
    List the groups of a Token.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function leverages the Windows API (GetTokenInformation) to list the groups that are associated to a token.

    .PARAMETER ProcessId
    The ID of a Process to retrieve information from. By default, the value is zero, which means retrieve information from the current process.

    .PARAMETER InformationClass
    The type of group to retrieve. Supported values are: "Groups", "RestrictedSids", "LogonSid", "Capabilities", "DeviceGroups" and "RestrictedDeviceGroups".

    .EXAMPLE
    PS C:\> Get-TokenInformationGroup -InformationClass Groups

    Name                                   Type           SID                                           Attributes
    ----                                   ----           ---                                           ----------
    DESKTOP-AAAAAAA\None                   Group          S-1-5-21-3539966466-3447975095-3309057754-513 Mandatory, Enabled, EnabledByDefault
    Everyone                               WellKnownGroup S-1-1-0                                       Mandatory, Enabled, EnabledByDefault
    BUILTIN\Users                          Alias          S-1-5-32-545                                  Mandatory, Enabled, EnabledByDefault
    BUILTIN\Performance Log Users          Alias          S-1-5-32-559                                  Mandatory, Enabled, EnabledByDefault
    NT AUTHORITY\INTERACTIVE               WellKnownGroup S-1-5-4                                       Mandatory, Enabled, EnabledByDefault
    CONSOLE LOGON                          WellKnownGroup S-1-2-1                                       Mandatory, Enabled, EnabledByDefault
    NT AUTHORITY\Authenticated Users       WellKnownGroup S-1-5-11                                      Mandatory, Enabled, EnabledByDefault
    NT AUTHORITY\This Organization         WellKnownGroup S-1-5-15                                      Mandatory, Enabled, EnabledByDefault
    NT AUTHORITY\Local account             WellKnownGroup S-1-5-113                                     Mandatory, Enabled, EnabledByDefault
    NT AUTHORITY\LogonSessionId_0_205547   LogonSession   S-1-5-5-0-205547                              Mandatory, Enabled, EnabledByDefault, LogonId
    LOCAL                                  WellKnownGroup S-1-2-0                                       Mandatory, Enabled, EnabledByDefault
    NT AUTHORITY\NTLM Authentication       WellKnownGroup S-1-5-64-10                                   Mandatory, Enabled, EnabledByDefault
    Mandatory Label\Medium Mandatory Level Label          S-1-16-8192                                   Integrity, IntegrityEnabled
    #>

    [CmdletBinding()]
    param(
        [UInt32] $ProcessId = 0,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Groups", "RestrictedSids", "LogonSid", "Capabilities", "DeviceGroups", "RestrictedDeviceGroups")]
        [String] $InformationClass
    )

    $InformationClasses = @{
        Groups                  = 2
        RestrictedSids          = 11
        LogonSid                = 28
        Capabilities            = 30
        DeviceGroups            = 37
        RestrictedDeviceGroups  = 38
    }

    $SupportedGroupAttributes = @{
        Enabled             = 0x00000004
        EnabledByDefault    = 0x00000002
        Integrity           = 0x00000020
        IntegrityEnabled    = 0x00000040
        LogonId             = 0xC0000000
        Mandatory           = 0x00000001
        Owner               = 0x00000008
        Resource            = 0x20000000
        UseForDenyOnly      = 0x00000010
    }

    $SupportedTypes = @{
        User            = 0x00000001
        Group           = 0x00000002
        Domain          = 0x00000003
        Alias           = 0x00000004
        WellKnownGroup  = 0x00000005
        DeletedAccount  = 0x00000006
        Invalid         = 0x00000007
        Unknown         = 0x00000008
        Computer        = 0x00000009
        Label           = 0x0000000A
        LogonSession    = 0x0000000B
    }

    $TokenHandle = Get-ProcessTokenHandle -ProcessId $ProcessId
    if (-not $TokenHandle) { return }

    $TokenGroupsPtr = Get-TokenInformationData -TokenHandle $TokenHandle -InformationClass $InformationClasses[$InformationClass]
    if (-not $TokenGroupsPtr) { $script:Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenGroups = [Runtime.InteropServices.Marshal]::PtrToStructure($TokenGroupsPtr, [type] $script:TOKEN_GROUPS)

    # Offset of the first SID_AND_ATTRIBUTES structure is +4 in 32-bits, and +8 in 64-bits (because
    # of the structure alignment in memory). Therefore we can use [IntPtr]::Size as the offset's
    # value for the first item in the array.
    $CurrentGroupPtr = [IntPtr] ($TokenGroupsPtr.ToInt64() + [IntPtr]::Size)
    for ($i = 0; $i -lt $TokenGroups.GroupCount; $i++) {

        $CurrentGroup = [Runtime.InteropServices.Marshal]::PtrToStructure($CurrentGroupPtr, [type] $script:SID_AND_ATTRIBUTES)

        $GroupAttributes = $SupportedGroupAttributes.GetEnumerator() | ForEach-Object {
            if ( $_.value -band $CurrentGroup.Attributes ) {
                $_.name
            }
        }

        $SidInfo = Convert-PSidToNameAndType -PSid $CurrentGroup.Sid
        $SidString = Convert-PSidToStringSid -PSid $CurrentGroup.Sid

        $GroupType = $SupportedTypes.GetEnumerator() | ForEach-Object {
            if ( $_.value -eq $SidInfo.Type ) {
                $_.name
            }
        }

        if (-not ($FilterWellKnown -and ($SidType -eq $SupportedTypes["WellKnownGroup"]))) {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $SidInfo.DisplayName
            $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $GroupType
            $Result | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $SidString
            $Result | Add-Member -MemberType "NoteProperty" -Name "Attributes" -Value ($GroupAttributes -join ", ")
            $Result
        }

        $CurrentGroupPtr = [IntPtr] ($CurrentGroupPtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([type] $script:SID_AND_ATTRIBUTES))
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenGroupsPtr)
    $script:Kernel32::CloseHandle($TokenHandle) | Out-Null
}

function Get-TokenInformationPrivilege {
    <#
    .SYNOPSIS
    List the privileges associated to a Process Token.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function leverages the Windows API (GetTokenInformation) to list the privileges that are associated to a token.

    .PARAMETER ProcessId
    The ID of Process. By default, the value is zero, which means retrieve information from the current process.

    .EXAMPLE
    PS C:\> Get-TokenInformationPrivilege

    Name                          State    Description
    ----                          -----    -----------
    SeShutdownPrivilege           Disabled Shut down the system
    SeChangeNotifyPrivilege       Enabled  Bypass traverse checking
    SeUndockPrivilege             Disabled Remove computer from docking station
    SeIncreaseWorkingSetPrivilege Disabled Increase a process working set
    SeTimeZonePrivilege           Disabled Change the time zone
    #>

    [CmdletBinding()]
    param(
        [UInt32] $ProcessId = 0
    )

    $PrivilegeDescriptions = @{
        SeAssignPrimaryTokenPrivilege               = "Replace a process-level token";
        SeAuditPrivilege                            = "Generate security audits";
        SeBackupPrivilege                           = "Back up files and directories";
        SeChangeNotifyPrivilege                     = "Bypass traverse checking";
        SeCreateGlobalPrivilege                     = "Create global objects";
        SeCreatePagefilePrivilege                   = "Create a pagefile";
        SeCreatePermanentPrivilege                  = "Create permanent shared objects";
        SeCreateSymbolicLinkPrivilege               = "Create symbolic links";
        SeCreateTokenPrivilege                      = "Create a token object";
        SeDebugPrivilege                            = "Debug programs";
        SeDelegateSessionUserImpersonatePrivilege   = "Impersonate other users";
        SeEnableDelegationPrivilege                 = "Enable computer and user accounts to be trusted for delegation";
        SeImpersonatePrivilege                      = "Impersonate a client after authentication";
        SeIncreaseBasePriorityPrivilege             = "Increase scheduling priority";
        SeIncreaseQuotaPrivilege                    = "Adjust memory quotas for a process";
        SeIncreaseWorkingSetPrivilege               = "Increase a process working set";
        SeLoadDriverPrivilege                       = "Load and unload device drivers";
        SeLockMemoryPrivilege                       = "Lock pages in memory";
        SeMachineAccountPrivilege                   = "Add workstations to domain";
        SeManageVolumePrivilege                     = "Manage the files on a volume";
        SeProfileSingleProcessPrivilege             = "Profile single process";
        SeRelabelPrivilege                          = "Modify an object label";
        SeRemoteShutdownPrivilege                   = "Force shutdown from a remote system";
        SeRestorePrivilege                          = "Restore files and directories";
        SeSecurityPrivilege                         = "Manage auditing and security log";
        SeShutdownPrivilege                         = "Shut down the system";
        SeSyncAgentPrivilege                        = "Synchronize directory service data";
        SeSystemEnvironmentPrivilege                = "Modify firmware environment values";
        SeSystemProfilePrivilege                    = "Profile system performance";
        SeSystemtimePrivilege                       = "Change the system time";
        SeTakeOwnershipPrivilege                    = "Take ownership of files or other objects";
        SeTcbPrivilege                              = "Act as part of the operating system";
        SeTimeZonePrivilege                         = "Change the time zone";
        SeTrustedCredManAccessPrivilege             = "Access Credential Manager as a trusted caller";
        SeUndockPrivilege                           = "Remove computer from docking station";
        SeUnsolicitedInputPrivilege                 = "N/A";
    }

    $TokenHandle = Get-ProcessTokenHandle -ProcessId $ProcessId
    if (-not $TokenHandle) { return }

    $TokenPrivilegesPtr = Get-TokenInformationData -TokenHandle $TokenHandle -InformationClass $script:TOKEN_INFORMATION_CLASS::TokenPrivileges
    if (-not $TokenPrivilegesPtr) { $script:Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [type] $script:TOKEN_PRIVILEGES)

    Write-Verbose "Number of privileges: $($TokenPrivileges.PrivilegeCount)"

    $CurrentPrivilegePtr = [IntPtr] ($TokenPrivilegesPtr.ToInt64() + 4)
    for ($i = 0; $i -lt $TokenPrivileges.PrivilegeCount; $i++) {

        $CurrentPrivilege = [Runtime.InteropServices.Marshal]::PtrToStructure($CurrentPrivilegePtr, [type] $script:LUID_AND_ATTRIBUTES)

        [UInt32] $Length = 0
        $Success = $script:Advapi32::LookupPrivilegeName($null, [ref] $CurrentPrivilege.Luid, $null, [ref] $Length)

        if ($Length -eq 0) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "LookupPrivilegeName - $([ComponentModel.Win32Exception] $LastError)"
            continue
        }

        Write-Verbose "LookupPrivilegeName() OK - Length: $Length"

        $Name = New-Object -TypeName System.Text.StringBuilder
        $Name.EnsureCapacity($Length + 1) |Out-Null
        $Success = $script:Advapi32::LookupPrivilegeName($null, [ref] $CurrentPrivilege.Luid, $Name, [ref] $Length)

        if (-not $Success) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "LookupPrivilegeName - $([ComponentModel.Win32Exception] $LastError)"
            continue
        }

        $PrivilegeName = $Name.ToString()

        Write-Verbose "LookupPrivilegeName() OK - Name: $PrivilegeName - Attributes: 0x$('{0:x8}' -f $CurrentPrivilege.Attributes)"

        $SE_PRIVILEGE_ENABLED = 0x00000002
        $PrivilegeEnabled = ($CurrentPrivilege.Attributes -band $SE_PRIVILEGE_ENABLED) -eq $SE_PRIVILEGE_ENABLED

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $PrivilegeName
        $Result | Add-Member -MemberType "NoteProperty" -Name "State" -Value $(if ($PrivilegeEnabled) { "Enabled" } else { "Disabled" })
        $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $PrivilegeDescriptions[$PrivilegeName]
        $Result

        $CurrentPrivilegePtr = [IntPtr] ($CurrentPrivilegePtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([type] $script:LUID_AND_ATTRIBUTES))
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)
    $script:Kernel32::CloseHandle($TokenHandle) | Out-Null
}

function Get-TokenInformationIntegrityLevel {
    <#
    .SYNOPSIS
    Get the integrity level of a Token.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function leverages the Windows API (GetTokenInformation) to get the integrity level of a Token.

    .PARAMETER ProcessId
    The ID of Process. By default, the value is zero, which means retrieve information from the current process.

    .EXAMPLE
    PS C:\> Get-TokenInformationIntegrityLevel

    Name                                   SID          Type
    ----                                   ---          ----
    Mandatory Label\Medium Mandatory Level S-1-16-8192 Label
    #>

    [CmdletBinding()]
    param(
        [UInt32] $ProcessId = 0
    )

    $TokenHandle = Get-ProcessTokenHandle -ProcessId $ProcessId -ProcessAccess $script:ProcessAccessRightEnum::QUERY_LIMITED_INFORMATION
    if (-not $TokenHandle) { return }

    $TokenMandatoryLabelPtr = Get-TokenInformationData -TokenHandle $TokenHandle -InformationClass $script:TOKEN_INFORMATION_CLASS::TokenIntegrityLevel
    if (-not $TokenMandatoryLabelPtr) { $script:Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenMandatoryLabel = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenMandatoryLabelPtr, [type] $script:TOKEN_MANDATORY_LABEL)

    $SidString = Convert-PSidToStringSid -PSid $TokenMandatoryLabel.Label.Sid
    $SidInfo = Convert-PSidToNameAndType -PSid $TokenMandatoryLabel.Label.Sid
    $TokenIntegrityLevel = Convert-PSidToRid -PSid $TokenMandatoryLabel.Label.Sid

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $SidInfo.Name
    $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $SidInfo.Domain
    $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value $SidInfo.DisplayName
    $Result | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $SidString
    $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value ($SidInfo.Type -as $script:SID_NAME_USE)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Level" -Value $TokenIntegrityLevel

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenMandatoryLabelPtr)
    $script:Kernel32::CloseHandle($TokenHandle) | Out-Null

    $Result
}

function Get-TokenInformationSessionId {
    <#
    .SYNOPSIS
    Get the session ID of a Token.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function leverages the Windows API (GetTokenInformation) to get the session ID of a Token.

    .PARAMETER ProcessId
    The ID of Process. By default, the value is zero, which means retrieve information from the current process.

    .EXAMPLE
    PS C:\> Get-TokenInformationSessionId

    1
    #>

    [OutputType([Int32])]
    [CmdletBinding()]
    param(
        [UInt32] $ProcessId = 0
    )

    $TokenHandle = Get-ProcessTokenHandle -ProcessId $ProcessId
    if (-not $TokenHandle) { return }

    $TokenSessionIdPtr = Get-TokenInformationData -TokenHandle $TokenHandle -InformationClass $script:TOKEN_INFORMATION_CLASS::TokenSessionId
    if (-not $TokenSessionIdPtr) { $script:Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenSessionId = [System.Runtime.InteropServices.Marshal]::ReadInt32($TokenSessionIdPtr)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenSessionIdPtr)
    $script:Kernel32::CloseHandle($TokenHandle) | Out-Null

    $TokenSessionId
}

function Get-TokenInformationStatistic {
    <#
    .SYNOPSIS
    Get general statistics about a Token.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function leverages the Windows API (GetTokenInformation) to get general statistics about a Token.

    .PARAMETER ProcessId
    The ID of Process. By default, the value is zero, which means retrieve information from the current process.

    .EXAMPLE
    PS C:\> Get-TokenInformationStatistic

    TokenId            : WinApiModule.LUID
    AuthenticationId   : WinApiModule.LUID
    ExpirationTime     : WinApiModule.LARGE_INTEGER
    TokenType          : TokenPrimary
    ImpersonationLevel : 0
    DynamicCharged     : 4096
    DynamicAvailable   : 3976
    GroupCount         : 13
    PrivilegeCount     : 5
    ModifiedId         : WinApiModule.LUID
    #>

    [CmdletBinding()]
    param(
        [UInt32] $ProcessId = 0
    )

    $TokenHandle = Get-ProcessTokenHandle -ProcessId $ProcessId
    if (-not $TokenHandle) { return }

    $TokenStatisticsPtr = Get-TokenInformationData -TokenHandle $TokenHandle -InformationClass $script:TOKEN_INFORMATION_CLASS::TokenStatistics
    if (-not $TokenStatisticsPtr) { $script:Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenStatistics = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenStatisticsPtr, [type] $script:TOKEN_STATISTICS)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenStatisticsPtr)
    $script:Kernel32::CloseHandle($TokenHandle) | Out-Null

    $TokenStatistics
}

function Get-TokenInformationOrigin {
    <#
    .SYNOPSIS
    Get the origin of a Token.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function leverages the Windows API (GetTokenInformation) to get the origin of a Token.

    .PARAMETER ProcessId
    The ID of Process. By default, the value is zero, which means retrieve information from the current process.

    .EXAMPLE
    PS C:\> Get-TokenInformationOrigin

    OriginatingLogonSession
    -----------------------
    WinApiModule.LUID
    #>

    [CmdletBinding()]
    param(
        [UInt32] $ProcessId = 0
    )

    $TokenHandle = Get-ProcessTokenHandle -ProcessId $ProcessId
    if (-not $TokenHandle) { return }

    $TokenOriginPtr = Get-TokenInformationData -TokenHandle $TokenHandle -InformationClass $script:TOKEN_INFORMATION_CLASS::TokenOrigin
    if (-not $TokenOriginPtr) { $script:Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenOrigin = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenOriginPtr, [type] $script:TOKEN_ORIGIN)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenOriginPtr)
    $script:Kernel32::CloseHandle($TokenHandle) | Out-Null

    $TokenOrigin
}

function Get-TokenInformationSource {
    <#
    .SYNOPSIS
    Get the source of a Token.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function leverages the Windows API (GetTokenInformation) to get the source of a Token.

    .PARAMETER ProcessId
    The ID of Process. By default, the value is zero, which means retrieve information from the current process.

    .EXAMPLE
    PS C:\> Get-TokenInformationSource

    SourceName             SourceIdentifier
    ----------             ----------------
    {85, 115, 101, 114...} WinApiModule.LUID
    #>

    [CmdletBinding()]
    param(
        [UInt32] $ProcessId = 0
    )

    $TokenHandle = Get-ProcessTokenHandle -ProcessId $ProcessId -TokenAccess $script:TokenAccessRightEnum::QuerySource
    if (-not $TokenHandle) { return }

    $TokenSourcePtr = Get-TokenInformationData -TokenHandle $TokenHandle -InformationClass $script:TOKEN_INFORMATION_CLASS::TokenSource
    if (-not $TokenSourcePtr) { $script:Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenSource = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenSourcePtr, [type] $script:TOKEN_SOURCE)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenSourcePtr)
    $script:Kernel32::CloseHandle($TokenHandle) | Out-Null

    $TokenSource
}

function Get-TokenInformationUser {
    <#
    .SYNOPSIS
    Get the user associated to a Token.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function leverages the Windows API (GetTokenInformation) to get the user associated to a Token.

    .PARAMETER ProcessId
    The ID of a Process to retrieve information from. By default, the value is zero, which means retrieve information from the current process.

    .EXAMPLE
    PS C:\> Get-TokenInformationUser

    DisplayName              SID                                            Type
    -----------              ---                                            ----
    DESKTOP-AAAAAAA\Lab-User S-1-5-21-3539966466-3447975095-3309057754-1002 User
    #>

    [CmdletBinding()]
    param(
        [UInt32] $ProcessId = 0
    )

    $TokenHandle = Get-ProcessTokenHandle -ProcessId $ProcessId
    if (-not $TokenHandle) { return }

    $TokenUserPtr = Get-TokenInformationData -TokenHandle $TokenHandle -InformationClass $script:TOKEN_INFORMATION_CLASS::TokenUser
    if (-not $TokenUserPtr) { $script:Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenUser = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenUserPtr, [type] $script:TOKEN_USER)

    $UserInfo = Convert-PSidToNameAndType -PSid $TokenUser.User.Sid
    $UserSid = Convert-PSidToStringSid -PSid $TokenUser.User.Sid

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value $UserInfo.DisplayName
    $Result | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $UserSid
    $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value ($UserInfo.Type -as $script:SID_NAME_USE)
    $Result

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenUserPtr)
    $script:Kernel32::CloseHandle($TokenHandle) | Out-Null
}

function Get-ObjectName {
    <#
    .SYNOPSIS
    Get the name of a Kernel object (if it has one).

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function leverages the NtQueryObject syscall to get the name of a Kernel object based on its handle.

    .PARAMETER ObjectHandle
    The handle of an object for which we should retrieve the name.
    #>

    [OutputType([String])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [IntPtr] $ObjectHandle
    )

    [UInt32] $DataSize = 0x1000
    [IntPtr] $ObjectNamePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($DataSize)
    [UInt32] $ReturnLength = 0

    while ($true) {

        # ObjectNameInformation = 1
        $Status = $script:Ntdll::NtQueryObject($ObjectHandle, 1, $ObjectNamePtr, $DataSize, [ref] $ReturnLength)
        if ($Status -eq 0xC0000004) {
            $DataSize = $DataSize * 2
            $ObjectNamePtr = [System.Runtime.InteropServices.Marshal]::ReAllocHGlobal($ObjectNamePtr, $DataSize)
        }
        else {
            break
        }
    }

    if ($Status -ne 0) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ObjectNamePtr)
        Write-Verbose "NtQueryObject - 0x$('{0:x8}' -f $Status)"
        return
    }

    $ObjectName = [Runtime.InteropServices.Marshal]::PtrToStructure($ObjectNamePtr, [type] $script:OBJECT_NAME_INFORMATION)
    [Runtime.InteropServices.Marshal]::PtrToStringUni($ObjectName.Name.Buffer)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ObjectNamePtr)
}

function Get-ObjectType {
    <#
    .SYNOPSIS
    Get a list of kernel object types.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Helper - This function leverages the NtQueryObject syscall to list the object types and return a list of PS custom objects containing their index and name.
    #>

    [OutputType([Object[]])]
    [CmdletBinding()]
    param()

    [UInt32] $DataSize = 0x10000
    [IntPtr] $ObjectTypesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($DataSize)
    [UInt32] $ReturnLength = 0

    while ($true) {

        # ObjectTypesInformation = 3
        $Status = $script:Ntdll::NtQueryObject([IntPtr]::Zero, 3, $ObjectTypesPtr, $DataSize, [ref] $ReturnLength)
        if ($Status -eq 0xC0000004) {
            $DataSize = $DataSize * 2
            $ObjectTypesPtr = [System.Runtime.InteropServices.Marshal]::ReAllocHGlobal($ObjectTypesPtr, $DataSize)
        }
        else {
            break
        }
    }

    if ($Status -ne 0) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ObjectTypesPtr)
        Write-Verbose "NtQueryObject - 0x$('{0:x8}' -f $Status)"
        return
    }

    $NumberOfTypes = [UInt32] [Runtime.InteropServices.Marshal]::ReadInt32($ObjectTypesPtr)

    Write-Verbose "Number of types: $($NumberOfTypes)"

    $Offset = (4 + [IntPtr]::Size - 1) -band (-bnot ([IntPtr]::Size - 1))
    $CurrentTypePtr = [IntPtr] ($ObjectTypesPtr.ToInt64() + $Offset)

    for ($i = 0; $i -lt $NumberOfTypes; $i++) {

        $CurrentType = [Runtime.InteropServices.Marshal]::PtrToStructure($CurrentTypePtr, [type] $script:OBJECT_TYPE_INFORMATION)

        $TypeName = [Runtime.InteropServices.Marshal]::PtrToStringUni($CurrentType.TypeName.Buffer)

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Index" -Value $CurrentType.TypeIndex
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $TypeName
        $Result

        $Offset = [Runtime.InteropServices.Marshal]::SizeOf([type] $script:OBJECT_TYPE_INFORMATION)
        $Offset += ($CurrentType.TypeName.MaximumLength + [IntPtr]::Size - 1) -band (-bnot ([IntPtr]::Size - 1))
        $CurrentTypePtr = [IntPtr] ($CurrentTypePtr.ToInt64() + $Offset)
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ObjectTypesPtr)
}

function Get-SystemInformationData {
    <#
    .SYNOPSIS
    Helper - Get system information through a syscall

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This helper leverages the syscall NtQuerySystemInformation to retrieve information about the system.

    .PARAMETER InformationClass
    The class of information to retrieve (e.g. basic, code integrity, processes, handles).

    .NOTES
    The information class is not defined as an enumeration because it is too big. Use hardcoded values instead when calling this function.
    #>

    [OutputType([IntPtr])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [UInt32] $InformationClass
    )

    [UInt32] $DataSize = 0x10000
    [IntPtr] $SystemInformationPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($DataSize)
    [UInt32] $ReturnLength = 0

    while ($true) {

        $Status = $script:Ntdll::NtQuerySystemInformation($InformationClass, $SystemInformationPtr, $DataSize, [ref] $ReturnLength)
        if ($Status -eq 0xC0000004) {
            $DataSize = $DataSize * 2
            $SystemInformationPtr = [System.Runtime.InteropServices.Marshal]::ReAllocHGlobal($SystemInformationPtr, $DataSize)
        }
        else {
            break
        }
    }

    if ($Status -ne 0) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($SystemInformationPtr)
        Write-Verbose "NtQuerySystemInformation - 0x$('{0:x8}' -f $Status)"
        return
    }

    $SystemInformationPtr
}

function Get-SystemInformationExtendedHandle {
    <#
    .SYNOPSIS
    Helper - List system handle information

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This helper calls another helper function - Get-SystemInformationData - in order to get a list of extended system handle information.

    .PARAMETER InheritedOnly
    Include only handles that are inherited from another process.

    .PARAMETER ProcessId
    Include only handles that are opened in a specific process.

    .PARAMETER TypeIndex
    Include only handles of a certain object type.

    .EXAMPLE
    PS C:\> Get-SystemInformationExtendedHandle -InheritedOnly

    Object           : -91242903594912
    UniqueProcessId  : 5980
    HandleValue      : 2964
    GrantedAccess    : 4
    HandleAttributes : 2
    ObjectTypeIndex  : 42
    ObjectType       : Section

    [...]
    #>

    [CmdletBinding()]
    param(
        [Switch] $InheritedOnly = $false,
        [UInt32] $ProcessId = 0,
        [UInt32] $TypeIndex = 0
    )

    $ObjectTypes = Get-ObjectType

    # SystemExtendedHandleInformation = 64
    $SystemHandlesPtr = Get-SystemInformationData -InformationClass 64
    if (-not $SystemHandlesPtr) { return }

    $SystemHandles = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SystemHandlesPtr, [type] $script:SYSTEM_HANDLE_INFORMATION_EX)

    Write-Verbose "Number of handles: $($SystemHandles.NumberOfHandles)"

    $CurrentHandleInfoPtr = [IntPtr] ($SystemHandlesPtr.ToInt64() + ([IntPtr]::Size * 2))
    for ($i = 0; $i -lt $SystemHandles.NumberOfHandles; $i++) {

        if (($i -ne 0) -and (($i % 5000) -eq 0)) {
            Write-Verbose "Collected information about $($i)/$($SystemHandles.NumberOfHandles) handles."
        }

        # Get the handle information structure at the current pointer.
        $CurrentHandleInfo = [Runtime.InteropServices.Marshal]::PtrToStructure($CurrentHandleInfoPtr, [type] $script:SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)

        # Pre-calculate the pointer for the next handle information structure.
        $CurrentHandleInfoPtr = [IntPtr] ($CurrentHandleInfoPtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([type] $script:SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX))

        # If InheritedOnly, ignore handles that are not inherited (HANDLE_INHERIT = 0x2).
        if ($InheritedOnly -and (($CurrentHandleInfo.HandleAttributes -band 0x2) -ne 0x2)) { continue }

        # If a PID filter is set, ignore handles that are not associated to this process.
        if (($ProcessId -ne 0) -and ($CurrentHandleInfo.UniqueProcessId -ne $ProcessId)) { continue }

        # If an object type index is set, ignore handles that are not of this type.
        if (($TypeIndex -ne 0) -and ($CurrentHandleInfo.ObjectTypeIndex -ne $TypeIndex)) { continue }

        $Result = $CurrentHandleInfo | Select-Object Object,UniqueProcessId,HandleValue,GrantedAccess,HandleAttributes,ObjectTypeIndex
        $Result | Add-Member -MemberType "NoteProperty" -Name "ObjectType" -Value $($ObjectTypes | Where-Object { $_.Index -eq $CurrentHandleInfo.ObjectTypeIndex } | Select-Object -ExpandProperty Name)
        $Result
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($SystemHandlesPtr)
}

function Convert-PSidToStringSid {

    [OutputType([String])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [IntPtr] $PSid
    )

    $StringSidPtr = [IntPtr]::Zero
    $Success = $script:Advapi32::ConvertSidToStringSidW($PSid, [ref] $StringSidPtr)

    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "ConvertSidToStringSidW - $([ComponentModel.Win32Exception] $LastError)"
        return
    }

    $StringSid = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($StringSidPtr)
    $script:Kernel32::LocalFree($StringSidPtr) | Out-Null

    $StringSid
}

function Convert-PSidToNameAndType {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [IntPtr] $PSid
    )

    $SidType = 0

    $NameSize = 256
    $Name = New-Object -TypeName System.Text.StringBuilder
    $Name.EnsureCapacity(256) | Out-Null

    $DomainSize = 256
    $Domain = New-Object -TypeName System.Text.StringBuilder
    $Domain.EnsureCapacity(256) | Out-Null

    $Success = $script:Advapi32::LookupAccountSid($null, $PSid, $Name, [ref] $NameSize, $Domain, [ref] $DomainSize, [ref] $SidType)
    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "LookupAccountSid - $([ComponentModel.Win32Exception] $LastError)"
        return
    }

    if ([String]::IsNullOrEmpty($Domain)) {
        $DisplayName = "$($Name)"
    }
    else {
        $DisplayName = "$($Domain)\$($Name)"
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value $DisplayName
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Name
    $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $Domain
    $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $SidType
    $Result
}

function Convert-PSidToRid {

    [OutputType([UInt32])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [IntPtr] $PSid
    )

    $SubAuthorityCountPtr = $script:Advapi32::GetSidSubAuthorityCount($PSid)
    $SubAuthorityCount = [Runtime.InteropServices.Marshal]::ReadByte($SubAuthorityCountPtr)
    $SubAuthorityPtr = $script:Advapi32::GetSidSubAuthority($PSid, $SubAuthorityCount - 1)
    $SubAuthority = [UInt32] [Runtime.InteropServices.Marshal]::ReadInt32($SubAuthorityPtr)
    $SubAuthority
}

function Convert-DosDeviceToDevicePath {
    <#
    .SYNOPSIS
    Helper - Convert a DOS device name (e.g. C:) to its device path

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function leverages the QueryDosDevice API to get the path of a DOS device (e.g. C: -> \Device\HarddiskVolume4)

    .PARAMETER DosDevice
    A DOS device name such as C:
    #>

    [OutputType([String])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String] $DosDevice
    )

    $TargetPathLen = 260
    $TargetPathPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TargetPathLen * 2)
    $TargetPathLen = $script:Kernel32::QueryDosDevice($DosDevice, $TargetPathPtr, $TargetPathLen)

    if ($TargetPathLen -eq 0) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TargetPathPtr)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "QueryDosDevice('$($DosDevice)') - $([ComponentModel.Win32Exception] $LastError)"
        return
    }

    [System.Runtime.InteropServices.Marshal]::PtrToStringUni($TargetPathPtr)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TargetPathPtr)
}

function Get-FileDacl {
    <#
    .SYNOPSIS
    Get security information about a file.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function leverages the Windows API to get some security information about a file, such as the owner and the DACL.

    .PARAMETER Path
    The path of a file such as "C:\Windows\win.ini", "\\.pipe\spoolss"

    .EXAMPLE
    PS C:\> Get-FileDacl -Path C:\Windows\win.ini

    Path     : C:\Windows\win.ini
    Owner    : NT AUTHORITY\SYSTEM
    OwnerSid : S-1-5-18
    Group    : NT AUTHORITY\SYSTEM
    GroupSid : S-1-5-18
    Access   : {System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce...}
    SDDL     : O:SYG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(A;ID;0x1200a9;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)

    .EXAMPLE
    PS C:\> Get-FileDacl -Path \\.\pipe\spoolss

    Path     : \\.\pipe\spoolss
    Owner    : NT AUTHORITY\SYSTEM
    OwnerSid : S-1-5-18
    Group    : NT AUTHORITY\SYSTEM
    GroupSid : S-1-5-18
    Access   : {System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce...}
    SDDL     : O:SYG:SYD:(A;;0x100003;;;BU)(A;;0x1201bb;;;WD)(A;;0x1201bb;;;AN)(A;;FA;;;CO)(A;;FA;;;SY)(A;;FA;;;BA)
    #>

    [CmdletBinding()]
    param(
        [String] $Path
    )

    $DesiredAccess = $script:FileAccessRightEnum::ReadControl
    $ShareMode = 0x00000001 # FILE_SHARE_READ
    $CreationDisposition = 3 # OPEN_EXISTING
    $FlagsAndAttributes = 0x80 # FILE_ATTRIBUTE_NORMAL
    $FileHandle = $script:Kernel32::CreateFile($Path, $DesiredAccess, $ShareMode, [IntPtr]::Zero, $CreationDisposition, $FlagsAndAttributes, [IntPtr]::Zero)

    if ($FileHandle -eq [IntPtr]-1) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "CreateFile KO - $([ComponentModel.Win32Exception] $LastError)"
        return
    }

    $ObjectType = 6 # SE_KERNEL_OBJECT
    $SecurityInfo = 7 # DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION
    $SidOwnerPtr = [IntPtr]::Zero
    $SidGroupPtr = [IntPtr]::Zero
    $DaclPtr = [IntPtr]::Zero
    $SaclPtr = [IntPtr]::Zero
    $SecurityDescriptorPtr = [IntPtr]::Zero
    $Result = $script:Advapi32::GetSecurityInfo($FileHandle, $ObjectType, $SecurityInfo, [ref] $SidOwnerPtr, [ref] $SidGroupPtr, [ref] $DaclPtr, [ref] $SaclPtr, [ref] $SecurityDescriptorPtr)

    if ($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "GetSecurityInfo KO ($Result) - $([ComponentModel.Win32Exception] $LastError)"
        $script:Kernel32::CloseHandle($FileHandle) | Out-Null
        return
    }

    $OwnerSidString = Convert-PSidToStringSid -PSid $SidOwnerPtr
    $OwnerSidInfo = Convert-PSidToNameAndType -PSid $SidOwnerPtr
    $GroupSidString = Convert-PSidToStringSid -PSid $SidGroupPtr
    $GroupSidInfo = Convert-PSidToNameAndType -PSid $SidGroupPtr

    $SecurityDescriptorString = ""
    $SecurityDescriptorStringLen = 0
    $Success = $script:Advapi32::ConvertSecurityDescriptorToStringSecurityDescriptor($SecurityDescriptorPtr, 1, $SecurityInfo, [ref] $SecurityDescriptorString, [ref] $SecurityDescriptorStringLen)

    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "ConvertSecurityDescriptorToStringSecurityDescriptor KO ($Result) - $([ComponentModel.Win32Exception] $LastError)"
        $script:Kernel32::LocalFree($SecurityDescriptorPtr) | Out-Null
        $script:Kernel32::CloseHandle($FileHandle) | Out-Null
        return
    }

    $SecurityDescriptorNewPtr = [IntPtr]::Zero
    $SecurityDescriptorNewSize = 0
    $Success = $script:Advapi32::ConvertStringSecurityDescriptorToSecurityDescriptor($SecurityDescriptorString, 1, [ref] $SecurityDescriptorNewPtr, [ref] $SecurityDescriptorNewSize)

    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "ConvertStringSecurityDescriptorToSecurityDescriptor KO ($Result) - $([ComponentModel.Win32Exception] $LastError)"
        $script:Kernel32::LocalFree($SecurityDescriptorPtr) | Out-Null
        $script:Kernel32::CloseHandle($FileHandle) | Out-Null
        return
    }

    $SecurityDescriptorNewBytes = New-Object Byte[]($SecurityDescriptorNewSize)
    for ($i = 0; $i -lt $SecurityDescriptorNewSize; $i++) {
        $Offset = [IntPtr] ($SecurityDescriptorNewPtr.ToInt64() + $i)
        $SecurityDescriptorNewBytes[$i] = [Runtime.InteropServices.Marshal]::ReadByte($Offset)
    }

    $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $SecurityDescriptorNewBytes, 0

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Path
    $Result | Add-Member -MemberType "NoteProperty" -Name "Owner" -Value $OwnerSidInfo.DisplayName
    $Result | Add-Member -MemberType "NoteProperty" -Name "OwnerSid" -Value $OwnerSidString
    $Result | Add-Member -MemberType "NoteProperty" -Name "Group" -Value $GroupSidInfo.DisplayName
    $Result | Add-Member -MemberType "NoteProperty" -Name "GroupSid" -Value $GroupSidString
    $Result | Add-Member -MemberType "NoteProperty" -Name "Access" -Value $RawSecurityDescriptor.DiscretionaryAcl
    $Result | Add-Member -MemberType "NoteProperty" -Name "SDDL" -Value $SecurityDescriptorString
    $Result

    $script:Kernel32::LocalFree($SecurityDescriptorNewPtr) | Out-Null
    $script:Kernel32::LocalFree($SecurityDescriptorPtr) | Out-Null
    $script:Kernel32::CloseHandle($FileHandle) | Out-Null
}

function Disable-Wow64FileSystemRedirection {
    <#
    .SYNOPSIS
    Disable filesystem redirection in Wow64 processes.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet invokes the Wow64DisableWow64FsRedirection API to temporarily disable file system redirection when running from a Wow64 PowerShell process.

    .NOTES
    https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-wow64disablewow64fsredirection
    #>

    [OutputType([IntPtr])]
    [CmdletBinding()]
    param ()

    begin {
        $OldValue = [IntPtr]::Zero
    }

    process {
        if ([IntPtr]::Size -eq 4) {
            if ($script:Kernel32::Wow64DisableWow64FsRedirection([ref] $OldValue)) {
                Write-Verbose "Wow64 file system redirection was disabled."
            }
            else {
                $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Wow64DisableWow64FsRedirection KO ($Result) - $([ComponentModel.Win32Exception] $LastError)"
            }
        }
    }

    end {
        $OldValue
    }
}

function Restore-Wow64FileSystemRedirection {
    <#
    .SYNOPSIS
    Restore filesystem redirection in Wow64 processes.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet invokes the Wow64RevertWow64FsRedirection API to re-enable file system redirection when running from a Wow64 PowerShell process.

    .PARAMETER OldValue
    The value returned by Disable-Wow64FileSystemRedirection.

    .NOTES
    https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-wow64revertwow64fsredirection
    #>

    [CmdletBinding()]
    param (
        [IntPtr] $OldValue
    )

    process {
        if ([IntPtr]::Size -eq 4) {
            if ($script:Kernel32::Wow64RevertWow64FsRedirection($OldValue)) {
                Write-Verbose "Wow64 file system redirection was restored."
            }
            else {
                $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Wow64RevertWow64FsRedirection KO ($Result) - $([ComponentModel.Win32Exception] $LastError)"
            }
        }
    }
}

function Get-FileExtensionAssociation {
    <#
    .SYNOPSIS
    Get the executable or command associated to a file extension.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet calls the API 'AssocQueryString' to query the executable or command associated to a file extension.

    .PARAMETER Extension
    A file extension to query (e.g. ".bat"). The dot (".") is mandatory; if not specified, the API 'AssocQueryString' will fail.

    .PARAMETER Type
    The type of association to query: executable or command line. This parameter is optional and defaults to "Executable" if not specified.

    .EXAMPLE
    PS C:\> Get-FileExtensionAssociation -Extension .wsh -Type Command
    "C:\Windows\System32\WScript.exe" "%1" %*

    .EXAMPLE
    PS C:\> Get-FileExtensionAssociation -Extension .wsh
    C:\Windows\System32\WScript.exe
    #>

    [CmdletBinding()]
    param (
        [ValidateNotNullOrEmpty()]
        [string] $Extension,
        [ValidateSet("Command", "Executable")]
        [string] $Type = "Executable"
    )

    begin {
        switch ($Type) {
            "Command" { $AssocType = $script:ASSOCSTR::ASSOCSTR_COMMAND; break }
            "Executable" { $AssocType = $script:ASSOCSTR::ASSOCSTR_EXECUTABLE; break }
            default { $AssocType = $script:ASSOCSTR::ASSOCSTR_EXECUTABLE }
        }
    }

    process {

        # The fourth parameter of "AssocQueryString" is an optional string that we don't
        # use. Passing "$null" wouldn't work because it would be casted as an empty string.
        # To actually pass a null value, we must use NullString::Value, but this is not
        # available in PSv2. As an alternative, the type of the unused parameter is set to
        # IntPtr, so we can actually pass null (see API declaration).

        [UInt32] $Length = 0
        $Result = $script:Shlwapi::AssocQueryStringW($script:ASSOCF::ASSOCF_NONE, $AssocType, $Extension, [IntPtr]::Zero, $null, [ref] $Length)
        if ($Result -ne 1) {
            if ($Result -eq 0x80070483) {
                Write-Warning "No file extension association found for '$($Extension)'."
            }
            else {
                Write-Warning "AssocQueryStringW KO ($Result)"
            }
            return
        }

        $ExtAssociation = New-Object -TypeName System.Text.StringBuilder
        $ExtAssociation.EnsureCapacity($Length + 1) | Out-Null
        $Result = $script:Shlwapi::AssocQueryStringW($script:ASSOCF::ASSOCF_NONE, $AssocType, $Extension, [IntPtr]::Zero, $ExtAssociation, [ref] $Length)
        if ($Result -ne 0) {
            Write-Warning "AssocQueryStringW KO ($Result)"
            return
        }

        $ExtAssociation.ToString()
    }
}

function Get-NetWkstaInfo {
    <#
    .SYNOPSIS
    Wrapper for the API NetWkstaGetInfo

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet is a wrapper for the Windows API NetWkstaGetInfo.

    .PARAMETER Level
    Specifies the information level of the data.

    .EXAMPLE
    PS C:\> Get-NetWkstaGetInfo -Level 102

    PlatformId    : 500
    ComputerName  : DESKTOP-AAAAAAA
    LanGroup      : WORKGROUP
    VerMajor      : 10
    VerMinor      : 0
    LanRoot       :
    LoggedOnUsers : 2

    .LINK
    https://learn.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstagetinfo
    #>

    [CmdletBinding()]
    param (
        [ValidateSet(100, 101, 102)]
        [UInt32] $Level = 100
    )

    begin {
        switch ($Level) {
            100 { $InfoType = $script:WKSTA_INFO_100 }
            101 { $InfoType = $script:WKSTA_INFO_101 }
            102 { $InfoType = $script:WKSTA_INFO_102 }
        }
    }

    process {
        $BufferPtr = [IntPtr]::Zero
        $RetVal = $Netapi32::NetWkstaGetInfo([IntPtr]::Zero, $Level, [ref] $BufferPtr)
        if ($RetVal -ne 0) {
            Write-Warning "NetWkstaGetInfo - $([ComponentModel.Win32Exception] $RetVal)"
            return
        }

        [System.Runtime.InteropServices.Marshal]::PtrToStructure($BufferPtr, [type] $InfoType)

        $RetVal = $Netapi32::NetApiBufferFree($BufferPtr)
        if ($RetVal -ne 0) {
            Write-Warning "NetApiBufferFree - $([ComponentModel.Win32Exception] $RetVal)"
            return
        }
    }
}

function ConvertTo-ArgumentList {
    <#
    .SYNOPSIS
    Wrapper for the API CommandLineToArgvW

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet is a wrapper for the Windows API CommandLineToArgvW.

    .PARAMETER CommandLine
    Unicode string that contains the full command line.
    #>

    [OutputType([string[]])]
    [CmdletBinding()]
    param (
        [string] $CommandLine
    )

    process {
        $NumArgs = [Int32] 0
        $RetVal = $script:Shell32::CommandLineToArgvW($CommandLine, [ref] $NumArgs)
        if ($RetVal -eq [IntPtr]::Zero) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "CommandLineToArgvW - $([ComponentModel.Win32Exception] $LastError)"
            return
        }

        $Arguments = [string[]] @()
        $PointerArrayPtr = $RetVal
        for ($i = 0; $i -lt $NumArgs; $i++) {

            $ArgumentPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($PointerArrayPtr)
            $Arguments += [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ArgumentPtr)

            $PointerArrayPtr = [IntPtr] ($PointerArrayPtr.ToInt64() + [IntPtr]::Size)
        }

        $Arguments

        $script:Kernel32::LocalFree($RetVal) | Out-Null
    }
}

function Resolve-ModulePath {
    <#
    .SYNOPSIS
    Resolve the full path of a module given its filename.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet uses the Windows APIs LoadLibrary and GetModuleFileName to retrieve the full path of a module given its name. If the module is not found, the return value is null.

    .PARAMETER Name
    The name of a module (EXE or DLL).

    .EXAMPLE
    PS C:\> Resolve-ModulePath -Name combase
    C:\Windows\System32\combase.dll

    .NOTES
    According to the documentation, using LoadLibrary is the recommended method for finding a module. The API SearchPath is not recommended as it is not guaranteed to use the same search order as LoadLibrary.

    .LINK
    https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-searchpatha#remarks
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String] $Name
    )

    begin {
        $ModuleHandle = [IntPtr]::Zero
        $MaxPathLength = 32767
    }

    process {
        $RetVal = $script:Kernel32::LoadLibrary($Name)
        if ($RetVal -eq [IntPtr]::Zero) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "LoadLibrary(`"$($Name)`") - $([ComponentModel.Win32Exception] $LastError)"
            return
        }

        $ModuleHandle = $RetVal

        $ModuleFileNameLength = 64
        $ModuleFileName = New-Object -TypeName System.Text.StringBuilder

        do {
            if ($ModuleFileNameLength -gt $MaxPathLength) { break }

            $ModuleFileName.EnsureCapacity($ModuleFileNameLength) | Out-Null

            # If the return value of GetModuleFileName is 0, it means that the API
            # failed. In that case, get the last error code, print the error
            # message, and return.
            $RetVal = $script:Kernel32::GetModuleFileName($ModuleHandle, $ModuleFileName, $ModuleFileNameLength)
            if ($RetVal -eq 0) {
                $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "GetModuleFileName - $([ComponentModel.Win32Exception] $LastError)"
                return
            }

            # If the return value is the length of our string buffer, it could mean that
            # it is too small. In that case, check the last error code. If the error code
            # is "insufficient buffer", then double the size of the buffer and try again.
            # Otherwise, print an error.
            if ($RetVal -eq $ModuleFileNameLength) {
                $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if ($LastError -eq $script:SystemErrorCodeEnum::ERROR_INSUFFICIENT_BUFFER) {
                    $ModuleFileNameLength = $ModuleFileNameLength * 2
                    continue
                }
                else {
                    Write-Warning "GetModuleFileName - $([ComponentModel.Win32Exception] $LastError)"
                    return
                }
            }

            $ModuleFileName.ToString()
            break

        } while ($true)
    }

    end {
        if ($ModuleHandle -ne [IntPtr]::Zero) {
            $script:Kernel32::FreeLibrary($ModuleHandle) | Out-Null
        }
    }
}

function Resolve-PathRelativeTo {
    <#
    .SYNOPSIS
    Determine a file or folder path relative to another path.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet uses the Windows API PathRelativePathToW to determine the path of a file or folder relative to another path. For example, the path of 'C:\Windows\System32', relative to 'C:\Windows', is '.\System32'.

    .PARAMETER From
    The base path (e.g. 'C:\Windows').

    .PARAMETER To
    The target path (e.g. 'C:\Windows\System32').

    .EXAMPLE
    C:\> Resolve-PathRelativeTo -From 'C:\windows' -To 'C:\Windows\system32'
    .\system32
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String] $From,
        [Parameter(Mandatory=$true)]
        [String] $To
    )

    begin {
        $FILE_ATTRIBUTE_DIRECTORY = 16
        $FILE_ATTRIBUTE_NORMAL = 128
        $MAX_PATH = 260
    }

    process {
        $PathOut = New-Object -TypeName System.Text.StringBuilder
        $PathOut.EnsureCapacity($MAX_PATH) | Out-Null

        $Result = $script:Shlwapi::PathRelativePathTo($PathOut, $From, $FILE_ATTRIBUTE_DIRECTORY, $To, $FILE_ATTRIBUTE_NORMAL)
        if (-not $Result) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Warning "PathRelativePathTo(`"$($From)`", `"$($To)`") error - $([ComponentModel.Win32Exception] $LastError)"
            return
        }

        $PathOut.ToString()
    }
}