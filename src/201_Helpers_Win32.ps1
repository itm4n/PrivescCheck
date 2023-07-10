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
    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0,
        [UInt32]$ProcessAccess = $ProcessAccessRightsEnum::QUERY_INFORMATION,
        [UInt32]$TokenAccess = $TokenAccessRightsEnum::Query
    )

    if ($ProcessId -eq 0) {
        $ProcessHandle = $Kernel32::GetCurrentProcess()
    }
    else {
        $ProcessHandle = $Kernel32::OpenProcess($ProcessAccess, $false, $ProcessId)

        if ($ProcessHandle -eq [IntPtr]::Zero) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "OpenProcess($($ProcessId), 0x$('{0:x8}' -f $ProcessAccess))) - $([ComponentModel.Win32Exception] $LastError)"
            return
        }
    }

    [IntPtr]$TokenHandle = [IntPtr]::Zero
    $Success = $Advapi32::OpenProcessToken($ProcessHandle, $TokenAccess, [ref]$TokenHandle)
    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "OpenProcessToken - $([ComponentModel.Win32Exception] $LastError)"
        $Kernel32::CloseHandle($ProcessHandle) | Out-Null
        return
    }

    $Kernel32::CloseHandle($ProcessHandle) | Out-Null

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
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [IntPtr]$TokenHandle,
        [Parameter(Mandatory=$true)]
        [UInt32]$InformationClass
    )

    $DataSize = 0
    $Success = $Advapi32::GetTokenInformation($TokenHandle, $InformationClass, 0, $null, [ref]$DataSize)
    if ($DataSize -eq 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "GetTokenInformation - $([ComponentModel.Win32Exception] $LastError)"
        return
    }

    [IntPtr]$DataPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($DataSize)

    $Success = $Advapi32::GetTokenInformation($TokenHandle, $InformationClass, $DataPtr, $DataSize, [ref]$DataSize)
    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "GetTokenInformation - $([ComponentModel.Win32Exception] $LastError)"
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($DataPtr)
        return
    }

    $DataPtr
}

function Get-TokenInformationGroups {
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
    PS C:\> Get-TokenInformationGroups -InformationClass Groups

    Name                                   Type           SID                                           Attributes
    ----                                   ----           ---                                           ----------
    DESKTOP-E1BRKMO\None                   Group          S-1-5-21-3539966466-3447975095-3309057754-513 Mandatory, Enabled, EnabledByDefault
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

    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0,
        [Parameter(Mandatory=$true)]
        [ValidateSet("Groups", "RestrictedSids", "LogonSid", "Capabilities", "DeviceGroups", "RestrictedDeviceGroups")]
        [String]$InformationClass
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
    if (-not $TokenGroupsPtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenGroups = [Runtime.InteropServices.Marshal]::PtrToStructure($TokenGroupsPtr, [type] $TOKEN_GROUPS)

    # Offset of the first SID_AND_ATTRIBUTES structure is +4 in 32-bits, and +8 in 64-bits (because
    # of the structure alignment in memory). Therefore we can use [IntPtr]::Size as the offset's
    # value for the first item in the array.
    $CurrentGroupPtr = [IntPtr] ($TokenGroupsPtr.ToInt64() + [IntPtr]::Size)
    for ($i = 0; $i -lt $TokenGroups.GroupCount; $i++) {

        $CurrentGroup = [Runtime.InteropServices.Marshal]::PtrToStructure($CurrentGroupPtr, [type] $SID_AND_ATTRIBUTES)

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

        $CurrentGroupPtr = [IntPtr] ($CurrentGroupPtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([type] $SID_AND_ATTRIBUTES))
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenGroupsPtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null
}

function Get-TokenInformationPrivileges {
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
    PS C:\> Get-TokenInformationPrivileges

    Name                          State    Description
    ----                          -----    -----------
    SeShutdownPrivilege           Disabled Shut down the system
    SeChangeNotifyPrivilege       Enabled  Bypass traverse checking
    SeUndockPrivilege             Disabled Remove computer from docking station
    SeIncreaseWorkingSetPrivilege Disabled Increase a process working set
    SeTimeZonePrivilege           Disabled Change the time zone
    #>

    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0
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

    $TokenPrivilegesPtr = Get-TokenInformationData -TokenHandle $TokenHandle -InformationClass $TOKEN_INFORMATION_CLASS::TokenPrivileges
    if (-not $TokenPrivilegesPtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [type] $TOKEN_PRIVILEGES)

    Write-Verbose "Number of privileges: $($TokenPrivileges.PrivilegeCount)"

    $CurrentPrivilegePtr = [IntPtr] ($TokenPrivilegesPtr.ToInt64() + 4)
    for ($i = 0; $i -lt $TokenPrivileges.PrivilegeCount; $i++) {

        $CurrentPrivilege = [Runtime.InteropServices.Marshal]::PtrToStructure($CurrentPrivilegePtr, [type] $LUID_AND_ATTRIBUTES)

        [UInt32]$Length = 0
        $Success = $Advapi32::LookupPrivilegeName($null, [ref] $CurrentPrivilege.Luid, $null, [ref]$Length)

        if ($Length -eq 0) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "LookupPrivilegeName - $([ComponentModel.Win32Exception] $LastError)"
            continue
        }

        Write-Verbose "LookupPrivilegeName() OK - Length: $Length"

        $Name = New-Object -TypeName System.Text.StringBuilder
        $Name.EnsureCapacity($Length + 1) |Out-Null
        $Success = $Advapi32::LookupPrivilegeName($null, [ref] $CurrentPrivilege.Luid, $Name, [ref]$Length)

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

        $CurrentPrivilegePtr = [IntPtr] ($CurrentPrivilegePtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([type] $LUID_AND_ATTRIBUTES))
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null
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

    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0
    )

    $TokenHandle = Get-ProcessTokenHandle -ProcessId $ProcessId -ProcessAccess $ProcessAccessRightsEnum::QUERY_LIMITED_INFORMATION
    if (-not $TokenHandle) { return }

    $TokenMandatoryLabelPtr = Get-TokenInformationData -TokenHandle $TokenHandle -InformationClass $TOKEN_INFORMATION_CLASS::TokenIntegrityLevel
    if (-not $TokenMandatoryLabelPtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenMandatoryLabel = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenMandatoryLabelPtr, [type] $TOKEN_MANDATORY_LABEL)

    $SidString = Convert-PSidToStringSid -PSid $TokenMandatoryLabel.Label.Sid
    $SidInfo = Convert-PSidToNameAndType -PSid $TokenMandatoryLabel.Label.Sid
    $TokenIntegrityLevel = Convert-PSidToRid -PSid $TokenMandatoryLabel.Label.Sid

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $SidInfo.Name
    $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $SidInfo.Domain
    $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value $SidInfo.DisplayName
    $Result | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $SidString
    $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value ($SidInfo.Type -as $SID_NAME_USE)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Level" -Value $TokenIntegrityLevel

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenMandatoryLabelPtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null

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
    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0
    )

    $TokenHandle = Get-ProcessTokenHandle -ProcessId $ProcessId
    if (-not $TokenHandle) { return }

    $TokenSessionIdPtr = Get-TokenInformationData -TokenHandle $TokenHandle -InformationClass $TOKEN_INFORMATION_CLASS::TokenSessionId
    if (-not $TokenSessionIdPtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenSessionId = [System.Runtime.InteropServices.Marshal]::ReadInt32($TokenSessionIdPtr)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenSessionIdPtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null

    $TokenSessionId
}

function Get-TokenInformationStatistics {
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
    PS C:\> Get-TokenInformationStatistics

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

    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0
    )

    $TokenHandle = Get-ProcessTokenHandle -ProcessId $ProcessId
    if (-not $TokenHandle) { return }

    $TokenStatisticsPtr = Get-TokenInformationData -TokenHandle $TokenHandle -InformationClass $TOKEN_INFORMATION_CLASS::TokenStatistics
    if (-not $TokenStatisticsPtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenStatistics = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenStatisticsPtr, [type] $TOKEN_STATISTICS)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenStatisticsPtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null

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

    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0
    )

    $TokenHandle = Get-ProcessTokenHandle -ProcessId $ProcessId
    if (-not $TokenHandle) { return }

    $TokenOriginPtr = Get-TokenInformationData -TokenHandle $TokenHandle -InformationClass $TOKEN_INFORMATION_CLASS::TokenOrigin
    if (-not $TokenOriginPtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenOrigin = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenOriginPtr, [type] $TOKEN_ORIGIN)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenOriginPtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null

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

    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0
    )

    $TokenHandle = Get-ProcessTokenHandle -ProcessId $ProcessId -TokenAccess $TokenAccessRightsEnum::QuerySource
    if (-not $TokenHandle) { return }

    $TokenSourcePtr = Get-TokenInformationData -TokenHandle $TokenHandle -InformationClass $TOKEN_INFORMATION_CLASS::TokenSource
    if (-not $TokenSourcePtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenSource = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenSourcePtr, [type] $TOKEN_SOURCE)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenSourcePtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null

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
    DESKTOP-E1BRKMO\Lab-User S-1-5-21-3539966466-3447975095-3309057754-1002 User
    #>

    [CmdletBinding()] Param(
        [UInt32]$ProcessId = 0
    )

    $TokenHandle = Get-ProcessTokenHandle -ProcessId $ProcessId
    if (-not $TokenHandle) { return }

    $TokenUserPtr = Get-TokenInformationData -TokenHandle $TokenHandle -InformationClass $TOKEN_INFORMATION_CLASS::TokenUser
    if (-not $TokenUserPtr) { $Kernel32::CloseHandle($TokenHandle) | Out-Null; return }

    $TokenUser = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenUserPtr, [type] $TOKEN_USER)

    $UserInfo = Convert-PSidToNameAndType -PSid $TokenUser.User.Sid
    $UserSid = Convert-PSidToStringSid -PSid $TokenUser.User.Sid

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value $UserInfo.DisplayName
    $Result | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $UserSid
    $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value ($UserInfo.Type -as $SID_NAME_USE)
    $Result

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenUserPtr)
    $Kernel32::CloseHandle($TokenHandle) | Out-Null
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
    The handle of an object for wchich we should retrieve the name.
    #>

    [OutputType([String])]
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [IntPtr]$ObjectHandle
    )

    [UInt32]$DataSize = 0x1000
    [IntPtr]$ObjectNamePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($DataSize)
    [UInt32]$ReturnLength = 0

    while ($true) {

        # ObjectNameInformation = 1
        $Status = $Ntdll::NtQueryObject($ObjectHandle, 1, $ObjectNamePtr, $DataSize, [ref] $ReturnLength)
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

    $ObjectName = [Runtime.InteropServices.Marshal]::PtrToStructure($ObjectNamePtr, [type] $OBJECT_NAME_INFORMATION)
    [Runtime.InteropServices.Marshal]::PtrToStringUni($ObjectName.Name.Buffer)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ObjectNamePtr)
}

function Get-ObjectTypes {
    <#
    .SYNOPSIS
    Get a list of kernel object types.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Helper - This function leverages the NtQueryObject syscall to list the object types and return a list of PS custom objects containing their index and name.
    #>

    [OutputType([Object[]])]
    [CmdletBinding()] Param()

    [UInt32]$DataSize = 0x10000
    [IntPtr]$ObjectTypesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($DataSize)
    [UInt32]$ReturnLength = 0

    while ($true) {

        # ObjectTypesInformation = 3
        $Status = $Ntdll::NtQueryObject([IntPtr]::Zero, 3, $ObjectTypesPtr, $DataSize, [ref] $ReturnLength)
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

        $CurrentType = [Runtime.InteropServices.Marshal]::PtrToStructure($CurrentTypePtr, [type] $OBJECT_TYPE_INFORMATION)

        $TypeName = [Runtime.InteropServices.Marshal]::PtrToStringUni($CurrentType.TypeName.Buffer)

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Index" -Value $CurrentType.TypeIndex
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $TypeName
        $Result

        $Offset = [Runtime.InteropServices.Marshal]::SizeOf([type] $OBJECT_TYPE_INFORMATION)
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
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [UInt32]$InformationClass
    )

    [UInt32]$DataSize = 0x10000
    [IntPtr]$SystemInformationPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($DataSize)
    [UInt32]$ReturnLength = 0

    while ($true) {

        $Status = $Ntdll::NtQuerySystemInformation($InformationClass, $SystemInformationPtr, $DataSize, [ref] $ReturnLength)
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

function Get-SystemInformationExtendedHandles {
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
    PS C:\> Get-SystemInformationExtendedHandles -InheritedOnly

    Object           : -91242903594912
    UniqueProcessId  : 5980
    HandleValue      : 2964
    GrantedAccess    : 4
    HandleAttributes : 2
    ObjectTypeIndex  : 42
    ObjectType       : Section

    [...]
    #>

    [CmdletBinding()] Param(
        [Switch]$InheritedOnly = $false,
        [UInt32]$ProcessId = 0,
        [UInt32]$TypeIndex = 0
    )

    $ObjectTypes = Get-ObjectTypes

    # SystemExtendedHandleInformation = 64
    $SystemHandlesPtr = Get-SystemInformationData -InformationClass 64
    if (-not $SystemHandlesPtr) { return }

    $SystemHandles = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SystemHandlesPtr, [type] $SYSTEM_HANDLE_INFORMATION_EX)
    
    Write-Verbose "Number of handles: $($SystemHandles.NumberOfHandles)"

    $CurrentHandleInfoPtr = [IntPtr] ($SystemHandlesPtr.ToInt64() + ([IntPtr]::Size * 2))
    for ($i = 0; $i -lt $SystemHandles.NumberOfHandles; $i++) {

        if (($i -ne 0) -and (($i % 5000) -eq 0)) {
            Write-Verbose "Collected information about $($i)/$($SystemHandles.NumberOfHandles) handles."
        }

        # Get the handle information structure at the current pointer.
        $CurrentHandleInfo = [Runtime.InteropServices.Marshal]::PtrToStructure($CurrentHandleInfoPtr, [type] $SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)

        # Pre-calculate the pointer for the next handle information structure.
        $CurrentHandleInfoPtr = [IntPtr] ($CurrentHandleInfoPtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([type] $SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX))

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