function Convert-FiletimeToDatetime {
    [CmdletBinding()] Param(
        [Parameter(Position = 1, Mandatory=$true)]
        [Object] # FILETIME
        $Filetime
    )

    [Int64]$Time = $Filetime.LowDateTime + $Filetime.HighDateTime * 0x100000000
    [DateTime]::FromFileTimeUtc($Time)
}

function Convert-SidStringToSid {

    [CmdletBinding()] Param(
        [String]$Sid
    )

    try {
        $IdentityUser = New-Object System.Security.Principal.NTAccount($(Convert-SidToName -Sid $Sid))
        $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch {

    }
}

function Convert-SidToName {
    <#
    .SYNOPSIS
    Helper - Converts a SID string to its corresponding username

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    This helper function takes a user SID as an input parameter and returns the account name associated to this SID. If an account name cannot be found, nothing is returned.
    
    .PARAMETER Sid
    A user account SID, e.g.: S-1-5-18.
    
    .EXAMPLE
    An example
    PS C:\> Convert-SidToName -Sid S-1-5-18"

    NT AUTHORITY\SYSTEM
    #>

    [CmdletBinding()] Param(
        [String]$Sid
    )

    try {
        $SidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $SidObj.Translate([System.Security.Principal.NTAccount]) | Select-Object -ExpandProperty Value
    }
    catch {
        # Do nothing
    }
}

function Convert-DateToString {
    <#
    .SYNOPSIS
    Helper - Converts a DateTime object to a string representation

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    The output string is a simplified version of the ISO format: YYYY-MM-DD hh:mm:ss. 
    
    .PARAMETER Date
    A System.DateTime object
    
    .EXAMPLE
    PS C:\> $Date = Get-Date; Convert-DateToString -Date $Date

    2020-01-16 - 10:26:11
    #>
    
    [CmdletBinding()] Param(
        [System.DateTime]
        $Date
    )

    $OutString = ""
    $OutString += $Date.ToString('yyyy-MM-dd - HH:mm:ss')
    #$OutString += " ($($Date.ToString('o')))" # ISO format
    $OutString
}

function Test-IsKnownService {

    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [Object]
        $Service
    )

    $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")

    foreach ($SeparationCharacterSet in $SeparationCharacterSets) {

        $CandidatePaths = ($Service.ImagePath).Split($SeparationCharacterSet) | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.trim())) }

        foreach ($CandidatePath in $CandidatePaths) {

            $TempPath = $([System.Environment]::ExpandEnvironmentVariables($CandidatePath))

            $TempPathResolved = Resolve-Path -Path $TempPath -ErrorAction SilentlyContinue -ErrorVariable ErrorResolvePath
            if ($ErrorResolvePath) { continue }

            $File = Get-Item -Path $TempPathResolved -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItem
            if ($ErrorGetItem) { continue }

            if ($File -and ($File.VersionInfo.LegalCopyright -Like "*Microsoft Corporation*")) { return $true }

            return $false
        }
    }

    return $false
}

function Get-UserPrivileges {
    <#
    .SYNOPSIS
    Helper - Enumerates the privileges of the current user 

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Enumerates the privileges of the current user using the Windows API. First, it gets a handle to the current access token using OpenProcessToken. Then it calls GetTokenInformation to list all the privileges that it contains along with their state (enabled/disabled). For each result a custom object is returned, indicating the name of the privilege and its state. 
    
    .EXAMPLE
    PS C:\> Get-UserPrivileges

    Name                          State    Description
    ----                          ------   -----------
    SeShutdownPrivilege           Disabled Shut down the system
    SeChangeNotifyPrivilege       Enabled  Bypass traverse checking
    SeUndockPrivilege             Disabled Remove computer from docking station
    SeIncreaseWorkingSetPrivilege Disabled Increase a process working set
    SeTimeZonePrivilege           Disabled Change the time zone

    .LINK
    https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
    #>
    
    [CmdletBinding()] Param()

    function Get-PrivilegeDescription {
        [CmdletBinding()] Param(
            [String]
            $Name
        )

        $PrivilegeDescriptions = @{
            "SeAssignPrimaryTokenPrivilege" =               "Replace a process-level token";
            "SeAuditPrivilege" =                            "Generate security audits";
            "SeBackupPrivilege" =                           "Back up files and directories";
            "SeChangeNotifyPrivilege" =                     "Bypass traverse checking";
            "SeCreateGlobalPrivilege" =                     "Create global objects";
            "SeCreatePagefilePrivilege" =                   "Create a pagefile";
            "SeCreatePermanentPrivilege" =                  "Create permanent shared objects";
            "SeCreateSymbolicLinkPrivilege" =               "Create symbolic links";
            "SeCreateTokenPrivilege" =                      "Create a token object";
            "SeDebugPrivilege" =                            "Debug programs";
            "SeDelegateSessionUserImpersonatePrivilege" =   "Impersonate other users";
            "SeEnableDelegationPrivilege" =                 "Enable computer and user accounts to be trusted for delegation";
            "SeImpersonatePrivilege" =                      "Impersonate a client after authentication";
            "SeIncreaseBasePriorityPrivilege" =             "Increase scheduling priority";
            "SeIncreaseQuotaPrivilege" =                    "Adjust memory quotas for a process";
            "SeIncreaseWorkingSetPrivilege" =               "Increase a process working set";
            "SeLoadDriverPrivilege" =                       "Load and unload device drivers";
            "SeLockMemoryPrivilege" =                       "Lock pages in memory";
            "SeMachineAccountPrivilege" =                   "Add workstations to domain";
            "SeManageVolumePrivilege" =                     "Manage the files on a volume";
            "SeProfileSingleProcessPrivilege" =             "Profile single process";
            "SeRelabelPrivilege" =                          "Modify an object label";
            "SeRemoteShutdownPrivilege" =                   "Force shutdown from a remote system";
            "SeRestorePrivilege" =                          "Restore files and directories";
            "SeSecurityPrivilege" =                         "Manage auditing and security log";
            "SeShutdownPrivilege" =                         "Shut down the system";
            "SeSyncAgentPrivilege" =                        "Synchronize directory service data";
            "SeSystemEnvironmentPrivilege" =                "Modify firmware environment values";
            "SeSystemProfilePrivilege" =                    "Profile system performance";
            "SeSystemtimePrivilege" =                       "Change the system time";
            "SeTakeOwnershipPrivilege" =                    "Take ownership of files or other objects";
            "SeTcbPrivilege" =                              "Act as part of the operating system";
            "SeTimeZonePrivilege" =                         "Change the time zone";
            "SeTrustedCredManAccessPrivilege" =             "Access Credential Manager as a trusted caller";
            "SeUndockPrivilege" =                           "Remove computer from docking station";
            "SeUnsolicitedInputPrivilege" =                 "N/A";
        }

        $PrivilegeDescriptions[$Name]
    }

    # Get a handle to a process the current user owns 
    $ProcessHandle = $Kernel32::GetCurrentProcess()
    Write-Verbose "Current process handle: $ProcessHandle"

    # Get a handle to the token corresponding to this process 
    $TOKEN_QUERY= 0x0008
    [IntPtr]$TokenHandle = [IntPtr]::Zero
    $Success = $Advapi32::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$TokenHandle)
    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($Success) {

        Write-Verbose "OpenProcessToken() OK - Token handle: $TokenHandle"

        $TOKEN_INFORMATION_CLASS = 0x0003 # = TokenPrivileges
        $TokenPrivilegesPtrSize = 0
        $Success = $Advapi32::GetTokenInformation($TokenHandle, $TOKEN_INFORMATION_CLASS, 0, $null, [ref]$TokenPrivilegesPtrSize)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if (-not ($TokenPrivilegesPtrSize -eq 0)) {

            Write-Verbose "GetTokenInformation() OK - TokenPrivilegesPtrSize = $TokenPrivilegesPtrSize"

            [IntPtr]$TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivilegesPtrSize)

            $Success = $Advapi32::GetTokenInformation($TokenHandle, $TOKEN_INFORMATION_CLASS, $TokenPrivilegesPtr, $TokenPrivilegesPtrSize, [ref]$TokenPrivilegesPtrSize)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {

                # Convert the unmanaged memory at offset $TokenPrivilegesPtr to a TOKEN_PRIVILEGES managed type 
                $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [type] $TOKEN_PRIVILEGES)
                $Offset = [IntPtr] ($TokenPrivilegesPtr.ToInt64() + 4)
                
                Write-Verbose "GetTokenInformation() OK - Privilege count: $($TokenPrivileges.PrivilegeCount)"

                For ($i = 0; $i -lt $TokenPrivileges.PrivilegeCount; $i++) {

                    # Cast the unmanaged memory at offset 
                    $LuidAndAttributes = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $LUID_AND_ATTRIBUTES)
                    
                    # Copy LUID to unmanaged memory 
                    $LuidSize = [System.Runtime.InteropServices.Marshal]::SizeOf($LuidAndAttributes.Luid)
                    [IntPtr]$LuidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidSize)
                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($LuidAndAttributes.Luid, $LuidPtr, $true)

                    [UInt32]$Length = 0
                    $Success = $Advapi32::LookupPrivilegeName($null, $LuidPtr, $null, [ref]$Length)
                    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if (-not ($Length -eq 0)) {

                        Write-Verbose "LookupPrivilegeName() OK - Length = $Length"

                        $Name = New-Object -TypeName System.Text.StringBuilder
                        $Name.EnsureCapacity($Length + 1) |Out-Null
                        $Success = $Advapi32::LookupPrivilegeName($null, $LuidPtr, $Name, [ref]$Length)
                        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Success) {

                            $PrivilegeName = $Name.ToString()

                            $SE_PRIVILEGE_ENABLED = 0x00000002
                            $PrivilegeEnabled = ($LuidAndAttributes.Attributes -band $SE_PRIVILEGE_ENABLED) -eq $SE_PRIVILEGE_ENABLED

                            Write-Verbose "LookupPrivilegeName() OK - Name: $PrivilegeName - Enabled: $PrivilegeEnabled"

                            $Result = New-Object -TypeName PSObject
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $PrivilegeName
                            $Result | Add-Member -MemberType "NoteProperty" -Name "State" -Value $(if ($PrivilegeEnabled) { "Enabled" } else { "Disabled" })
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(Get-PrivilegeDescription -Name $PrivilegeName)
                            $Result

                        }
                        else {
                            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
                        }

                    }
                    else {
                        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
                    }

                    # Cleanup - Free unmanaged memory
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidPtr)

                    # Update the offset to point to the next LUID_AND_ATTRIBUTES structure in the unmanaged buffer
                    $Offset = [IntPtr] ($Offset.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($LuidAndAttributes))
                }

            }
            else {
                Write-Verbose ([ComponentModel.Win32Exception] $LastError)
            }

            # Cleanup - Free unmanaged memory
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)

        }
        else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }

        # Cleanup - Close Token handle 
        $Success = $Kernel32::CloseHandle($TokenHandle)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($Success) {
            Write-Verbose "Token handle closed"
        }
        else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }

    }
    else {
        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
    }
}

function Get-UserFromProcess {
    <#
    .SYNOPSIS
    Helper - Gets the user associated to a given process

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    First it gets a handle to the process identified by the given PID. Then, it uses this handle to access the process token. GetTokenInformation() is then used to query the SID of the user. Finally the SID is converted to a domain name, user name and SID type. All this information is returned in a custom PS object. 
    
    .PARAMETER ProcessId
    The PID of the target process
    
    .EXAMPLE
    PS C:\> Get-UserFromProcess -ProcessId 6972

    Domain          Username Type
    ------          -------- ----
    DESKTOP-FEOHNOM lab-user User
    #>
    
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [Int]
        $ProcessId
    )

    $DesiredAccess = $ProcessAccessRightsEnum::QueryInformation
    $ProcessHandle = $Kernel32::OpenProcess($DesiredAccess, $false, $ProcessId)
    #$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if (-not ($null -eq $ProcessHandle)) {

        Write-Verbose "OpenProcess() OK - Handle: $ProcessHandle"

        $TokenHandle = [IntPtr]::Zero
        $DesiredAccess = $TokenAccessRightsEnum::Query
        $Success = $Advapi32::OpenProcessToken($ProcessHandle, $DesiredAccess, [ref]$TokenHandle);
        #$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if ($Success) {

            Write-Verbose "OpenProcessToken() OK - Handle: $ProcessHandle"

            # TOKEN_INFORMATION_CLASS - 1 = TokenUser
            $TokenUserPtrSize = 0
            $TokenInformationClass = $TOKEN_INFORMATION_CLASS::TokenUser
            $Success = $Advapi32::GetTokenInformation($TokenHandle, $TokenInformationClass, 0, $null, [ref]$TokenUserPtrSize)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if (($TokenUserPtrSize -gt 0) -and ($LastError -eq 122)) {

                Write-Verbose "GetTokenInformation() OK - Size: $TokenUserPtrSize"

                [IntPtr]$TokenUserPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenUserPtrSize)

                $Success = $Advapi32::GetTokenInformation($TokenHandle, $TokenInformationClass, $TokenUserPtr, $TokenUserPtrSize, [ref]$TokenUserPtrSize)
                $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error() 

                if ($Success) {

                    Write-Verbose "GetTokenInformation() OK"

                    # Cast unmanaged memory to managed TOKEN_USER struct 
                    $TokenUser = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenUserPtr, [type] $TOKEN_USER)

                    $SidType = 0

                    $UserNameSize = 256
                    $UserName = New-Object -TypeName System.Text.StringBuilder
                    $UserName.EnsureCapacity(256) | Out-Null

                    $UserDomainSize = 256
                    $UserDomain = New-Object -TypeName System.Text.StringBuilder
                    $UserDomain.EnsureCapacity(256) | Out-Null

                    $Success = $Advapi32::LookupAccountSid($null, $TokenUser.User.Sid, $UserName, [ref]$UserNameSize, $UserDomain, [ref]$UserDomainSize, [ref]$SidType)
                    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if ($Success) {

                        $Result = New-Object -TypeName PSObject
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $UserDomain.ToString()
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $UserName.ToString()
                        $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value "$($UserDomain.ToString())\$($UserName.ToString())"
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value ($SidType -as $SID_NAME_USE)
                        $Result
                        
                    }
                    else {
                        Write-Verbose "LookupAccountSid() failed."
                        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
                    }
                }
                else {
                    Write-Verbose "GetTokenInformation() failed."
                    Write-Verbose ([ComponentModel.Win32Exception] $LastError)
                }

                # Cleanup - Free unmanaged memory 
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenUserPtr)
            }

            # Cleanup - Close token handle 
            $Success = $Kernel32::CloseHandle($TokenHandle)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($Success) {
                Write-Verbose "Token handle closed"
            }
            else {
                Write-Verbose ([ComponentModel.Win32Exception] $LastError)
            }
        }
        else {
            Write-Verbose "Can't open token for process with PID $ProcessId"
        }

        # Cleanup - Close process handle 
        $Success = $Kernel32::CloseHandle($ProcessHandle)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($Success) {
            Write-Verbose "Process handle closed"
        }
        else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }
    }
    else {
        Write-Verbose "Can't open process with PID $ProcessId"
    }
}

function Get-NetworkEndpoints {
    <#
    .SYNOPSIS
    Helper - Gets a list of listening ports (TCP/UDP)

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    It uses the 'GetExtendedTcpTable' and 'GetExtendedUdpTable' functions of the Windows API to list the TCP/UDP endpoints on the local machine. It handles both IPv4 and IPv6. For each entry in the table, a custom PS object is returned, indicating the IP version (IPv4/IPv6), the protocol (TCP/UDP), the local address (e.g.: "0.0.0.0:445"), the state, the PID of the associated process and the name of the process. The name of the process is retrieved through a call to "Get-Process -PID <PID>".
    
    .EXAMPLE
    PS C:\> Get-NetworkEndpoints | ft
    
    IP   Proto LocalAddress LocalPort Endpoint         State       PID Name
    --   ----- ------------ --------- --------         -----       --- ----
    IPv4 TCP   0.0.0.0            135 0.0.0.0:135      LISTENING  1216 svchost
    IPv4 TCP   0.0.0.0            445 0.0.0.0:445      LISTENING     4 System
    IPv4 TCP   0.0.0.0           5040 0.0.0.0:5040     LISTENING  8580 svchost
    IPv4 TCP   0.0.0.0          49664 0.0.0.0:49664    LISTENING   984 lsass
    IPv4 TCP   0.0.0.0          49665 0.0.0.0:49665    LISTENING   892 wininit
    IPv4 TCP   0.0.0.0          49666 0.0.0.0:49666    LISTENING  1852 svchost
    IPv4 TCP   0.0.0.0          49667 0.0.0.0:49667    LISTENING  1860 svchost
    IPv4 TCP   0.0.0.0          49668 0.0.0.0:49668    LISTENING  2972 svchost
    IPv4 TCP   0.0.0.0          49669 0.0.0.0:49669    LISTENING  4480 spoolsv
    IPv4 TCP   0.0.0.0          49670 0.0.0.0:49670    LISTENING   964 services
    
    .EXAMPLE
    PS C:\> Get-NetworkEndpoints -UDP -IPv6 | ft

    IP   Proto LocalAddress LocalPort Endpoint    State  PID Name       
    --   ----- ------------ --------- --------    -----  --- ----
    IPv6 UDP   ::                 500 [::]:500    N/A   5000 svchost
    IPv6 UDP   ::                3702 [::]:3702   N/A   4128 dasHost
    IPv6 UDP   ::                3702 [::]:3702   N/A   4128 dasHost
    IPv6 UDP   ::                4500 [::]:4500   N/A   5000 svchost
    IPv6 UDP   ::               62212 [::]:62212  N/A   4128 dasHost
    IPv6 UDP   ::1               1900 [::1]:1900  N/A   5860 svchost
    IPv6 UDP   ::1              63168 [::1]:63168 N/A   5860 svchost 
    #>

    [CmdletBinding()] Param(
        [Switch]
        $IPv6 = $false, # IPv4 by default 
        [Switch]
        $UDP = $false # TCP by default 
    )

    $AF_INET6 = 23
    $AF_INET = 2
    
    if ($IPv6) { 
        $IpVersion = $AF_INET6
    }
    else {
        $IpVersion = $AF_INET
    }

    if ($UDP) {
        $UDP_TABLE_OWNER_PID = 1
        [Int]$BufSize = 0
        $Result = $Iphlpapi::GetExtendedUdpTable([IntPtr]::Zero, [ref]$BufSize, $true, $IpVersion, $UDP_TABLE_OWNER_PID, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }
    else {
        $TCP_TABLE_OWNER_PID_LISTENER = 3
        [Int]$BufSize = 0
        $Result = $Iphlpapi::GetExtendedTcpTable([IntPtr]::Zero, [ref]$BufSize, $true, $IpVersion, $TCP_TABLE_OWNER_PID_LISTENER, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }

    if ($Result -eq 122) {

        Write-Verbose "GetExtendedProtoTable() OK - Size: $BufSize"

        [IntPtr]$TablePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufSize)

        if ($UDP) {
            $Result = $Iphlpapi::GetExtendedUdpTable($TablePtr, [ref]$BufSize, $true, $IpVersion, $UDP_TABLE_OWNER_PID, 0)
        }
        else {
            $Result = $Iphlpapi::GetExtendedTcpTable($TablePtr, [ref]$BufSize, $true, $IpVersion, $TCP_TABLE_OWNER_PID_LISTENER, 0)
        }

        if ($Result -eq 0) {

            if ($UDP) {
                if ($IpVersion -eq $AF_INET) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $MIB_UDPTABLE_OWNER_PID)
                }
                elseif ($IpVersion -eq $AF_INET6) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $MIB_UDP6TABLE_OWNER_PID)
                }
            }
            else {
                if ($IpVersion -eq $AF_INET) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $MIB_TCPTABLE_OWNER_PID)
                }
                elseif ($IpVersion -eq $AF_INET6) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $MIB_TCP6TABLE_OWNER_PID)
                }
            }
            
            $NumEntries = $Table.NumEntries

            Write-Verbose "GetExtendedProtoTable() OK - NumEntries: $NumEntries"

            $Offset = [IntPtr] ($TablePtr.ToInt64() + 4)

            For ($i = 0; $i -lt $NumEntries; $i++) {

                if ($UDP) {
                    if ($IpVersion -eq $AF_INET) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $MIB_UDPROW_OWNER_PID)
                        $LocalAddr = (New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr)).IPAddressToString
                    }
                    elseif ($IpVersion -eq $AF_INET6) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $MIB_UDP6ROW_OWNER_PID)
                        $LocalAddr = New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr, $TableEntry.LocalScopeId)
                    }
                }
                else {
                    if ($IpVersion -eq $AF_INET) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $MIB_TCPROW_OWNER_PID)
                        $LocalAddr = (New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr)).IPAddressToString
                    }
                    elseif ($IpVersion -eq $AF_INET6) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $MIB_TCP6ROW_OWNER_PID)
                        $LocalAddr = New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr, [Int64] $TableEntry.LocalScopeId)
                    }
                }

                $LocalPort = $TableEntry.LocalPort[0] * 0x100 + $TableEntry.LocalPort[1]
                $ProcessId = $TableEntry.OwningPid

                if ($IpVersion -eq $AF_INET) {
                    $LocalAddress = "$($LocalAddr):$($LocalPort)"
                }
                elseif ($IpVersion -eq $AF_INET6) {
                    # IPv6.ToString doesn't work in PSv2 for some reason
                    try { $LocalAddress = "[$($LocalAddr)]:$($LocalPort)" } catch { $LocalAddress = "????:$($LocalPort)" }
                }

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "IP" -Value $(if ($IpVersion -eq $AF_INET) { "IPv4" } else { "IPv6" } )
                $Result | Add-Member -MemberType "NoteProperty" -Name "Proto" -Value $(if ($UDP) { "UDP" } else { "TCP" } )
                $Result | Add-Member -MemberType "NoteProperty" -Name "LocalAddress" -Value $LocalAddr
                $Result | Add-Member -MemberType "NoteProperty" -Name "LocalPort" -Value $LocalPort
                $Result | Add-Member -MemberType "NoteProperty" -Name "Endpoint" -Value $LocalAddress
                $Result | Add-Member -MemberType "NoteProperty" -Name "State" -Value $(if ($UDP) { "N/A" } else { "LISTENING" } )
                $Result | Add-Member -MemberType "NoteProperty" -Name "PID" -Value $ProcessId
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value (Get-Process -PID $ProcessId).ProcessName
                $Result

                $Offset = [IntPtr] ($Offset.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($TableEntry))
            }

        }
        else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TablePtr)

    }
    else {
        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
    }
}

function Get-InstalledPrograms {
    <#
    .SYNOPSIS
    Helper - Enumerates the installed applications 

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    This looks for applications installed in the common "Program Files" and "Program Files (x86)" folders. It also enumerates installed applications thanks to the registry by looking for all the subkeys in "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall".

    .PARAMETER Filtered
    If True, only non-default applications are returned. Otherwise, all the applications are returned. The filter is base on a list of known applications which are known to be installed by default (e.g.: "Windows Defender").
    
    .EXAMPLE
    PS C:\> Get-InstalledPrograms -Filtered

    Mode                LastWriteTime     Length Name
    ----                -------------     ------ ----
    d----        29/11/2019     10:51            Npcap
    d----        29/11/2019     10:51            Wireshark
    #>
    
    [CmdletBinding()] Param(
        [Switch]
        $Filtered = $false
    )

    $IgnoredPrograms = @("Common Files", "Internet Explorer", "ModifiableWindowsApps", "PackageManagement", "Windows Defender", "Windows Defender Advanced Threat Protection", "Windows Mail", "Windows Media Player", "Windows Multimedia Platform", "Windows NT", "Windows Photo Viewer", "Windows Portable Devices", "Windows Security", "WindowsPowerShell", "Microsoft.NET", "Windows Portable Devices", "dotnet", "MSBuild", "Intel", "Reference Assemblies")

    $InstalledPrograms = New-Object System.Collections.ArrayList

    # List all items in 'C:\Program Files' and 'C:\Program Files (x86)'
    $PathProgram32 = Join-Path -Path $env:SystemDrive -ChildPath "Program Files (x86)"
    $PathProgram64 = Join-Path -Path $env:SystemDrive -ChildPath "Program Files" 

    $Items = Get-ChildItem -Path $PathProgram32,$PathProgram64 -ErrorAction SilentlyContinue
    if ($Items) {
        [void]$InstalledPrograms.AddRange($Items)
    }
    
    $RegInstalledPrograms = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" 
    $RegInstalledPrograms6432 = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue
    if ($RegInstalledPrograms6432) { $RegInstalledPrograms += $RegInstalledPrograms6432 }

    foreach ($InstalledProgram in $RegInstalledPrograms) {

        $InstallLocation = [System.Environment]::ExpandEnvironmentVariables($InstalledProgram.GetValue("InstallLocation"))

        if (-not [String]::IsNullOrEmpty($InstallLocation)) {

            if (Test-Path -Path $InstallLocation -ErrorAction SilentlyContinue) {

                if ($InstallLocation[$InstallLocation.Length - 1] -eq "\") {
                    $InstallLocation = $InstallLocation.SubString(0, $InstallLocation.Length - 1)
                }

                $FileObject = Get-Item -Path $InstallLocation -ErrorAction SilentlyContinue -ErrorVariable GetItemError
                if ($GetItemError) { continue }

                if (-not ($FileObject -is [System.IO.DirectoryInfo])) { continue }

                [void]$InstalledPrograms.Add([Object]$FileObject)
            }
        }
    }

    $InstalledPrograms | Sort-Object -Property FullName -Unique | ForEach-Object {
        if ((-not $Filtered) -or ($Filtered -and (-not ($IgnoredPrograms -contains $_.Name)))) {
            $_ | Select-Object -Property Name,FullName
        }
    }
}

function Get-ServiceControlManagerDacl {
    <#
    .SYNOPSIS
    Helper - Get the DACL of the SCM (Service Control Manager)

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    The SCM (Service Control Manager) has its own DACL which defines which users/groups can connect / create services / enumerate services / etc. This function requests Read access to the SCM and queries this DACL. The DACL is returned as a Security Descriptor, which is a binary blob. Therefore, it is converted to a list of ACE objects, which can then be easily used by the caller.
    
    .EXAMPLE
    PS C:\> Get-ServiceControlManagerDacl

    AccessRights       : Connect
    BinaryLength       : 20
    AceQualifier       : AccessAllowed
    IsCallback         : False
    OpaqueLength       : 0
    AccessMask         : 1
    SecurityIdentifier : S-1-5-11
    AceType            : AccessAllowed
    AceFlags           : None
    IsInherited        : False
    InheritanceFlags   : None
    PropagationFlags   : None
    AuditFlags         : None
    ...
    
    .NOTES
    https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
    #>

    [CmdletBinding()] Param()

    $SERVICES_ACTIVE_DATABASE = "ServicesActive"
    $ServiceManagerHandle = $Advapi32::OpenSCManager($null, $SERVICES_ACTIVE_DATABASE, $ServiceControlManagerAccessRightsEnum::GenericRead)
    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($ServiceManagerHandle) {

        $SizeNeeded = 0
        $null = $Advapi32::QueryServiceObjectSecurity($ServiceManagerHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref] $SizeNeeded)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        # 122 == The data area passed to a system call is too small
        if (($LastError -eq 122) -and ($SizeNeeded -gt 0)) {

            Write-Verbose "Size needed: $($SizeNeeded)"

            $BinarySecurityDescriptor = New-Object Byte[]($SizeNeeded)

            $Success = $Advapi32::QueryServiceObjectSecurity($ServiceManagerHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $SizeNeeded)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {

                $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0
                
                $Dacl = $RawSecurityDescriptor.DiscretionaryAcl

                if ($null -eq $Dacl) {
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $ServiceControlManagerAccessRightsEnum::AllAccess
                    # $Result | Add-Member -MemberType "NoteProperty" -Name "AccessMask" -Value AccessRights.value__
                    $Result | Add-Member -MemberType "NoteProperty" -Name "SecurityIdentifier" -Value "S-1-1-0"
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AceType" -Value "AccessAllowed"
                    $Result
                }
                else {
                    $Dacl | ForEach-Object {
                        Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value ($_.AccessMask -as $ServiceControlManagerAccessRightsEnum) -PassThru
                    }
                }
            }

        }
        else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }

        $null = $Advapi32::CloseServiceHandle($ServiceManagerHandle)

    }
    else {
        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
    }
}

function Get-ServiceFromRegistry {

    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$Name
    )

    $ServicesRegPath = "HKLM\SYSTEM\CurrentControlSet\Services" 
    $ServiceRegPath = Join-Path -Path $ServicesRegPath -ChildPath $Name

    $ServiceProperties = Get-ItemProperty -Path "Registry::$ServiceRegPath" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
    if (-not $GetItemPropertyError) {

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $ServiceProperties.PSChildName
        $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value ([System.Environment]::ExpandEnvironmentVariables($ServiceProperties.DisplayName))
        $Result | Add-Member -MemberType "NoteProperty" -Name "User" -Value $ServiceProperties.ObjectName
        $Result | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $ServiceProperties.ImagePath
        $Result | Add-Member -MemberType "NoteProperty" -Name "StartMode" -Value ($ServiceProperties.Start -as $ServiceStartTypeEnum)
        $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value ($ServiceProperties.Type -as $ServiceTypeEnum)
        $Result | Add-Member -MemberType "NoteProperty" -Name "RegistryKey" -Value $ServicesRegPath
        $Result | Add-Member -MemberType "NoteProperty" -Name "RegistryPath" -Value $ServiceProperties.PSPath
        $Result
    }
}

function Get-ServiceList {
    <#
    .SYNOPSIS
    Helper - Enumerates services (based on the registry)

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    This uses the registry to enumerate the services by looking for the subkeys of "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services". This allows any user to get information about all the services. So, even if non-privileged users can't access the details of a service through the Service Control Manager, they can do so simply by accessing the registry.
    
    .PARAMETER FilterLevel
    This parameter can be used to filter out the result returned by the function based on the 
    following criteria:
        FilterLevel = 0 - No filtering 
        FilterLevel = 1 - Exclude 'Services with empty ImagePath'
        FilterLevel = 2 - Exclude 'Services with empty ImagePath' + 'Drivers' 
        FilterLevel = 3 - Exclude 'Services with empty ImagePath' + 'Drivers' + 'Known services' 
    
    .EXAMPLE
    PS C:\> Get-ServiceList -FilterLevel 3

    Name         : VMTools
    DisplayName  : VMware Tools
    User         : LocalSystem
    ImagePath    : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
    StartMode    : Automatic
    Type         : Win32OwnProcess
    RegistryKey  : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMTools
    RegistryPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMTools
    
    .NOTES
    A service "Type" can be one of the following:
        KernelDriver = 1
        FileSystemDriver = 2
        Adapter = 4
        RecognizerDriver = 8
        Win32OwnProcess = 16
        Win32ShareProcess = 32 
        InteractiveProcess = 256
    #>
    
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet(0,1,2,3)]
        [Int]
        $FilterLevel
    )

    if ($CachedServiceList.Count -eq 0) {

        # If the cached service list hasn't been initialized yet, enumerate all services and populate the 
        # cache.

        $ServicesRegPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
        $RegAllServices = Get-ChildItem -Path $ServicesRegPath -ErrorAction SilentlyContinue

        $RegAllServices | ForEach-Object { [void]$CachedServiceList.Add((Get-ServiceFromRegistry -Name $_.PSChildName)) }
    }

    foreach ($ServiceItem in $CachedServiceList) {

        # FilterLevel = 0 - Add the service to the list and go to the next one
        if ($FilterLevel -eq 0) { $ServiceItem; continue }

        if ($ServiceItem.ImagePath -and (-not [String]::IsNullOrEmpty($ServiceItem.ImagePath.trim()))) {

            # FilterLevel = 1 - Add the service to the list of its ImagePath is not empty
            if ($FilterLevel -le 1) { $ServiceItem; continue }

            if (@("Win32OwnProcess", "Win32ShareProcess", "InteractiveProcess") -contains $ServiceItem.Type) {

                # FilterLevel = 2 - Add the service to the list if it's not a driver
                if ($FilterLevel -le 2) { $ServiceItem; continue }

                if (-not (Test-IsKnownService -Service $ServiceItem)) {

                    # FilterLevel = 3 - Add the service if it's not a built-in Windows service
                    if ($FilterLevel -le 3) { $ServiceItem; continue }
                }
            }
        }
    }
}

function Get-ModifiablePath {
    <#
    .SYNOPSIS
    Parses a passed string containing multiple possible file/folder paths and returns the file paths where the current user has modification rights.

    Author: @harmj0y
    License: BSD 3-Clause

    .DESCRIPTION
    Takes a complex path specification of an initial file/folder path with possible configuration files, 'tokenizes' the string in a number of possible ways, and enumerates the ACLs for each path that currently exists on the system. Any path that the current user has modification rights on is returned in a custom object that contains the modifiable path, associated permission set, and the IdentityReference with the specified rights. The SID of the current user and any group he/she are a part of are used as the comparison set against the parsed path DACLs.

    @itm4n: I made some small changes to the original code in order to prevent false positives as much as possible. 

    .PARAMETER Path
    The string path to parse for modifiable files. Required

    .PARAMETER LiteralPaths
    Switch. Treat all paths as literal (i.e. don't do 'tokenization').

    .EXAMPLE
    PS C:\> '"C:\Temp\blah.exe" -f "C:\Temp\config.ini"' | Get-ModifiablePath

    Path                       Permissions                IdentityReference
    ----                       -----------                -----------------
    C:\Temp\blah.exe           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    C:\Temp\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...

    .EXAMPLE
    PS C:\> Get-ChildItem C:\Vuln\ -Recurse | Get-ModifiablePath

    Path                       Permissions                IdentityReference
    ----                       -----------                -----------------
    C:\Vuln\blah.bat           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    C:\Vuln\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    ...
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Switch]
        $LiteralPaths
    )

    BEGIN {

        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [UInt32]'0x80000000' = 'GenericRead'
            [UInt32]'0x40000000' = 'GenericWrite'
            [UInt32]'0x20000000' = 'GenericExecute'
            [UInt32]'0x10000000' = 'GenericAll'
            [UInt32]'0x02000000' = 'MaximumAllowed'
            [UInt32]'0x01000000' = 'AccessSystemSecurity'
            [UInt32]'0x00100000' = 'Synchronize'
            [UInt32]'0x00080000' = 'WriteOwner'
            [UInt32]'0x00040000' = 'WriteDAC'
            [UInt32]'0x00020000' = 'ReadControl'
            [UInt32]'0x00010000' = 'Delete'
            [UInt32]'0x00000100' = 'WriteAttributes'
            [UInt32]'0x00000080' = 'ReadAttributes'
            [UInt32]'0x00000040' = 'DeleteChild'
            [UInt32]'0x00000020' = 'Execute/Traverse'
            [UInt32]'0x00000010' = 'WriteExtendedAttributes'
            [UInt32]'0x00000008' = 'ReadExtendedAttributes'
            [UInt32]'0x00000004' = 'AppendData/AddSubdirectory'
            [UInt32]'0x00000002' = 'WriteData/AddFile'
            [UInt32]'0x00000001' = 'ReadData/ListDirectory'
        }

        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value

        $TranslatedIdentityReferences = @{}

        function Get-FirstExistingParentFolder {

            Param(
                [String]$Path
            )
    
            try {
                $ParentPath = Split-Path $Path -Parent
                if ($ParentPath -and $(Test-Path -Path $ParentPath -ErrorAction SilentlyContinue)) {
                    Resolve-Path -Path $ParentPath | Select-Object -ExpandProperty "Path"
                }
                else {
                    Get-FirstExistingParentFolder -Path $ParentPath
                }
            }
            catch {
                # because Split-Path doesn't handle -ErrorAction SilentlyContinue nicely
            }
        }
    }

    PROCESS {

        foreach ($TargetPath in $Path) {

            $CandidatePaths = @()

            # possible separator character combinations
            $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")

            if ($PSBoundParameters['LiteralPaths']) {

                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath))

                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {

                    $ResolvedPath = Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                    $CandidatePaths += $ResolvedPath

                    # If the path corresponds to a file, we want to check its parent directory as well. There are cases
                    # where the target file is configured with secure permissions but a user can still add files in the
                    # same folder. In such case, a DLL proxying attack is still possible.
                    if ($(Get-Item -Path $ResolvedPath -Force) -is [System.IO.FileInfo]) {
                        $CandidatePaths += Get-FirstExistingParentFolder -Path $ResolvedPath
                    }
                }
                else {

                    # If the path doesn't correspond to an existing file or directory, find the first existing parent
                    # directory (if such directory exists) and add it to the list of candidate paths.
                    $CandidatePaths += Get-FirstExistingParentFolder -Path $TempPath
                }
            }
            else {

                $TargetPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath)).Trim()
                
                foreach ($SeparationCharacterSet in $SeparationCharacterSets) {

                    $TargetPath.Split($SeparationCharacterSet) | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.trim())) } | ForEach-Object {

                        if (-not ($_ -match "^[A-Z]:`$")) {

                            if ($SeparationCharacterSet -notmatch ' ') {

                                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($_)).Trim()
    
                                # If the candidate path is something like '/svc', skip it because it will be interpreted as 
                                # 'C:\svc'. It should filter out a lot of false postives. There is also a small chance that 
                                # it will exclude actual vulnerable paths in some very particular cases where a path such 
                                # as '/Temp/Something' is used as an argument. This seems very unlikely though.
                                if ((-not ($TempPath -Like "/*")) -and (-not ($TempPath -match "^[A-Z]:`$"))) { 
    
                                    if (-not [String]::IsNullOrEmpty($TempPath)) {

                                        # Does the object exist? Be it a file or a directory.
                                        if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {

                                            $ResolvedPath = Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                                            $CandidatePaths += $ResolvedPath
                        
                                            # If the path corresponds to a file, we want to check its parent directory as well. There are cases
                                            # where the target file is configured with secure permissions but a user can still add files in the
                                            # same folder. In such case, a DLL proxying attack is still possible.
                                            if ($(Get-Item -Path $ResolvedPath -Force) -is [System.IO.FileInfo]) {
                                                $CandidatePaths += Get-FirstExistingParentFolder -Path $ResolvedPath
                                            }
                                        }
                                        else {
                        
                                            # If the path doesn't correspond to an existing file or directory, find the first existing parent
                                            # directory (if such directory exists) and add it to the list of candidate paths.
                                            $CandidatePaths += Get-FirstExistingParentFolder -Path $TempPath
                                        }
                                    }
                                }
                            }
                            else {
                                # if the separator contains a space
                                $CandidatePaths += Resolve-Path -Path $([System.Environment]::ExpandEnvironmentVariables($_)) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | ForEach-Object {$_.Trim()} | Where-Object { (-not [String]::IsNullOrEmpty($_)) -and (Test-Path -Path $_) }
                            }
                        }
                        else {
                            Write-Verbose "DEBUG: Got a drive letter as a path: $_"
                        }
                    }
                }
            }

            $CandidatePaths | Sort-Object -Unique | ForEach-Object {

                $CandidatePath = $_

                try {

                    $Acl = Get-Acl -Path $CandidatePath | Select-Object -ExpandProperty Access

                    # Check for NULL DACL first. If no DACL is set, 'Everyone' has full access on the object.
                    if ($null -eq $Acl) {
                        $Result = New-Object -TypeName PSObject
                        $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $CandidatePath
                        $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value (Convert-SidToName -Name "S-1-1-0")
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value "GenericAll"
                        $Result
                    }
                    else {
                        foreach ($Ace in $Acl) {

                            # If the type of the current ACE is not 'Allow', ignore it.
                            if ($Ace.AccessControlType -notmatch 'Allow') { continue }
    
                            # If the object we are checking is a directory (i.e. a Container), the Propagation flags are very
                            # important. This value determines whether the ACE applies to the object itself only or to the 
                            # child objects only. Although PropagationFlags allows a bitwise combination of its member values,
                            # they are not really compatible with one another. For example, it can have the value 
                            # NoPropagateInherit (1), which indicates that the ACE is not propagated to child objects. The 
                            # other possible value is InheritOnly (2) and indicates that the ACE is propagated *only* to child
                            # objects. Anyway, what's important to us is making sure that PropagationFlags does not contain the 
                            # value InheritOnly.
                            if ($Ace.PropagationFlags -band ([System.Security.AccessControl.PropagationFlags]"InheritOnly").value__) { continue }
        
                            $Permissions = $AccessMask.Keys | Where-Object { $Ace.FileSystemRights.value__ -band $_ } | ForEach-Object { $accessMask[$_] }
    
                            # the set of permission types that allow for modification
                            $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent
    
                            if ($Comparison) {
    
                                if ($Ace.IdentityReference -notmatch '^S-1-5.*' -and $Ace.IdentityReference -notmatch '^S-1-15-.*') {
    
                                    if (-not ($TranslatedIdentityReferences[$Ace.IdentityReference])) {
    
                                        # translate the IdentityReference if it's a username and not a SID
                                        $IdentityUser = New-Object System.Security.Principal.NTAccount($Ace.IdentityReference)
                                        $TranslatedIdentityReferences[$Ace.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                                    }
                                    $IdentitySID = $TranslatedIdentityReferences[$Ace.IdentityReference]
                                }
                                else {
                                    $IdentitySID = $Ace.IdentityReference
                                }
    
                                if ($CurrentUserSids -contains $IdentitySID) {
                                    $Result = New-Object -TypeName PSObject
                                    $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $CandidatePath
                                    $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $Ace.IdentityReference
                                    $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $Permissions
                                    $Result
                                }
                            }
                        }
                    }
                }
                catch {
                    # trap because Get-Acl doesn't handle -ErrorAction SilentlyContinue nicely
                }
            }
        }
    }
}

function Get-ExploitableUnquotedPath {
    <#
    .SYNOPSIS
    Helper - Parse a path, determine if it's "unquoted" and check whether it's exploitable.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Parse a path, determine if it's "unquoted" and check whether it's exploitable.
    
    .PARAMETER Path
    A path (or a command line for example)
    #>

    [CmdletBinding()] Param(
        [String] $Path
    )

    $PermissionsAddFile = @("WriteData/AddFile", "DeleteChild", "WriteDAC", "WriteOwner")
    # $PermissionsAddFolder = @("AppendData/AddSubdirectory", "DeleteChild", "WriteDAC", "WriteOwner")

    # If the Path doesn't start with a " or a ' 
    if (-not ($Path.StartsWith("`"") -or $Path.StartsWith("'"))) {
                
        # Extract the binpath from the ImagePath
        $BinPath = $Path.SubString(0, $Path.ToLower().IndexOf(".exe") + 4)

        # Write-Verbose "Unquoted path binary: $($BinPath)"

        # If the binpath contains spaces
        If ($BinPath -match ".* .*") {

            Write-Verbose "Found an unquoted path that contains spaces: $($BinPath)"

            $SplitPathArray = $BinPath.Split(' ')
            $ConcatPathArray = @()
            for ($i=0; $i -lt $SplitPathArray.Count; $i++) {
                $ConcatPathArray += $SplitPathArray[0..$i] -join ' '
            }

            # We exclude the binary path itself
            $ConcatPathArray | Where-Object { -not ($_ -like $BinPath) } | ForEach-Object {

                try {

                    $BinFolder = Split-Path -Path $_ -Parent

                    # Does the parent folder exist?
                    if (Test-Path -Path $BinFolder -ErrorAction SilentlyContinue) {

                        # If the parent folder exists, can we add files?
                        $ModifiablePaths = $BinFolder | Get-ModifiablePath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                        foreach ($ModifiablePath in $ModifiablePaths) {

                            # Verify that the permissions that were returned by Get-ModifiablePath really allow us to add files.
                            $PermissionsSet = $PermissionsAddFile
                            foreach ($Permission in $ModifiablePath.Permissions) {

                                if ($PermissionsSet -contains $Permission) {

                                    $ModifiablePath
                                    break
                                }
                            }
                        }
                    }
                }
                catch {
                    # because Split-Path doesn't handle -ErrorAction SilentlyContinue nicely
                }
            }
        }
    }
}

function Get-ModifiableRegistryPath {
    <#
    .SYNOPSIS
    Helper - Checks the permissions of a given registry key and returns the ones that the current user can modify. It's based on the same technique as the one used by @harmj0y in "Get-ModifiablePath".

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Any registry path that the current user has modification rights on is returned in a custom object that contains the modifiable path, associated permission set, and the IdentityReference with the specified rights. The SID of the current user and any group he/she are a part of are used as the comparison set against the parsed path DACLs.
    
    .PARAMETER Path
    A registry key path. Required
    
    .EXAMPLE
    PS C:\> Get-ModifiableRegistryPath -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DVWS"

    ModifiablePath    : {Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DVWS}
    IdentityReference : NT AUTHORITY\Authenticated Users
    Permissions       : {ReadControl, ReadData/ListDirectory, AppendData/AddSubdirectory, WriteData/AddFile...}
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [String[]]
        $Path
    )

    BEGIN {
        $AccessMask = @{
            # Generic access rights
            [UInt32]'0x10000000' = 'GenericAll'
            [UInt32]'0x20000000' = 'GenericExecute'
            [UInt32]'0x40000000' = 'GenericWrite'
            [UInt32]'0x80000000' = 'GenericRead'
            # Registry key access rights
            [UInt32]'0x00000001' = 'QueryValue'
            [UInt32]'0x00000002' = 'SetValue'
            [UInt32]'0x00000004' = 'CreateSubKey'
            [UInt32]'0x00000008' = 'EnumerateSubKeys'
            [UInt32]'0x00000010' = 'Notify'
            [UInt32]'0x00000020' = 'CreateLink'
            # Valid standard access rights for registry keys
            [UInt32]'0x00010000' = 'Delete'
            [UInt32]'0x00020000' = 'ReadControl'
            [UInt32]'0x00040000' = 'WriteDAC'
            [UInt32]'0x00080000' = 'WriteOwner'
        }

        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value

        $TranslatedIdentityReferences = @{}
    }

    PROCESS {
        $KeyAcl = Get-Acl -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetAclError
        if (-not $GetAclError) {

            # Check for NULL DACL first. If no DACL, 'Everyone' has full access rights on the object.
            if ($null -eq $KeyAcl) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $Path
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value (Convert-SidToName -Sid "S-1-1-0")
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value 'GenericAll'
                $Result
            }
            else {
                $Aces = $KeyAcl | Select-Object -ExpandProperty Access | Where-Object { $_.AccessControlType -match 'Allow' }

                foreach ($Ace in $Aces) {
                    $Permissions = $AccessMask.Keys | Where-Object { $Ace.RegistryRights.value__ -band $_ } | ForEach-Object { $AccessMask[$_] }
                    if ($null -eq $Permissions) {
                        Write-Verbose $Ace.RegistryRights.value__
                    }

                    # the set of permission types that allow for modification
                    $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('SetValue', 'CreateSubKey', 'WriteDAC', 'WriteOwner') -IncludeEqual -ExcludeDifferent

                    if (-not $Comparison) { continue }

                    if (($Ace.IdentityReference -notmatch '^S-1-5.*') -and ($Ace.IdentityReference -notmatch '^S-1-15-.*')) {
                        if (-not ($TranslatedIdentityReferences[$Ace.IdentityReference])) {
                            # translate the IdentityReference if it's a username and not an SID
                            $IdentityUser = New-Object System.Security.Principal.NTAccount($Ace.IdentityReference)
                            try {
                                $TranslatedIdentityReferences[$Ace.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                            }
                            catch {
                                $IdentitySID = $null
                            }
                        }
                        $IdentitySID = $TranslatedIdentityReferences[$Ace.IdentityReference]
                    }
                    else {
                        $IdentitySID = $Ace.IdentityReference
                    }

                    if ($CurrentUserSids -contains $IdentitySID) {
                        $Result = New-Object -TypeName PSObject
                        $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $Path
                        $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $Ace.IdentityReference
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $Permissions
                        $Result
                    }
                }
            }
        }
    } 
}

function Add-ServiceDacl {
    <#
    .SYNOPSIS
    Helper - Adds a Dacl field to a service object returned by Get-Service.

    Author: Matthew Graeber
    License: BSD 3-Clause

    .DESCRIPTION
    Takes one or more ServiceProcess.ServiceController objects on the pipeline and adds a Dacl field to each object. It does this by opening a handle with ReadControl for the service with using the GetServiceHandle Win32 API call and then uses QueryServiceObjectSecurity to retrieve a copy of the security descriptor for the service.

    @itm4n: I had to make some small changes to the original code because i don't import the Win32 API functions the same way it was done in PowerUp.

    .PARAMETER Name
    An array of one or more service names to add a service Dacl for. Passable on the pipeline.

    .EXAMPLE
    PS C:\> Get-Service | Add-ServiceDacl

    Add Dacls for every service the current user can read.

    .EXAMPLE
    PS C:\> Get-Service -Name VMTools | Add-ServiceDacl

    Add the Dacl to the VMTools service object.

    .OUTPUTS
    ServiceProcess.ServiceController

    .LINK
    https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
    #>

    [OutputType('ServiceProcess.ServiceController')]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name
    )

    BEGIN {
        filter Local:Get-ServiceReadControlHandle {
            [OutputType([IntPtr])]
            param (
                [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
                [ValidateNotNullOrEmpty()]
                [ValidateScript({ $_ -as 'ServiceProcess.ServiceController' })]
                $Service
            )
            Add-Type -AssemblyName System.ServiceProcess # ServiceProcess is not loaded by default  
            $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')
            $ReadControl = 0x00020000
            $RawHandle = $GetServiceHandle.Invoke($Service, @($ReadControl))
            $RawHandle
        }
    }

    PROCESS {
        foreach ($ServiceName in $Name) {

            $IndividualService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue -ErrorVariable GetServiceError
            if (-not $GetServiceError) {

                try {
                    $ServiceHandle = Get-ServiceReadControlHandle -Service $IndividualService
                }
                catch {
                    $ServiceHandle = $null
                }

                if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {
                    $SizeNeeded = 0

                    $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref] $SizeNeeded)
                    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    # 122 == The data area passed to a system call is too small
                    if ((-not $Result) -and ($LastError -eq 122) -and ($SizeNeeded -gt 0)) {
                        $BinarySecurityDescriptor = New-Object Byte[]($SizeNeeded)

                        $Result = $Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $SizeNeeded)
                        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Result) {
                            
                            $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0

                            $RawDacl = $RawSecurityDescriptor.DiscretionaryAcl

                            # Check for NULL DACL first
                            if ($nul -eq $RawDacl) {
                                $Ace = New-Object -TypeName PSObject
                                $Ace | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $ServiceAccessRightsEnum::GenericAll
                                # $Ace | Add-Member -MemberType "NoteProperty" -Name "AccessMask" -Value AccessRights.value__
                                $Ace | Add-Member -MemberType "NoteProperty" -Name "SecurityIdentifier" -Value (Convert-SidStringToSid -Sid "S-1-1-0")
                                $Ace | Add-Member -MemberType "NoteProperty" -Name "AceType" -Value "AccessAllowed"
                                $Dacl = @($Ace)
                            }
                            else {
                                $Dacl = $RawDacl | ForEach-Object {
                                    Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value ($_.AccessMask -as $ServiceAccessRightsEnum) -PassThru
                                }
                            }

                            Add-Member -InputObject $IndividualService -MemberType NoteProperty -Name Dacl -Value $Dacl -PassThru
                        }
                    }

                    $null = $Advapi32::CloseServiceHandle($ServiceHandle)
                }
            }
        }
    }
}

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

    [CmdletBinding()]Param()

    $OsVersion = [System.Environment]::OSVersion.Version

    # Windows >= 8/2012
    if (($OsVersion.Major -ge 10) -or (($OsVersion.Major -ge 6) -and ($OsVersion.Minor -ge 2))) {

        [UInt32]$FirmwareType = 0
        $Result = $Kernel32::GetFirmwareType([ref]$FirmwareType)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if ($Result -gt 0) {
            if ($FirmwareType -eq 1) {
                # FirmwareTypeBios = 1
                $Status = $false 
                $Description = "BIOS mode is Legacy"
            }
            elseif ($FirmwareType -eq 2) {
                # FirmwareTypeUefi = 2
                $Status = $true 
                $Description = "BIOS mode is UEFI"
            }
            else {
                $Description = "BIOS mode is unknown"
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
            $Description = "BIOS mode is Legacy"
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }
        else {
            $Status = $true 
            $Description = "BIOS mode is UEFI"
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }
        
    }
    else {
        $Description = "Cannot check BIOS mode"
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

    Name        Status Description
    ----        ------ -----------
    Secure Boot   True Secure Boot is enabled
    #>
    
    [CmdletBinding()]Param()

    $RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
    $Result = Get-ItemProperty -Path "Registry::$($RegPath)" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError 

    if (-not $GetItemPropertyError) {

        if (-not ($null -eq $Result.UEFISecureBootEnabled)) {

            if ($Result.UEFISecureBootEnabled -eq 1) {
                $Status = $true
                $Description = "Secure Boot is enabled"
            }
            else {
                $Status = $false
                $Description = "Secure Boot is disabled"
            }
        }
        else {
            $Status = $false
            $Description = "Secure Boot is not supported"
        }
    }
    else {
        $Status = $false
        $Description = "Secure Boot is not supported"
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "Secure Boot"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result
}

function Get-CredentialGuardStatus {
    <#
    .SYNOPSIS
    Helper - Gets the status of Windows Defender Credential Guard 

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Gets the status of the Credential Guard by reading the 'LsaCfgFlags' value of the following registry key: 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA'. Possible values are: None=>Not configured, 0=>Disabled, 1=>Enabled with UEFI lock, 2=>Disabled without UEFI lock.
    
    .EXAMPLE
    PS C:\> Get-CredentialGuardStatus

    Name             Status Description
    ----             ------ -----------
    Credential Guard  False Credential Guard is not configured
    
    .LINK
    https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage
    #>
    
    [CmdletBinding()]Param()

    $OsVersion = [System.Environment]::OSVersion.Version

    if ($OsVersion.Major -ge 10) {

        if ((($PSVersionTable.PSVersion.Major -eq 5) -and ($PSVersionTable.PSVersion.Minor -ge 1)) -or ($PSVersionTable.PSVersion.Major -gt 5)) {

            if (((Get-ComputerInfo).DeviceGuardSecurityServicesConfigured) -match 'CredentialGuard') {

                $Status = $false
                $Description = "Credential Guard is configured but is not running"
    
                if (((Get-ComputerInfo).DeviceGuardSecurityServicesRunning) -match 'CredentialGuard') {
                    $Status = $true
                    $Description = "Credential Guard is configured and running"
                }
            }
            else {
                $Status = $false
                $Description = "Credential Guard is not configured"
            }
        }
        else {

            $Status = $null
            $Description = "Check failed: Incompatible PS version"
        }
        
    }
    else {
        $Status = $false
        $Description = "Credential Guard is not supported on this OS"
    }
    
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "Credential Guard"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result
}

function Get-LsaRunAsPPLStatus {
    <#
    .SYNOPSIS
    Helper - Gets the status of RunAsPPL option for LSA

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    RunAsPPL can be enabled for the LSA process in the registry. If it's enabled and the device has Secure Boot or UEFI, this setting is stored in the UEFI firmware so removing the registry key won't disable this setting. 
    
    .EXAMPLE
    PS C:\> Get-LsaRunAsPPLStatus
    
    Name     Status Description        
    ----     ------ -----------
    RunAsPPL   True RunAsPPL is enabled

    .LINK
    https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
    #>

    [CmdletBinding()]Param()

    $OsVersion = [System.Environment]::OSVersion.Version

    # if Windows >= 8.1 / 2012 R2
    if ($OsVersion.Major -eq 10 -or ( ($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 3) )) {

        $RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
        $Result = Get-ItemProperty -Path "REgistry::$($RegPath)" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError

        if (-not $GetItemPropertyError) {

            if (-not ($null -eq $Result.RunAsPPL)) {

                if ($Result.RunAsPPL -eq 1) {
                    $Status = $true 
                    $Description = "RunAsPPL is enabled"
                }
                else {
                    $Status = $false 
                    $Description = "RunAsPPL is disabled"
                } 
            }
            else {
                $Status = $false 
                $Description = "RunAsPPL is not configured"
            }
        }

    }
    else {
        # RunAsPPL not supported 
        $Status = $false 
        $Description = "RunAsPPL is not supported on this OS"
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "RunAsPPL"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result
}

function Get-UnattendSensitiveData {
    <#
    .SYNOPSIS
    Helper - Extract sensitive data from an "unattend" XML file

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Unattend files are XML documents which may contain cleartext passwords if they are not properly sanitized. Most of the time, "Password" fields will be replaced by the generic "*SENSITIVE*DATA*DELETED*" mention but sometimes, the original value remains and is either present in its plaintext form or base64-encoded form. If a non-empty password field is found and if it's not equal to the default "*SENSITIVE*DATA*DELETED*", this function will return the corresponding set of credentials: domain, username and (decoded) password. 
    
    .PARAMETER Path
    The Path of the "unattend.xml" file to parse
    
    .EXAMPLE
    PS C:\> Get-UnattendSensitiveData -Path C:\Windows\Panther\Unattend.xml

    Type         Domain      Username      Password
    ----         ------      --------      --------
    Credentials  contoso.com Administrator Password1
    LocalAccount N/A         John          Password1
    AutoLogon    .           Administrator P@ssw0rd
    
    .NOTES 
    A password can be stored in three formats:

    1) Simple string

        <Password>Password</Password>

    2) XML node + plain value
    
        <Password>
            <Value>Password</Value>
            <PlainText>true</PlainText>
        </Password>

    3) XML node + base64-encoded value

        <Password>
            <Value>UABhAHMAcwB3AG8AcgBkAA==</Value>
            <PlainText>false</PlainText>
        </Password> 

    /!\ UNICODE encoding!
    #>

    [CmdletBinding()]Param(
        [Parameter(Mandatory=$true)]
        [String]$Path
    )

    function Get-DecodedPassword {

        [CmdletBinding()]Param(
            [Object]$XmlNode
        )

        if ($XmlNode.GetType().Name -eq "string") {
            $XmlNode
        }
        else {
            if ($XmlNode) {
                if ($XmlNode.PlainText -eq "false") {
                    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($XmlNode.Value))
                }
                else {
                    $XmlNode.Value
                }
            }
        }
    }

    [xml] $Xml = Get-Content -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetContentError

    if (-not $GetContentError) {

        $Xml.GetElementsByTagName("Credentials") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_.Password

            if ((-not [String]::IsNullOrEmpty($Password)) -and (-not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Credentials"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $_.Domain
                $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Username
                $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Result
            }
        }
    
        $Xml.GetElementsByTagName("LocalAccount") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_.Password
    
            if ((-not [String]::IsNullOrEmpty($Password)) -and (-not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "LocalAccount"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value "N/A"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Name
                $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Result
            }
        }
    
        $Xml.GetElementsByTagName("AutoLogon") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_.Password

            if ((-not [String]::IsNullOrEmpty($Password)) -and (-not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "AutoLogon"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $_.Domain
                $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Username
                $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Result
            }
        }

        $Xml.GetElementsByTagName("AdministratorPassword") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_

            if ((-not [String]::IsNullOrEmpty($Password)) -and (-not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "AdministratorPassword"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value "N/A"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value "N/A"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Result
            }
        }
    }
}

function Get-HotFixList {
    <#
    .SYNOPSIS
    Helper - Gets a list of installed updates and hotfixes.
    
    .DESCRIPTION
    This check reads the registry in order to enumerate all the installed KB hotfixes. The output is sorted by date so that most recent patches appear first in the list. The output is similar to the output of the built-in 'Get-HotFix' powershell command. There is a major difference between this script and the 'Get-HotFix' command though. The latter relies on WMI to delegate the "enumeration" whereas this script directly parses the registry. The other benefit of this method is that it allows one to extract more information related to the KBs (although it's not in the output of this script). If the current user can't read the registry, the script falls back to the built-in 'Get-HotFix' cmdlet.
    
    .EXAMPLE
    PS C:\> Get-HotFixList

    HotFixID  Description     InstalledBy           InstalledOn
    --------  -----------     -----------           -----------
    KB4557968 Security Update                       2020-05-11 07:37:09
    KB4560366 Security Update DESKTOP-7A0AKQI\admin 2020-06-22 12:40:39
    KB4566785 Security Update NT AUTHORITY\SYSTEM   2020-07-16 13:08:14
    KB4570334 Security Update NT AUTHORITY\SYSTEM   2020-08-13 17:45:34
    KB4577266 Security Update NT AUTHORITY\SYSTEM   2020-09-11 13:37:59
    KB4537759 Security Update                       2020-05-11 07:44:14
    KB4561600 Security Update NT AUTHORITY\SYSTEM   2020-06-22 13:00:50
    KB4578968 Update          NT AUTHORITY\SYSTEM   2020-10-14 18:06:18
    KB4580325 Security Update NT AUTHORITY\SYSTEM   2020-10-14 13:09:37
    #>

    [CmdletBinding()] Param()

    function Get-PackageInfo {

        Param(
            [String]$Path
        )

        $Info = New-Object -TypeName PSObject

        [xml] $PackageContentXml = Get-Content -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetContentError
        if (-not $GetContentError) {

            $PackageContentXml.GetElementsByTagName("assembly") | ForEach-Object {

                $Info | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value "$($_.displayName)"
                $Info | Add-Member -MemberType "NoteProperty" -Name "SupportInformation" -Value "$($_.supportInformation)"
            }

            $PackageContentXml.GetElementsByTagName("package") | ForEach-Object {

                $Info | Add-Member -MemberType "NoteProperty" -Name "Identifier" -Value "$($_.identifier)"
                $Info | Add-Member -MemberType "NoteProperty" -Name "ReleaseType" -Value "$($_.releaseType)"
            }

            $Info
        }
    }

    if ($CachedHotFixList.Count -eq 0) {

        # In the registry, one KB may have multiple entries because it can be split up into multiple
        # packages. This array will help keep track of KBs that have already been checked by the 
        # script.
        $InstalledKBs = New-Object -TypeName System.Collections.ArrayList

        $AllPackages = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetChildItem
        
        if (-not $ErrorGetChildItem) {

            $AllPackages | ForEach-Object {
        
                # Filter only KB-related packages
                if (($_.Name | Split-Path -Leaf) -Like "Package_*_for_KB*") {
            
                    $PackageProperties = $_ | Get-ItemProperty

                    # Get the KB id, e.g.: KBXXXXXXX
                    $PackageName = $PackageProperties.InstallName.Split('~')[0].Split('_') | Where-Object { $_ -Like "KB*" }
                    if ($PackageName) {

                        # Check whether this KB has already been handled
                        if (-not ($InstalledKBs -contains $PackageName)) {

                            # Add the KB id to the list so we don't check it multiple times
                            [void]$InstalledKBs.Add($PackageName)
        
                            # Who installed this update?
                            $InstalledBy = Convert-SidToName -Sid $PackageProperties.InstallUser
                            
                            # Get the install date. It's stored in the registry just like a FILETIME structure. So, we have to 
                            # combine the low part and the high part and convert the result to a DateTime object.
                            $DateHigh = $PackageProperties.InstallTimeHigh
                            $DateLow = $PackageProperties.InstallTimeLow
                            $FileTime = $DateHigh * [Math]::Pow(2, 32) + $DateLow
                            $InstallDate = [DateTime]::FromFileTime($FileTime)
        
                            # Parse the package metadata file and extract some useful information...
                            $ServicingPackagesPath = Join-Path -Path $env:windir -ChildPath "servicing\Packages"
                            $PackagePath = Join-Path -Path $ServicingPackagesPath -ChildPath $PackageProperties.InstallName
                            $PackageInfo = Get-PackageInfo -Path $PackagePath

                            $Result = New-Object -TypeName PSObject
                            $Result | Add-Member -MemberType "NoteProperty" -Name "HotFixID" -Value "$PackageName"
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "$($PackageInfo.ReleaseType)"
                            $Result | Add-Member -MemberType "NoteProperty" -Name "InstalledBy" -Value "$InstalledBy"
                            $Result | Add-Member -MemberType "NoteProperty" -Name "InstalledOn" -Value $InstallDate

                            [void]$CachedHotFixList.Add($Result)
                        }
                    }
                }
            }
        }
        else {
            # If we can't read the registry, fall back to the built-in 'Get-HotFix' cmdlet
            Get-HotFix | Select-Object HotFixID,Description,InstalledBy,InstalledOn | ForEach-Object {
                [void]$CachedHotFixList.Add($_)
            }
        }
    }

    $CachedHotFixList | ForEach-Object {
        $_
    }
}

function Get-SccmCacheFolder {
    <#
    .SYNOPSIS
    Helper - Get the SCCM cache folder as a PowerShell object if it exists.

    Author: @itm4n
    License: BSD 3-Clause
    #>

    [CmdletBinding()] param ()

    $CcmCachePath = Join-Path -Path $env:windir -ChildPath "CCMCache"
    Get-Item -Path $CcmCachePath -ErrorAction SilentlyContinue | Select-Object -Property FullName,Attributes,Exists
}

function Get-ScheduledTaskList {
    <#
    .SYNOPSIS
    Helper - Enumerate all the scheduled task that are not disabled and that are visible to the current user.
    
    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Connect to the task scheduler service and retrieve a list of all the scheduled tasks that are visible to the current user.
    
    .EXAMPLE
    PS C:\> Get-ScheduledTaskList | Select-Object -last 3

    TaskName           : UpdateLibrary
    TaskPath           : \Microsoft\Windows\Windows Media Sharing\UpdateLibrary
    TaskFile           : C:\Windows\System32\Tasks\Microsoft\Windows\Windows Media Sharing\UpdateLibrary
    RunAs              : NT AUTHORITY\Authenticated Users
    Command            : "%ProgramFiles%\Windows Media Player\wmpnscfg.exe"
    CurrentUserIsOwner : False

    TaskName           : Scheduled Start
    TaskPath           : \Microsoft\Windows\WindowsUpdate\Scheduled Start
    TaskFile           : C:\Windows\System32\Tasks\Microsoft\Windows\WindowsUpdate\Scheduled Start
    RunAs              : NT AUTHORITY\SYSTEM
    Command            : C:\Windows\system32\sc.exe start wuauserv
    CurrentUserIsOwner : False

    TaskName           : XblGameSaveTask
    TaskPath           : \Microsoft\XblGameSave\XblGameSaveTask
    TaskFile           : C:\Windows\System32\Tasks\Microsoft\XblGameSave\XblGameSaveTask
    RunAs              : NT AUTHORITY\SYSTEM
    Command            : %windir%\System32\XblGameSaveTask.exe standby
    CurrentUserIsOwner : False
    #>

    [CmdletBinding()] param ()

    function Get-ScheduledTasks {

        param (
            [Object]$Service,
            [String]$TaskPath
        )

        ($CurrentFolder = $Service.GetFolder($TaskPath)).GetTasks(0)
        $CurrentFolder.GetFolders(0) | ForEach-Object {
            Get-ScheduledTasks -Service $Service -TaskPath $(Join-Path -Path $TaskPath -ChildPath $_.Name )
        }
    }

    try {

        if ($CachedScheduledTaskList.Count -eq 0) {

            # If the cache is empty, enumerate scheduled tasks and populate the cache.

            $ScheduleService = New-Object -ComObject("Schedule.Service")
            $ScheduleService.Connect()
    
            Get-ScheduledTasks -Service $ScheduleService -TaskPath "\" | ForEach-Object {
    
                if ($_.Enabled) {
    
                    $TaskName = $_.Name
                    $TaskPath = $_.Path
                    $TaskFile = Join-Path -Path $(Join-Path -Path $env:windir -ChildPath "System32\Tasks") -ChildPath $TaskPath
    
                    [xml]$TaskXml = $_.Xml

                    $Principal = $TaskXml.GetElementsByTagName("Principal")
                    $CurrentUserIsOwner = $false
                    $PrincipalSid = $Principal | Select-Object -ExpandProperty "UserId" -ErrorAction SilentlyContinue -ErrorVariable ErrorSelectObject
                    if (-not $ErrorSelectObject) {
                        # No error occurred. This means that we were able to get the UserId attribute from the node and
                        # therefore the Principal is a User.
                        if ($(Invoke-UserCheck).SID -eq $PrincipalSid) {
                            $CurrentUserIsOwner = $true
                        }
                    }
                    else {
                        # An error occurred. This means that the node does not have a UserId attribute. Therefore is has to
                        # be a Group, so get the GroupId instead.
                        $PrincipalSid = $Principal | Select-Object -ExpandProperty "GroupId" -ErrorAction SilentlyContinue -ErrorVariable ErrorSelectObject
                    }

                    # We got a SID, convert it to the corresponding friendly name
                    $PrincipalName = Convert-SidToName -Sid $PrincipalSid
    
                    # According to the documentation, a Task can have up to 32 Actions. These Actions can be of 4 
                    # different Types: Exec, ComHandler, SendEmail, and ShowMessage. Here, we are only interested in 
                    # Exec Actions. However, as there can be more than one item, we need to iterate the list and create
                    # a new object for each Action. This will potentially create multiple Task objects with the same 
                    # Name but that's not really an issue. Note that, usually, Tasks are defined with only one Action. 
                    # So that's still an edge case.
                    $TaskXml.GetElementsByTagName("Exec") | ForEach-Object {

                        $TaskProgram = $_ | Select-Object -ExpandProperty "Command"
                        $TaskArguments = $_ | Select-Object -ExpandProperty "Arguments" -ErrorAction SilentlyContinue

                        if ($TaskArguments) {
                            $TaskCommandLine = "$($TaskProgram) $($TaskArguments)"
                        }
                        else {
                            $TaskCommandLine = "$($TaskProgram)"
                        }

                        if ($TaskCommandLine.Length -gt 0) {

                            $Result = New-Object -TypeName PSObject
                            $Result | Add-Member -MemberType "NoteProperty" -Name "TaskName" -Value $TaskName
                            $Result | Add-Member -MemberType "NoteProperty" -Name "TaskPath" -Value $TaskPath
                            $Result | Add-Member -MemberType "NoteProperty" -Name "TaskFile" -Value $TaskFile
                            $Result | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value $PrincipalName
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Command" -Value $TaskCommandLine
                            $Result | Add-Member -MemberType "NoteProperty" -Name "CurrentUserIsOwner" -Value $CurrentUserIsOwner

                            [void] $CachedScheduledTaskList.Add($Result)
                        }
                    }
                }
                else {
                    Write-Verbose "Task '$($_.Name)' is disabled"
                }
            }
        }

        $CachedScheduledTaskList | ForEach-Object { 
            $_
        }

    }
    catch {
        Write-Verbose $_
    }
}

function Get-RpcRange {
    <#
    .SYNOPSIS
    Helper - Dynamically identifies the range of randomized RPC ports from a list of ports.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    This function is a helper for the Invoke-TcpEndpointsCheck function. Windows uses a set of RPC ports that are randomly allocated in the range 49152-65535 by default. If we want to filter out these listening ports we must first figure out this set of ports. The aim of this function is to guess this range using basic statistics on a given array of port numbers. We can quite reliably identify the RPC port set because they are concentrated in a very small range. It's not 100% reliable but it will do the job most of the time.
    
    .PARAMETER Ports
    An array of port numbers
    
    .EXAMPLE
    PS C:\> Get-RpcRange -Ports $Ports 

    MinPort MaxPort
    ------- -------
    49664   49672
    #>

    [CmdletBinding()]Param(
        [Parameter(Mandatory=$true)]
        [Int[]]
        $Ports
    )

    function Get-Stats {
        [CmdletBinding()]Param(
            [Int[]]$Ports,
            [Int]$MinPort,
            [Int]$MaxPort,
            [Int]$Span
        )

        $Stats = @() 
        For ($i = $MinPort; $i -lt $MaxPort; $i += $Span) {
            $Counter = 0
            foreach ($Port in $Ports) {
                if (($Port -ge $i) -and ($Port -lt ($i + $Span))) {
                    $Counter += 1
                }
            }
            $RangeStats = New-Object -TypeName PSObject 
            $RangeStats | Add-Member -MemberType "NoteProperty" -Name "MinPort" -Value $i
            $RangeStats | Add-Member -MemberType "NoteProperty" -Name "MaxPort" -Value ($i + $Span)
            $RangeStats | Add-Member -MemberType "NoteProperty" -Name "PortsInRange" -Value $Counter
            $Stats += $RangeStats 
        }
        $Stats
    }

    # We split the range 49152-65536 into blocks of size 32 and then, we take the block which has 
    # greater number of ports in it. 
    $Stats = Get-Stats -Ports $Ports -MinPort 49152 -MaxPort 65536 -Span 32

    $MaxStat = $null
    foreach ($Stat in $Stats) {
        if ($Stat.PortsInRange -gt $MaxStat.PortsInRange) {
            $MaxStat = $Stat
        }
    } 

    For ($i = 0; $i -lt 8; $i++) {
        $Span = ($MaxStat.MaxPort - $MaxStat.MinPort) / 2
        $NewStats = Get-Stats -Ports $Ports -MinPort $MaxStat.MinPort -MaxPort $MaxStat.MaxPort -Span $Span
        if ($NewStats) {
            if ($NewStats[0].PortsInRange -eq 0) {
                $MaxStat = $NewStats[1]
            }
            elseif ($NewStats[1].PortsInRange -eq 0) {
                $MaxStat = $NewStats[0]
            }
            else {
                break 
            }
        }
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "MinPort" -Value $MaxStat.MinPort
    $Result | Add-Member -MemberType "NoteProperty" -Name "MaxPort" -Value $MaxStat.MaxPort
    $Result
}

function Convert-CredentialBlobToString {

    [CmdletBinding()] Param(
        [Parameter(Position = 1, Mandatory=$true)]
        [Object] # CREDENTIAL
        $RawObject
    )

    if (-not ($RawObject.CredentialBlobSize -eq 0)) {

        $TestFlags = 2 # IS_TEXT_UNICODE_STATISTICS
        $IsUnicode = $Advapi32::IsTextUnicode($RawObject.CredentialBlob, $RawObject.CredentialBlobSize, [ref]$TestFlags)
        
        if ($IsUnicode) {
            Write-Verbose "Encoding of input text is UNICODE"
            $Result = [Runtime.InteropServices.Marshal]::PtrToStringUni($RawObject.CredentialBlob, $RawObject.CredentialBlobSize / 2)
        }
        else {
            for ($i = 0; $i -lt $RawObject.CredentialBlobSize; $i++) {
                $BytePtr = [IntPtr] ($RawObject.CredentialBlob.ToInt64() + $i)
                $Byte = [Runtime.InteropServices.Marshal]::ReadByte($BytePtr)
                $Result += "{0:X2} " -f $Byte
            }
        }

        $Result
    }
}

function Get-VaultCreds {
    <#
    .SYNOPSIS
    Helper - Enumerates Windows Credentials
    
    .DESCRIPTION
    Invokes the Windows API to enumerate the credentials that are stored in the user's vault (Windows Credentials).
    
    .PARAMETER Filtered
    If True, only entries with a readable (i.e. non-empty) password are returned.
    
    .EXAMPLE
    PS C:\> Get-VaultCreds -Filtered
    
    TargetName : LegacyGeneric:target=https://github.com/
    UserName   : user@example.com
    Comment    :
    Type       : 1 - GENERIC
    Persist    : 2 - LOCAL_MACHINE
    Flags      : 0
    Credential : dBa2F06TTsrvSeLbyoW8
    
    #>

    [CmdletBinding()] Param(
        [Switch]
        $Filtered = $false
    )

    # CRED_ENUMERATE_ALL_CREDENTIALS = 0x1
    $Count = 0;
    $CredentialsPtr = [IntPtr]::Zero
    $Success = $Advapi32::CredEnumerate([IntPtr]::Zero, 1, [ref]$Count, [ref]$CredentialsPtr)
    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($Success) {

        Write-Verbose "CredEnumerate() OK - Count: $($Count)"

        # CredEnumerate() returns an array of $Count PCREDENTIAL pointers, so we need to iterate this array
        # in order to get each PCREDENTIAL pointer. Then we can use this pointer to convert a blob of 
        # unmanaged memory to a CREDENTIAL object.

        for ($i = 0; $i -lt $Count; $i++) {

            $CredentialPtrOffset = [IntPtr] ($CredentialsPtr.ToInt64() + [IntPtr]::Size * $i)
            $CredentialPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($CredentialPtrOffset) 
            $Cred = [System.Runtime.InteropServices.Marshal]::PtrToStructure($CredentialPtr, [type] $CREDENTIAL)
            $CredStr = Convert-CredentialBlobToString $Cred

            if ((-not $Filtered) -or ($Filtered -and (-not [String]::IsNullOrEmpty($CredStr)))) {

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "TargetName" -Value $Cred.TargetName
                $Result | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $Cred.UserName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Comment" -Value $Cred.Comment
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "$($Cred.Type -as $CRED_TYPE)"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Persist" -Value "$($Cred.Persist -as $CRED_PERSIST)"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Flags" -Value "0x$($Cred.Flags.ToString('X8'))"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Credential" -Value $CredStr
                $Result
            }
        }

        $Advapi32::CredFree($CredentialsPtr)

    }
    else {
        # If there is no saved credentials, CredEnumerate sets the last error to ERROR_NOT_FOUND but this
        # doesn't mean that the function really failed. The same thing applies for the error code 
        # ERROR_NO_SUCH_LOGON_SESSION.
        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
    }
}

function Get-VaultList {

    [CmdletBinding()] Param(
        [Switch]
        $Filtered = $false
    )

    function Get-VaultNameFromGuid {
        [CmdletBinding()] Param(
            [Guid] $VaultGuid
        )

        $VaultSchemaEnum = @{
            ([Guid] '2F1A6504-0641-44CF-8BB5-3612D865F2E5') = 'Windows Secure Note'
            ([Guid] '3CCD5499-87A8-4B10-A215-608888DD3B55') = 'Windows Web Password Credential'
            ([Guid] '154E23D0-C644-4E6F-8CE6-5069272F999F') = 'Windows Credential Picker Protector'
            ([Guid] '4BF4C442-9B8A-41A0-B380-DD4A704DDB28') = 'Web Credentials'
            ([Guid] '77BC582B-F0A6-4E15-4E80-61736B6F3B29') = 'Windows Credentials'
            ([Guid] 'E69D7838-91B5-4FC9-89D5-230D4D4CC2BC') = 'Windows Domain Certificate Credential'
            ([Guid] '3E0E35BE-1B77-43E7-B873-AED901B6275B') = 'Windows Domain Password Credential'
            ([Guid] '3C886FF3-2669-4AA2-A8FB-3F6759A77548') = 'Windows Extended Credential'
        }

        $VaultSchemaEnum[$VaultGuid]
    }

    # Highly inspired from "Get-VaultCredential.ps1", credit goes to Matthew Graeber
    # https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Get-VaultCredential.ps1
    function Get-VaultItemElementValue {
        [CmdletBinding()] Param(
            [IntPtr]
            $VaultItemElementPtr
        )

        if ($VaultItemElementPtr -eq [IntPtr]::Zero) {
            return
        }

        $VaultItemDataHeader = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemElementPtr, [type] $VAULT_ITEM_DATA_HEADER)
        $VaultItemDataValuePtr = [IntPtr] ($VaultItemElementPtr.ToInt64() + 16)

        switch ($VaultItemDataHeader.Type) {

            # ElementType_Boolean
            0x00 {
                [Bool] [Runtime.InteropServices.Marshal]::ReadByte($VaultItemDataValuePtr)
            }

            # ElementType_Short
            0x01 {
                [Runtime.InteropServices.Marshal]::ReadInt16($VaultItemDataValuePtr)
            }

            # ElementType_UnsignedShort
            0x02 {
                [Runtime.InteropServices.Marshal]::ReadInt16($VaultItemDataValuePtr)
            }

            # ElementType_Integer
            0x03 {
                [Runtime.InteropServices.Marshal]::ReadInt32($VaultItemDataValuePtr)
            }

            # ElementType_UnsignedInteger
            0x04 {
                [Runtime.InteropServices.Marshal]::ReadInt32($VaultItemDataValuePtr)
            }

            # ElementType_Double
            0x05 {
                [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemDataValuePtr, [Type] [Double])
            }

            # ElementType_Guid
            0x06 {
                [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemDataValuePtr, [Type] [Guid])
            }

            # ElementType_String
            0x07 { 
                $StringPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($VaultItemDataValuePtr)
                [Runtime.InteropServices.Marshal]::PtrToStringUni($StringPtr)
            }

            # ElementType_ByteArray
            0x08 {

            }

            # ElementType_TimeStamp
            0x09 {

            }

            # ElementType_ProtectedArray
            0x0a {

            }

            # ElementType_Attribute
            0x0b {

            }

            # ElementType_Sid
            0x0c {
                $SidPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($VaultItemDataValuePtr)
                $SidObject = [Security.Principal.SecurityIdentifier] ($SidPtr)
                $SidObject.Value
            }

            # ElementType_Max
            0x0d {
                
            }
        }
    }

    $VaultsCount = 0
    $VaultGuids = [IntPtr]::Zero 
    $Result = $Vaultcli::VaultEnumerateVaults(0, [ref]$VaultsCount, [ref]$VaultGuids)

    if ($Result -eq 0) {

        Write-Verbose "VaultEnumerateVaults() OK - Count: $($VaultsCount)"

        for ($i = 0; $i -lt $VaultsCount; $i++) {

            $VaultGuidPtr = [IntPtr] ($VaultGuids.ToInt64() + ($i * [Runtime.InteropServices.Marshal]::SizeOf([Type] [Guid])))
            $VaultGuid = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultGuidPtr, [type] [Guid])
            $VaultName = Get-VaultNameFromGuid -VaultGuid $VaultGuid

            Write-Verbose "Vault: $($VaultGuid) - $($VaultName)"

            $VaultHandle = [IntPtr]::Zero
            $Result = $Vaultcli::VaultOpenVault($VaultGuidPtr, 0, [ref]$VaultHandle)

            if ($Result -eq 0) {

                Write-Verbose "VaultOpenVault() OK - Vault Handle: 0x$($VaultHandle.ToString('X8'))"

                $VaultItemsCount = 0
                $ItemsPtr = [IntPtr]::Zero 
                $Result = $Vaultcli::VaultEnumerateItems($VaultHandle, 0x0200, [ref]$VaultItemsCount, [ref]$ItemsPtr)

                $VaultItemPtr = $ItemsPtr

                if ($Result -eq 0) {

                    Write-Verbose "VaultEnumerateItems() OK - Items Count: $($VaultItemsCount)"

                    $OSVersion = [Environment]::OSVersion.Version

                    try {

                        for ($j = 0; $j -lt $VaultItemsCount; $j++) {

                            if ($OSVersion.Major -le 6 -and $OSVersion.Minor -le 1) {
                                # Windows 7
                                $VaultItemType = [type] $VAULT_ITEM_7
                            }
                            else {
                                # Windows 8+
                                $VaultItemType = [type] $VAULT_ITEM_8
                            }
    
                            $VaultItem = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemPtr, [type] $VaultItemType)
    
                            if ($OSVersion.Major -le 6 -and $OSVersion.Minor -le 1) {
                                # Windows 7
                                $PasswordItemPtr = [IntPtr]::Zero
                                $Result = $Vaultcli::VaultGetItem7($VaultHandle, [ref]$VaultItem.SchemaId, $VaultItem.Resource, $VaultItem.Identity, [IntPtr]::Zero, 0, [ref]$PasswordItemPtr)
                            }
                            else {
                                # Windows 8+
                                $PasswordItemPtr = [IntPtr]::Zero
                                $Result = $Vaultcli::VaultGetItem8($VaultHandle, [ref]$VaultItem.SchemaId, $VaultItem.Resource, $VaultItem.Identity, $VaultItem.PackageSid, [IntPtr]::Zero, 0, [ref]$PasswordItemPtr)
                            }
    
                            if ($Result -eq 0) {

                                Write-Verbose "VaultGetItem() OK - ItemPtr: 0x$($PasswordItemPtr.ToString('X8'))"
                                $PasswordItem = [Runtime.InteropServices.Marshal]::PtrToStructure($PasswordItemPtr, [Type] $VaultItemType)
                                $Password = Get-VaultItemElementValue -VaultItemElementPtr $PasswordItem.Authenticator
                                $Vaultcli::VaultFree($PasswordItemPtr) | Out-Null

                            }
                            else {
                                Write-Verbose "VaultGetItem() failed - Err: 0x$($Result.ToString('X8'))"
                            }
    
                            if ((-not $Filtered) -or ($Filtered -and (-not [String]::IsNullOrEmpty($Password)))) {

                                $Result = New-Object -TypeName PSObject
                                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $VaultName
                                $Result | Add-Member -MemberType "NoteProperty" -Name "TargetName" -Value $(Get-VaultItemElementValue -VaultItemElementPtr $VaultItem.Resource)
                                $Result | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $(Get-VaultItemElementValue -VaultItemElementPtr $VaultItem.Identity)
                                $Result | Add-Member -MemberType "NoteProperty" -Name "Credential" -Value $Password
                                $Result | Add-Member -MemberType "NoteProperty" -Name "LastWritten" -Value $(Convert-FiletimeToDatetime $VaultItem.LastWritten)
                                $Result
                            }

                            $VaultItemPtr = [IntPtr] ($VaultItemPtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([Type] $VaultItemType))
                        }

                    }
                    catch [Exception] {
                        Write-Verbose $_.Exception.Message 
                    }

                }
                else {
                    Write-Verbose "VaultEnumerateItems() failed - Err: 0x$($Result.ToString('X8'))"
                }

                $Vaultcli::VaultCloseVault([ref]$VaultHandle) | Out-Null

            }
            else {
                Write-Verbose "VaultOpenVault() failed - Err: 0x$($Result.ToString('X8'))"
            }
        }

    }
    else {
        Write-Verbose "VaultEnumerateVaults() failed - Err: 0x$($Result.ToString('X8'))"
    }
}

function Test-ServiceDaclPermission {
    <#
    .SYNOPSIS
    Tests one or more passed services or service names against a given permission set, returning the service objects where the current user have the specified permissions.

    Author: @harmj0y, Matthew Graeber
    License: BSD 3-Clause

    .DESCRIPTION
    Takes a service Name or a ServiceProcess.ServiceController on the pipeline, and first adds a service Dacl to the service object with Add-ServiceDacl. All group SIDs for the current user are enumerated services where the user has some type of permission are filtered. The services are then filtered against a specified set of permissions, and services where the current user have the specified permissions are returned.

    .PARAMETER Name
    An array of one or more service names to test against the specified permission set.

    .PARAMETER Permissions
    A manual set of permission to test again. One of:'QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess'

    .PARAMETER PermissionSet
    A pre-defined permission set to test a specified service against. 'ChangeConfig', 'Restart', or 'AllAccess'.

    .OUTPUTS
    ServiceProcess.ServiceController

    .EXAMPLE
    PS C:\> Get-Service | Test-ServiceDaclPermission

    Return all service objects where the current user can modify the service configuration.

    .EXAMPLE
    PS C:\> Get-Service | Test-ServiceDaclPermission -PermissionSet 'Restart'

    Return all service objects that the current user can restart.

    .EXAMPLE
    PS C:\> Test-ServiceDaclPermission -Permissions 'Start' -Name 'VulnSVC'

    Return the VulnSVC object if the current user has start permissions.

    .LINK
    https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
    #>
    [OutputType('ServiceProcess.ServiceController')]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String[]]
        [ValidateSet('QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', 'UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess')]
        $Permissions,

        [String]
        [ValidateSet('ChangeConfig', 'Restart', 'AllAccess')]
        $PermissionSet = 'ChangeConfig'
    )

    BEGIN {
        $AccessMask = @{
            'QueryConfig'           = [UInt32]'0x00000001'
            'ChangeConfig'          = [UInt32]'0x00000002'
            'QueryStatus'           = [UInt32]'0x00000004'
            'EnumerateDependents'   = [UInt32]'0x00000008'
            'Start'                 = [UInt32]'0x00000010'
            'Stop'                  = [UInt32]'0x00000020'
            'PauseContinue'         = [UInt32]'0x00000040'
            'Interrogate'           = [UInt32]'0x00000080'
            'UserDefinedControl'    = [UInt32]'0x00000100'
            'Delete'                = [UInt32]'0x00010000'
            'ReadControl'           = [UInt32]'0x00020000'
            'WriteDac'              = [UInt32]'0x00040000'
            'WriteOwner'            = [UInt32]'0x00080000'
            'Synchronize'           = [UInt32]'0x00100000'
            'AccessSystemSecurity'  = [UInt32]'0x01000000'
            'GenericAll'            = [UInt32]'0x10000000'
            'GenericExecute'        = [UInt32]'0x20000000'
            'GenericWrite'          = [UInt32]'0x40000000'
            'GenericRead'           = [UInt32]'0x80000000'
            'AllAccess'             = [UInt32]'0x000F01FF'
        }
        
        $CheckAllPermissionsInSet = $false

        if ($PSBoundParameters['Permissions']) {
            $TargetPermissions = $Permissions
        }
        else {
            if ($PermissionSet -eq 'ChangeConfig') {
                $TargetPermissions = @('ChangeConfig', 'WriteDac', 'WriteOwner', 'GenericAll', ' GenericWrite', 'AllAccess')
            }
            elseif ($PermissionSet -eq 'Restart') {
                $TargetPermissions = @('Start', 'Stop')
                $CheckAllPermissionsInSet = $true # so we check all permissions && style
            }
            elseif ($PermissionSet -eq 'AllAccess') {
                $TargetPermissions = @('GenericAll', 'AllAccess')
            }
        }
    }

    PROCESS {

        foreach ($IndividualService in $Name) {

            $TargetService = $IndividualService | Add-ServiceDacl

            # We might not be able to access the Service at all so we must check whether Add-ServiceDacl 
            # returned something.
            if ($TargetService -and $TargetService.Dacl) { 

                # Enumerate all group SIDs the current user is a part of
                $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
                $CurrentUserSids += $UserIdentity.User.Value

                # Check all the Dacl objects of the current service 
                foreach ($Ace in $TargetService.Dacl) {

                    $MatchingDaclFound = $false

                    # An ACE object contains two properties we want to check: a SID and a list of AccessRights. First, 
                    # we want to check if the current Dacl SID is in the list of SIDs of the current user 
                    if ($CurrentUserSids -contains $Ace.SecurityIdentifier) {

                        if ($CheckAllPermissionsInSet) {

                            # If a Permission Set was specified, we want to make sure that we have all the necessary access 
                            # rights
                            $AllMatched = $true
                            foreach ($TargetPermission in $TargetPermissions) {
                                # check permissions && style
                                if (($Ace.AccessRights -band $AccessMask[$TargetPermission]) -ne $AccessMask[$TargetPermission]) {
                                    # Write-Verbose "Current user doesn't have '$TargetPermission' for $($TargetService.Name)"
                                    $AllMatched = $false
                                    break
                                }
                            }
                            if ($AllMatched) {
                                $TargetService | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $Ace.AccessRights
                                $TargetService | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $(Convert-SidToName -Sid $Ace.SecurityIdentifier)
                                $TargetService
                                $MatchingDaclFound = $true 
                            }
                        }
                        else {

                            foreach ($TargetPermission in $TargetPermissions) {
                                # check permissions || style
                                if (($Ace.AceType -eq 'AccessAllowed') -and ($Ace.AccessRights -band $AccessMask[$TargetPermission]) -eq $AccessMask[$TargetPermission]) {
                                    $TargetService | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $Ace.AccessRights
                                    $TargetService | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $(Convert-SidToName -Sid $Ace.SecurityIdentifier)
                                    $TargetService
                                    $MatchingDaclFound = $true 
                                    break
                                }
                            }
                        }
                    }

                    if ($MatchingDaclFound) {
                        # As soon as we find a matching Dacl, we can stop searching 
                        break
                    }
                }
            }
            else {
                Write-Verbose "Error enumerating the Dacl for service $IndividualService"
            }
        }
    }
}