function Test-IsRunningInConsole {
    return $Host.Name -match "ConsoleHost"
}

function Convert-FiletimeToDatetime {
    [OutputType([DateTime])]
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
        Write-Warning "$($MyInvocation.MyCommand) | Failed to translate SID: $($Sid)"
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

    [OutputType([String])]
    [CmdletBinding()] Param(
        [String]$Sid
    )

    try {
        $SidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $SidObj.Translate([System.Security.Principal.NTAccount]) | Select-Object -ExpandProperty Value
    }
    catch {
        # In case of failure, return the SID.
        $Sid
    }
}

function Convert-PSidToStringSid {

    [OutputType([String])]
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [IntPtr]$PSid
    )

    $StringSidPtr = [IntPtr]::Zero
    $Success = $Advapi32::ConvertSidToStringSidW($PSid, [ref] $StringSidPtr)

    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "ConvertSidToStringSidW - $([ComponentModel.Win32Exception] $LastError)"
        return
    }

    $StringSid = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($StringSidPtr)
    $Kernel32::LocalFree($StringSidPtr) | Out-Null

    $StringSid
}

function Convert-PSidToNameAndType {

    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [IntPtr]$PSid
    )

    $SidType = 0

    $NameSize = 256
    $Name = New-Object -TypeName System.Text.StringBuilder
    $Name.EnsureCapacity(256) | Out-Null

    $DomainSize = 256
    $Domain = New-Object -TypeName System.Text.StringBuilder
    $Domain.EnsureCapacity(256) | Out-Null

    $Success = $Advapi32::LookupAccountSid($null, $PSid, $Name, [ref]$NameSize, $Domain, [ref]$DomainSize, [ref]$SidType)
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

    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [IntPtr]$PSid
    )

    $SubAuthorityCountPtr = $Advapi32::GetSidSubAuthorityCount($PSid)
    $SubAuthorityCount = [Runtime.InteropServices.Marshal]::ReadByte($SubAuthorityCountPtr)
    $SubAuthorityPtr = $Advapi32::GetSidSubAuthority($PSid, $SubAuthorityCount - 1)
    $SubAuthority = [UInt32] [Runtime.InteropServices.Marshal]::ReadInt32($SubAuthorityPtr)
    $SubAuthority
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

    [OutputType([String])]
    [CmdletBinding()] Param(
        [System.DateTime]$Date
    )

    if ($null -ne $Date) {
        $OutString = ""
        $OutString += $Date.ToString('yyyy-MM-dd - HH:mm:ss')
        $OutString
    }
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
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [String]$DosDevice
    )

    $TargetPathLen = 260
    $TargetPathPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TargetPathLen * 2)
    $TargetPathLen = $Kernel32::QueryDosDevice($DosDevice, $TargetPathPtr, $TargetPathLen)

    if ($TargetPathLen -eq 0) {
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TargetPathPtr)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "QueryDosDevice('$($DosDevice)') - $([ComponentModel.Win32Exception] $LastError)"
        return
    }

    [System.Runtime.InteropServices.Marshal]::PtrToStringUni($TargetPathPtr)
    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TargetPathPtr)
}

function Get-WindowsVersion {

    [CmdletBinding()] Param()

    $RegKey = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $RegItem = Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue

    if ($null -eq $RegItem) {
        [System.Environment]::OSVersion.Version
        return
    }

    $Major = $RegItem.CurrentMajorVersionNumber
    $Minor = $RegItem.CurrentMinorVersionNumber

    if ($null -eq $Major) { $Major = $RegItem.CurrentVersion.Split(".")[0] }
    if ($null -eq $Minor) { $Minor = $RegItem.CurrentVersion.Split(".")[1] }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Major" -Value ([UInt32] $Major)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Minor" -Value ([UInt32] $Minor)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Build" -Value ([UInt32] $RegItem.CurrentBuildNumber)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Revision" -Value 0
    $Result | Add-Member -MemberType "NoteProperty" -Name "MajorRevision" -Value 0
    $Result | Add-Member -MemberType "NoteProperty" -Name "MinorRevision" -Value 0
    $Result | Add-Member -MemberType "NoteProperty" -Name "ReleaseId" -Value $RegItem.ReleaseId
    $Result | Add-Member -MemberType "NoteProperty" -Name "UBR" -Value $RegItem.UBR
    $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value $RegItem.ProductName
    $Result
}

function Test-IsMicrosoftFile {

    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [Object]$File
    )

    if ($File.VersionInfo.LegalCopyright -like "*Microsoft Corporation*") {
        return $true
    }

    return $false
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
    Access   : {System.Security.AccessControl.CommonAce, System.Security.AccessControl.CommonAce, System.Security.AccessCon
            trol.CommonAce, System.Security.AccessControl.CommonAce...}
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

    [CmdletBinding()] Param(
        [String]$Path
    )

    $DesiredAccess = $FileAccessRightsEnum::ReadControl
    $ShareMode = 0x00000001 # FILE_SHARE_READ
    $CreationDisposition = 3 # OPEN_EXISTING
    $FlagsAndAttributes = 0x80 # FILE_ATTRIBUTE_NORMAL
    $FileHandle = $Kernel32::CreateFile($Path, $DesiredAccess, $ShareMode, [IntPtr]::Zero, $CreationDisposition, $FlagsAndAttributes, [IntPtr]::Zero)

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
    $Result = $Advapi32::GetSecurityInfo($FileHandle, $ObjectType, $SecurityInfo, [ref]$SidOwnerPtr, [ref]$SidGroupPtr, [ref]$DaclPtr, [ref]$SaclPtr, [ref]$SecurityDescriptorPtr)

    if ($Result -ne 0) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "GetSecurityInfo KO ($Result) - $([ComponentModel.Win32Exception] $LastError)"
        $Kernel32::CloseHandle($FileHandle) | Out-Null
        return
    }

    $OwnerSidString = Convert-PSidToStringSid -PSid $SidOwnerPtr
    $OwnerSidInfo = Convert-PSidToNameAndType -PSid $SidOwnerPtr
    $GroupSidString = Convert-PSidToStringSid -PSid $SidGroupPtr
    $GroupSidInfo = Convert-PSidToNameAndType -PSid $SidGroupPtr

    $SecurityDescriptorString = ""
    $SecurityDescriptorStringLen = 0
    $Success = $Advapi32::ConvertSecurityDescriptorToStringSecurityDescriptor($SecurityDescriptorPtr, 1, $SecurityInfo, [ref]$SecurityDescriptorString, [ref]$SecurityDescriptorStringLen)

    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "ConvertSecurityDescriptorToStringSecurityDescriptor KO ($Result) - $([ComponentModel.Win32Exception] $LastError)"
        $Kernel32::LocalFree($SecurityDescriptorPtr) | Out-Null
        $Kernel32::CloseHandle($FileHandle) | Out-Null
        return
    }

    $SecurityDescriptorNewPtr = [IntPtr]::Zero
    $SecurityDescriptorNewSize = 0
    $Success = $Advapi32::ConvertStringSecurityDescriptorToSecurityDescriptor($SecurityDescriptorString, 1, [ref]$SecurityDescriptorNewPtr, [ref]$SecurityDescriptorNewSize)

    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "ConvertStringSecurityDescriptorToSecurityDescriptor KO ($Result) - $([ComponentModel.Win32Exception] $LastError)"
        $Kernel32::LocalFree($SecurityDescriptorPtr) | Out-Null
        $Kernel32::CloseHandle($FileHandle) | Out-Null
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

    $Kernel32::LocalFree($SecurityDescriptorNewPtr) | Out-Null
    $Kernel32::LocalFree($SecurityDescriptorPtr) | Out-Null
    $Kernel32::CloseHandle($FileHandle) | Out-Null
}

function Get-CurrentUserSids {

    [CmdletBinding()] Param()

    if ($null -eq $global:CachedCurrentUserSids) {
        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $global:CachedCurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $global:CachedCurrentUserSids += $UserIdentity.User.Value
    }

    $global:CachedCurrentUserSids
}

function Get-CurrentUserDenySids {

    [CmdletBinding()] Param()

    if ($null -eq $global:CachedCurrentUserDenySids) {
        $global:CachedCurrentUserDenySids = [string[]](Get-TokenInformationGroups -InformationClass Groups | Where-Object { $_.Attributes.Equals("UseForDenyOnly") } | Select-Object -ExpandProperty SID)
        if ($null -eq $global:CachedCurrentUserDenySids) {
            $global:CachedCurrentUserDenySids = @()
        }
    }

    $global:CachedCurrentUserDenySids
}

function Get-AclModificationRights {
    <#
    .SYNOPSIS
    Helper - Enumerates modification rights the current user has on an object.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    This cmdlet retrieves the ACL of an object and returns the ACEs that grant modification permissions to the current user. It should be noted that, in case of deny ACEs, restricted rights are removed from the permission list of the ACEs.
    
    .PARAMETER Path
    The full path of a securable object.
    
    .PARAMETER Type
    The target object type (e.g. "File").
    
    .EXAMPLE
    PS C:\> Get-AclModificationRights -Path C:\Temp\foo123.txt -Type File
    
    ModifiablePath    : C:\Temp\foo123.txt
    IdentityReference : NT AUTHORITY\Authenticated Users
    Permissions       : Delete, WriteAttributes, Synchronize, ReadControl, ReadData, AppendData, WriteExtendedAttributes,
                        ReadAttributes, WriteData, ReadExtendedAttributes, Execute

    .EXAMPLE
    PS C:\> Get-AclModificationRights -Path C:\Temp\deny-delete.txt -Type File

    ModifiablePath    : C:\Temp\deny-delete.txt
    IdentityReference : NT AUTHORITY\Authenticated Users
    Permissions       : WriteAttributes, Synchronize, ReadControl, ReadData, AppendData, WriteExtendedAttributes,
                        ReadAttributes, WriteData, ReadExtendedAttributes, Execute

    .EXAMPLE
    PS C:\> Get-AclModificationRights -Path C:\Temp\deny-write.txt -Type File

    ModifiablePath    : C:\Temp\deny-write.txt
    IdentityReference : NT AUTHORITY\Authenticated Users
    Permissions       : Delete, Synchronize, ReadControl, ReadData, ReadAttributes, ReadExtendedAttributes, Execute
    #>

    [CmdletBinding()] Param(
        [String]
        $Path,

        [ValidateSet("File", "Directory", "RegistryKey")]
        [String]
        $Type
    )

    BEGIN {
        $TypeFile = "File"
        $TypeDirectory = "Directory"
        $TypeRegistryKey = "RegistryKey"

        $FileAccessMask = @{
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
            [UInt32]'0x00000020' = 'Execute'
            [UInt32]'0x00000010' = 'WriteExtendedAttributes'
            [UInt32]'0x00000008' = 'ReadExtendedAttributes'
            [UInt32]'0x00000004' = 'AppendData'
            [UInt32]'0x00000002' = 'WriteData'
            [UInt32]'0x00000001' = 'ReadData'
        }

        $DirectoryAccessMask = @{
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
            [UInt32]'0x00000020' = 'Traverse'
            [UInt32]'0x00000010' = 'WriteExtendedAttributes'
            [UInt32]'0x00000008' = 'ReadExtendedAttributes'
            [UInt32]'0x00000004' = 'AddSubdirectory'
            [UInt32]'0x00000002' = 'AddFile'
            [UInt32]'0x00000001' = 'ListDirectory'
        }

        $RegistryKeyAccessMask = @{
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

        $AccessMask = @{
            $TypeFile = $FileAccessMask
            $TypeDirectory = $DirectoryAccessMask
            $TypeRegistryKey = $RegistryKeyAccessMask
        }

        $AccessRights = @{
            $TypeFile = "FileSystemRights"
            $TypeDirectory = "FileSystemRights"
            $TypeRegistryKey = "RegistryRights"
        }

        $ModificationRights = @{
            $TypeFile = @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'Delete', 'WriteData', 'AppendData')
            $TypeDirectory = @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'Delete', 'AddFile', 'AddSubdirectory')
            $TypeRegistryKey = @('SetValue', 'CreateSubKey', 'Delete', 'WriteDAC', 'WriteOwner')
        }

        $CurrentUserSids = Get-CurrentUserSids
        $CurrentUserDenySids = Get-CurrentUserDenySids

        $ResolvedIdentities = @{}

        function Convert-NameToSid {

            Param([String]$Name)

            if (($Name -match '^S-1-5.*') -or ($Name -match '^S-1-15-.*')) { $Name; return }

            if (-not ($ResolvedIdentities[$Name])) {
                $Identity = New-Object System.Security.Principal.NTAccount($Name)
                try {
                    $ResolvedIdentities[$Name] = $Identity.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                }
                catch {
                    $null = $_
                }
            }
            $ResolvedIdentities[$Name]
        }
    }

    PROCESS {

        try {
    
            # First things first, try to get the ACL of the object given its path.
            $Acl = Get-Acl -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetAclError
            if ($GetAclError) { return }
    
            # If no ACL is returned, it means that the object has a "null" DACL, in which case everyone is
            # granted full access to the object. We can therefore simply return a "virtual" ACE that grants
            # Everyone the "FullControl" right and exit.
            if ($null -eq $Acl) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $Path
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value (Convert-SidToName -Sid "S-1-1-0")
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value "GenericAll"
                $Result
                return
            }
            
            $DenyAces = [Object[]]($Acl | Select-Object -ExpandProperty Access | Where-Object { $_.AccessControlType -match "Deny" })
            $AllowAces = [Object[]]($Acl | Select-Object -ExpandProperty Access | Where-Object { $_.AccessControlType -match "Allow" })
    
            # Here we simply get the access mask, access list name and list of access rights that are
            # specific to the object type we are dealing with.
            $TypeAccessMask = $AccessMask[$Type]
            $TypeAccessRights = $AccessRights[$Type]
            $TypeModificationRights = $ModificationRights[$Type]

            # Before checking the object permissions, we first need to enumerate deny ACEs (if any) that
            # would restrict the rights we may have on the target object.
            $RestrictedRights = @()
            if ($DenyAces) { # Need to make sure it not null because of PSv2
                foreach ($DenyAce in $DenyAces) {
    
                    # Ignore "InheritOnly" ACEs because they only apply to child objects, not to the object itself
                    # (e.g.: a file in a directory or a sub-key of a registry key).
                    if ($DenyAce.PropagationFlags -band ([System.Security.AccessControl.PropagationFlags]"InheritOnly").value__) { continue }
        
                    # Convert the ACE's identity reference name to its SID. If the SID is not in the list
                    # of deny-only SIDs of the current Token, ignore it. If the SID does not match the 
                    # current user SID or the SID of any of its groups, ignore it as well.
                    # Note: deny-only SIDs are only used to check access-denied ACEs.
                    # https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-attributes-in-an-access-token
                    $IdentityReferenceSid = Convert-NameToSid -Name $DenyAce.IdentityReference
                    if ($CurrentUserDenySids -notcontains $IdentityReferenceSid) { continue }
                    if ($CurrentUserSids -notcontains $IdentityReferenceSid) { continue }
    
                    $Restrictions = $TypeAccessMask.Keys | Where-Object { $DenyAce.$TypeAccessRights.value__ -band $_ } | ForEach-Object { $TypeAccessMask[$_] }
                    $RestrictedRights += [String[]]$Restrictions
                }
            }
            
            # Need to make sure it not null because of PSv2
            if ($AllowAces) {
                foreach ($AllowAce in $AllowAces) {

                    # Ignore "InheritOnly" ACEs because they only apply to child objects, not to the object itself
                    # (e.g.: a file in a directory or a sub-key of a registry key).
                    if ($AllowAce.PropagationFlags -band ([System.Security.AccessControl.PropagationFlags]"InheritOnly").value__) { continue }

                    # Here, we simply extract the permissions granted by the current ACE
                    $Permissions = New-Object System.Collections.ArrayList
                    $TypeAccessMask.Keys | Where-Object { $AllowAce.$TypeAccessRights.value__ -band $_ } | ForEach-Object { $null = $Permissions.Add($TypeAccessMask[$_]) }
        
                    # ... and we remove any right that would be restricted due to deny ACEs.
                    if ($RestrictedRights) {
                        foreach ($RestrictedRight in $RestrictedRights) {
                            $null = $Permissions.Remove($RestrictedRight)
                        }
                    }
    
                    # Here, we filter out ACEs that do not apply to the current user by checking whether the ACE's
                    # identity reference is in the current user's SID list.
                    $IdentityReferenceSid = Convert-NameToSid -Name $AllowAce.IdentityReference
                    if ($CurrentUserSids -notcontains $IdentityReferenceSid) { continue }
    
                    # We compare the list of permissions (minus the potential restrictions) againts a list of
                    # predefined modification rights. If there is no match, we ignore the ACE.
                    $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject $TypeModificationRights -IncludeEqual -ExcludeDifferent
                    if (-not $Comparison) { continue }
    
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $Path
                    $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $AllowAce.IdentityReference
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $Permissions
                    $Result
                }
            }
        }
        catch {
            Write-Debug "Could not handle path: $($Path)"
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
                $null = $_
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

            foreach ($CandidatePath in $($CandidatePaths | Sort-Object -Unique)) {

                $CandidateItem = Get-Item -Path $CandidatePath -ErrorAction SilentlyContinue
                if (-not $CandidateItem) { continue }

                if ($CandidateItem -is [System.IO.DirectoryInfo]) {
                    Get-AclModificationRights -Path $CandidateItem.FullName -Type Directory
                }
                else {
                    Get-AclModificationRights -Path $CandidateItem.FullName -Type File
                }
            }
        }
    }
}

function Get-UnquotedPath {

    [OutputType([String])]
    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [String]$Path,
        [Switch]$Spaces = $false
    )

    # Check Check if the path starts with a " or '
    if ($Path.StartsWith("`"") -or $Path.StartsWith("'")) { return }

    # Extract EXE path
    $BinPath = $Path.SubString(0, $Path.ToLower().IndexOf(".exe") + 4)

    # If we don't have to check for spaces, return the path
    if (-not $Spaces) { return $BinPath }

    # Check if it contains spaces
    If ($BinPath -notmatch ".* .*") { return }

    return $BinPath
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
        [String]$Path
    )

    BEGIN {
        $PermissionsAddFile = @("AddFile", "DeleteChild", "WriteDAC", "WriteOwner")
    }

    PROCESS {

        $UnquotedPath = Get-UnquotedPath -Path $Path -Spaces

        if ([String]::IsNullOrEmpty($UnquotedPath)) { return }
    
        Write-Verbose "Found an unquoted path that contains spaces: $($UnquotedPath)"
    
        # Split path and build candidates paths
        $SplitPathArray = $UnquotedPath.Split(' ')
        $ConcatPathArray = @()
        for ($i=0; $i -lt $SplitPathArray.Count; $i++) {
            $ConcatPathArray += $SplitPathArray[0..$i] -join ' '
        }
        
        foreach ($ConcatPath in $ConcatPathArray) {
    
            # We exclude the binary path itself
            if ($ConcatPath -like $UnquotedPath) { continue }

            # Get parent folder. Split-Path does not handle errors nicely so catch exceptions
            # and continue on failure.
            try { $BinFolder = Split-Path -Path $ConcatPath -Parent -ErrorAction SilentlyContinue } catch { continue }
    
            # Split-Path failed without throwing an exception, so ignore and continue.
            if ( $null -eq $BinFolder) { continue }

            # If the parent folder does not exist, ignore and continue.
            if ( -not (Test-Path -Path $BinFolder -ErrorAction SilentlyContinue) ) { continue }

            # The parent folder exists, check if it is modifiable.
            $ModifiablePaths = $BinFolder | Get-ModifiablePath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }

            foreach ($ModifiablePath in $ModifiablePaths) {
    
                # To exploit an unquoted path we need to create a file, so make sure that the
                # permissions returned by Get-ModifiablePath really allow us to do that.
                foreach ($Permission in $ModifiablePath.Permissions) {

                    if ($PermissionsAddFile -contains $Permission) {

                        # If we find any permission that would allow us to write a file, we can report
                        # the path.
                        $ModifiablePath
                        break
                    }
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
    PS C:\> Get-ModifiableRegistryPath -Path "HKLM\SOFTWARE\Microsoft\Tracing"

    ModifiablePath    : HKLM\SOFTWARE\Microsoft\Tracing
    IdentityReference : BUILTIN\Users
    Permissions       : Notify, ReadControl, EnumerateSubKeys, CreateSubKey, SetValue, QueryValue
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [String[]]$Path
    )

    BEGIN { }

    PROCESS {

        $Path | ForEach-Object {
            $RegPath = "Registry::$($_)"
            $OrigPath = $_
            Get-AclModificationRights -Path $RegPath -Type RegistryKey | ForEach-Object { $_.ModifiablePath = $OrigPath; $_ }
        }
    }
}

# function Convert-DomainName {

#     [CmdletBinding()] Param(
#         [string]$FullyQualifiedName,
#         [string]$DistinguishedName
#     )

#     if (-not [string]::IsNullOrEmpty($FullyQualifiedName)) {
#         "DC=" + ($FullyQualifiedName.Split('.') -join ",DC=")
#         return
#     }

#     if (-not [string]::IsNullOrEmpty($DistinguishedName)) {
#         ($DistinguishedName.Split(',') | ForEach-Object { $_.Replace("DC=", "") }) -join "."
#         return
#     }
# }

function Get-ADDomain {

    [CmdletBinding()] Param()

    $RegKey = "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters"
    $RegValue = "Domain"
    (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
}

function Test-IsDomainJoined {

    [CmdletBinding()] Param()

    return (-not [string]::IsNullOrEmpty($(Get-ADDomain)))
}

function Get-FileHashHex {
    <#
    .SYNOPSIS
    Compute the hash of a file given its path.

    Author: @itm4n
    Credit: @jaredcatkinson
    License: BSD 3-Clause
    
    .DESCRIPTION
    This cmdlet is a simplified version of 'Get-FileHash', which is not available in PSv2.
    
    .PARAMETER FilePath
    The path of the file for which we want to compute the hash.
    
    .PARAMETER Algorithm
    A hash algorithm: md5, sha1, or sha256
    
    .EXAMPLE
    PS C:\> Get-FileHashHex -FilePath "C:\Windows\System32\drivers\RTCore64.sys"
    01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd

    PS C:\> Get-FileHashHex -FilePath "C:\Windows\System32\drivers\RTCore64.sys" -Algorithm sha1
    f6f11ad2cd2b0cf95ed42324876bee1d83e01775

    PS C:\> Get-FileHashHex -FilePath "C:\Windows\System32\drivers\RTCore64.sys" -Algorithm md5 
    2d8e4f38b36c334d0a32a7324832501d
    
    .NOTES
    Credit goes to https://github.com/jaredcatkinson for the code.

    .LINK
    https://gist.github.com/jaredcatkinson/7d561b553a04501238f8e4f061f112b7
    #>#

    [CmdletBinding()] param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [ValidateSet("MD5", "SHA1", "SHA256")]
        [string] $Algorithm = "SHA256"
    )

    try {
        $FileStream = [System.IO.File]::OpenRead($FilePath)
        $HashAlg = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
        $Hash = [byte[]] $HashAlg.ComputeHash($FileStream)
        [System.BitConverter]::ToString($Hash).Replace("-","").ToLower()
    }
    catch {
        Write-Warning "Failed to get hash of '$($FilePath)': $($_.Exception.Message.Trim())"
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
        [Switch]$Filtered = $false
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