function Test-IsRunningInConsole {
    return $Host.Name -match "ConsoleHost"
}

function Convert-FiletimeToDatetime {
    [OutputType([DateTime])]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, Mandatory=$true)]
        [Object] # FILETIME
        $Filetime
    )

    [Int64] $Time = $Filetime.LowDateTime + $Filetime.HighDateTime * 0x100000000
    [DateTime]::FromFileTimeUtc($Time)
}

function Convert-SidStringToSid {

    [CmdletBinding()]
    param(
        [String] $Sid
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
    [CmdletBinding()]
    param(
        [String] $Sid
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
    [CmdletBinding()]
    param(
        [System.DateTime] $Date
    )

    if ($null -ne $Date) {
        $OutString = ""
        $OutString += $Date.ToString('yyyy-MM-dd - HH:mm:ss')
        $OutString
    }
}

function Get-WindowsVersion {

    [CmdletBinding()]
    param()

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

    [OutputType([Boolean])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Object] $File
    )

    if ($File.VersionInfo.LegalCopyright -like "*Microsoft Corporation*") {
        return $true
    }

    return $false
}

function Test-CommonApplicationFile {

    [OutputType([Boolean])]
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string] $Path
    )

    process {
        $script:CommonApplicationExtensions -contains ([System.IO.Path]::GetExtension($Path)).Replace('.', '')
    }
}

function Test-IsSystemFolder {

    [OutputType([Boolean])]
    [CmdletBinding()]
    param(
        [string] $Path
    )

    begin {
        $SystemPaths = @()
    }

    process {
        # Initialize system path list
        if ($SystemPaths.Count -eq 0) {
            [string[]] $SystemPaths += $env:windir
            [string[]] $SystemPaths += Join-Path -Path "$($env:windir)" -ChildPath "System"
            [string[]] $SystemPaths += Join-Path -Path "$($env:windir)" -ChildPath "System32"
            [string[]] $SystemPaths += Join-Path -Path "$($env:windir)" -ChildPath "Syswow64"
            [string[]] $SystemPaths += Join-Path -Path "$($env:windir)" -ChildPath "Sysnative"
            [string[]] $SystemPaths += $env:ProgramFiles
            [string[]] $SystemPaths += ${env:ProgramFiles(x86)}
            [string[]] $SystemPaths += $env:ProgramData
        }

        $SystemPaths -contains $Path.TrimEnd('\\')
    }
}

function Get-CurrentUserSid {

    [CmdletBinding()]
    param()

    if ($null -eq $script:CachedCurrentUserSids) {
        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $script:CachedCurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $script:CachedCurrentUserSids += $UserIdentity.User.Value
    }

    $script:CachedCurrentUserSids
}

function Get-CurrentUserDenySid {

    [CmdletBinding()]
    param()

    if ($null -eq $script:CachedCurrentUserDenySids) {
        $script:CachedCurrentUserDenySids = [string[]](Get-TokenInformationGroup -InformationClass Groups | Where-Object { $_.Attributes.Equals("UseForDenyOnly") } | Select-Object -ExpandProperty SID)
        if ($null -eq $script:CachedCurrentUserDenySids) {
            $script:CachedCurrentUserDenySids = @()
        }
    }

    $script:CachedCurrentUserDenySids
}

function Get-AclModificationRight {
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
    PS C:\> Get-AclModificationRight -Path C:\Temp\foo123.txt -Type File

    ModifiablePath    : C:\Temp\foo123.txt
    IdentityReference : NT AUTHORITY\Authenticated Users
    Permissions       : Delete, WriteAttributes, Synchronize, ReadControl, ReadData, AppendData, WriteExtendedAttributes,
                        ReadAttributes, WriteData, ReadExtendedAttributes, Execute

    .EXAMPLE
    PS C:\> Get-AclModificationRight -Path C:\Temp\deny-delete.txt -Type File

    ModifiablePath    : C:\Temp\deny-delete.txt
    IdentityReference : NT AUTHORITY\Authenticated Users
    Permissions       : WriteAttributes, Synchronize, ReadControl, ReadData, AppendData, WriteExtendedAttributes,
                        ReadAttributes, WriteData, ReadExtendedAttributes, Execute

    .EXAMPLE
    PS C:\> Get-AclModificationRight -Path C:\Temp\deny-write.txt -Type File

    ModifiablePath    : C:\Temp\deny-write.txt
    IdentityReference : NT AUTHORITY\Authenticated Users
    Permissions       : Delete, Synchronize, ReadControl, ReadData, ReadAttributes, ReadExtendedAttributes, Execute
    #>

    [CmdletBinding()]
    param(
        [String]
        $Path,

        [ValidateSet("File", "Directory", "RegistryKey")]
        [String]
        $Type
    )

    begin {
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

        $CurrentUserSids = Get-CurrentUserSid
        $CurrentUserDenySids = Get-CurrentUserDenySid

        $ResolvedIdentities = @{}

        function Convert-NameToSid {

            param([String] $Name)

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

    process {

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
                    $RestrictedRights += [String[]] $Restrictions
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

                    # We compare the list of permissions (minus the potential restrictions) against a list of
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
    Helper - Get modification rights the current user has on a file or folder.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet takes the path of a file or folder as an input, and returns any modification right the current user has on the object. If the supplied path doesn't exist, this cmdlet attempts to find the first existing parent folder, and returns any modification right the current user has on it.

    .PARAMETER Path
    The path of the file or folder to check.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String] $Path
    )

    begin {
        $CheckedPaths = @()
    }

    process {
        $CandidatePaths = @()

        if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {
            $CandidatePaths += $Path
            # If the path corresponds to a file, we want to check its parent directory as
            # well. There are cases where the target file is configured with secure
            # permissions but a user can still add files in the same folder. In such case,
            # a DLL proxying attack is still possible.
            if ($(Get-Item -Path $Path -Force) -is [System.IO.FileInfo]) {
                $CandidatePaths += Get-FirstExistingParentFolderPath -Path $Path
            }
        }
        else {
            # If the path doesn't correspond to an existing file or directory, find the
            # first existing parent directory (if such directory exists) and add it to
            # the list of candidate paths.
            $CandidatePaths += Get-FirstExistingParentFolderPath -Path $Path
        }

        foreach ($CandidatePath in $CandidatePaths) {

            if ([String]::IsNullOrEmpty($CandidatePath)) { continue }
            if ($CheckedPaths -contains $CandidatePath) { continue }

            $CandidateItem = Get-Item -Path $CandidatePath -Force -ErrorAction SilentlyContinue
            if (-not $CandidateItem) {
                $CheckedPaths += $CandidatePath
                continue
            }

            $ModifiablePath = $null
            if ($CandidateItem -is [System.IO.DirectoryInfo]) {
                $ModifiablePath = Get-AclModificationRight -Path $CandidateItem.FullName -Type Directory
            }
            else {
                $ModifiablePath = Get-AclModificationRight -Path $CandidateItem.FullName -Type File
            }

            if ($ModifiablePath) { $ModifiablePath; break }

            $CheckedPaths += $CandidatePath
        }
    }
}

function Get-UnquotedPath {

    [OutputType([String])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String] $Path,
        [Switch] $Spaces = $false
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

    [CmdletBinding()]
    param(
        [String] $Path
    )

    begin {
        $PermissionsAddFile = @("AddFile", "DeleteChild", "WriteDAC", "WriteOwner")
    }

    process {

        $UnquotedPath = Get-UnquotedPath -Path $Path -Spaces

        if ([String]::IsNullOrEmpty($UnquotedPath)) { return }

        Write-Verbose "Found an unquoted path that contains spaces: $($UnquotedPath)"

        # Split path and build candidates paths
        $SplitPathArray = $UnquotedPath.Split(' ')
        $ConcatPathArray = @()
        for ($i=0; $i -lt $SplitPathArray.Count; $i++) {
            $ConcatPathArray += $SplitPathArray[0..$i] -join ' '
        }

        $CheckedPaths = @()

        foreach ($ConcatPath in $ConcatPathArray) {

            # We exclude the binary path itself
            if ($ConcatPath -like $UnquotedPath) { continue }

            # Get parent folder. Split-Path does not handle errors nicely so catch exceptions
            # and continue on failure.
            try { $BinFolder = Split-Path -Path $ConcatPath -Parent -ErrorAction SilentlyContinue } catch { continue }

            # Split-Path failed without throwing an exception, so ignore and continue.
            if ([String]::IsNullOrEmpty($BinFolder)) { continue }

            # If the current path was already checked, ignore it and continue.
            if ($CheckedPaths -contains $BinFolder) { continue }

            # If the parent folder does not exist, ignore and continue.
            if ( -not (Test-Path -Path $BinFolder -ErrorAction SilentlyContinue) ) { continue }

            # The parent folder exists, check if it is modifiable.
            $ModifiablePaths = Get-ModifiablePath -Path $BinFolder | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }

            $CheckedPaths += $BinFolder

            if ($null -eq $ModifiablePaths) { continue }
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
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [String[]] $Path
    )

    process {
        $Path | ForEach-Object {
            $RegPath = "Registry::$($_)"
            $OrigPath = $_
            Get-AclModificationRight -Path $RegPath -Type RegistryKey | ForEach-Object { $_.ModifiablePath = $OrigPath; $_ }
        }
    }
}

function Test-IsDomainJoined {

    [OutputType([Boolean])]
    [CmdletBinding()]
    param()

    $WorkstationInfo = Get-NetWkstaInfo
    if ($null -eq $WorkstationInfo) {
        Write-Warning "Test-IsDomainJoined - Failed to get workstation information."
        return $false
    }

    if ([string]::IsNullOrEmpty($WorkstationInfo.LanGroup)) {
        Write-Warning "Test-IsDomainJoined - Attribute 'LanGroup' is null."
        return $false
    }

    Write-Verbose "Test-IsDomainJoined - LAN group: $($WorkstationInfo.LanGroup)"

    return $WorkstationInfo.LanGroup -ne "WORKGROUP"
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

    [CmdletBinding()]
    param(
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

function Get-InstalledProgram {
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
    PS C:\> Get-InstalledProgram -Filtered

    Mode                LastWriteTime     Length Name
    ----                -------------     ------ ----
    d----        29/11/2019     10:51            Npcap
    d----        29/11/2019     10:51            Wireshark
    #>

    [CmdletBinding()]
    param(
        [switch] $Filtered = $false
    )

    $IgnoredPrograms = @("Common Files", "Internet Explorer", "ModifiableWindowsApps", "PackageManagement", "Windows Defender", "Windows Defender Advanced Threat Protection", "Windows Mail", "Windows Media Player", "Windows Multimedia Platform", "Windows NT", "Windows Photo Viewer", "Windows Portable Devices", "Windows Security", "WindowsPowerShell", "Microsoft.NET", "Windows Portable Devices", "dotnet", "MSBuild", "Intel", "Reference Assemblies")

    $InstalledPrograms = New-Object System.Collections.ArrayList

    # List all items in 'C:\Program Files' and 'C:\Program Files (x86)'
    $PathProgram32 = Join-Path -Path $env:SystemDrive -ChildPath "Program Files (x86)"
    $PathProgram64 = Join-Path -Path $env:SystemDrive -ChildPath "Program Files"

    $Items = Get-ChildItem -Path $PathProgram32,$PathProgram64 -ErrorAction SilentlyContinue
    if ($Items) {
        [void] $InstalledPrograms.AddRange($Items)
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

                [void] $InstalledPrograms.Add([Object] $FileObject)
            }
        }
    }

    foreach ($InstalledProgram in $($InstalledPrograms | Sort-Object -Property "FullName" -Unique)) {
        if ([string]::IsNullOrEmpty($InstalledProgram.FullName)) { continue }
        if (Test-IsSystemFolder -Path $InstalledProgram.FullName) { continue }
        if ($Filtered -and ($IgnoredPrograms -contains $InstalledProgram.Name)) { continue }
        $InstalledProgram | Select-Object -Property Name,FullName
    }
}

function Resolve-CommandLine {

    [OutputType([String[]])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String] $CommandLine
    )

    process {
        $CommandLineResolved = [System.Environment]::ExpandEnvironmentVariables($CommandLine)

        # Is it a quoted path, i.e. a string surrounded by quotes, without quotes inside?
        # -> regex = ^"([^"])+"$
        if ($CommandLineResolved -match "^`"([^`"])+`"`$") {
            # This is a file path, return input after trimming double quotes
            return [String[]] $CommandLineResolved.Trim('"')
        }

        # Is it an unquoted path, without spaces?
        # -> regex = ^[^",^ ,^\t]+$
        if ($CommandLineResolved -match "^[^`",^ ,^\t]+`$") {
            # This a file path, return input as is.
            return [String[]] $CommandLineResolved
        }

        # Is it a command line in which the path of the executable is quoted?
        # -> regex = ^".+[ ,\t].*$
        if ($CommandLineResolved -match "^`".+\s.+" -and $CommandLineResolved) {
            return [String[]] (ConvertTo-ArgumentList -CommandLine $CommandLineResolved)
        }

        $Arguments = [String[]] (ConvertTo-ArgumentList -CommandLine $CommandLineResolved)
        if ($Arguments.Length -eq 0) {
            Write-Warning "Resolve-CommandLine failed for input: $($CommandLine)"
            return $null
        }

        if (-not [System.IO.Path]::IsPathRooted($Arguments[0])) {
            $PathResolved = Resolve-ModulePath -Name $Arguments[0]
            if (-not [String]::IsNullOrEmpty($PathResolved)) { $Arguments[0] = $PathResolved }
        }

        if (Test-Path -Path $Arguments[0] -ErrorAction SilentlyContinue) {
            # If arg0 is a valid file path, command line parsing worked, we can stop there.
            return $Arguments
        }

        for ($i = $Arguments.Length - 1; $i -ge 0; $i--) {
            $PathToAnalyze = $Arguments[0..$i] -join " "
            if (Test-Path -Path $PathToAnalyze -ErrorAction SilentlyContinue) {
                $Result = @()
                $Result += $PathToAnalyze
                if ($i -lt ($Arguments.Length - 1)) {
                    $Result += $Arguments[$($i + 1)..$($Arguments.Length - 1)]
                }
                return [String[]] $Result
            }
        }

        Write-Warning "Resolve-CommandLine failed for input: $($CommandLine)"
    }
}

function Get-FirstExistingParentFolderPath {

    [CmdletBinding()]
    param (
        [String] $Path
    )

    try {
        $ParentPath = Split-Path $Path -Parent
        if ($ParentPath -and $(Test-Path -Path $ParentPath -ErrorAction SilentlyContinue)) {
            Resolve-Path -Path $ParentPath | Select-Object -ExpandProperty "Path"
        }
        else {
            Get-FirstExistingParentFolderPath -Path $ParentPath
        }
    }
    catch {
        $null = $_
    }
}