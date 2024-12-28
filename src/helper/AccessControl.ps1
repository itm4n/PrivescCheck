function Get-ModificationRight {
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
    PS C:\> Get-ModificationRight -Path C:\Temp\foo123.txt -Type File

    ModifiablePath    : C:\Temp\foo123.txt
    IdentityReference : NT AUTHORITY\Authenticated Users
    Permissions       : Delete, WriteAttributes, Synchronize, ReadControl, ReadData, AppendData, WriteExtendedAttributes,
                        ReadAttributes, WriteData, ReadExtendedAttributes, Execute

    .EXAMPLE
    PS C:\> Get-ModificationRight -Path C:\Temp\deny-delete.txt -Type File

    ModifiablePath    : C:\Temp\deny-delete.txt
    IdentityReference : NT AUTHORITY\Authenticated Users
    Permissions       : WriteAttributes, Synchronize, ReadControl, ReadData, AppendData, WriteExtendedAttributes,
                        ReadAttributes, WriteData, ReadExtendedAttributes, Execute

    .EXAMPLE
    PS C:\> Get-ModificationRight -Path C:\Temp\deny-write.txt -Type File

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
                $ModifiablePath = Get-ModificationRight -Path $CandidateItem.FullName -Type Directory
            }
            else {
                $ModifiablePath = Get-ModificationRight -Path $CandidateItem.FullName -Type File
            }

            if ($ModifiablePath) { $ModifiablePath; break }

            $CheckedPaths += $CandidatePath
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
            Get-ModificationRight -Path $RegPath -Type RegistryKey | ForEach-Object { $_.ModifiablePath = $OrigPath; $_ }
        }
    }
}

function Get-ModifiableComClassEntryRegistryPath {
    <#
    .SYNOPSIS
    Helper - Test the permissions of COM class entry in the registry.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet is used as a helper function by 'Invoke-ComServerRegistryPermissionCheck' to support multithreading. It checks the permissions of a single COM class entry in the registry.

    .PARAMETER ComClassEntry
    A mandatory COM class registry entry returned by 'Get-ComClassFromRegistry'.

    .EXAMPLE
    PS C:\> $RegisteredComClasses = Get-ComClassFromRegistry
    PS C:\> Get-ModifiableComClassEntryRegistryPath -ComClassEntry $RegisteredComClasses[0]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Object] $ComClassEntry
    )

    process {
        Get-ModifiableRegistryPath -Path $ComClassEntry.FullPath | ForEach-Object {
            $Result = $ComClassEntry.PSObject.Copy()
            $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
            $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
            $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($_.Permissions -join ", ")
            $Result
        }
    }
}

function Get-ModifiableComClassEntryImagePath {
    <#
    .SYNOPSIS
    Helper - Test the permissions of COM class' image file.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet is used as a helper function by 'Invoke-ComServerImagePermissionCheck' to support multithreading. It checks the permissions of the image file of a single COM class entry.

    .PARAMETER ComClassEntry
    A mandatory COM class registry entry returned by 'Get-ComClassFromRegistry'.

    .PARAMETER CheckedPaths
    An optional synchronized array list. This list is populated each time a filesystem path is analyzed and is found to not be vulnerable. This helps reduce the overall time it takes to check a large number of paths by avoiding to inspect them multiple times.

    .EXAMPLE
    PS C:\> $RegisteredComClasses = Get-ComClassFromRegistry
    PS C:\> Get-ModifiableComClassEntryImagePath -ComClassEntry $RegisteredComClasses[0]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Object] $ComClassEntry,

        [System.Collections.ArrayList] $CheckedPaths = $null
    )

    begin {
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
        if ($null -eq $CheckedPaths) { $CheckedPaths = New-Object System.Collections.ArrayList }
    }

    process {
        $CandidatePaths = @()

        switch ($ComClassEntry.DataType) {
            "FileName" {
                Resolve-ModulePath -Name $ComClassEntry.Data | ForEach-Object { $CandidatePaths += $_ }
            }
            "FilePath" {
                $CandidatePaths += [System.Environment]::ExpandEnvironmentVariables($ComClassEntry.Data).Trim('"')
            }
            "CommandLine" {
                $CommandLineResolved = [string[]] (Resolve-CommandLine -CommandLine $ComClassEntry.Data)
                if ($null -eq $CommandLineResolved) { continue }

                $CandidatePaths += $CommandLineResolved[0]

                if (($CommandLineResolved[0] -match ".*rundll32(\.exe)?`$") -and ($CommandLineResolved.Count -gt 1) -and ($CommandLineResolved[1] -like "*.dll,*")) {
                    $PathToAnalyze = $CommandLineResolved[1].Split(',')[0]
                    if ([System.IO.Path]::IsPathRooted($PathToAnalyze)) {
                        $CandidatePaths += $PathToAnalyze
                    }
                    else {
                        Resolve-ModulePath -Name $PathToAnalyze | ForEach-Object { $CandidatePaths += $_ }
                    }
                }
            }
            default {
                Write-Warning "Unknown server data type: $($ComClassEntry.DataType)"
                continue
            }
        }

        foreach ($CandidatePath in $CandidatePaths) {

            if ([String]::IsNullOrEmpty($CandidatePath)) { continue }
            if ($CheckedPaths -contains $CandidatePath) { continue }

            $ModifiablePaths = Get-ModifiablePath -Path $CandidatePath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
            if ($null -eq $ModifiablePaths) { $null = $CheckedPaths.Add($CandidatePath); continue }

            foreach ($ModifiablePath in $ModifiablePaths) {

                $Result = $ComClassEntry.PSObject.Copy()
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $ModifiablePath.ModifiablePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $ModifiablePath.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($ModifiablePath.Permissions -join ", ")
                $Result
            }
        }
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Get-ModifiableApplicationFile {
    <#
    .SYNOPSIS
    Helper - Test the permissions of application files.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet is used as a helper function by 'Invoke-InstalledApplicationPermissionCheck' to support multithreading. It checks the permissions of a single application folder, which can be a time consuming if it has a lot of sub-folders and files.

    .PARAMETER FileItem
    A mandatory input file item (file or directory) returned by 'Get-InstalledApplication'.

    .EXAMPLE
    PS C:\> $Applications = Get-InstalledApplication -Filtered
    PS C:\> Get-ModifiableApplicationFile -FileItem $Applications[0]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Object] $FileItem
    )

    begin {
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        # Ensure the path is not a known system folder, in which case it does not make
        # sense to check it. This also prevents the script from spending a considerable
        # amount of time and resources searching those paths recursively.
        if (Test-IsSystemFolder -Path $FileItem.FullName) {
            Write-Warning "System path detected, ignoring: $($FileItem.FullName)"
            return
        }

        # Build the search path list. The following trick is used to search recursively
        # without using the 'Depth' option, which is only available in PSv5+. This
        # allows us to maintain compatibility with PSv2.
        $SearchPath = @()
        $SearchPath += $(Join-Path -Path $FileItem.FullName -ChildPath "\*")
        $SearchPath += $(Join-Path -Path $FileItem.FullName -ChildPath "\*\*")

        # Enumerate sub-folders and files, return immediately if nothing is found.
        $CandidateItems = Get-ChildItem -Path $SearchPath -ErrorAction SilentlyContinue
        if ($null -eq $CandidateItems) { return }

        foreach ($CandidateItem in $CandidateItems) {

            # Ignore application files that do not have a common extension such as '.exe'
            # or '.dll'.
            if (($CandidateItem -is [System.IO.FileInfo]) -and (-not (Test-IsCommonApplicationFile -Path $CandidateItem.FullName))) { continue }

            Get-ModifiablePath -Path $CandidateItem.FullName | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
        }
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
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

    [CmdletBinding()]
    param(
        [String] $Path
    )

    begin {
        $PermissionsAddFile = @("AddFile", "DeleteChild", "WriteDAC", "WriteOwner")
    }

    process {
        # Make sure the path doesn't start with a white space, otherwise it might not be
        # interpreted correctly in the next checks.
        $Path = $Path.trim()

        # If the path starts with a simple or double quote, consider that the it is
        # quoted, and therefore not vulnerable.
        if ($Path.StartsWith("`"") -or $Path.StartsWith("'")) { return }

        # Try to resolve the input path as a command line. If it works, we will check
        # the executable path directly, otherwise we will try to determine one as best
        # as we can by locating any occurrence of the '.exe' extension.
        $CommandLineResolved = [string[]] (Resolve-CommandLine -CommandLine $Path)
        if ($null -eq $CommandLineResolved) {
            $ExeExtensionIndex = $Path.ToLower().IndexOf(".exe")
            if ($ExeExtensionIndex -ge 0) {
                $PathToAnalyze = $Path.SubString(0, $ExeExtensionIndex + 4)
            }
            else {
                Write-Warning "Failed to determine executable path in input: $($Path)"
                return
            }
        }
        else {
            $PathToAnalyze = $CommandLineResolved[0]
        }

        # If the executable path doesn't contain any space, it isn't vulnerable, we
        # can stop the search there.
        If ($PathToAnalyze -notmatch ".* .*") { return }

        Write-Verbose "Found an unquoted path that contains spaces: $($PathToAnalyze)"

        # Split path and build candidates paths
        $SplitPathArray = $PathToAnalyze.Split(' ')
        $ConcatPathArray = @()
        for ($i=0; $i -lt $SplitPathArray.Count; $i++) {
            $ConcatPathArray += $SplitPathArray[0..$i] -join ' '
        }

        $CheckedPaths = @()

        foreach ($ConcatPath in $ConcatPathArray) {

            # We exclude the binary path itself
            if ($ConcatPath -like $PathToAnalyze) { continue }

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

function Add-ServiceDiscretionaryAccessControlList {
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
    PS C:\> Get-Service | Add-ServiceDiscretionaryAccessControlList

    Add DACLs for every service the current user can read.

    .EXAMPLE
    PS C:\> Get-Service -Name VMTools | Add-ServiceDiscretionaryAccessControlList

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
        [ValidateNotNullOrEmpty()]
        [String[]] $Name
    )

    begin {
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

    process {
        foreach ($ServiceName in $Name) {

            $ServiceObject = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($null -eq $ServiceObject) {
                Write-Warning "Failed to query service '$($ServiceName)'."
                continue
            }

            try { $ServiceHandle = Get-ServiceReadControlHandle -Service $ServiceObject } catch { $ServiceHandle = $null }
            if (($null -eq $ServiceHandle) -or ($ServiceHandle -eq [IntPtr]::Zero)) {
                Write-Warning "Failed to obtain handle for service '$($ServiceName)'."
                continue
            }

            $SizeNeeded = 0
            $Result = $script:Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref] $SizeNeeded)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if (($LastError -ne $script:SystemErrorCode::ERROR_INSUFFICIENT_BUFFER) -or ($SizeNeeded -eq 0)) {
                Write-Warning "QueryServiceObjectSecurity - $([ComponentModel.Win32Exception] $LastError)"
                $null = $script:Advapi32::CloseServiceHandle($ServiceHandle)
                continue
            }

            $BinarySecurityDescriptor = New-Object Byte[]($SizeNeeded)
            $Result = $script:Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $SizeNeeded)

            if (-not $Result) {
                Write-Warning "QueryServiceObjectSecurity - $([ComponentModel.Win32Exception] $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
                $null = $script:Advapi32::CloseServiceHandle($ServiceHandle)
                continue
            }

            $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0
            $RawDacl = $RawSecurityDescriptor.DiscretionaryAcl

            # Check for NULL DACL first
            if ($null -eq $RawDacl) {
                $Ace = New-Object -TypeName PSObject
                $Ace | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $script:ServiceAccessRight::AllAccess
                $Ace | Add-Member -MemberType "NoteProperty" -Name "SecurityIdentifier" -Value (Convert-SidStringToSid -Sid "S-1-1-0")
                $Ace | Add-Member -MemberType "NoteProperty" -Name "AceType" -Value "AccessAllowed"
                $Dacl = @($Ace)
            }
            else {
                $Dacl = $RawDacl | ForEach-Object {
                    Add-Member -InputObject $_ -MemberType "NoteProperty" -Name "AccessRights" -Value ($_.AccessMask -as $script:ServiceAccessRight) -PassThru
                }
            }

            Add-Member -InputObject $ServiceObject -MemberType "NoteProperty" -Name "Dacl" -Value $Dacl -PassThru

            $null = $script:Advapi32::CloseServiceHandle($ServiceHandle)
        }
    }
}

function Test-ServiceDiscretionaryAccessControlList {
    <#
    .SYNOPSIS
    Tests one or more passed services or service names against a given permission set, returning the service objects where the current user have the specified permissions.

    Author: @harmj0y, Matthew Graeber
    License: BSD 3-Clause

    .DESCRIPTION
    Takes a service Name or a ServiceProcess.ServiceController on the pipeline, and first adds a service Dacl to the service object with Add-ServiceDiscretionaryAccessControlList. All group SIDs for the current user are enumerated services where the user has some type of permission are filtered. The services are then filtered against a specified set of permissions, and services where the current user have the specified permissions are returned.

    .PARAMETER Name
    An array of one or more service names to test against the specified permission set.

    .PARAMETER Permissions
    A manual set of permission to test again. One of:'QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess'

    .PARAMETER PermissionSet
    A pre-defined permission set to test a specified service against. 'ChangeConfig', 'Restart', or 'AllAccess'.

    .OUTPUTS
    ServiceProcess.ServiceController

    .EXAMPLE
    PS C:\> Get-Service | Test-ServiceDiscretionaryAccessControlList

    Return all service objects where the current user can modify the service configuration.

    .EXAMPLE
    PS C:\> Get-Service | Test-ServiceDiscretionaryAccessControlList -PermissionSet 'Restart'

    Return all service objects that the current user can restart.

    .EXAMPLE
    PS C:\> Test-ServiceDiscretionaryAccessControlList -Permissions 'Start' -Name 'VulnSVC'

    Return the VulnSVC object if the current user has start permissions.

    .LINK
    https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
    #>
    [OutputType('ServiceProcess.ServiceController')] param(
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

    begin {
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

        $CurrentUserSids = Get-CurrentUserSid
    }

    process {

        foreach ($IndividualService in $Name) {

            $TargetService = $IndividualService | Add-ServiceDiscretionaryAccessControlList

            # We might not be able to access the Service at all so we must check whether Add-ServiceDiscretionaryAccessControlList
            # returned something.
            if ($TargetService -and $TargetService.Dacl) {

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