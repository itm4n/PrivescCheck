function Get-ObjectAccessRight {
    <#
    .SYNOPSIS
    Helper - Enumerates access rights the current user has on an object.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet retrieves the ACL of an object and returns the ACEs that grant modification permissions to the current user. It should be noted that, in case of deny ACEs, restricted rights are removed from the permission list of the ACEs.

    .PARAMETER Name
    A mandatory parameter representing the name of an object.

    .PARAMETER Type
    A mandatory parameter representing the type of object being queried (e.g. "File", "Directory", "RegistryKey", "Service", etc.).

    .PARAMETER SecurityInformation
    An optional parameter containing a security information object. If not specified, the helper function 'Get-ObjectSecurityInfo' is invoked to retrieve security information about the input object.

    .PARAMETER AccessRights
    An optional parameter representing a list of target access rights to test. If not specified, this cmdlet checks for modification rights specific to the input object type.

    .EXAMPLE
    PS C:\> Get-ObjectAccessRight -Name "C:\Workspace\foo123.txt" -Type File

    ModifiablePath    : C:\Workspace\foo123.txt
    IdentityReference : NT AUTHORITY\Authenticated Users (S-1-5-11)
    Permissions       : {ReadData, WriteData, AppendData, ReadExtendedAttributes...}

    .EXAMPLE
    PS C:\> Get-ObjectAccessRight -Name "C:\Workspace" -Type Directory

    ModifiablePath    : C:\Workspace
    IdentityReference : NT AUTHORITY\Authenticated Users (S-1-5-11)
    Permissions       : {ListDirectory, AddFile, AddSubdirectory, ReadExtendedAttributes...}

    .EXAMPLE
    PS C:\> Get-ObjectAccessRight -Name "VulnerableService" -Type Service

    ModifiablePath    : VulnerableService
    IdentityReference : BUILTIN\Users (S-1-5-32-545)
    Permissions       : {ChangeConfig}

    .EXAMPLE
    PS C:\> Get-ObjectAccessRight -Name "wuauserv" -Type Service -AccessRights @($script:ServiceAccessRight::Start)

    ModifiablePath    : wuauserv
    IdentityReference : NT AUTHORITY\Authenticated Users (S-1-5-11)
    Permissions       : {QueryConfig, QueryStatus, EnumerateDependents, Start...}

    .EXAMPLE
    PS C:\> Get-ObjectAccessRight -Name SCM -Type ServiceControlManager -AccessRights @($script:ServiceControlManagerAccessRight::Connect)

    ModifiablePath    : SCM
    IdentityReference : NT AUTHORITY\Authenticated Users (S-1-5-11)
    Permissions       : {Connect}

    ModifiablePath    : SCM
    IdentityReference : NT AUTHORITY\INTERACTIVE (S-1-5-4)
    Permissions       : {Connect, EnumerateService, QueryLockStatus, GenericRead}
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String] $Name,

        [Parameter(Mandatory=$true)]
        [ValidateSet("File", "Directory", "RegistryKey", "Service", "ServiceControlManager", "Process", "Thread", "ScheduledTask")]
        [String] $Type,

        [Object] $SecurityInformation,

        [UInt32[]] $AccessRights = $null
    )

    begin {
        $FileModificationRights = @(
            $script:FileAccessRight::WriteData,
            $script:FileAccessRight::AppendData,
            $script:FileAccessRight::WriteAttributes,
            $script:FileAccessRight::Delete,
            $script:FileAccessRight::WriteDac,
            $script:FileAccessRight::WriteOwner,
            $script:FileAccessRight::GenericWrite,
            $script:FileAccessRight::AllAccess
        )

        $DirectoryModificationRights = @(
            $script:DirectoryAccessRight::AddFile,
            $script:DirectoryAccessRight::AddSubdirectory,
            $script:DirectoryAccessRight::DeleteChild,
            $script:DirectoryAccessRight::WriteAttributes,
            $script:DirectoryAccessRight::Delete,
            $script:DirectoryAccessRight::WriteDac,
            $script:DirectoryAccessRight::WriteOwner,
            $script:DirectoryAccessRight::GenericWrite,
            $script:DirectoryAccessRight::AllAccess
        )

        $RegistryKeyModificationRights = @(
            $script:RegistryKeyAccessRight::SetValue,
            $script:RegistryKeyAccessRight::CreateSubKey,
            $script:RegistryKeyAccessRight::Delete,
            $script:RegistryKeyAccessRight::WriteDac,
            $script:RegistryKeyAccessRight::WriteOwner,
            $script:RegistryKeyAccessRight::GenericWrite,
            $script:RegistryKeyAccessRight::AllAccess
        )

        $ServiceModificationRights = @(
            $script:ServiceAccessRight::ChangeConfig,
            $script:ServiceAccessRight::WriteDac,
            $script:ServiceAccessRight::WriteOwner,
            $script:ServiceAccessRight::GenericWrite,
            $script:ServiceAccessRight::AllAccess
        )

        $ServiceControlManagerModificationRights = @(
            $script:ServiceControlManagerAccessRight::CreateService,
            $script:ServiceControlManagerAccessRight::ModifyBootConfig,
            $script:ServiceControlManagerAccessRight::WriteDac,
            $script:ServiceControlManagerAccessRight::WriteOwner,
            $script:ServiceControlManagerAccessRight::GenericWrite,
            $script:ServiceControlManagerAccessRight::AllAccess
        )

        $ProcessModificationRights = @(
            $script:ProcessAccessRight::TERMINATE,
            $script:ProcessAccessRight::CREATE_THREAD,
            $script:ProcessAccessRight::SET_SESSIONID,
            $script:ProcessAccessRight::SET_SESSIONID,
            $script:ProcessAccessRight::VM_READ,
            $script:ProcessAccessRight::VM_WRITE,
            $script:ProcessAccessRight::DUP_HANDLE,
            $script:ProcessAccessRight::CREATE_PROCESS,
            $script:ProcessAccessRight::SET_INFORMATION,
            $script:ProcessAccessRight::SUSPEND_RESUME,
            $script:ProcessAccessRight::SET_LIMITED_INFORMATION,
            $script:ProcessAccessRight::Delete,
            $script:ProcessAccessRight::WriteDac,
            $script:ProcessAccessRight::WriteOwner,
            $script:ProcessAccessRight::AllAccess
        )

        $ThreadModificationRights = @(
            $script:ThreadAccessRight::Terminate,
            $script:ThreadAccessRight::SuspendResume,
            $script:ThreadAccessRight::SetContext,
            $script:ThreadAccessRight::SetInformation,
            $script:ThreadAccessRight::Impersonate,
            $script:ThreadAccessRight::DirectImpersonation,
            $script:ThreadAccessRight::Delete,
            $script:ThreadAccessRight::WriteDac,
            $script:ThreadAccessRight::WriteOwner,
            $script:ThreadAccessRight::AllAccess
        )

        $CurrentUserSids = Get-CurrentUserSid
        $CurrentUserDenySids = Get-CurrentUserDenySid
    }

    process {
        # Make sure to initialize the handle value to 0 each time an object is processed
        # to avoid reuse of previously closed handle in case of error when attempting to
        # open the current object.
        $Handle = [IntPtr]::Zero

        switch ($Type) {
            "File" {
                $ObjectAccessRights = $script:FileAccessRight
                $TargetAccessRights = $(if ($PSBoundParameters['AccessRights']) { $AccessRights } else { $FileModificationRights })
                $Handle = Get-FileHandle -Path $Name -AccessRights $script:FileAccessRight::ReadControl -ErrorAction SilentlyContinue
            }
            "Directory" {
                $ObjectAccessRights = $script:DirectoryAccessRight
                $TargetAccessRights = $(if ($PSBoundParameters['AccessRights']) { $AccessRights } else { $DirectoryModificationRights })
                $Handle = Get-FileHandle -Path $Name -AccessRights $script:DirectoryAccessRight::ReadControl -Directory -ErrorAction SilentlyContinue
            }
            "RegistryKey" {
                $ObjectAccessRights = $script:RegistryKeyAccessRight
                $TargetAccessRights = $(if ($PSBoundParameters['AccessRights']) { $AccessRights } else { $RegistryKeyModificationRights })
                $Handle = Get-RegistryKeyHandle -Path $Name -AccessRights $script:RegistryKeyAccessRight::ReadControl -ErrorAction SilentlyContinue
            }
            "Service" {
                $ObjectAccessRights = $script:ServiceAccessRight
                $TargetAccessRights = $(if ($PSBoundParameters['AccessRights']) { $AccessRights } else { $ServiceModificationRights })
                $Handle = Get-ServiceHandle -Name $Name -AccessRights $script:ServiceAccessRight::ReadControl -ErrorAction SilentlyContinue
            }
            "ServiceControlManager" {
                $ObjectAccessRights = $script:ServiceControlManagerAccessRight
                $TargetAccessRights = $(if ($PSBoundParameters['AccessRights']) { $AccessRights } else { $ServiceControlManagerModificationRights })
                $Handle = Get-ServiceHandle -Name "SCM" -SCM -AccessRights $script:ServiceAccessRight::ReadControl -ErrorAction SilentlyContinue
            }
            "Process" {
                $ObjectAccessRights = $script:ProcessAccessRight
                $TargetAccessRights = $(if ($PSBoundParameters['AccessRights']) { $AccessRights } else { $ProcessModificationRights })
                $Handle = Get-ProcessHandle -ProcessId $Name -AccessRights $script:ProcessAccessRight::ReadControl -ErrorAction SilentlyContinue
            }
            "Thread" {
                $ObjectAccessRights = $script:ThreadAccessRight
                $TargetAccessRights = $(if ($PSBoundParameters['AccessRights']) { $AccessRights } else { $ThreadModificationRights })
                $Handle = Get-ThreadHandle -ThreadId $Name -AccessRights $script:ThreadAccessRight::ReadControl -ErrorAction SilentlyContinue
            }
            "ScheduledTask" {
                $ObjectAccessRights = $script:FileAccessRight
                $TargetAccessRights = $(if ($PSBoundParameters['AccessRights']) { $AccessRights } else { $FileModificationRights })
            }
            default {
                throw "Unhandled object type: $($Type)"
            }
        }

        # Sanity check. Just in case we add other object types in the future, we want to
        # make sure its permission set (access right enum) is properly set. Especially,
        # we assume that it has an 'AllAccess' member because it is used further in the
        # code.
        if ($null -eq $ObjectAccessRights::AllAccess) { throw "Permission set for object type '$($Type)' does not have an 'AllAccess' member." }

        # Sanity check. Make sure the input access right set to test is valid.
        $TargetAccessRights | ForEach-Object {
            if ($ObjectAccessRights.GetEnumValues() -notcontains $_) {
                Write-Warning "Permission set for object type '$($Type)' does not contain an access right named '$($_)'."
            }
        }

        # If the input object's security information is not supplied, retrieve it first
        # using the helper function 'Get-ObjectSecurityInfo'.
        if ($null -eq $SecurityInformation) {
            # If we failed to open the target object with appropriate privileges, the
            # resulting handle will be invalid. We must account for this and return
            # immediately, otherwise we might end up with an undefined behavior.
            if (($null -eq $Handle) -or ($Handle -eq [IntPtr]::Zero) -or ($Handle -eq -1)) { return }
            $SecurityInfo = Get-ObjectSecurityInfo -Handle $Handle -Type $Type
        }
        else {
            $SecurityInfo = $SecurityInformation
        }

        if ($null -eq $SecurityInfo) { return }

        $DenyAces = $SecurityInfo.Dacl | Where-Object { $_.AceType -eq "AccessDenied" }
        $AllowAces = $SecurityInfo.Dacl | Where-Object { $_.AceType -eq "AccessAllowed" }

        # Before checking the object permissions, we first need to enumerate deny ACEs (if any) that
        # would restrict the rights we may have on the target object.
        $Restrictions = @()
        # Need to make sure it not null because of PSv2
        if ($DenyAces) {

            foreach ($DenyAce in $DenyAces) {

                # Ignore "InheritOnly" ACEs because they only apply to child objects, not to the object itself
                # (e.g.: a file in a directory or a sub-key of a registry key).
                if ($DenyAce.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly.value__) { continue }

                # Convert the ACE's identity reference name to its SID. If the SID is not in the list
                # of deny-only SIDs of the current Token, ignore it. If the SID does not match the
                # current user SID or the SID of any of its groups, ignore it as well.
                # Note: deny-only SIDs are only used to check access-denied ACEs.
                # https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-attributes-in-an-access-token
                if ($CurrentUserDenySids -notcontains $DenyAce.SecurityIdentifier) { continue }
                if ($CurrentUserSids -notcontains $DenyAce.SecurityIdentifier) { continue }

                $ObjectAccessRights.GetEnumValues() |
                    Where-Object { ($DenyAce.AccessMask -band $ObjectAccessRights::$_.value__) -eq $ObjectAccessRights::$_.value__ } |
                        ForEach-Object { $Restrictions += $_ }
            }
        }

        # Need to make sure it not null because of PSv2
        if ($AllowAces) {

            foreach ($AllowAce in $AllowAces) {

                # Ignore "InheritOnly" ACEs because they only apply to child objects, not to the object itself
                # (e.g.: a file in a directory or a sub-key of a registry key).
                if ($AllowAce.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly.value__) { continue }

                # Here, we simply extract the permissions granted by the current ACE
                $Permissions = @()
                $ObjectAccessRights.GetEnumValues() |
                    Where-Object { ($AllowAce.AccessMask -band $ObjectAccessRights::$_.value__) -eq $ObjectAccessRights::$_.value__ } |
                        ForEach-Object { $Permissions += $_ }

                # If the ACE grants 'AllAccess', then all access rights match. In such a case,
                # instead of reporting all access rights + AllAccess, we modify the list and
                # set AllAccess only.
                if ($Permissions -contains $ObjectAccessRights::AllAccess) { $Permissions = @( $ObjectAccessRights::AllAccess )}

                # ... and we remove any right that would be restricted due to deny ACEs.
                if ($Restrictions.Count -gt 0) {
                    $Permissions = $Permissions | Where-Object { $Restrictions -notcontains $_ }
                }

                # Here, we filter out ACEs that do not apply to the current user by checking whether the ACE's
                # identity reference is in the current user's SID list.
                if ($CurrentUserSids -notcontains $AllowAce.SecurityIdentifier) { continue }

                # We compare the list of permissions (minus the potential restrictions) against a list of
                # predefined modification rights. If there is no match, we ignore the ACE.
                $GrantedModificationRights = $Permissions | Where-Object { $TargetAccessRights -contains $_ }
                if ($null -eq $GrantedModificationRights) { continue }

                $ResolvedIdentity = Convert-SidToName -Sid $AllowAce.SecurityIdentifier
                if ($ResolvedIdentity) {
                    $IdentityReference = "$($ResolvedIdentity) ($($AllowAce.SecurityIdentifier))"
                }
                else {
                    $IdentityReference = $AllowAce.SecurityIdentifier
                }

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $Name
                $Result | Add-Member -MemberType "NoteProperty" -Name "Owner" -Value $SecurityInfo.Owner
                $Result | Add-Member -MemberType "NoteProperty" -Name "OwnerSid" -Value $SecurityInfo.OwnerSid
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $Permissions
                $Result
            }
        }
    }

    end {
        switch ($Type) {
            "File"                  { if (($Handle -ne [IntPtr]::Zero) -and ($Handle -ne -1)) { $null = $script:Kernel32::CloseHandle($Handle) } }
            "Directory"             { if (($Handle -ne [IntPtr]::Zero) -and ($Handle -ne -1)) { $null = $script:Kernel32::CloseHandle($Handle) } }
            "RegistryKey"           { if ($Handle -ne [IntPtr]::Zero) { $null = $script:Kernel32::CloseHandle($Handle) } }
            "Service"               { if ($Handle -ne [IntPtr]::Zero) { $null = $script:Advapi32::CloseServiceHandle($Handle) } }
            "ServiceControlManager" { if ($Handle -ne [IntPtr]::Zero) { $null = $script:Advapi32::CloseServiceHandle($Handle) } }
            "Process"               { if ($Handle -ne [IntPtr]::Zero) { $null = $script:Kernel32::CloseHandle($Handle) } }
            "Thread"                { if ($Handle -ne [IntPtr]::Zero) { $null = $script:Kernel32::CloseHandle($Handle) } }
            "ScheduledTask"         { }
            default {
                # Sanity check. We want to make sure to add a 'CloseHandle' function whenever
                # a new object type is added to this helper to avoid handle leaks.
                throw "No handle closing handler defined for object type: $($Type)"
            }
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
                $ModifiablePath = Get-ObjectAccessRight -Name $CandidateItem.FullName -Type Directory
            }
            else {
                $ModifiablePath = Get-ObjectAccessRight -Name $CandidateItem.FullName -Type File
            }

            if ($ModifiablePath) { $ModifiablePath; break }

            $CheckedPaths += $CandidatePath
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
        Get-ObjectAccessRight -Name $ComClassEntry.FullPath -Type RegistryKey | ForEach-Object {
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

function Get-ModifiableRootFolder {
    <#
    .SYNOPSIS
    Helper - Test the permissions of a root folder and the common application files it contains.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet is used as a helper function by 'Invoke-RootFolderPermissionCheck' to support multithreading. It checks the permissions of a single root folder, which can be a time consuming if it has a lot of sub-folders and files.

    .PARAMETER Path
    A mandatory input string representing the absolute path of a root folder.

    .EXAMPLE
    PS C:\> Get-ModifiableRootFolder -Path "C:\Microsoft Shared"
    #>

    [CmdletBinding()]

    param (
        [Parameter(Position=0, Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $Path
    )

    begin {
        $Vulnerable = $false
        $Description = ""
        $MaxFileCount = 8
    }

    process {
        # Check whether the current user has any modification right on the root folder.
        $RootFolderModifiablePaths = Get-ModifiablePath -Path $Path | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
        if ($RootFolderModifiablePaths) {
            $Description = "The current user has modification rights on this root folder."
        }
        else {
            $Description = "The current user does not have modification rights on this root folder."
        }

        # Check whether the current user has any modification rights on a common app
        # file within this root folder.
        $ApplicationFileModifiablePaths = @()
        $ApplicationFiles = Get-ChildItem -Path $Path -Force -Recurse -ErrorAction SilentlyContinue | Where-Object { ($_ -is [System.IO.FileInfo]) -and (Test-IsCommonApplicationFile -Path $_.FullName) }
        foreach ($ApplicationFile in $ApplicationFiles) {
            if ($ApplicationFileModifiablePaths.Count -gt $MaxFileCount) { break }
            if ([String]::IsNullOrEmpty($ApplicationFile.FullName)) { continue }
            $ModifiablePaths = Get-ModifiablePath -Path $ApplicationFile.FullName | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
            if ($ModifiablePaths) { $ApplicationFileModifiablePaths += $ApplicationFile.FullName }
        }

        # If at least one modifiable application file is found, consider the folder as
        # 'vulnerable'. Even if application files are not modifiable, consider the folder
        # as 'vulnerable' if the current user has any modification rights on it.
        if ($ApplicationFileModifiablePaths) { $Vulnerable = $true }
        if (($ApplicationFiles.Count -gt 0) -and $RootFolderModifiablePaths) { $Vulnerable = $true }

        if ($ApplicationFiles.Count -gt 0) {
            if ($ApplicationFileModifiablePaths) {
                $Description = "$($Description) A total of $($ApplicationFiles.Count) common application files were found. The current user has modification rights on some, or all of them."
            }
            else {
                $Description = "$($Description) A total of $($ApplicationFiles.Count) common application files were found. The current user does not have any modification right on them."
            }
        }
        else {
            $Description = "$($Description) This folder does not seem to contain any common application file."
        }

        $ModifiableChildPathResult = ($ApplicationFileModifiablePaths | ForEach-Object { Resolve-PathRelativeTo -From $Path -To $_ } | Select-Object -First $MaxFileCount) -join "; "
        if ($ApplicationFileModifiablePaths.Count -gt $MaxFileCount) { $ModifiableChildPathResult += "; ..." }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Path
        $Result | Add-Member -MemberType "NoteProperty" -Name "Modifiable" -Value ($null -ne $RootFolderModifiablePaths)
        $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePaths" -Value $ModifiableChildPathResult
        $Result | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value $Vulnerable
        $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
        $Result
    }
}