function Invoke-ScheduledTaskImagePermissionCheck {
    <#
    .SYNOPSIS
    Enumerates scheduled tasks with a modifiable path

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function enumerates all the scheduled tasks which are visible by the current user but are not owned by the current user. For each task, it extracts the command line and checks whether it contains a path pointing to a modifiable file. If a task is run as the current user, it is filtered out.

    .EXAMPLE
    PS C:\> Invoke-ScheduledTaskImagePermissionCheck

    Name              : VulnerableTask
    Path              : \VulnerableTask
    FilePath          : C:\WINDOWS\System32\Tasks\VulnerableTask
    RunAs             : NT AUTHORITY\SYSTEM
    Command           : "C:\tools\invalid path\MyTask.exe"
    ModifiablePath    : C:\tools
    IdentityReference : NT AUTHORITY\Authenticated Users (S-1-5-11)
    Permissions       : ListDirectory, AddFile, AddSubdirectory, ReadExtendedAttributes, WriteExtendedAttributes,
                        Traverse, ReadAttributes, WriteAttributes, Delete, ReadControl, Synchronize, GenericRead,
                        GenericExecute, GenericWrite
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
        $CurrentUserSids = Get-CurrentUserSid
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {

        foreach ($ScheduledTask in (Get-RegisteredScheduledTask | Where-Object { $_.Enabled })) {

            $RunAsPrincipalSid = $ScheduledTask.RunAs.UserId
            $RunAsPrincipalName = $ScheduledTask.RunAs.User
            if ([String]::IsNullOrEmpty($RunAsPrincipalSid)) {
                $RunAsPrincipalSid = $ScheduledTask.RunAs.GroupId
                $RunAsPrincipalName = $ScheduledTask.RunAs.Group
            }

            # Ignore tasks that a are run as the current user
            if ($CurrentUserSids -contains $RunAsPrincipalSid) { continue }

            foreach ($ExecAction in $ScheduledTask.ExecActions) {

                $Command = $ExecAction.Command.Trim("`"")
                $ModifiablePaths = Get-ModifiablePath -Path $Command | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                if ($null -eq $ModifiablePaths) { continue }

                foreach ($ModifiablePath in $ModifiablePaths) {

                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $ScheduledTask.Name
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $ScheduledTask.Path
                    $Result | Add-Member -MemberType "NoteProperty" -Name "FilePath" -Value $ScheduledTask.FilePath
                    $Result | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value $RunAsPrincipalName
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Command" -Value "$($ExecAction.Command) $($ExecAction.Arguments)"
                    $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $ModifiablePath.ModifiablePath
                    $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $ModifiablePath.IdentityReference
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($ModifiablePath.Permissions -join ", ")
                    $AllResults += $Result
                }
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Invoke-ScheduledTaskUnquotedPathCheck {
    <#
    .SYNOPSIS
    Enumerates scheduled tasks with an exploitable unquoted path

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This script first enumerates all the tasks that are visible to the current user. Then, it checks the 'Command' value to see if it is not surrounded by quotes (unquoted path). If so, it checks whether the path contains spaces and if one of the intermediate directories is exploitable. Note that, as a low privileged user, not all the tasks are visible.

    .EXAMPLE
    PS C:\> Invoke-ScheduledTaskUnquotedPathCheck

    TaskName           : VulnTask
    TaskPath           : \CustomTasks\VulnTask
    TaskFile           : C:\WINDOWS\System32\Tasks\CustomTasks\VulnTask
    RunAs              : NT AUTHORITY\SYSTEM
    Command            : C:\APPS\Custom Tasks\task.exe
    CurrentUserIsOwner : False
    ModifiablePath     : C:\APPS
    IdentityReference  : NT AUTHORITY\Authenticated Users
    Permissions        : {Delete, WriteAttributes, Synchronize, ReadControl...}

    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
        $CurrentUserSids = Get-CurrentUserSid
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {

        foreach ($ScheduledTask in (Get-RegisteredScheduledTask | Where-Object { $_.Enabled })) {

            $RunAsPrincipalSid = $ScheduledTask.RunAs.UserId
            $RunAsPrincipalName = $ScheduledTask.RunAs.User
            if ([String]::IsNullOrEmpty($RunAsPrincipalSid)) {
                $RunAsPrincipalSid = $ScheduledTask.RunAs.GroupId
                $RunAsPrincipalName = $ScheduledTask.RunAs.Group
            }

            # Ignore tasks that a are run as the current user
            if ($CurrentUserSids -contains $RunAsPrincipalSid) { continue }

            $RunAsPrincipalName = $ScheduledTask.RunAs.User
            if ([String]::IsNullOrEmpty($RunAsPrincipalName)) {
                $RunAsPrincipalName = $ScheduledTask.RunAs.Group
            }

            foreach ($ExecAction in $ScheduledTask.ExecActions) {

                $UnquotedPaths = Get-ExploitableUnquotedPath -Path $ExecAction.Command

                foreach ($UnquotedPath in $UnquotedPaths) {

                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $ScheduledTask.Name
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $ScheduledTask.Path
                    $Result | Add-Member -MemberType "NoteProperty" -Name "FilePath" -Value $ScheduledTask.FilePath
                    $Result | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value $RunAsPrincipalName
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Command" -Value "$($ExecAction.Command) $($ExecAction.Arguments)"
                    $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $UnquotedPath.ModifiablePath
                    $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $UnquotedPath.IdentityReference
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($UnquotedPath.Permissions -join ", ")
                    $AllResults += $Result
                }
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Invoke-ScheduledTaskPermissionCheck {
    <#
    .SYNOPSIS
    Find scheduled tasks configured with a weak DACL.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet first obtains the list of all readable scheduled tasks, and then determines whether their DACL grants modification rights to the current user.

    .EXAMPLE
    PS C:\> Invoke-ScheduledTaskPermissionCheck

    Name              : MareBackup
    Path              : \Microsoft\Windows\Application Experience\MareBackup
    FilePath          : C:\WINDOWS\System32\Tasks\Microsoft\Windows\Application Experience\MareBackup
    RunAs             : NT AUTHORITY\SYSTEM
    ModifiablePath    : \Microsoft\Windows\Application Experience\MareBackup
    IdentityReference : BUILTIN\Users (S-1-5-32-545)
    Permissions       : AllAccess
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
        $CurrentUserSids = Get-CurrentUserSid
    }

    process {

        foreach ($ScheduledTask in (Get-RegisteredScheduledTask)) {

            $RunAsPrincipalSid = $ScheduledTask.RunAs.UserId
            $RunAsPrincipalName = $ScheduledTask.RunAs.User
            if ([String]::IsNullOrEmpty($RunAsPrincipalSid)) {
                $RunAsPrincipalSid = $ScheduledTask.RunAs.GroupId
                $RunAsPrincipalName = $ScheduledTask.RunAs.Group
            }

            # Ignore tasks that a are run as the current user
            if ($CurrentUserSids -contains $RunAsPrincipalSid) { continue }

            # Ignore tasks owned by the current user
            if ($CurrentUserSids -contains $ScheduledTask.SecurityInfo.OwnerSid) { continue }
            if ($CurrentUserSids -contains $ScheduledTask.SecurityInfo.GroupSid) { continue }

            Get-ObjectAccessRight -Name $ScheduledTask.Path -Type ScheduledTask -SecurityInformation $ScheduledTask.SecurityInfo | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) } | Foreach-Object {

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $ScheduledTask.Name
                $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $ScheduledTask.Path
                $Result | Add-Member -MemberType "NoteProperty" -Name "FilePath" -Value $ScheduledTask.FilePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value $RunAsPrincipalName
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($_.Permissions -join ", ")
                $AllResults += $Result
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}