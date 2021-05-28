function Invoke-ScheduledTasksImagePermissionsCheck {
    <#
    .SYNOPSIS
    Enumrates scheduled tasks with a modifiable path

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    This function enumerates all the scheduled tasks which are visible by the current user but are not owned by the current user. For each task, it extracts the command line and checks whether it contains a path pointing to a modifiable file. If a task is run as the current user, it is filtered out. 
    
    .EXAMPLE
    PS C:\> Invoke-ScheduledTasksImagePermissionsCheck

    TaskName           : DummyTask
    TaskPath           : \CustomTasks\DummyTask
    TaskFile           : C:\Windows\System32\Tasks\CustomTasks\DummyTask
    RunAs              : NT AUTHORITY\SYSTEM
    Command            : C:\APPS\MyTask.exe
    CurrentUserIsOwner : False
    ModifiablePath     : C:\APPS\
    IdentityReference  : NT AUTHORITY\Authenticated Users
    Permissions        : {Delete, WriteAttributes, Synchronize, ReadControl...}
    #>

    [CmdletBinding()] Param()

    Get-ScheduledTaskList | Where-Object { -not $_.CurrentUserIsOwner } | ForEach-Object {

        $CurrentTask = $_

        $CurrentTask.Command | Get-ModifiablePath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) } | ForEach-Object {

            $ResultItem = $CurrentTask.PsObject.Copy()
            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $_.Permissions
            $ResultItem
        }
    }
}

function Invoke-ScheduledTasksUnquotedPathCheck {
    <#
    .SYNOPSIS

    Enumerates scheduled tasks with an exploitable unquoted path

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    This script first enumerates all the tasks that are visible to the current user. Then, it checks the 'Command' value to see if it is not surrounded by quotes (unquoted path). If so, it checks whether the path contains spaces and if one of the intermediate directories is exploitable. Note that, as a low privileged user, not all the tasks are visible.
    
    .EXAMPLE

    PS C:\> Invoke-ScheduledTasksUnquotedPathCheck

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

    [CmdletBinding()] Param()

    Get-ScheduledTaskList | Where-Object { $_.CurrentUserIsOwner -eq $false} | ForEach-Object {

        $CurrentTask = $_

        Get-ExploitableUnquotedPath -Path $CurrentTask.Command | ForEach-Object {

            $ResultItem = $CurrentTask.PsObject.Copy()
            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $_.Permissions
            $ResultItem
        }
    }
}