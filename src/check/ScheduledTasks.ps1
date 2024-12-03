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

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        $ScheduledTasks = Get-ScheduledTaskList | Where-Object { (-not $_.CurrentUserIsOwner) -and (-not [String]::IsNullOrEmpty($_.Program)) }

        foreach ($ScheduledTask in $ScheduledTasks) {

            $ModifiablePaths = Get-ModifiablePath -Path $ScheduledTask.Program | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
            if ($null -eq $ModifiablePaths) { continue }
            foreach ($ModifiablePath in $ModifiablePaths) {

                $Result = $ScheduledTask.PsObject.Copy()
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $ModifiablePath.ModifiablePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $ModifiablePath.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($ModifiablePath.Permissions -join ", ")
                $AllResults += $Result
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
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
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        Get-ScheduledTaskList | Where-Object { $_.CurrentUserIsOwner -eq $false} | ForEach-Object {

            $CurrentTask = $_

            Get-ExploitableUnquotedPath -Path $CurrentTask.Command | ForEach-Object {

                $Result = $CurrentTask.PsObject.Copy()
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $_.Permissions
                $AllResults += $Result
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}