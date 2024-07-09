function Get-ScheduledTaskList {
    <#
    .SYNOPSIS
    Helper - Enumerate all the scheduled task that are not disabled and that are visible to the current user.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Connect to the task scheduler service and retrieve a list of all the scheduled tasks that are visible to the current user.

    .EXAMPLE
    PS C:\> Get-ScheduledTaskList
    ...
    TaskName           : XblGameSaveTask
    TaskPath           : \Microsoft\XblGameSave\XblGameSaveTask
    TaskFile           : C:\Windows\System32\Tasks\Microsoft\XblGameSave\XblGameSaveTask
    RunAs              : NT AUTHORITY\SYSTEM
    Command            : %windir%\System32\XblGameSaveTask.exe standby
    CurrentUserIsOwner : False
    ...
    #>

    [CmdletBinding()]
    param()

    function Get-ScheduledTaskCustom {

        param (
            [object] $Service,
            [string] $TaskPath
        )

        ($CurrentFolder = $Service.GetFolder($TaskPath)).GetTasks(0)
        $CurrentFolder.GetFolders(0) | ForEach-Object {
            Get-ScheduledTaskCustom -Service $Service -TaskPath $(Join-Path -Path $TaskPath -ChildPath $_.Name )
        }
    }

    try {

        if ($script:CachedScheduledTaskList.Count -eq 0) {

            # If the cache is empty, enumerate scheduled tasks and populate the cache.

            $ScheduleService = New-Object -ComObject("Schedule.Service")
            $ScheduleService.Connect()

            Get-ScheduledTaskCustom -Service $ScheduleService -TaskPath "\" | ForEach-Object {

                if ($_.Enabled) {

                    $TaskName = $_.Name
                    $TaskPath = $_.Path
                    $TaskFile = Join-Path -Path $(Join-Path -Path $env:windir -ChildPath "System32\Tasks") -ChildPath $TaskPath

                    [xml] $TaskXml = $_.Xml

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
                            $TaskCommandLine = "`"$($TaskProgram)`" $($TaskArguments)"
                        }
                        else {
                            $TaskCommandLine = "`"$($TaskProgram)`""
                        }

                        if ($TaskCommandLine.Length -gt 0) {

                            $Result = New-Object -TypeName PSObject
                            $Result | Add-Member -MemberType "NoteProperty" -Name "TaskName" -Value $TaskName
                            $Result | Add-Member -MemberType "NoteProperty" -Name "TaskPath" -Value $TaskPath
                            $Result | Add-Member -MemberType "NoteProperty" -Name "TaskFile" -Value $TaskFile
                            $Result | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value $PrincipalName
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Program" -Value $TaskProgram
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Arguments" -Value $TaskArguments
                            $Result | Add-Member -MemberType "NoteProperty" -Name "CommandLine" -Value $TaskCommandLine
                            $Result | Add-Member -MemberType "NoteProperty" -Name "CurrentUserIsOwner" -Value $CurrentUserIsOwner

                            [void] $script:CachedScheduledTaskList.Add($Result)
                        }
                    }
                }
                else {
                    Write-Verbose "Task '$($_.Name)' is disabled"
                }
            }
        }

        $script:CachedScheduledTaskList | ForEach-Object {
            $_
        }

    }
    catch {
        Write-Verbose $_
    }
}

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