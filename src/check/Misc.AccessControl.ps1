function Invoke-ProcessAndThreadPermissionCheck {
    <#
    .SYNOPSIS
    Check permissions of processes and threads.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet enumerates all processes and threads, and checks whether the current user has any privileged access rights on objects which they do not own.
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
        $Processes = [Object[]] (Get-SystemInformationProcessAndThread)

        $ProgressCount = 0
        Write-Progress -Activity "Checking process and thread permissions (0/$($Processes.Count))..." -Status "0% Complete:" -PercentComplete 0

        foreach ($Process in $Processes) {

            $ProgressPercent = [UInt32] ($ProgressCount * 100 / $Processes.Count)
            Write-Progress -Activity "Checking process and thread permissions ($($ProgressCount)/$($Processes.Count)): PID=$($Process.ProcessId)" -Status "$($ProgressPercent)% Complete:" -PercentComplete $ProgressPercent
            $ProgressCount += 1

            # Check the permissions of the process first. Filter out processes owned by the
            # current user.
            $ProcessModificationRightsFound = $false
            $ProcessModificationRights = Get-ObjectAccessRight -Name $Process.ProcessId -Type Process | Where-Object { $CurrentUserSids -notcontains $_.OwnerSid }
            foreach ($ProcessModificationRight in $ProcessModificationRights) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $Process.ProcessId
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Process"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Owner" -Value $ProcessModificationRight.Owner
                $Result | Add-Member -MemberType "NoteProperty" -Name "OwnerSid" -Value $ProcessModificationRight.OwnerSid
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $ProcessModificationRight.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($ProcessModificationRight.Permissions -join ", ")
                $AllResults += $Result
                $ProcessModificationRightsFound = $true
            }

            # We found modification rights on the process, so no need to check thread
            # permissions.
            if ($ProcessModificationRightsFound) { continue }

            foreach ($Thread in $Process.Threads) {

                # Check the permissions of each thread in the process. Filter out threads owned
                # by the current user.
                $ThreadModificationRights = Get-ObjectAccessRight -Name $Thread.ThreadId -Type Thread | Where-Object { $CurrentUserSids -notcontains $_.OwnerSid }
                foreach ($ThreadModificationRight in $ThreadModificationRights) {
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $Thread.ThreadId
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Thread"
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Owner" -Value $ThreadModificationRight.Owner
                    $Result | Add-Member -MemberType "NoteProperty" -Name "OwnerSid" -Value $ThreadModificationRight.OwnerSid
                    $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $ThreadModificationRight.IdentityReference
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($ThreadModificationRight.Permissions -join ", ")
                    $AllResults += $Result
                }
            }
        }

        Write-Progress -Activity "Checking process and thread permissions ($($Processes.Count)/$($Processes.Count))..." -Status "100% Complete:" -Completed

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}

function Invoke-NamedPipePermissionCheck {
    <#
    .SYNOPSIS
    Get information about named pipes low-privileged users can write to.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet enumerates named pipes with a DACL that grants write access to the current user.

    .EXAMPLE
    PS C:\> Invoke-NamedPipePermissionCheck

    FullName          : \\.\pipe\eventlog
    Owner             : NT AUTHORITY\LOCAL SERVICE (S-1-5-19)
    IdentityReference : Everyone (S-1-1-0)
    Permissions       : ReadData, WriteData, ReadExtendedAttributes, WriteExtendedAttributes, ReadAttributes, WriteAttributes, ReadControl, Synchronize, GenericRead

    FullName          : \\.\pipe\WinFsp.{14E7137D-22B4-437A-B0C1-D21D1BDF3767}
    Owner             : NT AUTHORITY\SYSTEM (S-1-5-18)
    IdentityReference : Everyone (S-1-1-0)
    Permissions       : ReadData, WriteData, ReadExtendedAttributes, ReadAttributes, WriteAttributes, ReadControl, Synchronize, GenericRead

    FullName          : \\.\pipe\ROUTER
    Owner             : NT AUTHORITY\SYSTEM (S-1-5-18)
    IdentityReference : Everyone (S-1-1-0)
    Permissions       : ReadData, WriteData, ReadExtendedAttributes, WriteExtendedAttributes, ReadAttributes, WriteAttributes, ReadControl, Synchronize, GenericRead

    FullName          : \\.\pipe\ProtectedPrefix\LocalService\FTHPIPE
    Owner             : NT AUTHORITY\LOCAL SERVICE (S-1-5-19)
    IdentityReference : NT AUTHORITY\INTERACTIVE (S-1-5-4)
    Permissions       : ReadData, WriteData, AppendData, ReadExtendedAttributes, WriteExtendedAttributes, ReadAttributes, WriteAttributes, ReadControl, Synchronize, GenericRead, GenericWrite

    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    process {

        $Results = @()
        $CurrentUserSid = [String[]] (Get-CurrentUserSid)
        $PipeItems = Get-ChildItem -Path "\\.\pipe\"

        foreach ($PipeItem in $PipeItems) {

            $ModifiablePaths = Get-ObjectAccessRight -Name $PipeItem.FullName -Type File

            foreach ($ModifiablePath in $ModifiablePaths) {

                # Exclude named pipes owned by the current user
                if ($CurrentUserSid -contains $ModifiablePath.OwnerSid) { continue }

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "FullName" -Value $PipeItem.FullName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Owner" -Value "$($ModifiablePath.Owner) ($($ModifiablePath.OwnerSid))"
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $ModifiablePath.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $($ModifiablePath.Permissions -join ", ")
                $Results += $Result
            }
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
        $Result
    }
}

function Invoke-ExploitableLeakedHandleCheck {
    <#
    .SYNOPSIS
    Check whether the current user has access to a process that contains a leaked handle to a privileged process, thread, or file object.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet attempts to enumerate handles to privileged objects that are inherited in processes we can open with the PROCESS_DUP_HANDLE access right. If the granted access rights of the handle are interesting, and we can duplicate it, this could result in a privilege escalation. For instance, a process running as SYSTEM could open another process running as SYSTEM with the parameter bInheritHandle set to TRUE, and then create subprocesses as a low-privileged user. In this case, we might be able to duplicate the handle, and access the process running as SYSTEM. This check is inspired from the project 'LeakedHandlesFinder' (see reference in the LINK section).

    .LINK
    https://github.com/lab52io/LeakedHandlesFinder
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()

        $ObjectTypeOfInterest = @( "Process", "Thread", "File" )
        $AccessMasks = @{
            "Process" = $script:ProcessAccessRight::CREATE_PROCESS -bor $script:ProcessAccessRight::CREATE_THREAD -bor $script:ProcessAccessRight::DUP_HANDLE -bor $script:ProcessAccessRight::VM_OPERATION -bor $script:ProcessAccessRight::VM_READ -bor $script:ProcessAccessRight::VM_WRITE
            "Thread"  = $script:ThreadAccessRight::DirectImpersonation -bor $script:ThreadAccessRight::SetContext
            "File"    = $script:FileAccessRight::WriteData -bor $script:FileAccessRight::AppendData -bor $script:FileAccessRight::WriteOwner -bor $script:FileAccessRight::WriteDac
        }

        $DUPLICATE_SAME_ACCESS = 2
        $CurrentProcessHandle = $script:Kernel32::GetCurrentProcess()

        $ProcessHandles = @{}
        $DuplicatedHandles = @()

        $DosDevices = @{}
        (Get-PSDrive -PSProvider "FileSystem" | Select-Object -ExpandProperty Root) | ForEach-Object {
            $DriverLetter = $_.Trim('\')
            $DosDevices += @{ $DriverLetter = Convert-DosDeviceToDevicePath -DosDevice $DriverLetter }
        }
    }

    process {
        $ExploitableHandles = @()

        # Get a list of all inherited handles
        $InheritedHandles = [Object[]] (Get-SystemInformationExtendedHandle -InheritedOnly | Where-Object { $ObjectTypeOfInterest -contains $_.ObjectType })
        Write-Verbose "Inherited handles of interest: $($InheritedHandles.Count)"

        foreach ($InheritedHandle in $InheritedHandles) {

            # In the C-style structure, the PID is returned as a ULONG_PTR, which is
            # represented as an IntPtr in .Net, so we convert it as an Int.
            $ProcessId = $InheritedHandle.UniqueProcessId.ToInt64()

            # Make sure we have an access mask for this object type. If not, throw an
            # exception. This should never happen since we already filtered the list
            # at the beginning.
            $AccessMask = $AccessMasks[$InheritedHandle.ObjectType]
            if (($null -eq $AccessMask) -or ($AccessMask -eq 0)) {
                throw "Unhandled type for object 0x$('{0:x}' -f $InheritedHandle.Object) in process $($ProcessId) (handle: $('{0:x}' -f $InheritedHandle.HandleValue)): $($InheritedHandle.ObjectType)"
            }

            # If the handle has access rights which are not interesting, or cannot be
            # exploited, ignore it.
            if (($InheritedHandle.GrantedAccess -band $AccessMask) -eq 0) { continue }

            # Try to open the process holding the handle with PROCESS_DUP_HANDLE. If it
            # succeeds, this means that we can duplicate the handle. Otherwise, the handle
            # will not be exploitable. Whatever the result, save it to a local hashtable
            # for future use.
            if ($ProcessHandles.Keys -notcontains $ProcessId) {
                $ProcHandle = $script:Kernel32::OpenProcess($script:ProcessAccessRight::DUP_HANDLE, $false, $ProcessId)
                $ProcessHandles += @{ $ProcessId = $ProcHandle }
            }

            # If we don't have a valid handle for the process holding the target handle,
            # we won't be able to exploit it, so we can ignore it.
            if (($null -eq $ProcessHandles[$ProcessId]) -or ($ProcessHandles[$ProcessId] -eq [IntPtr]::Zero)) {
                continue
            }

            # Duplicate the handle to inspect it.
            $InheritedHandleDuplicated = [IntPtr]::Zero
            if (-not $script:Kernel32::DuplicateHandle($ProcessHandles[$ProcessId], $InheritedHandle.HandleValue, $CurrentProcessHandle, [ref] $InheritedHandleDuplicated, 0, $false, $DUPLICATE_SAME_ACCESS)) {
                # This should not happen since we already made sure that the target process
                # can be opened with the access right "duplicate handle". So, print a warning,
                # just in case.
                $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Warning "Failed to duplicate handle 0x$('{0:x}' -f $InheritedHandle.HandleValue) - $(Format-Error $LastError)"
                continue
            }

            $DuplicatedHandles += $InheritedHandleDuplicated

            if (($InheritedHandle.GrantedAccess -ne 0x0012019f) -and ($InheritedHandle.GrantedAccess -ne 0x1A019F) -and ($InheritedHandle.GrantedAccess -ne 0x1048576f) -and ($InheritedHandle.GrantedAccess -ne 0x120189)) {
                $InheritedHandleName = Get-ObjectName -ObjectHandle $InheritedHandleDuplicated
            }

            $CandidateHandle = $InheritedHandle.PSObject.Copy()
            $CandidateHandle | Add-Member -MemberType "NoteProperty" -Name "ObjectName" -Value $InheritedHandleName

            # Determine exploitability depending on object type...

            switch ($CandidateHandle.ObjectType) {
                "Process" {
                    # Determine the process' ID using the duplicated handle.
                    $TargetProcessId = $script:Kernel32::GetProcessId($InheritedHandleDuplicated)
                    if ($TargetProcessId -eq 0) {
                        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetProcessId KO - $(Format-Error $LastError)"
                        continue
                    }
                    $CandidateHandle | Add-Member -MemberType "NoteProperty" -Name "TargetProcessId" -Value $TargetProcessId
                    # Check if can open the process with the same access rights directly. If so,
                    # the handle isn't interesting, so ignore it.
                    $TargetProcessHandle = $script:Kernel32::OpenProcess($CandidateHandle.GrantedAccess, $false, $TargetProcessId)
                    if ($TargetProcessHandle -ne [IntPtr]::Zero) {
                        $null = $script:Kernel32::CloseHandle($TargetProcessHandle)
                        continue
                    }
                    $CandidateHandle | Add-Member -MemberType "NoteProperty" -Name "TargetProcessAccessRights" -Value ($CandidateHandle.GrantedAccess -as $script:ProcessAccessRight)
                    $ExploitableHandles += $CandidateHandle
                }
                "Thread" {
                    $TargetThreadId = $script:Kernel32::GetThreadId($InheritedHandleDuplicated)
                    if ($TargetThreadId -eq 0) {
                        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetThreadId KO - $(Format-Error $LastError)"
                        continue
                    }
                    $CandidateHandle | Add-Member -MemberType "NoteProperty" -Name "TargetThreadId" -Value $TargetThreadId
                    # Check if we can open the thread with the same access rights directly. If so,
                    # the handle isn't interesting, so ignore it.
                    $TargetThreadHandle = $script:Kernel32::OpenThread($CandidateHandle.GrantedAccess, $false, $TargetThreadId)
                    if ($TargetThreadHandle -ne [IntPtr]::Zero) {
                        $null = $script:Kernel32::CloseHandle($TargetThreadHandle)
                        continue
                    }
                    $CandidateHandle | Add-Member -MemberType "NoteProperty" -Name "TargetThreadAccessRights" -Value ($CandidateHandle.GrantedAccess -as $script:ThreadAccessRight)
                    $ExploitableHandles += $CandidateHandle
                }
                "File" {
                    if ([String]::IsNullOrEmpty($CandidateHandle.ObjectName)) { continue }
                    $TargetFilename = $CandidateHandle.ObjectName
                    # For each path replace the device path with the DOS device name. For instance,
                    # transform the path '\Device\HarddiskVolume1\Temp\test.txt' into 'C:\Temp\test.txt'.
                    foreach ($DosDevice in $DosDevices.Keys) {
                        if ($TargetFilename.StartsWith($DosDevices[$DosDevice])) {
                            $TargetFilename = $TargetFilename.Replace($DosDevices[$DosDevice], $DosDevice)
                            break
                        }
                    }
                    $CandidateHandle | Add-Member -MemberType "NoteProperty" -Name "TargetFilename" -Value $TargetFilename
                    # Handle only standard files and directories here, like 'C:\path\to\file.txt'.
                    # Ignore device paths such as '\Device\Afd'.
                    if ($TargetFilename -notmatch "^?:\\.*$") { continue }
                    # Check if we have any modification rights on the target file or folder, If so,
                    # the handle isn't interesting, so ignore it.
                    $ModifiablePaths = Get-ModifiablePath -Path $TargetFilename | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                    if ($null -ne $ModifiablePaths) { continue }
                    $CandidateHandle | Add-Member -MemberType "NoteProperty" -Name "TargetFileAccessRights" -Value ($CandidateHandle.GrantedAccess -as $script:FileAccessRight)
                    $ExploitableHandles += $CandidateHandle
                }
                default {
                    throw "Unhandled type for object 0x$('{0:x}' -f $CandidateHandle.Object) in process $($ProcessId) (handle: $('{0:x}' -f $CandidateHandle.HandleValue)): $($CandidateHandle.ObjectType)"
                }
            }
        }

        foreach ($ExploitableHandle in $ExploitableHandles) {
            $ExploitableHandle.Object = "0x$('{0:x}' -f $ExploitableHandle.Object.ToInt64())"
            $ExploitableHandle.HandleValue = "0x$('{0:x}' -f $ExploitableHandle.HandleValue.ToInt64())"
            $ExploitableHandle.GrantedAccess = "0x$('{0:x}' -f $ExploitableHandle.GrantedAccess)"
            $AllResults += $ExploitableHandle
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }

    end {
        foreach ($DuplicatedHandle in $DuplicatedHandles) {
            $null = $script:Kernel32::CloseHandle($DuplicatedHandle)
        }
        foreach ($ProcessHandle in $ProcessHandles.Values) {
            $null = $script:Kernel32::CloseHandle($ProcessHandle)
        }
    }
}