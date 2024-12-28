function New-InitialSessionState {
    <#
    .SYNOPSIS
    Construct an InitialSessionState object for use in a separate runspace.

    .DESCRIPTION
    This cmdlet creates an InitialSessionState object and populates it with global variables and custom functions defined in the current session. The returned InitialSessionState object can then be used to invoke code in a separate runspace.

    .EXAMPLE
    PS C:\> $iss = New-InitialSessionState; Invoke-SomeCommand -InitialSessionState $iss

    .LINK
    https://www.get-blog.com/?p=189
    https://devblogs.microsoft.com/scripting/powertip-add-custom-function-to-runspace-pool/
    #>

    [OutputType([Management.Automation.Runspaces.InitialSessionState])]
    [CmdletBinding()]
    param ()

    process {
        $InitialSessionState = [Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

        # Enumerate all session variables used to define types and functions in
        # 'WinApiModule' as well as custom global variables.
        $SessionVariables = Get-Variable -Scope Script | Where-Object {
            ($_.Value -and $_.Value.ToString() -like "WinApiModule.*") -or ($_.Name -and $_.Name -like "Global*")
        }

        # Populate the initial session state object with all our session variables.
        $SessionVariables | ForEach-Object {
            $SessionStateVariableEntry = New-Object System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $_.Name, $_.Value, $null
            $InitialSessionState.Variables.Add($SessionStateVariableEntry)
        }

        # List all function defined in the current session and add them to the new
        # initial session state object.
        Get-ChildItem Function: | Where-Object { $_.Name -like "*-*" } | ForEach-Object {
            $SessionStateFunction = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $_.Name, $_.Definition
            $InitialSessionState.Commands.Add($SessionStateFunction)
        }

        return $InitialSessionState
    }
}

function Invoke-CommandMultithread {
    <#
    .SYNOPSIS
    Invoke a PowerShell command using multiple threads.

    .DESCRIPTION
    This cmdlet can be used to process a large number of objects in parallel threads.

    .PARAMETER InitialSessionState
    A mandatory InitialStateObject used to initialize the PowerShell runspace.

    .PARAMETER Command
    A mandatory PowerShell command to execute.

    .PARAMETER ObjectList
    A mandatory list of objects to process in parallel. Complex objects are not supported, the input objects must be of a base type such as 'String' or 'UInt32'.

    .PARAMETER InputParameter
    An optional PowerShell command name to use to pass each entry in the object list. If not specified, object entries are passed as an argument in the PowerShell command.

    .PARAMETER OptionalParameter
    An optional PowerShell command parameter (e.g. '-Param Foo') to add to the command invocation.

    .PARAMETER OptionalSwitch
    An optional PowerShell command switch (e.g. '-Verbose') to add to the command invocation.

    .EXAMPLE
    PS C:\> $iss = New-InitialSessionState
    PS C:\> $RegisteredClasses = Get-ComClassFromRegistry | Where-Object { ($_.Value -like '*server*') -and ($null -ne $_.Path) }
    PS C:\> $RegPaths = $RegisteredClasses | ForEach-Object { Join-Path -Path $_.Path -ChildPath $_.Value }
    PS C:\> $RegPaths | Invoke-CommandMultithread -InitialSessionState $iss -Command 'Get-ModifiableRegistryPath'

    .LINK
    https://www.get-blog.com/?p=189
    https://devblogs.microsoft.com/scripting/powertip-add-custom-function-to-runspace-pool/
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Management.Automation.Runspaces.InitialSessionState] $InitialSessionState,

        [String] $Command,

        [Parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Object[]] $ObjectList,

        [String] $InputParameter,
        [HashTable] $OptionalParameter = @{},
        [String[]] $OptionalSwitch = @()
    )

    begin {
        $ThreadWatchTimer = 100
        $RunspacePool = [RunspaceFactory]::CreateRunspacePool(1, $env:NUMBER_OF_PROCESSORS + 1, $InitialSessionState, $Host)
        $RunspacePool.Open()
        $Jobs = @()
    }

    process {
        foreach ($Object in $ObjectList) {
            $PowerShellThread = [powershell]::Create()

            $null = $PowerShellThread.AddCommand($Command)

            # Add 'Invoke-Command -Param Foo' or 'Invoke-Command Foo'.
            if ([String]::IsNullOrEmpty($InputParameter)) {
                $null = $PowerShellThread.AddArgument($Object)
            }
            else {
                $null = $PowerShellThread.AddParameter($InputParameter, $Object)
            }

            # Add 'Invoke-Command -Option Bar'.
            foreach ($Key in $OptionalParameter.Keys) {
                $null = $PowerShellThread.AddParameter($Key, $OptionalParameter.$Key)
            }

            # Add 'Invoke-Command -Switch'.
            foreach ($Switch in $OptionalSwitch) {
                $null = $PowerShellThread.AddParameter($Switch)
            }

            $PowerShellThread.RunspacePool = $RunspacePool
            $ThreadHandle = $PowerShellThread.BeginInvoke()

            $JobEntry = New-Object -TypeName PSObject
            $JobEntry | Add-Member -MemberType "NoteProperty" -Name "Handle" -Value $ThreadHandle
            $JobEntry | Add-Member -MemberType "NoteProperty" -Name "Thread" -Value $PowerShellThread
            $Jobs += $JobEntry
        }
    }

    end {
        while (@($Jobs | Where-Object { $null -ne $_.Handle }).Count -gt 0) {

            foreach ($Job in $($Jobs | Where-Object { $_.Handle.IsCompleted -eq $true })) {

                $Job.Thread.EndInvoke($Job.Handle)
                $Job.Thread.Dispose()
                $Job.Thread = $null
                $Job.Handle = $null
            }

            Start-Sleep -Milliseconds $ThreadWatchTimer
        }

        $null = $RunspacePool.Close()
        $null = $RunspacePool.Dispose()
    }
}