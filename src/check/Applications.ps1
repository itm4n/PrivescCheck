function Invoke-InstalledApplicationCheck {
    <#
    .SYNOPSIS
    Enumerates the applications that are not installed by default

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Uses the custom "Get-InstalledProgram" function to get a filtered list of installed programs and then returns each result as a simplified PS object, indicating the name and the path of the application.
    #>

    [CmdletBinding()]
    param()

    Get-InstalledProgram -Filtered | Select-Object -Property Name,FullName
}

function Invoke-InstalledApplicationPermissionCheck {
    <#
    .SYNOPSIS
    Identifies applications which have a modifiable EXE of DLL file

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    For each non-default application, enumerates the .exe and .dll files that the current user has modify permissions on.
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
        $InstalledPrograms = Get-InstalledProgram -Filtered

        foreach ($InstalledProgram in $InstalledPrograms) {

            # Ensure the path is not a known system folder, in which case it does not make
            # sense to check it. This also prevents the script from spending a considerable
            # amount of time and resources searching those paths recursively.
            if (Test-IsSystemFolder -Path $InstalledProgram.FullName) {
                Write-Warning "System path detected, ignoring: $($InstalledProgram.FullName)"
                continue
            }

            # Build the search path list. The following trick is used to search recursively
            # without using the 'Depth' option, which is only available in PSv5+. This
            # allows us to maintain compatibility with PSv2.
            $SearchPath = New-Object -TypeName System.Collections.ArrayList
            [void] $SearchPath.Add([String] $(Join-Path -Path $InstalledProgram.FullName -ChildPath "\*"))
            [void] $SearchPath.Add([String] $(Join-Path -Path $InstalledProgram.FullName -ChildPath "\*\*"))

            $CandidateItems = Get-ChildItem -Path $SearchPath -ErrorAction SilentlyContinue
            if ($null -eq $CandidateItems) { continue }

            foreach ($CandidateItem in $CandidateItems) {

                if (($CandidateItem -is [System.IO.FileInfo]) -and (-not (Test-CommonApplicationFile -Path $CandidateItem.FullName))) { continue }
                if ([String]::IsNullOrEmpty($CandidateItem.FullName)) { continue }

                $ModifiablePaths = Get-ModifiablePath -Path $CandidateItem.FullName | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                if ($null -eq $ModifiablePaths) { continue }
                foreach ($ModifiablePath in $ModifiablePaths) {
                    $ModifiablePath.Permissions = $ModifiablePath.Permissions -join ', '
                    $AllResults += $ModifiablePath
                }
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

function Invoke-ProgramDataPermissionCheck {
    <#
    .SYNOPSIS
    Checks for modifiable files and folders under non default ProgramData folders.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This script first lists all the subfolders under 'C:\ProgramData\'. For each folder that is not a "known" default Windows folder, it lists all the files and folders it contains. If a modifiable file or folder is found, it is reported by the script.

    .EXAMPLE
    PS C:\> Invoke-ProgramDataPermissionCheck

    ModifiablePath    : C:\ProgramData\VMware\logs
    IdentityReference : BUILTIN\Users
    Permissions       : {WriteAttributes, AppendData/AddSubdirectory, WriteExtendedAttributes, WriteData/AddFile}
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $IgnoredProgramData = @("Microsoft", "Microsoft OneDrive", "Package Cache", "Packages", "SoftwareDistribution", "ssh", "USOPrivate", "USOShared")
        $AllResults = @()
    }

    process {
        $ProgramDataFolders = Get-ChildItem -Path $env:ProgramData -Force -ErrorAction SilentlyContinue | Where-Object { ($_ -is [System.IO.DirectoryInfo]) -and (-not ($IgnoredProgramData -contains $_.Name)) }

        foreach ($ProgramDataFolder in $ProgramDataFolders) {

            $ProgramDataFolderChildItems = Get-ChildItem -Path $ProgramDataFolder.FullName -Recurse -Force -ErrorAction SilentlyContinue
            if ($null -eq $ProgramDataFolderChildItems) {continue }

            foreach ($ProgramDataFolderChildItem in $ProgramDataFolderChildItems) {

                # Ignore non-executable files
                if ([String]::IsNullOrEmpty($ProgramDataFolderChildItem.FullName)) { continue }
                if ($ProgramDataFolderChildItem -is [System.IO.DirectoryInfo]) { continue }
                if (($ProgramDataFolderChildItem -is [System.IO.FileInfo]) -and (-not (Test-CommonApplicationFile -Path $ProgramDataFolderChildItem.FullName))) { continue }

                $ModifiablePaths = Get-ModifiablePath -Path $ProgramDataFolderChildItem.FullName | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                if ($null -eq $ModifiablePaths) { continue }
                foreach ($ModifiablePath in $ModifiablePaths) {
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $ProgramDataFolderChildItem.FullName
                    $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $ModifiablePath.ModifiablePath
                    $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $ModifiablePath.IdentityReference
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($ModifiablePath.Permissions -join ", ")
                    $AllResults += $Result
                }
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }
}

function Invoke-StartupApplicationPermissionCheck {
    <#
    .SYNOPSIS
    Enumerates the applications which are run on startup

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Applications can be run on startup or whenever a user logs on. They can be either configured in the registry or by adding an shortcut file (.LNK) in a Start Menu folder.
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
        [string[]] $RegistryPaths = "HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        $RegistryPaths | ForEach-Object {

            $RegKeyPath = $_

            $Item = Get-Item -Path "Registry::$($RegKeyPath)" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItem
            if (-not $ErrorGetItem) {

                $Values = [string[]] ($Item | Select-Object -ExpandProperty Property)
                foreach ($Value in $Values) {

                    $RegKeyValueName = $Value
                    $RegKeyValueData = $Item.GetValue($RegKeyValueName, "", "DoNotExpandEnvironmentNames")
                    if ([String]::IsNullOrEmpty($RegKeyValueData)) { continue }

                    $CommandLineResolved = [string[]] (Resolve-CommandLine -CommandLine $RegKeyValueData)
                    if ($null -eq $CommandLineResolved) { continue }
                    $ExecutablePath = $CommandLineResolved[0]

                    $ModifiablePaths = Get-ModifiablePath -Path $ExecutablePath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                    $IsModifiable = $($null -ne $ModifiablePaths)

                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegKeyValueName
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value "$($RegKeyPath)\$($RegKeyValueName)"
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegKeyValueData
                    $Result | Add-Member -MemberType "NoteProperty" -Name "IsModifiable" -Value $IsModifiable
                    $AllResults += $Result
                }
            }
        }

        $Root = (Get-Item -Path $env:windir).PSDrive.Root

        # We want to check only startup applications that affect all users
        [string[]] $FileSystemPaths = "\Users\All Users\Start Menu\Programs\Startup"

        $FileSystemPaths | ForEach-Object {

            $StartupFolderPath = Join-Path -Path $Root -ChildPath $_

            $StartupFolders = Get-ChildItem -Path $StartupFolderPath -ErrorAction SilentlyContinue

            foreach ($StartupFolder in $StartupFolders) {

                $EntryName = $StartupFolder.Name
                $EntryPath = $StartupFolder.FullName

                if ($EntryPath -Like "*.lnk") {

                    try {
                        $Wsh = New-Object -ComObject WScript.Shell
                        $Shortcut = $Wsh.CreateShortcut((Resolve-Path -Path $EntryPath))
                        if ([String]::IsNullOrEmpty($Shortcut.TargetPath)) { continue }

                        $CommandLineResolved = [String[]] (Resolve-CommandLine -CommandLine $Shortcut.TargetPath)
                        if ($nul -eq $CommandLineResolved) { continue }
                        $ExecutablePath = $CommandLineResolved[0]

                        $ModifiablePaths = Get-ModifiablePath -Path $ExecutablePath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                        $IsModifiable = $($null -ne $ModifiablePaths)

                        $Result = New-Object -TypeName PSObject
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $EntryName
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $EntryPath
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value "$($Shortcut.TargetPath) $($Shortcut.Arguments)"
                        $Result | Add-Member -MemberType "NoteProperty" -Name "IsModifiable" -Value $IsModifiable
                        $AllResults += $Result
                    }
                    catch {
                        Write-Warning "$($MyInvocation.MyCommand) | Failed to create Shortcut object from path: $($EntryPath)"
                    }
                }
            }
        }

        $ModifiableCount = ([object[]] ($AllResults | Where-Object { $_.IsModifiable })).Count

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ModifiableCount -gt 0) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Invoke-RunningProcessCheck {
    <#
    .SYNOPSIS
    Enumerates the running processes

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    First, it lists all the processes thanks to the built-in "Get-Process" function. Then, it filters the result in order to return only the non-default Windows processes. By default, this function returns only process that are NOT owned by teh current user but you can use the "-Self" flag to get them.

    .PARAMETER Self
    Use this flag to get a list of all the process owned by the current user
    #>

    [CmdletBinding()]
    param(
        [switch] $Self = $false
    )

    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $IgnoredProcessNames = @("Idle", "services", "Memory Compression", "TrustedInstaller", "PresentationFontCache", "Registry", "ServiceShell", "System", "csrss", "dwm", "msdtc", "smss", "svchost")

    $AllProcess = Get-Process
    if ($null -eq $AllProcess) { return }

    foreach ($Process in $AllProcess) {

        if (-not ($IgnoredProcessNames -contains $Process.Name )) {

            $ProcessUser = (Get-TokenInformationUser -ProcessId $Process.Id).DisplayName

            $ReturnProcess = $false

            if ($Self) {
                if ($ProcessUser -eq $CurrentUser) {
                    $ReturnProcess = $true
                }
            }
            else {
                if (-not ($ProcessUser -eq $CurrentUser)) {

                    # Here, I check whether 'C:\Windows\System32\<PROC_NAME>.exe' exists. Not ideal but it's a quick
                    # way to check whether it's a built-in binary. There might be some issues because of the
                    # FileSystem Redirector if the script is run from a 32-bits instance of powershell.exe (->
                    # SysWow64 instead of System32).
                    $PotentialImagePath = Join-Path -Path $env:SystemRoot -ChildPath "System32"
                    $PotentialImagePath = Join-Path -Path $PotentialImagePath -ChildPath "$($Process.name).exe"

                    # If we can't find it in System32, add it to the list
                    if (-not (Test-Path -Path $PotentialImagePath)) {
                        $ReturnProcess = $true
                    }
                    $ReturnProcess = $true
                }
            }

            if ($ReturnProcess) {
                $Process | Select-Object -Property Name,Id,Path,SessionId | Add-Member -MemberType "NoteProperty" -Name "User" -Value $ProcessUser -PassThru
            }

        }
        else {
            Write-Verbose "Ignored: $($Process.Name)"
        }
    }
}

function Invoke-RootFolderPermissionCheck {

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        # $IgnoredRootFolders = @( "Windows", "Users", "Program Files", "Program Files (x86)", "PerfLogs")
        $IgnoredRootFolders = @( "`$Recycle.Bin", "`$WinREAgent", "Documents and Settings", "PerfLogs", "Program Files", "Program Files (x86)", "ProgramData", "Recovery", "System Volume Information", "Users", "Windows" )
        $MaxFileCount = 8
        $AllResults = @()
    }

    process {
        # List all "fixed" drives.
        # From: https://superuser.com/a/787643
        $FixedDrives = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' }
        foreach ($FixedDrive in $FixedDrives) {

            # For each fixed drive, list the root folders. Here, we also use the option
            # -Force to specify that we want to include hidden ones. The resulting list
            # is then filtered to exclude known folders such as "C:\Windows".
            $RootFolders = Get-ChildItem -Path $FixedDrive -Force -ErrorAction SilentlyContinue | Where-Object { ($_ -is [System.IO.DirectoryInfo]) -and ($IgnoredRootFolders -notcontains $_.Name) }
            if ($null -eq $RootFolders) { continue }
            foreach ($RootFolder in $RootFolders) {

                $Vulnerable = $false

                # Check whether the current user has any modification right on the root folder.
                $RootFolderModifiablePaths = Get-ModifiablePath -Path $RootFolder.FullName | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                if ($RootFolderModifiablePaths) {
                    $Description = "The current user has modification rights on this root folder."
                }
                else {
                    $Description = "The current user does not have modification rights on this root folder."
                }

                # Check whether the current user has any modification right on a common app
                # file within this root folder.
                $ApplicationFileModifiablePaths = @()
                $ApplicationFiles = Get-ChildItem -Path $RootFolder.FullName -Force -Recurse -ErrorAction SilentlyContinue | Where-Object { ($_ -is [System.IO.FileInfo]) -and (Test-CommonApplicationFile -Path $_.FullName) }
                foreach ($ApplicationFile in $ApplicationFiles) {
                    if ($ApplicationFileModifiablePaths.Count -gt $MaxFileCount) { break }
                    if ([String]::IsNullOrEmpty($ApplicationFile.FullName)) { continue }
                    $ModifiablePaths = Get-ModifiablePath -Path $ApplicationFile.FullName | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                    if ($ModifiablePaths) { $ApplicationFileModifiablePaths += $ApplicationFile.FullName }
                }

                # If at least one modifiable application file is found, consider the folder as
                # 'vulnerable'. Even if application files are not modifiable, consider the folder
                # as 'vulnerable' if the current user has any modification right on it.
                if ($ApplicationFileModifiablePaths) { $Vulnerable = $true }
                if ($ApplicationFiles.Count -gt 0 -and $RootFolderModifiablePaths) { $Vulnerable = $true }

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

                if (($null -ne $RootFolderFiles) -or ($null -ne $RootFolderModifiablePaths)) {

                    $ModifiableChildPathResult = ($ApplicationFileModifiablePaths | ForEach-Object { Resolve-PathRelativeTo -From $RootFolder.FullName -To $_ } | Select-Object -First $MaxFileCount) -join "; "
                    if ($ApplicationFileModifiablePaths.Count -gt $MaxFileCount) { $ModifiableChildPathResult += "; ..." }

                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $RootFolder.FullName
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Modifiable" -Value ($null -ne $RootFolderModifiablePaths)
                    $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePaths" -Value $ModifiableChildPathResult
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value $Vulnerable
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                    $AllResults += $Result
                }
            }
        }

        $Vulnerable = ($AllResults | Where-Object { $_.Vulnerable }).Count -gt 0

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }
}