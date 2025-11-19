function Invoke-InstalledApplicationCheck {
    <#
    .SYNOPSIS
    Get information about Microsoft applications installed on the machine by searching the registry and the default install locations.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Uses the custom "Get-InstalledApplication" function to get a filtered list of installed programs and then returns each result as a simplified PS object, indicating the name and the path of the application.
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    $Results = Get-InstalledApplication | Where-Object { $_.Publisher -like "*Microsoft*" } | ForEach-Object {

        $AppName = $_.DisplayName
        if ([String]::IsNullOrEmpty($AppName)) {
            $AppName = $_.Name
        }
        else {
            if ($_.Name -ne $_.DisplayName) {
                $AppName = "$($_.Name) ($($_.DisplayName))"
            }
        }

        $DisplayName = "$($AppName.Substring(0, [System.Math]::Min($AppName.Length, 50)))"
        if ($DisplayName.Length -ne $AppName.Length) {
            $DisplayName = "$($DisplayName)..."
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $DisplayName
        $Result | Add-Member -MemberType "NoteProperty" -Name "Version" -Value $_.Version
        $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $_.Location
        $Result
    } | Sort-Object -Unique -Property Name, Version

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
    $Result
}

function Invoke-InstalledApplicationThirdPartyCheck {
    <#
    .SYNOPSIS
    Get information about third-party applications installed on the machine by searching the registry and the default install locations.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Uses the custom "Get-InstalledApplication" function to get a filtered list of installed programs and then returns each result as a simplified PS object, indicating the name and the path of the application.
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    $Results = Get-InstalledApplication | Where-Object { $_.Publisher -notlike "*Microsoft*" } | ForEach-Object {

        $AppName = $_.DisplayName
        if ([String]::IsNullOrEmpty($AppName)) {
            $AppName = $_.Name
        }
        else {
            if ($_.Name -ne $_.DisplayName) {
                $AppName = "$($_.Name) ($($_.DisplayName))"
            }
        }

        $DisplayName = "$($AppName.Substring(0, [System.Math]::Min($AppName.Length, 50)))"
        if ($DisplayName.Length -ne $AppName.Length) {
            $DisplayName = "$($DisplayName)..."
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $DisplayName
        $Result | Add-Member -MemberType "NoteProperty" -Name "Version" -Value $_.Version
        $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $_.Location
        $Result
    } | Sort-Object -Unique -Property Name, Version

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
    $Result
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
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        $Results = @()
        $Candidates = Get-InstalledApplication | Select-Object -ExpandProperty Location | Where-Object { -not [String]::IsNullOrEmpty($_) }
        $ProgressCount = 0
        Write-Progress -Activity "Checking application file and folder permissions (0/$($Candidates.Count))..." -Status "0% Complete:" -PercentComplete 0
        foreach ($Candidate in $Candidates) {
            $ProgressPercent = [UInt32] ($ProgressCount * 100 / $Candidates.Count)
            Write-Progress -Activity "Checking application file and folder permissions ($($ProgressCount)/$($Candidates.Count)): $($Candidate)" -Status "$($ProgressPercent)% Complete:" -PercentComplete $ProgressPercent
            Get-ModifiableApplicationFile -Path $Candidate | ForEach-Object {
                $_.Permissions = $_.Permissions -join ', '
                $Results += $_
            }
            $ProgressCount += 1
        }
        Write-Progress -Activity "Checking application file and folder permissions ($($Candidates.Count)/$($Candidates.Count))..." -Status "100% Complete:" -Completed

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
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
            if ($null -eq $ProgramDataFolderChildItems) { continue }

            foreach ($ProgramDataFolderChildItem in $ProgramDataFolderChildItems) {

                # Ignore non-executable files
                if ([String]::IsNullOrEmpty($ProgramDataFolderChildItem.FullName)) { continue }
                if ($ProgramDataFolderChildItem -is [System.IO.DirectoryInfo]) { continue }
                if (($ProgramDataFolderChildItem -is [System.IO.FileInfo]) -and (-not (Test-IsCommonApplicationFile -Path $ProgramDataFolderChildItem.FullName))) { continue }

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
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
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
        $SystemDriveLetter = (Get-Item -Path $env:windir).PSDrive.Root
        $StartupAppRegistryPaths = @("HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce")
        $StartupAppFileSystemPaths = @("\Users\All Users\Start Menu\Programs\Startup")
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        # 1. Inspect registry keys
        foreach ($StartupAppRegistryPath in $StartupAppRegistryPaths) {

            $RegItem = Get-Item -Path "Registry::$($StartupAppRegistryPath)" -ErrorAction SilentlyContinue
            if ($null -eq $RegItem) { continue }

            $RegValues = [string[]] ($RegItem | Select-Object -ExpandProperty Property)
            foreach ($RegValue in $RegValues) {

                $RegData = $RegItem.GetValue($RegValue, "", "DoNotExpandEnvironmentNames")
                if ([String]::IsNullOrEmpty($RegData)) { continue }

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegValue
                $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value "$($StartupAppRegistryPath)\$($RegValue)"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegData
                $AllResults += $Result
            }
        }

        # 2. Inspect global start menu
        foreach ($StartupAppFileSystemPath in $StartupAppFileSystemPaths) {

            $StartupAppFileSystemPath = Join-Path -Path $SystemDriveLetter -ChildPath $StartupAppFileSystemPath
            $StartupAppFolders = Get-ChildItem -Path $StartupAppFileSystemPath -ErrorAction SilentlyContinue

            foreach ($StartupAppFolder in $StartupAppFolders) {

                $EntryName = $StartupAppFolder.Name
                $EntryPath = $StartupAppFolder.FullName

                # Check only .lnk file
                if ($EntryPath -notlike "*.lnk") { continue }

                try {
                    $Wsh = New-Object -ComObject WScript.Shell
                    $Shortcut = $Wsh.CreateShortcut($(Resolve-Path -Path $EntryPath | Convert-Path))
                    if ([String]::IsNullOrEmpty($Shortcut.TargetPath)) { continue }

                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $EntryName
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $EntryPath
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value "$($Shortcut.TargetPath) $($Shortcut.Arguments)"
                    $AllResults += $Result
                }
                catch {
                    Write-Warning "$($MyInvocation.MyCommand) | Failed to create Shortcut object from path: $($EntryPath)"
                }
            }
        }

        # 3. Inspect each item to see of the path is modifiable
        foreach ($Result in $AllResults) {

            $CommandLineResolved = [string[]] (Resolve-CommandLine -CommandLine $Result.Data)
            $IsModifiable = $null

            if ($null -ne $CommandLineResolved) {
                $ExecutablePath = $CommandLineResolved[0]
                $ModifiablePaths = Get-ModifiablePath -Path $ExecutablePath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                $IsModifiable = $($null -ne $ModifiablePaths)
            }

            $Result | Add-Member -MemberType "NoteProperty" -Name "IsModifiable" -Value $IsModifiable
        }

        $ModifiableCount = ([object[]] ($AllResults | Where-Object { $_.IsModifiable })).Count

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ModifiableCount -gt 0) { $BaseSeverity } else { $script:SeverityLevel::None })
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
        [UInt32] $BaseSeverity
    )

    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $IgnoredProcessNames = @("Idle", "services", "Memory Compression", "TrustedInstaller", "PresentationFontCache", "Registry", "ServiceShell", "System", "csrss", "dwm", "msdtc", "smss", "svchost")

    $Results = @()
    foreach ($Process in $(Get-Process)) {

        if (-not ($IgnoredProcessNames -contains $Process.Name )) {

            $ProcessUser = (Get-TokenInformationUser -ProcessId $Process.Id).DisplayName

            if (-not ($ProcessUser -eq $CurrentUser)) {

                $Result = $Process | Select-Object -Property Id, SessionId, Name, Path | Add-Member -MemberType "NoteProperty" -Name "User" -Value $ProcessUser -PassThru

                $Resolved = Resolve-ModuleSearchPath -Name $Process.Name -Extension ".exe"
                if ($Resolved) {
                    $Result.Path = $Resolved
                }

                $Results += $Result
            }
        }
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
    $Result
}

function Invoke-RootFolderPermissionCheck {

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $IgnoredRootFolders = @( "`$Recycle.Bin", "`$WinREAgent", "Documents and Settings", "PerfLogs", "Program Files", "Program Files (x86)", "ProgramData", "Recovery", "System Volume Information", "Users", "Windows", "Windows.old" )
    }

    process {
        $Results = @()

        # List all "fixed" drives.
        # From: https://superuser.com/a/787643
        $FixedDrives = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' }
        foreach ($FixedDrive in $FixedDrives) {

            # For each fixed drive, list the root folders. Here, we also use the option
            # -Force to specify that we want to include hidden ones. The resulting list
            # is then filtered to exclude known folders such as "C:\Windows".
            $RootFolders = Get-ChildItem -Path $FixedDrive -Force -ErrorAction SilentlyContinue | Where-Object { ($_ -is [System.IO.DirectoryInfo]) -and ($IgnoredRootFolders -notcontains $_.Name) }
            if ($null -eq $RootFolders) { continue }

            $Candidates = $RootFolders | Select-Object -ExpandProperty "Fullname"
            $ProgressCount = 0
            Write-Progress -Activity "Checking root folder permissions (0/$($Candidates.Count))..." -Status "0% Complete:" -PercentComplete 0
            foreach ($Candidate in $Candidates) {
                $ProgressPercent = [UInt32] ($ProgressCount * 100 / $Candidates.Count)
                Write-Progress -Activity "Checking root folder permissions ($($ProgressCount)/$($Candidates.Count)): $($Candidate)" -Status "$($ProgressPercent)% Complete:" -PercentComplete $ProgressPercent
                Get-ModifiableRootFolder -Path $Candidate | ForEach-Object {
                    $Results += $_
                }
                $ProgressCount += 1
            }
            Write-Progress -Activity "Checking root folder permissions ($($Candidates.Count)/$($Candidates.Count))..." -Status "100% Complete:" -Completed
        }

        $Vulnerable = ([object[]]($Results | Where-Object { $_.Vulnerable })).Count -gt 0

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}