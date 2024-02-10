function Invoke-InstalledProgramsCheck {
    <#
    .SYNOPSIS
    Enumerates the applications that are not installed by default

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Uses the custom "Get-InstalledPrograms" function to get a filtered list of installed programs and then returns each result as a simplified PS object, indicating the name and the path of the application.

    .EXAMPLE
    PS C:\> Invoke-InstalledProgramsCheck | ft

    Name            FullPath
    ----            --------
    Npcap           C:\Program Files\Npcap
    Wireshark       C:\Program Files\Wireshark
    #>

    [CmdletBinding()] Param()

    Get-InstalledPrograms -Filtered | Select-Object -Property Name,FullName
}

function Invoke-ProgramsInDriveRootCheck {
    <#
    .SYNOPSIS
    Identifies modifiable folders in the roots of fixed drives. Append ACE's are inherited by default from the drive that can allow DLL hijacking when executable files are stored in such insecure locations.

    Author: buherator
    License: BSD 3-Clause

    .DESCRIPTION
    For each fixed drive enumerates first level directories that are modifiable by the current user.

    .EXAMPLE
    PS C:\> Invoke-ProgramsInDriveRootCheck | ft

    ModifiablePath                      IdentityReference    Permissions
    --------------                      -----------------    -----------
    C:\Install                          BUILTIN\Users        AddSubdirectory
    C:\Install                          BUILTIN\Users        AddFile
    #>

    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )

    PROCESS {
        $ArrayOfResults = @()

        $FixedDrives = [System.IO.DriveInfo]::getdrives() | Where-Object {$_.DriveType -eq 'Fixed'} # From: https://superuser.com/a/787643
        $IgnoredRootFolders = @("Windows", "Users", "Program Files", "Program Files (x86)", "PerfLogs")
        
        foreach($Drive in $FixedDrives){
            Get-ChildItem -Path $Drive -Depth 0 -ErrorAction SilentlyContinue | ForEach-Object { 
                if ($_ -is [System.IO.DirectoryInfo] -and (-not ($IgnoredRootFolders -contains $_.Name))) {
                    $FullPath = Join-Path -Path $Drive -ChildPath $_
                    $ModifiablePaths = $FullPath | Get-ModifiablePath -LiteralPaths
                    foreach($Path in $ModifiablePaths){
                        $Path.Permissions = ($Path.Permissions -join ', ')
                        $ArrayOfResults += $Path
                    }
                }    
            }
        }
        
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
}

function Invoke-ModifiableProgramsCheck {
    <#
    .SYNOPSIS
    Identifies applications which have a modifiable EXE of DLL file

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    For each non-default application, enumerates the .exe and .dll files that the current user has modify permissions on.

    .EXAMPLE
    PS C:\> Invoke-ModifiableProgramsCheck | ft

    ModifiablePath                      IdentityReference    Permissions
    --------------                      -----------------    -----------
    C:\Program Files\VulnApp\Packages   DESKTOP-FEOHNOM\user {WriteOwner, Delete, WriteAttributes, Synchronize...}
    C:\Program Files\VulnApp\app.exe    DESKTOP-FEOHNOM\user {WriteOwner, Delete, WriteAttributes, Synchronize...}
    C:\Program Files\VulnApp\foobar.dll DESKTOP-FEOHNOM\user {WriteOwner, Delete, WriteAttributes, Synchronize...}
    #>

    [CmdletBinding()] Param(
        [UInt32] $BaseSeverity
    )

    PROCESS {
        $Items = Get-InstalledPrograms -Filtered
        $ArrayOfResults = @()

        $FsRedirectionValue = Disable-Wow64FileSystemRedirection

        foreach ($Item in $Items) {
    
            # Ensure the path is not a known system folder, in which case it does not make
            # sense to check it. This also prevents the script from spending a considerable
            # amount of time and resources searching those paths recursively.
            if (Test-IsSystemFolder -Path $Item.FullName) {
                Write-Warning "System path detected, ignoring: $($Item.FullName)"
                continue
            }
    
            # Build the search path list. The following trick is used to search recursively
            # without using the 'Depth' option, which is only available in PSv5+. This
            # allows us to maintain compatibility with PSv2.
            $SearchPath = New-Object -TypeName System.Collections.ArrayList
            [void]$SearchPath.Add([String]$(Join-Path -Path $Item.FullName -ChildPath "\*"))
            [void]$SearchPath.Add([String]$(Join-Path -Path $Item.FullName -ChildPath "\*\*"))
    
            Get-ChildItem -Path $SearchPath -ErrorAction SilentlyContinue | ForEach-Object {
    
                if ($_ -is [System.IO.DirectoryInfo]) {
                    $ModifiablePaths = $_ | Get-ModifiablePath -LiteralPaths
                }
                else {
                    # Check only .exe and .dll ???
                    # TODO: maybe consider other extensions
                    if ($_.FullName -Like "*.exe" -or $_.FullName -Like "*.dll") {
                        $ModifiablePaths = $_ | Get-ModifiablePath -LiteralPaths
                    }
                }

                foreach ($Path in $ModifiablePaths) {
                    if ($Path.ModifiablePath -eq $_.FullName) {
                        $Path.Permissions = ($Path.Permissions -join ', ')
                        $ArrayOfResults += $Path
                    }
                }
            }
        }

        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
        $Result
    }
}

function Invoke-ProgramDataCheck {
    <#
    .SYNOPSIS
    Checks for modifiable files and folders under non default ProgramData folders.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This script first lists all the subfolders under 'C:\ProgramData\'. For each folder that is not a "known" default Windows folder, it lists all the files and folders it contains. If a modifiable file or folder is found, it is reported by the script.

    .EXAMPLE
    PS C:\> Invoke-ProgramDataCheck

    ModifiablePath    : C:\ProgramData\chocolatey\logs
    IdentityReference : BUILTIN\Users
    Permissions       : {WriteAttributes, Synchronize, AppendData/AddSubdirectory, WriteExtendedAttributes...}

    ModifiablePath    : C:\ProgramData\chocolatey\logs\choco.summary.log
    IdentityReference : BUILTIN\Users
    Permissions       : {WriteAttributes, Synchronize, AppendData/AddSubdirectory, WriteExtendedAttributes...}

    ModifiablePath    : C:\ProgramData\chocolatey\logs\chocolatey.log
    IdentityReference : BUILTIN\Users
    Permissions       : {WriteAttributes, Synchronize, AppendData/AddSubdirectory, WriteExtendedAttributes...}

    ModifiablePath    : C:\ProgramData\shimgen\generatedfiles
    IdentityReference : BUILTIN\Users
    Permissions       : {WriteAttributes, AppendData/AddSubdirectory, WriteExtendedAttributes, WriteData/AddFile}

    ModifiablePath    : C:\ProgramData\VMware\logs
    IdentityReference : BUILTIN\Users
    Permissions       : {WriteAttributes, AppendData/AddSubdirectory, WriteExtendedAttributes, WriteData/AddFile}
    #>

    [CmdletBinding()] Param()

    $IgnoredProgramData = @("Microsoft", "Microsoft OneDrive", "Package Cache", "Packages", "SoftwareDistribution", "ssh", "USOPrivate", "USOShared", "")

    Get-ChildItem -Path $env:ProgramData | ForEach-Object {

        if ($_ -is [System.IO.DirectoryInfo] -and (-not ($IgnoredProgramData -contains $_.Name))) {

            $_ | Get-ChildItem -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {

                $_ | Get-ModifiablePath -LiteralPaths | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
            }
        }
    }
}

function Invoke-ApplicationsOnStartupCheck {
    <#
    .SYNOPSIS
    Enumerates the applications which are run on startup

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Applications can be run on startup or whenever a user logs on. They can be either configured in the registry or by adding an shortcut file (.LNK) in a Start Menu folder.

    .PARAMETER Info
    Report all start-up applications, whether or not the application path is vulnerable.

    .EXAMPLE
    PS C:\> Invoke-ApplicationsOnStartupCheck

    Name         : SecurityHealth
    Path         : HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SecurityHealth
    Data         : %windir%\system32\SecurityHealthSystray.exe
    IsModifiable : False

    Name         : VMware User Process
    Path         : HKLM\Software\Microsoft\Windows\CurrentVersion\Run\VMware User Process
    Data         : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
    IsModifiable : False
    #>

    [CmdletBinding()] Param(
        [switch] $Info = $false,
        [UInt32] $BaseSeverity
    )

    begin {
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        $ArrayOfResults = @()

        [string[]]$RegistryPaths = "HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    
        $RegistryPaths | ForEach-Object {
    
            $RegKeyPath = $_
    
            $Item = Get-Item -Path "Registry::$($RegKeyPath)" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItem
            if (-not $ErrorGetItem) {
    
                $Values = $Item | Select-Object -ExpandProperty Property
                foreach ($Value in $Values) {
    
                    $RegKeyValueName = $Value
                    $RegKeyValueData = $Item.GetValue($RegKeyValueName, "", "DoNotExpandEnvironmentNames")
    
                    if ([String]::IsNullOrEmpty($RegKeyValueData)) { continue }
    
                    $ModifiablePaths = $RegKeyValueData | Get-ModifiablePath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                    if (([Object[]]$ModifiablePaths).Length -gt 0) {
                        $IsModifiable = $true
                    }
                    else {
                        $IsModifiable = $false
                    }
    
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegKeyValueName
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value "$($RegKeyPath)\$($RegKeyValueName)"
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegKeyValueData
                    $Result | Add-Member -MemberType "NoteProperty" -Name "IsModifiable" -Value $IsModifiable
    
                    if ($Info) { $Result; continue } # If Info, report directly and inspect the next value
                    if ($IsModifiable) { $ArrayOfResults += $Result } # If vulnerable, report
                }
            }
        }
    
        $Root = (Get-Item -Path $env:windir).PSDrive.Root
    
        # We want to check only startup applications that affect all users
        [string[]]$FileSystemPaths = "\Users\All Users\Start Menu\Programs\Startup"
    
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
    
                        $ModifiablePaths = $Shortcut.TargetPath | Get-ModifiablePath -LiteralPaths | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                        if (([Object[]]$ModifiablePaths).Length -gt 0) {
                            $IsModifiable = $true
                        }
                        else {
                            $IsModifiable = $false
                        }
    
                        $Result = New-Object -TypeName PSObject
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $EntryName
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $EntryPath
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value "$($Shortcut.TargetPath) $($Shortcut.Arguments)"
                        $Result | Add-Member -MemberType "NoteProperty" -Name "IsModifiable" -Value $IsModifiable
    
                        if ($Info) { $Result; continue } # If Info, report directly and inspect the next value
                        if ($IsModifiable) { $ArrayOfResults += $Result } # If vulnerable, report
                    }
                    catch {
                        Write-Warning "$($MyInvocation.MyCommand) [ Failed to create Shortcut object from path: $($EntryPath)"
                    }
                }
            }
        }
    
        if (-not $Info) {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $ArrayOfResults
            $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($ArrayOfResults) { $BaseSeverity } else { $SeverityLevelEnum::None })
            $Result
        }
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

    .EXAMPLE
    PS C:\> Invoke-RunningProcessCheck | ft

    Name                   PID User Path SessionId
    ----                   --- ---- ---- ---------
    cmd                   4224 N/A               1
    conhost               5336 N/A               1
    ctfmon                7436 N/A               1
    dllhost               3584 N/A               0
    dllhost               4172 N/A               1
    fontdrvhost            860 N/A               0
    fontdrvhost            928 N/A               1
    lsass                  732 N/A               0
    MsMpEng               3524 N/A               0
    MsMpEngCP             1132 N/A               0
    NisSrv                4256 N/A               0
    regedit               8744 N/A               1
    SearchFilterHost      9360 N/A               0
    SearchIndexer          596 N/A               0
    SearchProtocolHost      32 N/A               0
    SecurityHealthService 7980 N/A               0
    SgrmBroker            9512 N/A               0
    spoolsv               2416 N/A               0
    TabTip                7456 N/A               1
    wininit                564 N/A               0
    winlogon               676 N/A               1
    WmiPrvSE              3972 N/A               0
    #>

    [CmdletBinding()] Param(
        [switch] $Self = $false
    )

    $CurrentUser = $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

    # csrss -> Client/Server Runtime Subsystem
    # dwm -> Desktop Window Manager
    # msdtc -> Microsoft Distributed Transaction Coordinator
    # smss -> Session Manager Subsystem
    # svchost -> Service Host
    $IgnoredProcessNames = @("Idle", "services", "Memory Compression", "TrustedInstaller", "PresentationFontCache", "Registry", "ServiceShell", "System", "csrss", "dwm", "msdtc", "smss", "svchost")

    $AllProcess = Get-Process

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