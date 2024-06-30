function Get-RemoteDesktopUserSessionList {
    <#
    .SYNOPSIS
    List the sessions of the currently logged-on users through the WTS API.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet simply invokes the WTSEnumerateSessionsEx API to enumerate the sessions of the logged-on users. This API returns a list of TS_SESSION_INFO_1W structures containing the sessions info.

    .EXAMPLE
    PS C:\> Get-RemoteDesktopUserSessionList

    ExecEnvId   : 0
    State       : Disconnected
    SessionId   : 0
    SessionName : Services
    HostName    :
    UserName    :
    DomainName  :
    FarmName    :

    ExecEnvId   : 1
    State       : Active
    SessionId   : 1
    SessionName : Console
    HostName    :
    UserName    : lab-user
    DomainName  : DESKTOP-U7FQ7U5
    FarmName    :
    #>

    [CmdletBinding()]
    param()

    $Level = 1
    $SessionInfoListPtr = [IntPtr] 0
    $SessionInfoCount = [UInt32] 0

    $Success = $script:Wtsapi32::WTSEnumerateSessionsEx(0, [ref] $Level, 0, [ref] $SessionInfoListPtr, [ref] $SessionInfoCount)
    Write-Verbose "WTSEnumerateSessionsEx: $($Success) | Count: $($SessionInfoCount) | List: 0x$('{0:x16}' -f [Int64] $SessionInfoListPtr)"

    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "WTSEnumerateSessionsEx - $([ComponentModel.Win32Exception] $LastError)"
        return
    }

    $SessionInfoPtr = $SessionInfoListPtr
    for ($i = 0; $i -lt $SessionInfoCount; $i++) {

        $SessionInfo = [Runtime.InteropServices.Marshal]::PtrToStructure($SessionInfoPtr, [type] $script:WTS_SESSION_INFO_1W)
        $SessionInfo

        $SessionInfoPtr = [IntPtr] ($SessionInfoPtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([type] $script:WTS_SESSION_INFO_1W))
    }

    $Success = $script:Wtsapi32::WTSFreeMemoryEx(2, $SessionInfoListPtr, $SessionInfoCount)
    Write-Verbose "WTSFreeMemoryEx: $($Success)"

    if (-not $Success) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Verbose "WTSFreeMemoryEx - $([ComponentModel.Win32Exception] $LastError)"
        return
    }
}

function Invoke-SystemInformationCheck {
    <#
    .SYNOPSIS
    Gets the name of the operating system and the full version string.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Reads the "Product Name" from the registry and gets the full version string based on the operating system.

    .EXAMPLE
    Invoke-SystemInformationCheck | fl

    Name    : Windows 10 Home
    Version : 10.0.18363 Version 1909 (18363.535)
    .LINK
    https://techthoughts.info/windows-version-numbers/
    #>

    [CmdletBinding()]
    param()

    $OsVersion = Get-WindowsVersion

    if ($null -eq $OsVersion) { return }

    if ($OsVersion.Major -ge 10) {
        $OsVersionStr = "$($OsVersion.Major).$($OsVersion.Minor).$($OsVersion.Build) Version $($OsVersion.ReleaseId) ($($OsVersion.Build).$($OsVersion.UBR))"
    }
    else {
        $OsVersionStr = "$($OsVersion.Major).$($OsVersion.Minor).$($OsVersion.Build) N/A Build $($OsVersion.Build)"
    }

    # Windows 11 has the same version number as Windows 10. To differentiate them,
    # we can use the build version though. According to Microsoft, if the build
    # version is greater than 22000, it is Windows 11.
    $ProductName = $OsVersion.ProductName
    if (($OsVersion.Major -ge 10) -and ($OsVersion.Build -ge 22000)) {
        $ProductName = $ProductName -replace "Windows 10","Windows 11"
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $ProductName
    $Result | Add-Member -MemberType "NoteProperty" -Name "Version" -Value $OsVersionStr
    $Result
}

function Invoke-SystemStartupHistoryCheck {
    <#
    .SYNOPSIS
    Gets a list of all the system startup events which occurred in the given time span.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    It uses the Event Log to get a list of all the events that indicate a system startup. The start event of the Event Log service is used as a reference.

    .PARAMETER TimeSpanInDays
    An optional parameter indicating the time span to check in days. e.g.: check the last 31 days.

    .EXAMPLE
    PS C:\> Invoke-SystemStartupHistoryCheck

    Index Time
    ----- ----
         1 2020-01-11 - 21:36:59
         2 2020-01-08 - 08:45:01
         3 2020-01-07 - 11:45:43
         4 2020-01-06 - 14:43:41
         5 2020-01-05 - 23:07:41
         6 2020-01-05 - 11:41:39
         7 2020-01-04 - 14:18:46
         8 2020-01-04 - 14:18:10
         9 2020-01-04 - 12:51:51
        10 2020-01-03 - 10:41:15
        11 2019-12-27 - 13:57:30
        12 2019-12-26 - 10:56:38
        13 2019-12-25 - 12:12:14
        14 2019-12-24 - 17:41:04

    .NOTES
    Event ID 6005: The Event log service was started, i.e. system startup theoretically.
    #>

    [CmdletBinding()]
    param(
        [Int] $TimeSpanInDays = 31
    )

    try {
        $SystemStartupHistoryResult = New-Object -TypeName System.Collections.ArrayList

        $StartDate = (Get-Date).AddDays(-$TimeSpanInDays)
        $EndDate = Get-Date

        $StartupEvents = Get-EventLog -LogName "System" -EntryType "Information" -After $StartDate -Before $EndDate | Where-Object { $_.EventID -eq 6005 }

        $EventNumber = 1

        foreach ($Event in $StartupEvents) {

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Index" -Value $EventNumber
            $Result | Add-Member -MemberType "NoteProperty" -Name "Time" -Value "$(Convert-DateToString -Date $Event.TimeGenerated)"

            [void] $SystemStartupHistoryResult.Add($Result)
            $EventNumber += 1
        }

        $SystemStartupHistoryResult | Select-Object -First 10
    }
    catch {
        # We might get an "access denied"
        Write-Verbose "Error while querying the Event Log."
    }
}

function Invoke-SystemDriveCheck {
    <#
    .SYNOPSIS
    Gets a list of local drives and network shares that are currently mapped

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function is a wrapper for the "Get-PSDrive" standard cmdlet. For each result returned by "Get-PSDrive", a custom PS object is returned, indicating the drive letter (if applicable), the display name (if applicable) and the description.

    .EXAMPLE
    PS C:\> Invoke-SystemDriveCheck

    Root DisplayRoot Description
    ---- ----------- -----------
    C:\              OS
    E:\              DATA
    #>

    [CmdletBinding()]
    param()

    $Drives = Get-PSDrive -PSProvider "FileSystem"

    foreach ($Drive in $Drives) {
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Root" -Value "$($Drive.Root)"
        $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayRoot" -Value "$($Drive.DisplayRoot)"
        $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "$($Drive.Description)"
        $Result
    }
}

function Invoke-LocalAdminGroupCheck {
    <#
    .SYNOPSIS
    Enumerates the members of the default local admin group

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    For every member of the local admin group, it will check whether it's a local/domain user/group. If it's local it will also check if the account is enabled.

    .EXAMPLE
    PS C:\> Invoke-LocalAdminGroupCheck

    Name          Type IsLocal IsEnabled
    ----          ---- ------- ---------
    Administrator User    True     False
    lab-admin     User    True      True

    .NOTES
    S-1-5-32-544 = SID of the local admin group
    #>

    [CmdletBinding()]
    param()

    $LocalAdminGroupFullname = ([Security.Principal.SecurityIdentifier]"S-1-5-32-544").Translate([Security.Principal.NTAccount]).Value
    $LocalAdminGroupName = $LocalAdminGroupFullname.Split('\')[1]
    Write-Verbose "Admin group name: $LocalAdminGroupName"

    $AdsiComputer = [ADSI]("WinNT://$($env:COMPUTERNAME),computer")

    try {
        $LocalAdminGroup = $AdsiComputer.psbase.children.find($LocalAdminGroupName, "Group")

        if ($LocalAdminGroup) {

            foreach ($LocalAdminGroupMember in $LocalAdminGroup.psbase.invoke("members")) {

                $MemberName = $LocalAdminGroupMember.GetType().InvokeMember("Name", 'GetProperty', $null, $LocalAdminGroupMember, $null)
                Write-Verbose "Found an admin member: $MemberName"

                $Member = $AdsiComputer.Children | Where-Object { (($_.SchemaClassName -eq "User") -or ($_.SchemaClassName -eq "Group")) -and ($_.Name -eq $MemberName) }

                if ($Member) {

                    if ($Member.SchemaClassName -eq "User") {
                        $UserFlags = $Member.UserFlags.value
                        $MemberIsEnabled = -not $($UserFlags -band $script:ADS_USER_FLAGS::AccountDisable)
                        $MemberType = "User"
                        $MemberIsLocal = $true
                    }
                    elseif ($Member.SchemaClassName -eq "Group") {
                        $GroupType = $Member.GroupType.value
                        $MemberIsLocal = $($GroupType -band $script:GROUP_TYPE_FLAGS::ResourceGroup)
                        $MemberType = "Group"
                        $MemberIsEnabled = $true
                    }
                }
                else {

                    $MemberType = ""
                    $MemberIsLocal = $false
                    $MemberIsEnabled = $null
                }

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $MemberName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $MemberType
                $Result | Add-Member -MemberType "NoteProperty" -Name "IsLocal" -Value $MemberIsLocal
                $Result | Add-Member -MemberType "NoteProperty" -Name "IsEnabled" -Value $MemberIsEnabled
                $Result
            }
        }
    }
    catch {
        Write-Verbose "$($_.Exception)"
    }
}

function Invoke-UserHomeFolderCheck {
    <#
    .SYNOPSIS
    Enumerates the local user home folders.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Enumerates the folders located in C:\Users\. For each one, this function checks whether the folder is readable and/or writable by the current user.

    .EXAMPLE
    PS C:\> Invoke-UserHomeFolderCheck

    HomeFolderPath         Read Write
    --------------         ---- -----
    C:\Users\Lab-Admin    False False
    C:\Users\Lab-User      True  True
    C:\Users\Public        True  True
    #>

    [CmdletBinding()]
    param()

    $UsersHomeFolder = Join-Path -Path $((Get-Item $env:windir).Root) -ChildPath Users

    foreach ($HomeFolder in $(Get-ChildItem -Path $UsersHomeFolder)) {

        $FolderPath = $HomeFolder.FullName
        $ReadAccess = $false
        $WriteAccess = $false

        $ChildItems = Get-ChildItem -Path $FolderPath -ErrorAction SilentlyContinue
        if ($ChildItems) {
            $ReadAccess = $true
            if ([String]::IsNullOrEmpty($FolderPath)) { continue }
            $ModifiablePaths = Get-ModifiablePath -Path $FolderPath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
            if ($ModifiablePaths) { $WriteAccess = $true }
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "HomeFolderPath" -Value $FolderPath
        $Result | Add-Member -MemberType "NoteProperty" -Name "Read" -Value $ReadAccess
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $WriteAccess
        $Result
    }
}

function Invoke-MachineRoleCheck {
    <#
    .SYNOPSIS
    Gets the role of the machine (workstation, server, domain controller)

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    The role of the machine can be checked by reading the following registry key: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions. The "ProductType" value represents the role of the machine.

    .EXAMPLE
    PS C:\> Invoke-MachineRoleCheck

    Name  Role
    ----  ----
    WinNT WorkStation

    .NOTES
    WinNT = workstation
    LanmanNT = domain controller
    ServerNT = server
    #>

    [CmdletBinding()]
    param()

    Get-MachineRole
}

function Invoke-EndpointProtectionCheck {
    <#
    .SYNOPSIS
    Gets a list of security software products

    .DESCRIPTION
    This check was inspired by the script Invoke-EDRChecker.ps1 (PwnDexter). It enumerates the DLLs that are loaded in the current process, the processes that are currently running, the installed applications and the installed services. For each one of these entries, it extracts some metadata and checks whether it contains some known strings related to a given security software product. If there is a match, the corresponding entry is returned along with the data that was matched.

    .EXAMPLE
    PS C:\> Invoke-EndpointProtectionCheck

    ProductName      Source                Pattern
    -----------      ------                -------
    AMSI             Loaded DLL            FileName=C:\Windows\SYSTEM32\amsi.dll
    AMSI             Loaded DLL            InternalName=amsi.dll
    AMSI             Loaded DLL            OriginalFilename=amsi.dll
    ...
    Windows Defender Service               RegistryKey=HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService
    Windows Defender Service               RegistryPath=Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService
    Windows Defender Service               DisplayName=@C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe,-1001
    Windows Defender Service               ImagePath="C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"
    Windows Defender Service               DisplayName=@C:\Program Files\Windows Defender\MpAsDesc.dll,-390
    Windows Defender Service               DisplayName=@C:\Program Files\Windows Defender\MpAsDesc.dll,-330
    Windows Defender Service               DisplayName=@C:\Program Files\Windows Defender\MpAsDesc.dll,-370
    Windows Defender Service               DisplayName=@C:\Program Files\Windows Defender\MpAsDesc.dll,-320
    Windows Defender Service               ImagePath="C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2008.9-0\NisSrv.exe"
    Windows Defender Service               DisplayName=@C:\Program Files\Windows Defender\MpAsDesc.dll,-310
    Windows Defender Service               ImagePath="C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2008.9-0\MsMpEng.exe"

    .NOTES
    Credit goes to PwnDexter: https://github.com/PwnDexter/Invoke-EDRChecker
    #>

    [CmdletBinding()]
    param()

    $Signatures = @{
        "AMSI"                          = "amsi.dll"
        "AppSense"                      = "emcoreservice,emsystem,watchdogagent"
        "Avast"                         = "avast"
        "Avecto Defendpoint"            = "avecto,defendpoint,pgeposervice,pgsystemtray,privilegeguard"
        "Carbon Black"                  = "carbon,cb.exe,logrhythm"
        "Cisco AMP"                     = "ciscoamp"
        "CounterTack"                   = "countertack"
        "CrowdStrike"                   = "crowdstrike,csagent,csfalcon,csshell,windowssensor"
        "Cybereason"                    = "activeconsole,cramtray,crssvc,cybereason"
        "Cylance"                       = "cylance,cyoptics,cyupdate"
        "Endgame"                       = "endgame"
        "ESET Endpoint Inspector"       = "inspector"
        "eTrust EZ AV"                  = "groundling"
        "FireEye"                       = "fireeye,mandiant,xagt"
        "ForeScout"                     = "forescout,secureconnector"
        "IBM QRadar"                    = "qradar,wincollect"
        "Ivanti"                        = "ivanti"
        "Kaspersky"                     = "kaspersky"
        "Lacuna"                        = "lacuna"
        "McAfee"                        = "mcafee"
        "Morphisec"                     = "morphisec"
        "Program Protector"             = "protectorservice"
        "Red Canary"                    = "canary"
        "Red Cloak"                     = "procwall,redcloak,cyclorama"
        "SentinelOne"                   = "sentinel"
        "Sophos"                        = "sophos"
        "Symantec Endpoint Protection"  = "eectrl,semlaunchsvc,sepliveupdate,sisidsservice,sisipsservice,sisipsutil,smc.exe,smcgui,snac64,srtsp,symantec,symcorpui,symefasi"
        "Sysinternals Antivirus"        = "sysinternal"
        "Sysinternals Sysmon"           = "sysmon"
        "Tanium Enforce"                = "tanium,tpython"
        "Traps"                         = "cyvera,cyserver,cytray,PaloAltoNetworks,tda.exe,tdawork"
        "Trend Micro"                   = "ntrtscan,tmlisten,tmbmsrv,tmssclient,tmccsf,trend"
        "Windows Defender"              = "defender,msascuil,msmpeng,nissrv,securityhealthservice"
    }

    function Find-ProtectionSoftware {

        param(
            [Object] $Object
        )

        $Signatures.Keys | ForEach-Object {

            $ProductName = $_
            $ProductSignatures = $Signatures.Item($_).Split(",")

            $Object | Select-String -Pattern $ProductSignatures -AllMatches | ForEach-Object {

                $($_ -Replace "@{").Trim("}").Split(";") | ForEach-Object {

                    $_.Trim() | Select-String -Pattern $ProductSignatures -AllMatches | ForEach-Object {

                        $Result = New-Object -TypeName PSObject
                        $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value "$ProductName"
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Pattern" -Value "$($_)"
                        $Result
                    }
                }
            }
        }
    }

    # Need to store all the results into one ArrayList so we can sort them on the product name.
    $Results = New-Object System.Collections.ArrayList

    # Check DLLs loaded in the current process
    Get-Process -Id $PID -Module | ForEach-Object {

        if (Test-Path -Path $_.FileName) {

            $DllDetails = (Get-Item $_.FileName).VersionInfo | Select-Object -Property CompanyName,FileDescription,FileName,InternalName,LegalCopyright,OriginalFileName,ProductName
            Find-ProtectionSoftware -Object $DllDetails | ForEach-Object {

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value "$($_.ProductName)"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Source" -Value "Loaded DLL"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Pattern" -Value "$($_.Pattern)"
                [void] $Results.Add($Result)
            }
        }
    }

    # Check running processes
    Get-Process | Select-Object -Property ProcessName,Name,Path,Company,Product,Description | ForEach-Object {

        Find-ProtectionSoftware -Object $_ | ForEach-Object {

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value "$($_.ProductName)"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Source" -Value "Running process"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Pattern" -Value "$($_.Pattern)"
            [void] $Results.Add($Result)
        }
    }

    # Check installed applications
    Get-InstalledProgram | Select-Object -Property Name | ForEach-Object {

        Find-ProtectionSoftware -Object $_ | ForEach-Object {

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value "$($_.ProductName)"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Source" -Value "Installed application"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Pattern" -Value "$($_.Pattern)"
            [void] $Results.Add($Result)
        }
    }

    # Check installed services
    Get-ServiceList -FilterLevel 1 | ForEach-Object {

        Find-ProtectionSoftware -Object $_ | ForEach-Object {

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value "$($_.ProductName)"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Source" -Value "Service"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Pattern" -Value "$($_.Pattern)"
            [void] $Results.Add($Result)
        }
    }

    $Results | Sort-Object -Property ProductName,Source
}

function Invoke-HijackableDllCheck {
    <#
    .SYNOPSIS
    Lists hijackable DLLs depending on the version of the OS

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    On Windows, some services load DLLs without using a "secure" search path. Therefore, they try to load them from the folders listing in the %PATH% environment variable. If one of these folders is configured with weak permissions, a local attacker may plant a malicious version of a DLL in order to execute arbitrary code in the context of the service.

    .EXAMPLE
    PS C:\> Invoke-HijackableDllCheck

    Name           : cdpsgshims.dll
    Description    : Loaded by CDPSvc upon service startup
    RunAs          : NT AUTHORITY\LOCAL SERVICE
    RebootRequired : True

    .EXAMPLE
    PS C:\> Invoke-HijackableDllCheck

    Name           : windowsperformancerecordercontrol.dll
    Description    : Loaded by DiagTrack upon service startup or shutdown
    RunAs          : NT AUTHORITY\SYSTEM
    RebootRequired : True

    Name           : diagtrack_win.dll
    Description    : Loaded by DiagTrack upon service startup
    RunAs          : NT AUTHORITY\SYSTEM
    RebootRequired : True

    Name           : wlbsctrl.dll
    Description    : Loaded by IKEEXT upon service startup
    RunAs          : NT AUTHORITY\SYSTEM
    RebootRequired : True

    Name           : wlanhlp.dll
    Description    : Loaded by NetMan when listing network interfaces
    RunAs          : NT AUTHORITY\SYSTEM
    RebootRequired : False

    .LINK
    https://www.reddit.com/r/hacking/comments/b0lr05/a_few_binary_plating_0days_for_windows/
    #>

    [CmdletBinding()]
    param()

    function Test-DllExistence {

        [OutputType([Boolean])]
        [CmdletBinding()]
        param(
            [String] $Name
        )

        $WindowsDirectories = New-Object System.Collections.ArrayList
        [void] $WindowsDirectories.Add($(Join-Path -Path $env:windir -ChildPath "System32"))
        [void] $WindowsDirectories.Add($(Join-Path -Path $env:windir -ChildPath "SysNative"))
        [void] $WindowsDirectories.Add($(Join-Path -Path $env:windir -ChildPath "System"))
        [void] $WindowsDirectories.Add($env:windir)

        foreach ($WindowsDirectory in [String[]] $WindowsDirectories) {
            $Path = Join-Path -Path $WindowsDirectory -ChildPath $Name
            $null = Get-Item -Path $Path -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItem
            if (-not $ErrorGetItem) {
                return $true
            }
        }
        return $false
    }

    function Test-HijackableDll {

        [CmdletBinding()]
        param (
            [String] $ServiceName,
            [String] $DllName,
            [String] $Description,
            [Boolean] $RebootRequired = $true,
            [String] $Link
        )

        $Service = Get-ServiceFromRegistry -Name $ServiceName
        if ($Service -and ($Service.StartMode -ne "Disabled")) {

            if (-not (Test-DllExistence -Name $DllName)) {

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $DllName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                $Result | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value $Service.User
                $Result | Add-Member -MemberType "NoteProperty" -Name "RebootRequired" -Value $RebootRequired
                $Result | Add-Member -MemberType "NoteProperty" -Name "Link" -Value $Link
                $Result
            }
        }
    }

    $OsVersion = Get-WindowsVersion

    # Windows 10, 11, ?
    if ($OsVersion.Major -ge 10) {
        Test-HijackableDll -ServiceName "CDPSvc" -DllName "cdpsgshims.dll" -Description "Loaded by the Connected Devices Platform Service (CDPSvc) upon startup." -Link "https://nafiez.github.io/security/eop/2019/11/05/windows-service-host-process-eop.html"
        Test-HijackableDll -ServiceName "Schedule" -DllName "WptsExtensions.dll" -Description "Loaded by the Task Scheduler service (Schedule) upon startup." -Link "http://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.html"
        Test-HijackableDll -ServiceName "StorSvc" -DllName "SprintCSP.dll" -Description "Loaded by the Storage Service (StorSvc) when the RPC procedure 'SvcRebootToFlashingMode' is invoked." -RebootRequired $false -Link "https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc"
    }

    # Windows 7, 8, 8.1
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 1) -and ($OsVersion.Minor -le 3)) {
        Test-HijackableDll -ServiceName "DiagTrack" -DllName "windowsperformancerecordercontrol.dll" -Description "Loaded by the Connected User Experiences and Telemetry service (DiagTrack) upon startup or shutdown." -Link "https://www.reddit.com/r/hacking/comments/b0lr05/a_few_binary_plating_0days_for_windows/"
        Test-HijackableDll -ServiceName "DiagTrack" -DllName "diagtrack_win.dll" -Description "Loaded by the Connected User Experiences and Telemetry service (DiagTrack) upon startup." -Link "https://www.reddit.com/r/hacking/comments/b0lr05/a_few_binary_plating_0days_for_windows/"
    }

    # Windows Vista, 7, 8
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 0) -and ($OsVersion.Minor -le 2)) {
        $RebootRequired = $true
        $Service = Get-Service -Name "IKEEXT" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetService
        if ((-not $ErrorGetService) -and ($Service.Status -eq "Stopped")) {
            $RebootRequired = $false
        }
        Test-HijackableDll -ServiceName "IKEEXT" -DllName "wlbsctrl.dll" -Description "Loaded by the IKE and AuthIP IPsec Keying Modules service (IKEEXT) upon startup." -RebootRequired $RebootRequired -Link "https://www.reddit.com/r/hacking/comments/b0lr05/a_few_binary_plating_0days_for_windows/"
    }

    # Windows 7
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -eq 1)) {
        Test-HijackableDll -ServiceName "NetMan" -DllName "wlanhlp.dll" -Description "Loaded by the Network Connections service (NetMan) when listing network interfaces." -RebootRequired $false -Link "https://itm4n.github.io/windows-server-netman-dll-hijacking/"
    }

    # Windows 8, 8.1, 10
    if (($OsVersion.Major -ge 10) -or (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 2) -and ($OsVersion.Minor -le 3))) {
        Test-HijackableDll -ServiceName "NetMan" -DllName "wlanapi.dll" -Description "Loaded by the Network Connections service (NetMan) when listing network interfaces." -RebootRequired $false -Link "https://itm4n.github.io/windows-server-netman-dll-hijacking/"
    }
}

function Invoke-NamedPipePermissionCheck {
    <#
    .SYNOPSIS
    List modifiable named pipes that are not owned by the current user.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    List modifiable named pipes that are not owned by the current user.

    .EXAMPLE
    An example
    #>

    [CmdletBinding()]
    param()

    $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $CurrentUserSids = Get-CurrentUserSid

    ForEach ($NamedPipe in $(Get-ChildItem -Path "\\.\pipe\")) {

        $NamedPipeDacl = Get-FileDacl -Path $NamedPipe.FullName

        if ($null -eq $NamedPipeDacl) { continue }

        if ($UserIdentity.User.Value -match $NamedPipeDacl.OwnerSid) { continue }

        if ($null -eq $NamedPipeDacl.Access) {

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Pipe" -Value $NamedPipe.FullName
            $Result | Add-Member -MemberType "NoteProperty" -Name "Owner" -Value $NamedPipeDacl.Owner
            # $Result | Add-Member -MemberType "NoteProperty" -Name "Group" -Value $NamedPipeDacl.Group
            $Result | Add-Member -MemberType "NoteProperty" -Name "AceType" -Value "AccessAllowed"
            $Result | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value "GenericAll"
            $Result | Add-Member -MemberType "NoteProperty" -Name "SecurityIdentifier" -Value "S-1-1-0"
            $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityName" -Value (Convert-SidToName -Sid "S-1-1-0")
            $Result
            continue
        }

        $PermissionReference = @(
            $script:FileAccessRightEnum::Delete,
            $script:FileAccessRightEnum::WriteDac,
            $script:FileAccessRightEnum::WriteOwner,
            $script:FileAccessRightEnum::FileWriteEa,
            $script:FileAccessRightEnum::FileWriteAttributes
        )

        ForEach ($Ace in $NamedPipeDacl.Access) {

            if ($Ace.AceType -notmatch "AccessAllowed") { continue }

            $Permissions = [Enum]::GetValues($script:FileAccessRightEnum) | Where-Object {
                ($Ace.AccessMask -band ($script:FileAccessRightEnum::$_)) -eq ($script:FileAccessRightEnum::$_)
            }

            if (Compare-Object -ReferenceObject $Permissions -DifferenceObject $PermissionReference -IncludeEqual -ExcludeDifferent) {

                $IdentityReference = $($Ace | Select-Object -ExpandProperty "SecurityIdentifier").ToString()

                if ($CurrentUserSids -contains $IdentityReference) {

                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Pipe" -Value $NamedPipe.FullName
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Owner" -Value $NamedPipeDacl.Owner
                    # $Result | Add-Member -MemberType "NoteProperty" -Name "Group" -Value $NamedPipeDacl.Group
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AceType" -Value ($Ace | Select-Object -ExpandProperty "AceType")
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value ($Ace.AccessMask -as $script:FileAccessRightEnum)
                    $Result | Add-Member -MemberType "NoteProperty" -Name "SecurityIdentifier" -Value $IdentityReference
                    $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityName" -Value (Convert-SidToName -Sid $IdentityReference)
                    $Result
                }
            }
        }
    }
}

function Invoke-UserSessionCheck {
    <#
    .SYNOPSIS
    List the the sessions of the currently logged-on users (similar to the command 'query session').

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This check is essentially a wrapper for the helper function Get-RemoteDesktopUserSessionList.

    .EXAMPLE
    PS C:\> Invoke-UserSessionCheck

    SessionName UserName              Id        State
    ----------- --------              --        -----
    Services                           0 Disconnected
    Console     SRV01\Administrator    1       Active
    RDP-Tcp#3   SANDBOX\Administrator  3       Active
    #>

    [CmdletBinding()]
    param()

    foreach ($Session in (Get-RemoteDesktopUserSessionList)) {

        if ([String]::IsNullOrEmpty($Session.UserName)) {
            $UserName = ""
        }
        else {
            if ([String]::IsNullOrEmpty($Session.DomainName)) {
                $UserName = $Session.UserName
            }
            else {
                $UserName = "$($Session.DomainName)\$($Session.UserName)"
            }
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "SessionName" -Value $Session.SessionName
        $Result | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $UserName
        $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $Session.SessionId
        $Result | Add-Member -MemberType "NoteProperty" -Name "State" -Value $Session.State
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
            "Process" = $script:ProcessAccessRightEnum::CREATE_PROCESS -bor $script:ProcessAccessRightEnum::CREATE_THREAD -bor $script:ProcessAccessRightEnum::DUP_HANDLE -bor $script:ProcessAccessRightEnum::VM_OPERATION -bor $script:ProcessAccessRightEnum::VM_READ -bor $script:ProcessAccessRightEnum::VM_WRITE
            "Thread" = $script:ThreadAccessRightEnum::DirectImpersonation -bor $script:ThreadAccessRightEnum::SetContext
            "File" = $script:FileAccessRightEnum::WriteData -bor $script:FileAccessRightEnum::AppendData -bor $script:FileAccessRightEnum::WriteOwner -bor $script:FileAccessRightEnum::WriteDac
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
                $ProcHandle = $script:Kernel32::OpenProcess($script:ProcessAccessRightEnum::DUP_HANDLE, $false, $ProcessId)
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
                Write-Warning "Failed to duplicate handle 0x$('{0:x}' -f $InheritedHandle.HandleValue) - $([ComponentModel.Win32Exception] $LastError)"
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
                    if ($HandleProcessId -eq 0) {
                        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetProcessId KO - $([ComponentModel.Win32Exception] $LastError)"
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
                    $CandidateHandle | Add-Member -MemberType "NoteProperty" -Name "TargetProcessAccessRights" -Value ($CandidateHandle.GrantedAccess -as $script:ProcessAccessRightEnum)
                    $ExploitableHandles += $CandidateHandle
                }
                "Thread" {
                    $TargetThreadId = $script:Kernel32::GetThreadId($InheritedHandleDuplicated)
                    if ($HandleThreadId -eq 0) {
                        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                        Write-Warning "GetThreadId KO - $([ComponentModel.Win32Exception] $LastError)"
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
                    $CandidateHandle | Add-Member -MemberType "NoteProperty" -Name "TargetThreadAccessRights" -Value ($CandidateHandle.GrantedAccess -as $script:ThreadAccessRightEnum)
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
                    $CandidateHandle | Add-Member -MemberType "NoteProperty" -Name "TargetFileAccessRights" -Value ($CandidateHandle.GrantedAccess -as $script:FileAccessRightEnum)
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
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
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

function Invoke-MsiCustomActionCheck {
    <#
    .SYNOPSIS
    Search for MSI files that run Custom Actions as SYSTEM.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet retrieves a list of cached MSI files and analyzes them to find potentially unsafe Custom Actions.

    .EXAMPLE
    PS C:\> Invoke-MsiCustomActionCheck
    ...
    Path              : C:\Windows\Installer\38896.msi
    IdentifyingNumber : 180E1C56-3A53-44D2-B300-ADC28A080515
    Name              : Online Plug-in
    Vendor            : Citrix Systems, Inc.
    Version           : 23.11.0.197
    AllUsers          : 1
    CandidateCount    : 15
    Candidates        : CA_FixCachedIcaWebWrapper; BackupAFDWindowSize; BackupAFDWindowSize_RB; BackupTcpIPWindowSize; BackupTcpIPWindowSize_RB; CallCtxCreatePFNRegKeyIfUpg; CtxModRegForceLAA; FixIniFile; HideCancelButton;
                        GiveUsersLicensingAccess; LogInstallTime; RestoreAFDWindowSize; RestorePassThroughKey; RestoreTcpIPWindowSize; SetTimestamps
    AnalyzeCommand    : Get-MsiFileItem -FilePath "C:\Windows\Installer\38896.msi" | Select-Object -ExpandProperty CustomActions | Where-Object { $_.Candidate }
    RepairCommand     : Start-Process -FilePath "msiexec.exe" -ArgumentList "/fa C:\Windows\Installer\38896.msi"
    ...
    #>

    [CmdletBinding()]
    param ()

    begin {
        $MsiItems = [object[]] (Get-MsiFileItem)
        $CandidateCount = 0
    }

    process {
        foreach ($MsiItem in $MsiItems) {

            Write-Verbose "Analyzing file: $($MsiItem.Path)"

            # If the MSI doesn't force the installation for all users (i.e., system-wide),
            # ignore it.
            if ($MsiItem.AllUsers -ne 1) { continue }

            # If the MSI doesn't have any Custom Action, ignore it.
            if ($null -eq $MsiItem.CustomActions) { continue }

            $CandidateCustomActions = [object[]] ($MsiItem.CustomActions | Where-Object { $_.Candidate -eq $true })

            # No interesting Custom Action found, ignore it.
            if ($CandidateCustomActions.Count -eq 0) { continue }

            $CandidateCount += 1

            $AnalyzeCommand = "Get-MsiFileItem -FilePath `"$($MsiItem.Path)`" | Select-Object -ExpandProperty CustomActions | Where-Object { `$_.Candidate }"
            $RepairCommand = "Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/fa $($MsiItem.Path)`""

            $MsiItem | Add-Member -MemberType "NoteProperty" -Name "CandidateCount" -Value $CandidateCustomActions.Count
            $MsiItem | Add-Member -MemberType "NoteProperty" -Name "Candidates" -Value "$(($CandidateCustomActions | Select-Object -ExpandProperty "Action") -join "; ")"
            $MsiItem | Add-Member -MemberType "NoteProperty" -Name "AnalyzeCommand" -Value $AnalyzeCommand
            $MsiItem | Add-Member -MemberType "NoteProperty" -Name "RepairCommand" -Value $RepairCommand
            $MsiItem | Select-Object -Property * -ExcludeProperty "CustomActions"
        }
    }

    end {
        Write-Verbose "Candidate count: $($CandidateCount) / $($MsiItems.Count)"
    }
}

function Invoke-MsiExtractBinaryData {

    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true)]
        [string] $Path,
        [Parameter(Position=1, Mandatory=$true)]
        [string] $Name,
        [Parameter(Position=2, Mandatory=$true)]
        [string] $OutputPath
    )

    begin {
        $Installer = New-Object -ComObject WindowsInstaller.Installer
    }

    process {
        try {
            if ([string]::IsNullOrEmpty($OutputPath)) { $OutputPath = "$($Name)" }
            Write-Verbose "Output path: $($OutputPath)"

            $Database = Invoke-MsiOpenDatabase -Installer $Installer -Path $Path -Mode 0
            $BinaryData = Get-MsiBinaryDataProperty -Database $Database -Name $Name

            Set-Content -Path $OutputPath -Value $BinaryData
        }
        catch {
            Write-Warning "Invoke-MsiExtractBinaryData exception: $($_)"
        }
    }

    end {
        $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Installer)
    }
}