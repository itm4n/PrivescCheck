function Invoke-SystemInfoCheck {
    <#
    .SYNOPSIS
    Gets the name of the operating system and the full version string.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Reads the "Product Name" from the registry and gets the full version string based on the operating system.
    
    .EXAMPLE
    Invoke-SystemInfoCheck | fl

    Name    : Windows 10 Home
    Version : 10.0.18363 Version 1909 (18363.535)
    .LINK
    https://techthoughts.info/windows-version-numbers/
    #>
    
    [CmdletBinding()] Param()

    $OsVersion = [System.Environment]::OSVersion.Version

    $Item = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
    if (-not $GetItemPropertyError) {

        $OsName = $Item.ProductName

        if ($OsVersion -like "10.*") {
            # Windows >= 10/2016
            $OsVersion = "$($Item.CurrentMajorVersionNumber).$($Item.CurrentMinorVersionNumber).$($Item.CurrentBuild) Version $($Item.ReleaseId) ($($Item.CurrentBuild).$($Item.UBR))"
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $OsName
        $Result | Add-Member -MemberType "NoteProperty" -Name "Version" -Value $OsVersion
        $Result

    }
    else {
        Write-Verbose $GetItemPropertyError
    }
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
    
    [CmdletBinding()] Param(
        [Int]
        $TimeSpanInDays = 31
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

            [void]$SystemStartupHistoryResult.Add($Result)
            $EventNumber += 1
        }

        $SystemStartupHistoryResult | Select-Object -First 10
    }
    catch {
        # We might get an "acces denied"
        Write-Verbose "Error while querying the Event Log."
    }
}

function Invoke-SystemStartupCheck {
    <#
    .SYNOPSIS
    Gets the last system startup time
    
    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Gets the tickcount in milliseconds thanks to the GetTickCount64 Win32 function and substracts the value to the current date. This yields the date and time of the last system startup. The result is returned in a custom PS Object containing a string representation of the DateTime object. 
    
    .EXAMPLE
    PS C:\> Invoke-SystemStartupCheck

    Time
    ----
    2020-01-11 - 21:36:41

    .NOTES
    [Environment]::TickCount is a 32-bit signed integer
    The max value it can hold is 49.7 days. That's why GetTickCount64() is used instead.
    #>
    
    [CmdletBinding()] Param() 

    try {
        $TickcountMilliseconds = [PrivescCheck.Win32]::GetTickCount64()

        $StartupDate = (Get-Date).AddMilliseconds(-$TickcountMilliseconds)

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Time" -Value "$(Convert-DateToString -Date $StartupDate)"
        $Result
    
    }
    catch {
        # We are dealing with the Windows API so let's silently catch any exception, just in case...
    }
}

function Invoke-SystemDrivesCheck {
    <#
    .SYNOPSIS
    Gets a list of local drives and network shares that are currently mapped

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    This function is a wrapper for the "Get-PSDrive" standard cmdlet. For each result returned by "Get-PSDrive", a custom PS object is returned, indicating the drive letter (if applicable), the display name (if applicable) and the description.
    
    .EXAMPLE
    PS C:\> Invoke-SystemDrivesCheck 

    Root DisplayRoot Description
    ---- ----------- -----------
    C:\              OS
    E:\              DATA
    #>
    
    [CmdletBinding()] Param()

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

    [CmdletBinding()] Param()

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
                        $MemberIsEnabled = -not $($UserFlags -band $ADS_USER_FLAGS::AccountDisable)
                        $MemberType = "User"
                        $MemberIsLocal = $true
                    } 
                    elseif ($Member.SchemaClassName -eq "Group") {
                        $GroupType = $Member.GroupType.value
                        $MemberIsLocal = $($GroupType -band $GROUP_TYPE_FLAGS::ResourceGroup)
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
        Write-Verbose $_.Exception
    }
}

function Invoke-UsersHomeFolderCheck {
    <#
    .SYNOPSIS
    Enumerates the local user home folders.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Enumerates the folders located in C:\Users\. For each one, this function checks whether the folder is readable and/or writable by the current user. 
    
    .EXAMPLE
    PS C:\> Invoke-UsersHomeFolderCheck

    HomeFolderPath         Read Write
    --------------         ---- -----
    C:\Users\Lab-Admin    False False
    C:\Users\Lab-User      True  True
    C:\Users\Public        True  True
    #>

    [CmdletBinding()] Param()
    
    $UsersHomeFolder = Join-Path -Path $((Get-Item $env:windir).Root) -ChildPath Users

    Get-ChildItem -Path $UsersHomeFolder | ForEach-Object {

        $FolderPath = $_.FullName
        $ReadAccess = $false
        $WriteAccess = $false

        $null = Get-ChildItem -Path $FolderPath -ErrorAction SilentlyContinue -ErrorVariable ErrorGetChildItem 
        if (-not $ErrorGetChildItem) {

            $ReadAccess = $true 

            $ModifiablePaths = $FolderPath | Get-ModifiablePath -LiteralPaths
            if (([Object[]]$ModifiablePaths).Length -gt 0) {
                $WriteAccess = $true
            }
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "HomeFolderPath" -Value $FolderPath
        $Result | Add-Member -MemberType "NoteProperty" -Name "Read" -Value $ReadAccess
        $Result | Add-Member -MemberType "NoteProperty" -Name "NamWritee" -Value $WriteAccess
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
    
    [CmdletBinding()] Param()

    $Item = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
    
    $FriendlyNames = @{
        "WinNT"     = "WorkStation";
        "LanmanNT"  = "Domain Controller";
        "ServerNT"  = "Server";
    }

    if (-not $GetItemPropertyError){
        try {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Item.ProductType
            $Result | Add-Member -MemberType "NoteProperty" -Name "Role" -Value $FriendlyNames[$Item.ProductType]
            $Result
        }
        catch {
            Write-Verbose "Hashtable error."
        }
    }
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
    Windows Defender Loaded DLL            FileName=C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2008.9-0\MpOav.dll
    Windows Defender Loaded DLL            FileName=C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2008.9-0\MPCLIENT.DLL
    Windows Defender Running process       ProcessName=MsMpEng
    Windows Defender Running process       Name=MsMpEng
    Windows Defender Running process       ProcessName=NisSrv
    Windows Defender Running process       Name=NisSrv
    Windows Defender Running process       ProcessName=SecurityHealthService
    Windows Defender Running process       Name=SecurityHealthService
    Windows Defender Running process       Description=Windows Defender SmartScreen
    Windows Defender Installed application Name=Windows Defender
    Windows Defender Installed application Name=Windows Defender
    Windows Defender Installed application Name=Windows Defender Advanced Threat Protection
    Windows Defender Service               Name=SecurityHealthService
    Windows Defender Service               ImagePath=C:\Windows\system32\SecurityHealthService.exe
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

    [CmdletBinding()] Param()

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

        Param(
            [Object]$Object
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

    # Need to store all the results into one arraylist so we can sort them on the product name.
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
    Get-InstalledPrograms | Select-Object -Property Name | ForEach-Object {

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

function Invoke-HijackableDllsCheck {
    <#
    .SYNOPSIS
    Lists hijackable DLLs depending on the version of the OS

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    On Windows, some services load DLLs without using a "secure" search path. Therefore, they try to load them from the folders listing in the %PATH% environment variable. If one of these folders is configured with weak permissions, a local attacker may plant a malicious version of a DLL in order to execute arbitrary code in the context of the service.
    
    .EXAMPLE
    PS C:\> Invoke-HijackableDllsCheck

    Name           : cdpsgshims.dll
    Description    : Loaded by CDPSvc upon service startup
    RunAs          : NT AUTHORITY\LOCAL SERVICE
    RebootRequired : True

    .EXAMPLE
    PS C:\> Invoke-HijackableDllsCheck

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
    https://www.reddit.com/r/hacking/comments/b0lr05/a_few_binary_plating_0days_for_windows/?utm_source=amp&utm_medium=&utm_content=post_title
    #>

    [CmdletBinding()] Param()

    function Test-DllExists {

        [CmdletBinding()] Param(
            [String]$Name
        )

        $WindowsDirectories = New-Object System.Collections.ArrayList
        [void]$WindowsDirectories.Add($(Join-Path -Path $env:windir -ChildPath "System32"))
        [void]$WindowsDirectories.Add($(Join-Path -Path $env:windir -ChildPath "SysNative"))
        [void]$WindowsDirectories.Add($(Join-Path -Path $env:windir -ChildPath "System"))
        [void]$WindowsDirectories.Add($env:windir)

        foreach ($WindowsDirectory in [String[]]$WindowsDirectories) {
            $Path = Join-Path -Path $WindowsDirectory -ChildPath $Name 
            $null = Get-Item -Path $Path -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItem 
            if (-not $ErrorGetItem) {
                return $true
            }
        }
        return $false
    }

    function Test-HijackableDll {

        [CmdletBinding()] param (
            [String]$ServiceName,
            [String]$DllName,
            [String]$Description,
            [Boolean]$RebootRequired = $true
        )

        $Service = Get-ServiceFromRegistry -Name $ServiceName 
        if ($Service -and ($Service.StartMode -ne "Disabled")) {

            if (-not (Test-DllExists -Name $DllName)) {

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $DllName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                $Result | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value $Service.User
                $Result | Add-Member -MemberType "NoteProperty" -Name "RebootRequired" -Value $RebootRequired
                $Result
            }
        }
    }

    $OsVersion = [System.Environment]::OSVersion.Version

    if ($OsVersion.Major -eq 10) {
        Test-HijackableDll -ServiceName "CDPSvc" -DllName "cdpsgshims.dll" -Description "Loaded by CDPSvc upon service startup"
        Test-HijackableDll -ServiceName "Schedule" -DllName "WptsExtensions.dll" -Description "Loaded by the Task Scheduler upon service startup"
    }

    # Windows 7, 8, 8.1
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 1) -and ($OsVersion.Minor -le 3)) {
        Test-HijackableDll -ServiceName "DiagTrack" -DllName "windowsperformancerecordercontrol.dll" -Description "Loaded by DiagTrack upon service startup or shutdown"
        Test-HijackableDll -ServiceName "DiagTrack" -DllName "diagtrack_win.dll" -Description "Loaded by DiagTrack upon service startup"
    }

    # Windows Vista, 7, 8
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 0) -and ($OsVersion.Minor -le 2)) {
        $RebootRequired = $true
        $Service = Get-Service -Name "IKEEXT" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetService
        if ((-not $ErrorGetService) -and ($Service.Status -eq "Stopped")) {
            $RebootRequired = $false
        }
        Test-HijackableDll -ServiceName "IKEEXT" -DllName "wlbsctrl.dll" -Description "Loaded by IKEEXT upon service startup" -RebootRequired $RebootRequired
    }

    # Windows 7
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -eq 1)) {
        Test-HijackableDll -ServiceName "NetMan" -DllName "wlanhlp.dll" -Description "Loaded by NetMan when listing network interfaces" -RebootRequired $false
    }

    # Windows 8, 8.1, 10
    if (($OsVersion.Major -eq 10) -or (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 2) -and ($OsVersion.Minor -le 3))) {
        Test-HijackableDll -ServiceName "NetMan" -DllName "wlanapi.dll" -Description "Loaded by NetMan when listing network interfaces" -RebootRequired $false
    }
}

function Invoke-NamedPipePermissionsCheck {
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

    [CmdletBinding()] Param()

    $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
    $CurrentUserSids += $UserIdentity.User.Value

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
            $FileAccessRightsEnum::Delete, 
            $FileAccessRightsEnum::WriteDac, 
            $FileAccessRightsEnum::WriteOwner,
            $FileAccessRightsEnum::FileWriteEa,
            $FileAccessRightsEnum::FileWriteAttributes
        )

        ForEach ($Ace in $NamedPipeDacl.Access) {

            if ($Ace.AceType -notmatch "AccessAllowed") { continue }

            $Permissions = [Enum]::GetValues($FileAccessRightsEnum) | Where-Object {
                ($Ace.AccessMask -band ($FileAccessRightsEnum::$_)) -eq ($FileAccessRightsEnum::$_)
            }

            if (Compare-Object -ReferenceObject $Permissions -DifferenceObject $PermissionReference -IncludeEqual -ExcludeDifferent) {

                $IdentityReference = $($Ace | Select-Object -ExpandProperty "SecurityIdentifier").ToString()

                if ($CurrentUserSids -contains $IdentityReference) {

                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Pipe" -Value $NamedPipe.FullName
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Owner" -Value $NamedPipeDacl.Owner
                    # $Result | Add-Member -MemberType "NoteProperty" -Name "Group" -Value $NamedPipeDacl.Group
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AceType" -Value ($Ace | Select-Object -ExpandProperty "AceType")
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value ($Ace.AccessMask -as $FileAccessRightsEnum)
                    $Result | Add-Member -MemberType "NoteProperty" -Name "SecurityIdentifier" -Value $IdentityReference
                    $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityName" -Value (Convert-SidToName -Sid $IdentityReference)
                    $Result
                }
            }
        }
    }
}