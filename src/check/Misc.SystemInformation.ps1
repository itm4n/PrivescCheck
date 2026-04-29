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
    param(
        [UInt32] $BaseSeverity
    )

    $OsVersion = Get-WindowsVersionFromRegistry
    $SystemInformation = Get-SystemInformation

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
        $ProductName = $ProductName -replace "Windows 10", "Windows 11"
    }

    $Results = @()
    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value $ProductName
    $Result | Add-Member -MemberType "NoteProperty" -Name "Version" -Value $OsVersionStr
    $Result | Add-Member -MemberType "NoteProperty" -Name "BuildString" -Value $SystemInformation.BuildString
    $Result | Add-Member -MemberType "NoteProperty" -Name "BaseBoardManufacturer" -Value $SystemInformation.BaseBoardManufacturer
    $Result | Add-Member -MemberType "NoteProperty" -Name "BaseBoardProduct" -Value $SystemInformation.BaseBoardProduct
    $Result | Add-Member -MemberType "NoteProperty" -Name "BiosMode" -Value $SystemInformation.BiosMode
    $Result | Add-Member -MemberType "NoteProperty" -Name "BiosReleaseDate" -Value $SystemInformation.BiosReleaseDate
    $Result | Add-Member -MemberType "NoteProperty" -Name "BiosVendor" -Value $SystemInformation.BiosVendor
    $Result | Add-Member -MemberType "NoteProperty" -Name "BiosVersion" -Value $SystemInformation.BiosVersion
    $Result | Add-Member -MemberType "NoteProperty" -Name "SystemFamily" -Value $SystemInformation.SystemFamily
    $Result | Add-Member -MemberType "NoteProperty" -Name "SystemManufacturer" -Value $SystemInformation.SystemManufacturer
    $Result | Add-Member -MemberType "NoteProperty" -Name "SystemProductName" -Value $SystemInformation.SystemProductName
    $Result | Add-Member -MemberType "NoteProperty" -Name "SystemSKU" -Value $SystemInformation.SystemSKU
    $Results += $Result

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
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
        [UInt32] $BaseSeverity
    )

    process {
        $Results = @()

        $TimeSpanInDays = 31
        $SystemStartupHistoryResult = @()
        $StartDate = (Get-Date).AddDays(-$TimeSpanInDays)
        $EndDate = Get-Date
        $StartupEvents = Get-WinEvent -LogName "System" -ErrorAction SilentlyContinue | Where-Object { ($_.Id -eq 6005) -and ($_.TimeCreated -ge $StartDate) -and ($_.TimeCreated -le $EndDate) }
        $EventNumber = 1

        foreach ($StartupEvent in $StartupEvents) {

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Index" -Value $EventNumber
            $Result | Add-Member -MemberType "NoteProperty" -Name "Time" -Value "$(Convert-DateToString -Date $StartupEvent.TimeCreated -IncludeTime)"
            $SystemStartupHistoryResult += $Result
            $EventNumber += 1
        }

        $Results += $SystemStartupHistoryResult | Select-Object -First 10

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
        $Result
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
    param(
        [UInt32] $BaseSeverity
    )

    $Results = @()
    $Drives = Get-PSDrive -PSProvider "FileSystem"

    foreach ($Drive in $Drives) {
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Root" -Value "$($Drive.Root)"
        $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayRoot" -Value "$($Drive.DisplayRoot)"
        $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "$($Drive.Description)"
        $Results += $Result
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
    $Result
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
    param(
        [UInt32] $BaseSeverity
    )

    $Results = Get-MachineRole

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
    $Result
}

function Invoke-TpmDeviceInformationCheck {
    <#
    .SYNOPSIS
    Get information a TPM (if present).

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet is a wrapper for the custom 'Get-TpmDeviceInformation' command. It returns all the information cOllected about the TPM as is.
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    process {
        $Results = Get-TpmDeviceInformation

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
        $Result
    }
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
    param(
        [UInt32] $BaseSeverity
    )

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

        $Service = Get-ServiceFromRegistry -FilterLevel 2 | Where-Object { $_.Name -eq $ServiceName }
        if (($null -eq $Service) -or ($Service.StartMode -eq "Disabled")) { return }

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

    $Results = @()

    $OsVersion = Get-WindowsVersionFromRegistry

    # Windows 10, 11, ?
    if ($OsVersion.Major -ge 10) {
        $Results += Test-HijackableDll -ServiceName "CDPSvc" -DllName "cdpsgshims.dll" -Description "Loaded by the Connected Devices Platform Service (CDPSvc) upon startup." -Link "https://nafiez.github.io/security/eop/2019/11/05/windows-service-host-process-eop.html"
        $Results += Test-HijackableDll -ServiceName "Schedule" -DllName "WptsExtensions.dll" -Description "Loaded by the Task Scheduler service (Schedule) upon startup." -Link "http://remoteawesomethoughts.blogspot.com/2019/05/windows-10-task-schedulerservice.html"
        $Results += Test-HijackableDll -ServiceName "StorSvc" -DllName "SprintCSP.dll" -Description "Loaded by the Storage Service (StorSvc) when the RPC procedure 'SvcRebootToFlashingMode' is invoked." -RebootRequired $false -Link "https://github.com/blackarrowsec/redteam-research/tree/master/LPE%20via%20StorSvc"
    }

    # Windows 7, 8, 8.1
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 1) -and ($OsVersion.Minor -le 3)) {
        $Results += Test-HijackableDll -ServiceName "DiagTrack" -DllName "windowsperformancerecordercontrol.dll" -Description "Loaded by the Connected User Experiences and Telemetry service (DiagTrack) upon startup or shutdown." -Link "https://www.reddit.com/r/hacking/comments/b0lr05/a_few_binary_plating_0days_for_windows/"
        $Results += Test-HijackableDll -ServiceName "DiagTrack" -DllName "diagtrack_win.dll" -Description "Loaded by the Connected User Experiences and Telemetry service (DiagTrack) upon startup." -Link "https://www.reddit.com/r/hacking/comments/b0lr05/a_few_binary_plating_0days_for_windows/"
    }

    # Windows Vista, 7, 8
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 0) -and ($OsVersion.Minor -le 2)) {
        $RebootRequired = $true
        $ServiceStatus = Get-ServiceStatus -Name "IKEEXT"
        if ($ServiceStatus -eq $script:ServiceState::Stopped) {
            $RebootRequired = $false
        }
        $Results += Test-HijackableDll -ServiceName "IKEEXT" -DllName "wlbsctrl.dll" -Description "Loaded by the IKE and AuthIP IPsec Keying Modules service (IKEEXT) upon startup." -RebootRequired $RebootRequired -Link "https://www.reddit.com/r/hacking/comments/b0lr05/a_few_binary_plating_0days_for_windows/"
    }

    # Windows 7
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -eq 1)) {
        $Results += Test-HijackableDll -ServiceName "NetMan" -DllName "wlanhlp.dll" -Description "Loaded by the Network Connections service (NetMan) when listing network interfaces." -RebootRequired $false -Link "https://itm4n.github.io/windows-server-netman-dll-hijacking/"
    }

    # Windows 8, 8.1, 10
    if (($OsVersion.Major -ge 10) -or (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 2) -and ($OsVersion.Minor -le 3))) {
        $Results += Test-HijackableDll -ServiceName "NetMan" -DllName "wlanapi.dll" -Description "Loaded by the Network Connections service (NetMan) when listing network interfaces." -RebootRequired $false -Link "https://itm4n.github.io/windows-server-netman-dll-hijacking/"
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
    $Result
}