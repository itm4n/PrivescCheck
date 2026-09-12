function Invoke-InstalledServiceCheck {
    <#
    .SYNOPSIS
    Enumerates non-default services

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    It uses the custom "Get-ServiceFromRegistry" function to get a filtered list of services that are configured on the local machine. Then it returns each result in a custom PS object, indicating the name, display name, binary path, user and start mode of the service.

    .EXAMPLE
    PS C:\> Invoke-InstalledServiceCheck | ft

    Name    DisplayName  ImagePath                                           User        StartMode
    ----    -----------  ---------                                           ----        ---------
    VMTools VMware Tools "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" LocalSystem Automatic
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $StartStopRights = @(
            $script:ServiceAccessRight::Start,
            $script:ServiceAccessRight::Stop
        )
    }

    process {
        $AllResults = @()
        $AllServices = Get-ServiceFromRegistry -FilterLevel 3

        foreach ($Service in $AllServices) {

            $AllAccessRights = @()

            Get-ObjectAccessRight -Name $Service.Name -Type Service -AccessRights $StartStopRights | ForEach-Object {
                $_.Permissions | ForEach-Object {
                    if ($StartStopRights -contains $_) { $AllAccessRights += $_ }
                }
            }

            $ServiceItem = $Service | Select-Object -Property Name,DisplayName,ImagePath,User,StartMode
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value ($AllAccessRights -contains "Start")
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value ($AllAccessRights -contains "Stop")

            $AllResults += $ServiceItem
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}

function Invoke-ServiceRegistryPermissionCheck {
    <#
    .SYNOPSIS
    Checks the permissions of the service settings in the registry

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    The configuration of the services is maintained in the registry. Being able to modify these registry keys means being able to change the settings of a service. In addition, a complete machine reboot isn't necessary for these settings to be taken into account. Only the affected service needs to be restarted.

    .EXAMPLE
    PS C:\> Invoke-ServiceRegistryPermissionCheck

    Name              : DVWS
    ImagePath         : C:\DVWS\Vuln Service\service.exe
    User              : NT AUTHORITY\LocalService
    ModifiablePath    : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DVWS
    IdentityReference : NT AUTHORITY\Authenticated Users
    Permissions       : {ReadControl, ReadData/ListDirectory, AppendData/AddSubdirectory, WriteData/AddFile...}
    Status            : Stopped
    UserCanStart      : True
    UserCanStop       : True
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
    }

    process {
        # Get all services except the ones with an empty ImagePath or Drivers
        $AllServices = Get-ServiceFromRegistry -FilterLevel 2
        Write-Verbose "Enumerating $($AllServices.Count) services..."

        foreach ($Service in $AllServices) {

            Get-ObjectAccessRight -Name $Service.RegistryPath -Type RegistryKey | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) } | Foreach-Object {

                $VulnerableService = New-Object -TypeName PSObject
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $Service.RegistryPath
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($_.Permissions -join ", ")
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $(Get-ServiceStatus -Name $Service.Name)
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $($null -ne (Get-ObjectAccessRight -Name $Service.Name -Type Service -AccessRights @($script:ServiceAccessRight::Start)))
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $($null -ne (Get-ObjectAccessRight -Name $Service.Name -Type Service -AccessRights @($script:ServiceAccessRight::Stop)))
                $AllResults += $VulnerableService
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}

function Invoke-ServiceRegistryPermissionExCheck {
    <#
    .SYNOPSIS
    Checks the permissions of services' registry sub-keys.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This check aims to enumerate the service registry keys that can be modified by low-privileged users.

    .EXAMPLE
    PS C:\> Invoke-ServiceRegistryPermissionExCheck

    Name              : embeddedmode
    DisplayName       : @C:\WINDOWS\system32\embeddedmodesvc.dll,-201
    StartMode         : Manual
    ImagePath         : C:\WINDOWS\System32\svchost.exe -k LocalSystemNetworkRestricted -p
    User              : LocalSystem
    ModifiablePath    : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\embeddedmode\Parameters
    IdentityReference : NT AUTHORITY\Authenticated Users (S-1-5-11)
    Permissions       : QueryValue, CreateSubKey, EnumerateSubKeys, Notify, ReadControl, GenericRead
    Status            : Stopped
    UserCanStart      : True
    UserCanStop       : False

    ...

    .NOTES
    A typical access right that low-privileged users may have is "CreateSubKey". This access right could be abused to create registry symbolic links, for instance.
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $StartStopRights = @(
            $script:ServiceAccessRight::Start,
            $script:ServiceAccessRight::Stop
        )
    }

    process {
        $AllResults = @()

        # Get all services except the ones with an empty ImagePath or Drivers
        $AllServices = Get-ServiceFromRegistry -FilterLevel 2

        foreach ($Service in $AllServices) {

            $ServiceStatus = $null
            $UserCanStart = $null
            $UserCanStop = $null

            Get-ChildItem -Path "registry::$($Service.RegistryPath)" -ErrorAction SilentlyContinue | ForEach-Object {

                $ServiceSubKeyPath = $_.Name

                Get-ObjectAccessRight -Name $ServiceSubKeyPath -Type RegistryKey | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) } | Foreach-Object {

                    if ($null -eq $ServiceStatus) {
                        $ServiceStatus = Get-ServiceStatus -Name $Service.Name
                    }

                    if (($null -eq $UserCanStart) -or ($null -eq $UserCanStop)) {
                        $ServiceStartStopRights = @()
                        Get-ObjectAccessRight -Name $Service.Name -Type Service -AccessRights $StartStopRights | ForEach-Object {
                            $_.Permissions | ForEach-Object {
                                if ($StartStopRights -contains $_) { $ServiceStartStopRights += $_ }
                            }
                        }
                        $UserCanStart = $ServiceStartStopRights -contains "Start"
                        $UserCanStop = $ServiceStartStopRights -contains "Stop"
                    }

                    $VulnerableService = $Service | Select-Object -Property Name,StartMode,ImagePath,User
                    $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $ServiceSubKeyPath
                    $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
                    $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($_.Permissions -join ", ")
                    $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $ServiceStatus
                    $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
                    $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $UserCanStop
                    $AllResults += $VulnerableService
                }
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}

function Invoke-ServiceUnquotedPathCheck {
    <#
    .SYNOPSIS
    Enumerates all the services with an unquoted path. For each one of them, enumerates paths that the current user can modify. Based on the original "Get-ServiceUnquoted" function from PowerUp.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    In my version of this function, I tried to eliminate as much false positives as possible. PowerUp tends to report "C:\" as exploitable whenever a program located in "C:\Program Files" is identified. The problem is that we cannot write "C:\program.exe" so the service wouldn't be exploitable. We can only create folders in "C:\" by default.

    .EXAMPLE
    PS C:\> Invoke-ServiceUnquotedPathCheck

    Name              : VulnService
    ImagePath         : C:\APPS\My App\service.exe
    User              : LocalSystem
    ModifiablePath    : C:\APPS
    IdentityReference : NT AUTHORITY\Authenticated Users
    Permissions       : {Delete, WriteAttributes, Synchronize, ReadControl...}
    Status            : Unknown
    UserCanStart      : False
    UserCanStop       : False
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        # Get all services which have a non-empty ImagePath (exclude drivers as well)
        $Services = Get-ServiceFromRegistry -FilterLevel 2
        $AllResults = @()
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        Write-Verbose "Enumerating $($Services.Count) services..."
        foreach ($Service in $Services) {

            $ImagePath = $Service.ImagePath.trim()

            $ExploitablePaths = [object[]] (Get-ExploitableUnquotedPath -Path $ImagePath)
            if ($null -eq $ExploitablePaths) { continue }

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
            $Result | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
            $Result | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
            $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $(Get-ServiceStatus -Name $Service.Name)
            $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $($null -ne (Get-ObjectAccessRight -Name $Service.Name -Type Service -AccessRights @($script:ServiceAccessRight::Start)))
            $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $($null -ne (Get-ObjectAccessRight -Name $Service.Name -Type Service -AccessRights @($script:ServiceAccessRight::Stop)))

            foreach ($ExploitablePath in $ExploitablePaths) {
                $ResultItem = $Result.PSObject.Copy()
                $ResultItem | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $ExploitablePath.ModifiablePath
                $ResultItem | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $ExploitablePath.IdentityReference
                $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $($ExploitablePath.Permissions -join ', ')
                $AllResults += $ResultItem
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults.Count -gt 0) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Invoke-ServiceImagePermissionCheck {
    <#
    .SYNOPSIS
    Enumerates all the services that have a modifiable binary (or argument)

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    FIrst, it enumerates the services thanks to the custom "Get-ServiceFromRegistry" function. For each result, it checks the permissions of the ImagePath setting thanks to the "Get-ModifiablePath" function. Each result is returned in a custom PS object.

    .EXAMPLE
    PS C:\> Invoke-ServiceImagePermissionCheck

    Name              : VulnService
    ImagePath         : C:\APPS\service.exe
    User              : LocalSystem
    ModifiablePath    : C:\APPS\service.exe
    IdentityReference : NT AUTHORITY\Authenticated Users
    Permissions       : {Delete, WriteAttributes, Synchronize, ReadControl...}
    Status            : Unknown
    UserCanStart      : False
    UserCanStop       : False
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $Services = Get-ServiceFromRegistry -FilterLevel 2
        $AllResults = @()
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        $ProgressCount = 0
        Write-Progress -Activity "Checking service image file permissions (0/$($Services.Count))..." -Status "0% Complete:" -PercentComplete 0

        foreach ($Service in $Services) {

            $ProgressPercent = [UInt32] ($ProgressCount * 100 / $Services.Count)
            Write-Progress -Activity "Checking service image file permissions ($($ProgressCount)/$($Services.Count)): $($Service.Name)" -Status "$($ProgressPercent)% Complete:" -PercentComplete $ProgressPercent
            $ProgressCount += 1

            if ([String]::IsNullOrEmpty($Service.ImagePath)) { continue }

            $CommandLineResolved = [string[]] (Resolve-CommandLine -CommandLine $Service.ImagePath)
            if ($null -eq $CommandLineResolved) { continue }
            $ExecutablePath = $CommandLineResolved[0]

            $ModifiablePaths = Get-ModifiablePath -Path $ExecutablePath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
            if ($null -eq $ModifiablePaths) { continue }

            $Result = $Service.PSObject.Copy()
            $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $(Get-ServiceStatus -Name $Service.Name)
            $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $($null -ne (Get-ObjectAccessRight -Name $Service.Name -Type Service -AccessRights @($script:ServiceAccessRight::Start)))
            $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $($null -ne (Get-ObjectAccessRight -Name $Service.Name -Type Service -AccessRights @($script:ServiceAccessRight::Stop)))

            foreach ($ModifiablePath in $ModifiablePaths) {

                $ResultWithPath = $Result.PSObject.Copy()
                $ResultWithPath | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $ModifiablePath.ModifiablePath
                $ResultWithPath | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $ModifiablePath.IdentityReference
                $ResultWithPath | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($ModifiablePath.Permissions -join ", ")
                $AllResults += $ResultWithPath
            }
        }

        Write-Progress -Activity "Checking service image file permissions ($($Services.Count)/$($Services.Count))..." -Status "100% Complete:" -Completed

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Invoke-ServicePermissionCheck {
    <#
    .SYNOPSIS
    Enumerates the services the current can modify through the service manager. In addition, it shows whether the service can be started/restarted.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet enumerates Windows services and checks their DACL to see if the current user has any modification right on them.

    .EXAMPLE
    PS C:\> Invoke-ServicePermissionCheck

    Name              : UnquotedService
    DisplayName       :
    User              : LocalSystem
    ImagePath         : C:\Workspace\Test Service\cmd.exe /c net user add
    StartMode         : Manual
    Type              : Win32OwnProcess
    RegistryKey       : HKLM\SYSTEM\CurrentControlSet\Services
    RegistryPath      : HKLM\SYSTEM\CurrentControlSet\Services\UnquotedService
    Status            : Stopped
    UserCanStart      : False
    UserCanStop       : False
    IdentityReference : BUILTIN\Users (S-1-5-32-545)
    Permissions       : ChangeConfig
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    process {
        $AllResults = @()

        $Candidates = Get-ServiceFromRegistry -FilterLevel 1

        $ProgressCount = 0
        Write-Progress -Activity "Checking service permissions (0/$($Candidates.Count))..." -Status "0% Complete:" -PercentComplete 0
        foreach ($Candidate in $Candidates) {
            $ProgressPercent = [UInt32] ($ProgressCount * 100 / $Candidates.Count)
            Write-Progress -Activity "Checking service permissions ($($ProgressCount)/$($Candidates.Count)): $($Candidate.Name)" -Status "$($ProgressPercent)% Complete:" -PercentComplete $ProgressPercent

            Get-ObjectAccessRight -Name $Candidate.Name -Type Service | ForEach-Object {
                $Result = $Candidate.PSObject.Copy()
                $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $(Get-ServiceStatus -Name $Candidate.Name)
                $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $($null -ne (Get-ObjectAccessRight -Name $Candidate.Name -Type Service -AccessRights @($script:ServiceAccessRight::Start)))
                $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $($null -ne (Get-ObjectAccessRight -Name $Candidate.Name -Type Service -AccessRights @($script:ServiceAccessRight::Stop)))
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($_.Permissions -join ", ")
                $AllResults += $Result
            }

            $ProgressCount += 1
        }
        Write-Progress -Activity "Checking service permission ($($Candidates.Count)/$($Candidates.Count))..." -Status "100% Complete:" -Completed

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}

function Invoke-ServiceControlManagerPermissionCheck {
    <#
    .SYNOPSIS
    Checks whether the permissions of the SCM allows the current user to perform privileged actions.

    .DESCRIPTION
    The SCM (Service Control Manager) has its own DACL, which is defined by the system. Though, it is possible to apply a custom one using the built-in "sc.exe" command line tool and a modified SDDL string for example. However, such manipulation is dangerous and is prone to errors. Therefore, the objective of this function is to check whether the current user as any modification rights on the SCM itself.

    .EXAMPLE
    PS C:\> Invoke-ServiceControlManagerPermissionCheck

    AceType      : AccessAllowed
    AccessRights : AllAccess
    IdentitySid  : S-1-5-32-545
    IdentityName : BUILTIN\Users
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    process {
        $AllResults = @()

        Get-ObjectAccessRight -Name "SCM" -Type ServiceControlManager | Foreach-Object {

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "ServiceControlManager"
            $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
            $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $_.Permissions
            $AllResults += $Result
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}

function Invoke-ThirdPartyDriverCheck {
    <#
    .SYNOPSIS
    Lists non-Microsoft drivers.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    For each service registered as a driver, the properties of the driver file are queried. If the file does not originate from Microsoft, the service object is reported. In addition, the file's metadata is appended to the object.
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
        foreach ($Driver in (Get-KernelDriver)) {

            $ImageFile = Get-Item -Path $Driver.ImagePathResolved -ErrorAction SilentlyContinue

            if ($null -eq $ImageFile) { Write-Warning "Failed to open file: $($Driver.ImagePathResolved)"; continue }
            if (Test-IsMicrosoftFile -File $ImageFile) { continue }

            $VersionInfo = $ImageFile | Select-Object -ExpandProperty VersionInfo

            $DriverEntry = $Driver | Select-Object Name, ImagePath, StartMode, Type
            $DriverEntry | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $(Get-ServiceStatus -Name $Driver.Name)
            $DriverEntry | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value $(if ($VersionInfo.ProductName) { $VersionInfo.ProductName.trim() } else { "Unknown" })
            $DriverEntry | Add-Member -MemberType "NoteProperty" -Name "Company" -Value $(if ($VersionInfo.CompanyName) { $VersionInfo.CompanyName.trim() } else { "Unknown" })
            $DriverEntry | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ($VersionInfo.FileDescription) { $VersionInfo.FileDescription.trim() } else { "Unknown" })
            $DriverEntry | Add-Member -MemberType "NoteProperty" -Name "Version" -Value $(if ($VersionInfo.FileVersion) { $VersionInfo.FileVersion.trim() } else { "Unknown" })
            $DriverEntry | Add-Member -MemberType "NoteProperty" -Name "Copyright" -Value $(if ($VersionInfo.LegalCopyright) { $VersionInfo.LegalCopyright.trim() } else { "Unknown" })
            $Results += $DriverEntry
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
        $Result
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Invoke-VulnerableDriverCheck {
    <#
    .SYNOPSIS
    Find vulnerable drivers.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This check relies on the list of known vulnerable drivers provided by loldrivers.io to find vulnerable drivers installed on the host. For each installed driver, it computes its hash and check whether it is in the list of vulnerable drivers.

    .EXAMPLE
    PS C:\> Invoke-VulnerableDriverCheck

    Name        : RTCore64
    DisplayName : Micro-Star MSI Afterburner
    ImagePath   : \SystemRoot\System32\drivers\RTCore64.sys
    StartMode   : Automatic
    Type        : KernelDriver
    Status      : Running
    Hash        : 01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd
    Url         : https://www.loldrivers.io/drivers/e32bc3da-4db1-4858-a62c-6fbe4db6afbd
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    process {
        $AllResults = @()
        $Candidates = Get-KernelDriver
        $SampleList = [Object[]] (Get-KnownVulnerableKernelDriverSampleList)

        $ProgressCount = 0
        Write-Progress -Activity "Checking for known vulnerable drivers (0/$($Candidates.Count)) against $($SampleList.Count) samples..." -Status "0% Complete:" -PercentComplete 0
        foreach ($Candidate in $Candidates) {
            $ProgressPercent = [UInt32] ($ProgressCount * 100 / $Candidates.Count)
            Write-Progress -Activity "Checking for known vulnerable drivers ($($ProgressCount)/$($Candidates.Count)) against $($SampleList.Count) samples: $($Candidate.Name)" -Status "$($ProgressPercent)% Complete:" -PercentComplete $ProgressPercent

            $Candidate | Get-KnownVulnerableKernelDriver | ForEach-Object {
                $AllResults += $_ | Select-Object -Property * -ExcludeProperty User,RegistryKey,RegistryPath,ImagePathResolved
            }

            $ProgressCount += 1
        }
        Write-Progress -Activity "Checking for known vulnerable drivers ($($Candidates.Count)/$($Candidates.Count)) against $($SampleList.Count) samples..." -Status "100% Complete:" -Completed

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}

function Invoke-VulnerableDriverBlockingPolicyCheck {
    <#
    .SYNOPSIS
    Identify known vulnerable drivers which are not blocked by a Code Integrity policy.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This check first tries to read local Code Integrity policy files, and then loops through the malware sample list to determine whether they would be blocked, based on their hash, version, or signer code signing information. The implementation is heavily inspired by the tool BYOVDFinder. It is important to note that the sample list is filtered on "vulnerable drivers"; it does not take into account "malware" drivers.

    .EXAMPLE
    PS C:\> Invoke-VulnerableDriverBlockingPolicyCheck

    ...

    Name    : afd.sys
    Version : 10.0.22621.1105 (WinBuild.160101.0800), 10.0.22621.608 (WinBuild.160101.0800)
    Id      : 394f49b2-2d78-4d0d-b374-1399695455f3
    Url     : https://www.loldrivers.io/drivers/394f49b2-2d78-4d0d-b374-1399695455f3

    Name    : ViveRRAudio.sys
    Version : 0.1.11.7
    Id      : 4cb95b41-43b4-4806-b536-ae5fd8c76b0e
    Url     : https://www.loldrivers.io/drivers/4cb95b41-43b4-4806-b536-ae5fd8c76b0e

    ...

    .LINK
    https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules

    .LINK
    https://github.com/ghostbyt3/BYOVDFinder
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $DriverPolicyFilePaths = @(
            (Join-Path -Path $env:windir -ChildPath "System32\CodeIntegrity\DriversIPolicy.p7b"),
            (Join-Path -Path $env:windir -ChildPath "System32\CodeIntegrity\SiPolicy.p7b")
        )

        $VulnerableDriverSamples = [Object[]] (Get-KnownVulnerableKernelDriverSampleList)
    }

    process {
        $AllResults = @()
        $AllowedSamples = @()
        $DriverPolicies = @{}

        # Parse all the policy files we can find.
        foreach ($DriverPolicyFilePath in $DriverPolicyFilePaths) {

            $DriverPolicy = Get-CodeIntegrityPolicy -FilePath $DriverPolicyFilePath

            if ($null -ne $DriverPolicy) {

                $FileDenyRules = $DriverPolicy.FileRules | Where-Object { $_.Type -eq "Deny" }
                $FileVersionDenyRules = $FileDenyRules | Where-Object { -not [String]::IsNullOrEmpty($_.FileName) }
                $FileAttribRules = $DriverPolicy.FileRules | Where-Object { $_.Type -eq "FileAttrib" }
                $SignerRules = $DriverPolicy.SignerRules | Where-Object { $_.CertRootType -eq "TBS" }

                $DriverPolicies[$DriverPolicyFilePath] = @{
                    "FileDenyRules" = $FileDenyRules
                    "FileVersionDenyRules" = $FileVersionDenyRules
                    "FileAttribRules" = $FileAttribRules
                    "SignerRules" = $SignerRules
                }
            }
        }

        foreach ($VulnerableDriverSample in $VulnerableDriverSamples) {

            $DriverSampleAllowed = $true

            # Build a list of all the file hashes for this driver sample.
            $VulnerableDriverSampleFileHashes = [String[]] @()
            foreach ($HashAlg in @("MD5", "SHA1", "SHA256")) {
                $FileHash = $VulnerableDriverSample.$HashAlg
                if (-not [String]::IsNullOrEmpty($FileHash)) {
                    $VulnerableDriverSampleFileHashes += $FileHash
                }
            }

            # Build a list of all the authenticode hashes for this driver sample.
            $VulnerableDriverSampleAuthenticodeHashes = [String[]] @()
            foreach ($HashAlg in @("SHA1", "SHA256")) {
                $AuthenticodeHash = $VulnerableDriverSample."Authenticode$($HashAlg)"
                if (-not [String]::IsNullOrEmpty($AuthenticodeHash)) {
                    $VulnerableDriverSampleAuthenticodeHashes += $AuthenticodeHash
                }
            }

            # Build a list of all the TBS certificate hashes for this driver sample.
            $VulnerableDriverSampleTbsHashes = [String[]] @()
            foreach ($HashAlg in @("MD5", "SHA1", "SHA256", "SHA384")) {
                $TbsHashes = $VulnerableDriverSample."Tbs$($HashAlg)"
                if (-not [String]::IsNullOrEmpty($TbsHashes)) {
                    foreach ($TbsHash in $TbsHashes.Split(",")) {
                        $VulnerableDriverSampleTbsHashes += $TbsHash
                    }
                }
            }

            foreach ($k in $DriverPolicies.Keys) {

                $DriverPolicy = $DriverPolicies[$k]

                if ($null -eq $DriverPolicy) { continue }

                # ==============================================================================
                # Is there a "file deny rule" that would block this driver based on its hash,
                # or its Authenticode hash?
                # ==============================================================================

                foreach ($FileDenyRule in $DriverPolicy['FileDenyRules']) {

                    # Is there a match on the file hash?
                    if ($VulnerableDriverSampleFileHashes -contains $FileDenyRule.Hash) {

                        # Write-Verbose "Found a match on file hash '$($FileDenyRule.Hash)'."
                        $DriverSampleAllowed = $false
                        break
                    }

                    # Is there a match on the authenticode hash?
                    if ($VulnerableDriverSampleAuthenticodeHashes -contains $FileDenyRule.Hash) {

                        # Write-Verbose "Found a match on authenticode hash '$($FileDenyRule.Hash)'."
                        $DriverSampleAllowed = $false
                        break
                    }
                }

                if (-not $DriverSampleAllowed) { continue }

                $VulnerableDriverSampleFileAttribs = $null
                if (-not [String]::IsNullOrEmpty($VulnerableDriverSample.Name)) {
                    $VulnerableDriverSampleFileAttribs = [Object[]] ($DriverPolicy['FileAttribRules'] | Where-Object { $_.FileName -eq $VulnerableDriverSample.Name })
                }

                # ==============================================================================
                # Is there a "signer rule" that would block this driver based on its signer
                # data?
                # ==============================================================================

                foreach ($SignerRule in $DriverPolicy['SignerRules']) {

                    $SignerRuleTbsHash = $SignerRule.CertRootValue

                    # Is the signer blocked?
                    if ($VulnerableDriverSampleTbsHashes -contains $SignerRuleTbsHash) {

                        $SignerRuleFileAttribRef = [String[]] $SignerRule.FileAttribRef

                        # If there isn't a list of file references, then consider that all drivers for
                        # this signer rule are blocked.
                        if ($SignerRuleFileAttribRef.Count -eq 0) {

                            # Write-Verbose "Found a match on TBS hash '$($SignerRuleTbsHash)' without any particular file reference."
                            $DriverSampleAllowed = $false
                            break
                        }

                        # If there is a list of file references, check whether the driver sample filename
                        # appears in the list.
                        foreach ($VulnerableDriverSampleFileAttrib in $VulnerableDriverSampleFileAttribs) {

                            if ($SignerRuleFileAttribRef -contains $VulnerableDriverSampleFileAttrib.Id) {

                                # Write-Verbose "Found a match on TBS hash '$($SignerRuleTbsHash)' with reference filename '$($VulnerableDriverSample.Name)'."
                                $DriverSampleAllowed = $false
                                break
                            }
                        }

                        if (-not $DriverSampleAllowed) { break }
                    }
                }

                if (-not $DriverSampleAllowed) { continue }

                # ==============================================================================
                # Is there a "file version rule" that would block this driver based on its name
                # and a maximum version?
                # ==============================================================================

                # Is the version blocked?
                if (-not [String]::IsNullOrEmpty($VulnerableDriverSample.Version)) {

                    try {
                        $VulnerableDriverSampleFileVersion = [Version] (-split ($VulnerableDriverSample.Version -replace ',\s*', '.'))[0]

                        foreach ($FileVersionDenyRule in $DriverPolicy['FileVersionDenyRules']) {

                            if ($FileVersionDenyRule.FileName -eq $VulnerableDriverSample.Name) {

                                $MaximumFileVersion = [Version] $FileVersionDenyRule.MaximumFileVersion

                                if ($VulnerableDriverSampleFileVersion -le $MaximumFileVersion) {

                                    # Write-Verbose "Found a match on filename '$($VulnerableDriverSample.Name)' with maximum version '$($MaximumFileVersion)'."
                                    $DriverSampleAllowed = $false
                                    break
                                }
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Error while parsing file version: $($_.Exception.Message)"
                    }
                }

                if (-not $DriverSampleAllowed) { continue }

                # ==============================================================================
                # Apply a few more filters to reduce the probability of returning false
                # positives.
                # ==============================================================================

                if ($VulnerableDriverSampleFileHashes.Count -eq 0) {
                    # No file hash provided. This could very likely yield a false positive, ignore it.
                    continue
                }

                if ($VulnerableDriverSampleAuthenticodeHashes.Count -eq 0) {
                    # No authenticode hash provided. This could very likely yield a false positive, ignore it.
                    continue
                }

                if ($VulnerableDriverSampleTbsHashes.Count -eq 0) {
                    # No TBS hash provided. This could very likely yield a false positive, ignore it.
                    continue
                }

                $AllowedSamples += $VulnerableDriverSample
            }
        }

        Write-Verbose "Found $($AllowedSamples.Count)/$($VulnerableDriverSamples.Count) known vulnerable driver samples which are not blocked."

        $VulnerableDrivers = @{}
        $AllowedSamples | ForEach-Object { $_ | Select-Object -ExpandProperty "Id" } | Sort-Object -Unique

        foreach ($AllowedSample in $AllowedSamples) {

            if (-not $VulnerableDrivers.ContainsKey($AllowedSample.Id)) {
                $DriverObject = New-Object -TypeName PSObject
                $DriverObject | Add-Member -MemberType "NoteProperty" -Name "Name" -Value ([String[]] @())
                $DriverObject | Add-Member -MemberType "NoteProperty" -Name "Version" -Value ([String[]] @())
                $DriverObject | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $AllowedSample.Id
                $DriverObject | Add-Member -MemberType "NoteProperty" -Name "Url" -Value $AllowedSample.Url
                $VulnerableDrivers[$AllowedSample.Id] = $DriverObject
            }

            $DriverObject = $VulnerableDrivers[$AllowedSample.Id]

            if (-not [String]::IsNullOrEmpty($AllowedSample.Name)) {
                if ($DriverObject.Name -notcontains $AllowedSample.Name) {
                    $DriverObject.Name += $AllowedSample.Name
                }
            }

            if (-not [String]::IsNullOrEmpty($AllowedSample.Version)) {
                $Version = $AllowedSample.Version -replace ',\s*', '.'
                if ($DriverObject.Version -notcontains $Version) {
                    $DriverObject.Version += $Version
                }
            }
        }

        Write-Verbose "Total samples allowed: $($AllowedSamples.Count) | Total drivers allowed: $($VulnerableDrivers.Keys.Count)"

        foreach ($k in $VulnerableDrivers.Keys) {
            $VulnerableDrivers[$k].Name = $VulnerableDrivers[$k].Name -join ", "
            $VulnerableDrivers[$k].Version = $VulnerableDrivers[$k].Version -join ", "
            $AllResults += $VulnerableDrivers[$k]
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}

function Invoke-ServiceCredentialCheck {
    <#
    .SYNOPSIS
    Find services configured with hardcoded credentials.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet enumerates services and attempts to determine whether they are configured with hardcoded credentials based on the account name.

    .EXAMPLE
    PS C:\> Invoke-ServiceCredentialCheck

    Name         : ServiceWithCreds
    DisplayName  :
    User         : .\admin
    ImagePath    : C:\Windows\System32\cmd.exe
    StartMode    : Manual
    Type         : Win32OwnProcess
    RegistryKey  : HKLM\SYSTEM\CurrentControlSet\Services
    RegistryPath : HKLM\SYSTEM\CurrentControlSet\Services\ServiceWithCreds
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $ServiceAccountList = @(
            "LocalSystem",
            "LocalService",
            "NetworkService"
        )

        $WellKnownSidValues = [System.Security.Principal.WellKnownSidType[]] [System.Enum]::GetValues([System.Security.Principal.WellKnownSidType])
        $WellKnownSids = @()

        function Test-IsWellKnownSid {
            param ([System.Security.Principal.SecurityIdentifier] $Sid)
            if ($WellKnownSids -contains $Sid) { return $true }
            foreach ($WellKnownSidValue in $WellKnownSidValues) {
                if ($Sid.IsWellKnown($WellKnownSidValue)) { $WellKnownSids += $Sid; return $true }
            }
            return $false
        }
    }

    process {

        $AllResults = @()
        $FilteredServices = Get-ServiceFromRegistry -FilterLevel 2 | Where-Object { ($null -ne $_.User) -and ($ServiceAccountList -notcontains $_.User) }

        foreach ($Service in $FilteredServices) {

            # We'll attempt to convert the service account name to an SID next, but the
            # ".\ACCOUNT_NAME" format is not recognized. Therefore, in that case we need
            # to replace the dot with the actual computer's name.
            $ServiceAccountName = $Service.User
            if ($ServiceAccountName -like ".\*") {
                $ServiceAccountName = $ServiceAccountName -replace "\.\\", "$($env:COMPUTERNAME)\"
            }

            # Try to convert the service account name to an SID. We'll use that information
            # to exclude well known service accounts.
            $ServiceAccountSid = Convert-NameToSid -Name $ServiceAccountName
            if ($null -eq $ServiceAccountSid) {
                Write-Warning "Failed to translate identity '$($ServiceAccountName)' for service '$($Service.Name)'."
                continue
            }

            # Filter out well known SIDs, such as S-1-5-18 for LocalSystem.
            if (Test-IsWellKnownSid -Sid $ServiceAccountSid) { continue }

            # Filter out virtual service accounts. Their SID starts with "S-1-5-80".
            if ($ServiceAccountSid.Value -like "S-1-5-80-*") { continue }

            $AllResults += $Service
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}

function Invoke-NamedKernelDeviceCheck {
    <#
    .SYNOPSIS
    Get information about named kernel devices low-privileged users can write to.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet enumerates named kernel devices and identifies the ones that grant write access to the current user.

    .EXAMPLE
    PS C:\> Invoke-NamedKernelDeviceCheck

    Name              : \Device\Afd
    ModifiablePath    : \\?\GLOBALROOT\Device\Afd
    IdentityReference : Everyone (S-1-1-0)
    Permissions       : ReadData, WriteData, AppendData, ReadExtendedAttributes, WriteExtendedAttributes, Execute,
                        ReadAttributes, WriteAttributes, ReadControl, Synchronize, GenericRead, GenericExecute,
                        GenericWrite

    Name              : \Device\ahcache
    ModifiablePath    : \\?\GLOBALROOT\Device\ahcache
    IdentityReference : Everyone (S-1-1-0)
    Permissions       : ReadData, WriteData, AppendData, ReadExtendedAttributes, WriteExtendedAttributes, Execute,
                        ReadAttributes, WriteAttributes, ReadControl, Synchronize, GenericRead, GenericExecute,
                        GenericWrite

    ...

    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $IgnoredDevices = @("Beep", "Mailslot", "NamedPipe", "Null")
    }

    process {

        $Devices = Get-NtObjectItem -Path "\Device" | Where-Object { $_.Type -eq "Device" } | Sort-Object -Property Name

        $Results = @()
        foreach ($Device in $Devices) {

            if ($Device.Name -match "0000[0-9a-fA-F]{4}") { continue }
            if ($Device.Name -match "NTPNP_*") { continue }
            if ($IgnoredDevices -contains $Device.Name) { continue }

            $Win32Path = Join-Path -Path "\\?\GLOBALROOT" -ChildPath $Device.FullName
            $ModifiablePaths = Get-ObjectAccessRight -Name $Win32Path -Type File

            foreach ($ModifiablePath in $ModifiablePaths) {

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Device.FullName
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $ModifiablePath.ModifiablePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $ModifiablePath.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($ModifiablePath.Permissions -join ", ")
                $Results += $Result
            }
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
        $Result
    }
}

function Invoke-ServiceRestartAsUserCheck {
    <#
    .SYNOPSIS
    Get information about services that can be restarted by unprivileged users.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This check enumerates system services that can be restarted by unprivileged users.

    .EXAMPLE
    PS C:\> Invoke-ServiceRestartAsUserCheck

    ...

    Name              : RmSvc
    User              : NT AUTHORITY\LocalService
    ImagePath         : C:\WINDOWS\System32\svchost.exe -k LocalServiceNetworkRestricted
    StartMode         : Manual
    Type              : Win32ShareProcess
    Status            : Running
    IdentityReference : BUILTIN\Users (S-1-5-32-545)
    Permissions       : Start, Stop

    ...
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $ServiceStartStopAccessRights = @(
            $script:ServiceAccessRight::Start,
            $script:ServiceAccessRight::Stop
        )

        $ExcludedServiceTypes = @(
            $script:ServiceType::UserService,
            $script:ServiceType::UserOwnProcess,
            $script:ServiceType::UserShareProcess,
            $script:ServiceType::UserServiceInstance
        )
    }

    process {
        $Win32Services = Get-ServiceFromRegistry -FilterLevel 2 | Where-Object {
            (-not [String]::IsNullOrEmpty($_.User)) -and (-not [String]::IsNullOrEmpty($_.Name)) -and ($ExcludedServiceTypes -notcontains $_.Type) -and ($_.StartMode -ne "Disabled")
        }

        $AllResults = @()

        $ProgressCount = 0
        Write-Progress -Activity "Checking service start and stop permissions (0/$($Win32Services.Count))..." -Status "0% Complete:" -PercentComplete 0

        foreach ($Service in $Win32Services) {

            $ProgressPercent = [UInt32] ($ProgressCount * 100 / $Win32Services.Count)
            Write-Progress -Activity "Checking service start and stop permissions ($($ProgressCount)/$($Win32Services.Count)): $($Service.Name)" -Status "$($ProgressPercent)% Complete:" -PercentComplete $ProgressPercent

            $Candidate = New-Object -TypeName PSObject
            $Candidate | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
            $Candidate | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
            $Candidate | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
            $Candidate | Add-Member -MemberType "NoteProperty" -Name "StartMode" -Value $Service.StartMode
            $Candidate | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $Service.Type
            $Candidate | Add-Member -MemberType "NoteProperty" -Name "Status" -Value ""
            $Candidate | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value ([String[]] @())
            $Candidate | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value @()

            Get-ObjectAccessRight -Name $Service.Name -Type Service -AccessRights $ServiceStartStopAccessRights | ForEach-Object {

                $Candidate.IdentityReference += $_.IdentityReference

                if ($_.Permissions -contains $script:ServiceAccessRight::Start) {
                    $Candidate.Permissions += $script:ServiceAccessRight::Start
                }

                if ($_.Permissions -contains $script:ServiceAccessRight::Stop) {
                    $Candidate.Permissions += $script:ServiceAccessRight::Stop
                }
            }

            $IsValidCandidate = $Candidate.Permissions -contains $script:ServiceAccessRight::Start -and $Candidate.Permissions -contains $script:ServiceAccessRight::Stop

            if ($IsValidCandidate) {
                $Candidate.Status = Get-ServiceStatus -Name $Service.Name
                $Candidate.IdentityReference = ($Candidate.IdentityReference | Sort-Object -Unique) -join ", "
                $Candidate.Permissions = ($Candidate.Permissions | Sort-Object -Unique) -join ", "
                $AllResults += $Candidate
            }

            $ProgressCount += 1
        }

        Write-Progress -Activity "Checking service start and stop permissions ($($ProgressCount)/$($Win32Services.Count))..." -Status "100% Complete:" -Completed

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $Result
    }
}