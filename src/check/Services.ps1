function Invoke-InstalledServiceCheck {
    <#
    .SYNOPSIS
    Enumerates non-default services

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    It uses the custom "Get-ServiceList" function to get a filtered list of services that are configured on the local machine. Then it returns each result in a custom PS object, indicating the name, display name, binary path, user and start mode of the service.

    .EXAMPLE
    PS C:\> Invoke-InstalledServiceCheck | ft

    Name    DisplayName  ImagePath                                           User        StartMode
    ----    -----------  ---------                                           ----        ---------
    VMTools VMware Tools "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" LocalSystem Automatic
    #>

    [CmdletBinding()]
    param()

    Get-ServiceList -FilterLevel 3 | Select-Object -Property Name,DisplayName,ImagePath,User,StartMode
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
        $AllServices = Get-ServiceList -FilterLevel 2
        Write-Verbose "Enumerating $($AllServices.Count) services..."

        foreach ($Service in $AllServices) {

            Get-ModifiableRegistryPath -Path "$($Service.RegistryPath)" | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) } | Foreach-Object {

                $Status = "Unknown"
                $UserCanStart = $false
                $UserCanStop = $false

                $ServiceObject = Get-Service -Name $Service.Name -ErrorAction SilentlyContinue
                if ($ServiceObject) {
                    $Status = $ServiceObject | Select-Object -ExpandProperty "Status"
                    $ServiceCanStart = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Start'
                    if ($ServiceCanStart) { $UserCanStart = $true } else { $UserCanStart = $false }
                    $ServiceCanStop = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Stop'
                    if ($ServiceCanStop) { $UserCanStop = $true } else { $UserCanStop = $false }
                }

                $VulnerableService = New-Object -TypeName PSObject
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $Service.RegistryPath
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($_.Permissions -join ", ")
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
                $VulnerableService | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $UserCanStop
                $AllResults += $VulnerableService
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
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
        $Services = Get-ServiceList -FilterLevel 2
        $AllResults = @()
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        Write-Verbose "Enumerating $($Services.Count) services..."
        foreach ($Service in $Services) {

            $Vulnerable = $false
            $ImagePath = $Service.ImagePath.trim()

            # If the path is quoted or doesn't contain spaces, ignore it.
            $UnquotedPath = Get-UnquotedPath -Path $ImagePath -Spaces
            if ([string]::IsNullOrEmpty($UnquotedPath)) { continue }

            $ExploitablePaths = [object[]] (Get-ExploitableUnquotedPath -Path $ImagePath)

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
            $Result | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
            $Result | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User

            $Status = "Unknown"
            $UserCanStart = $false
            $UserCanStop = $false

            $ServiceObject = Get-Service -Name $Service.Name -ErrorAction SilentlyContinue
            if ($ServiceObject) {
                $Status = $ServiceObject | Select-Object -ExpandProperty "Status"
                $ServiceCanStart = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Start'
                if ($ServiceCanStart) { $UserCanStart = $true } else { $UserCanStart = $false }
                $ServiceCanStop = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Stop'
                if ($ServiceCanStop) { $UserCanStop = $true } else { $UserCanStop = $false }
            }

            $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
            $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
            $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $UserCanStop

            $ModifiablePathString = ""
            if ($ExploitablePaths.Count -gt 0) {
                $Vulnerable = $true
                $ModifiablePathString = $(($ExploitablePaths | Select-Object -ExpandProperty "ModifiablePath") -join "; ")
            }

            $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $ModifiablePathString
            $Result | Add-Member -MemberType "NoteProperty" -Name "Vulnerable" -Value $Vulnerable
            $AllResults += $Result
        }

        $VulnerableCount = ([object[]] ($AllResults | Where-Object { $_.Vulnerable })).Count

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($VulnerableCount -gt 0) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
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
    FIrst, it enumerates the services thanks to the custom "Get-ServiceList" function. For each result, it checks the permissions of the ImagePath setting thanks to the "Get-ModifiablePath" function. Each result is returned in a custom PS object.

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
        $Services = Get-ServiceList -FilterLevel 2
        $AllResults = @()
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        Write-Verbose "Enumerating $($Services.Count) services..."
        foreach ($Service in $Services) {

            if ([String]::IsNullOrEmpty($Service.ImagePath)) { continue }

            $CommandLineResolved = [string[]] (Resolve-CommandLine -CommandLine $Service.ImagePath)
            if ($null -eq $CommandLineResolved) { continue }
            $ExecutablePath = $CommandLineResolved[0]

            $ModifiablePaths = Get-ModifiablePath -Path $ExecutablePath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
            if ($null -eq $ModifiablePaths) { continue }
            foreach ($ModifiablePath in $ModifiablePaths) {

                $Status = "Unknown"
                $UserCanStart = $false
                $UserCanStop = $false

                $ServiceObject = Get-Service -Name $Service.Name -ErrorAction SilentlyContinue
                if ($ServiceObject) {
                    $Status = $ServiceObject | Select-Object -ExpandProperty "Status"
                    $ServiceCanStart = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Start'
                    if ($ServiceCanStart) { $UserCanStart = $true } else { $UserCanStart = $false }
                    $ServiceCanStop = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Stop'
                    if ($ServiceCanStop) { $UserCanStop = $true } else { $UserCanStop = $false }
                }

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
                $Result | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
                $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $ModifiablePath.ModifiablePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $ModifiablePath.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($ModifiablePath.Permissions -join ", ")
                $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
                $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
                $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $UserCanStop
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

function Invoke-ServicePermissionCheck {
    <#
    .SYNOPSIS
    Enumerates the services the current can modify through the service manager. In addition, it shows whether the service can be started/restarted.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This is based on the original "Get-ModifiableService" from PowerUp.

    .EXAMPLE
    PS C:\> Invoke-ServicePermissionCheck

    Name           : DVWS
    ImagePath      : C:\DVWS\Vuln Service\service.exe
    User           : LocalSystem
    Status         : Stopped
    UserCanStart   : True
    UserCanStop    : True

    .LINK
    https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
    }

    process {
        # Get-ServiceList returns a list of custom Service objects. The properties of a custom Service
        # object are: Name, DisplayName, User, ImagePath, StartMode, Type, RegistryKey, RegistryPath.
        # We also apply the FilterLevel 1 to filter out services which have an empty ImagePath
        $Services = Get-ServiceList -FilterLevel 1
        Write-Verbose "Enumerating $($Services.Count) services..."



        # For each custom Service object in the list
        foreach ($Service in $Services) {

            # Get a 'real' Service object and the associated DACL, based on its name
            $TargetService = Test-ServiceDaclPermission -Name $Service.Name -PermissionSet 'ChangeConfig'

            if ($TargetService) {

                $Status = "Unknown"
                $UserCanStart = $false
                $UserCanStop = $false

                $ServiceObject = Get-Service -Name $Service.Name -ErrorAction SilentlyContinue
                if ($ServiceObject) {
                    $Status = $ServiceObject | Select-Object -ExpandProperty "Status"
                    $ServiceCanStart = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Start'
                    if ($ServiceCanStart) { $UserCanStart = $true } else { $UserCanStart = $false }
                    $ServiceCanStop = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Stop'
                    if ($ServiceCanStop) { $UserCanStop = $true } else { $UserCanStop = $false }
                }

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
                $Result | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
                $Result | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
                $Result | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $TargetService.AccessRights
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $TargetService.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
                $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
                $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $UserCanStop
                $AllResults += $Result
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
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

    begin {
        $CurrentUserSids = Get-CurrentUserSid
        $AllResults = @()
    }

    process {
        Get-ServiceControlManagerDacl | Where-Object { $($_ | Select-Object -ExpandProperty "AceType") -match "AccessAllowed" } | ForEach-Object {

            $CurrentAce = $_

            $Permissions = [Enum]::GetValues($script:ServiceControlManagerAccessRightEnum) | Where-Object {
                ($CurrentAce.AccessMask -band ($script:ServiceControlManagerAccessRightEnum::$_)) -eq ($script:ServiceControlManagerAccessRightEnum::$_)
            }

            $PermissionReference = @(
                $script:ServiceControlManagerAccessRightEnum::CreateService,
                $script:ServiceControlManagerAccessRightEnum::ModifyBootConfig,
                $script:ServiceControlManagerAccessRightEnum::AllAccess,
                $script:ServiceControlManagerAccessRightEnum::GenericWrite
            )

            if (Compare-Object -ReferenceObject $Permissions -DifferenceObject $PermissionReference -IncludeEqual -ExcludeDifferent) {

                $IdentityReference = $($CurrentAce | Select-Object -ExpandProperty "SecurityIdentifier").ToString()

                if ($CurrentUserSids -contains $IdentityReference) {

                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AceType" -Value $($CurrentAce | Select-Object -ExpandProperty "AceType")
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $($CurrentAce | Select-Object -ExpandProperty "AccessRights")
                    $Result | Add-Member -MemberType "NoteProperty" -Name "IdentitySid" -Value $IdentityReference
                    $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityName" -Value $(Convert-SidToName -Sid $IdentityReference)
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
    param()

    begin {
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {

        foreach ($Driver in (Get-DriverList)) {

            $ImageFile = Get-Item -Path $Driver.ImagePathResolved -ErrorAction SilentlyContinue

            if ($null -eq $ImageFile) { Write-Warning "Failed to open file: $($Driver.ImagePathResolved)"; continue }
            if (Test-IsMicrosoftFile -File $ImageFile) { continue }

            $ServiceObject = Get-Service -Name $Driver.Name -ErrorAction SilentlyContinue

            if ($null -eq $ServiceObject) { Write-Warning "Failed to query service '$($Driver.Name)'"; continue }

            $VersionInfo = $ImageFile | Select-Object -ExpandProperty VersionInfo

            $Result = $Driver | Select-Object Name,ImagePath,StartMode,Type
            $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $(if ($ServiceObject) { $ServiceObject.Status} else { "Unknown" })
            $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value $(if ($VersionInfo.ProductName) { $VersionInfo.ProductName.trim() } else { "Unknown" })
            $Result | Add-Member -MemberType "NoteProperty" -Name "Company" -Value $(if ($VersionInfo.CompanyName) { $VersionInfo.CompanyName.trim() } else { "Unknown" })
            $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ($VersionInfo.FileDescription) { $VersionInfo.FileDescription.trim() } else { "Unknown" })
            $Result | Add-Member -MemberType "NoteProperty" -Name "Version" -Value $(if ($VersionInfo.FileVersion) { $VersionInfo.FileVersion.trim() } else { "Unknown" })
            $Result | Add-Member -MemberType "NoteProperty" -Name "Copyright" -Value $(if ($VersionInfo.LegalCopyright) { $VersionInfo.LegalCopyright.trim() } else { "Unknown" })
            $Result
        }
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

    .NOTES
    When building the scripting, the driver list is downloaded from loldrivers.io, filtered, and exported again as a CSV file embedded in the script as a global variable.
    #>#

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
    }

    process {
        Get-DriverList | Find-VulnerableDriver | ForEach-Object {

            $ServiceObject = Get-Service -Name $_.Name -ErrorAction SilentlyContinue
            if ($null -eq $ServiceObject) { Write-Warning "Failed to query service $($_.Name)" }

            $ServiceObjectResult = $_ | Select-Object Name,DisplayName,ImagePath,StartMode,Type
            $ServiceObjectResult | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $(if ($ServiceObject) { $ServiceObject.Status} else { "Unknown" })
            $ServiceObjectResult | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value $_.FileHash
            $ServiceObjectResult | Add-Member -MemberType "NoteProperty" -Name "Url" -Value $_.Url
            $AllResults += $ServiceObjectResult
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }
}