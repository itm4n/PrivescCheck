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
    param()

    Get-ServiceFromRegistry -FilterLevel 3 | Select-Object -Property Name,DisplayName,ImagePath,User,StartMode
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
        Write-Verbose "Enumerating $($Services.Count) services..."
        foreach ($Service in $Services) {

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

        Get-ServiceFromRegistry -FilterLevel 1 | ForEach-Object {
            $ServiceObject = $_
            Get-ObjectAccessRight -Name $ServiceObject.Name -Type Service | ForEach-Object {
                $Result = $ServiceObject.PSObject.Copy()
                $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $(Get-ServiceStatus -Name $ServiceObject.Name)
                $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $($null -ne (Get-ObjectAccessRight -Name $ServiceObject.Name -Type Service -AccessRights @($script:ServiceAccessRight::Start)))
                $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $($null -ne (Get-ObjectAccessRight -Name $ServiceObject.Name -Type Service -AccessRights @($script:ServiceAccessRight::Stop)))
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($_.Permissions -join ", ")
                $AllResults += $Result
            }
        }

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
    param()

    begin {
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {

        foreach ($Driver in (Get-KernelDriver)) {

            $ImageFile = Get-Item -Path $Driver.ImagePathResolved -ErrorAction SilentlyContinue

            if ($null -eq $ImageFile) { Write-Warning "Failed to open file: $($Driver.ImagePathResolved)"; continue }
            if (Test-IsMicrosoftFile -File $ImageFile) { continue }

            $VersionInfo = $ImageFile | Select-Object -ExpandProperty VersionInfo

            $Result = $Driver | Select-Object Name,ImagePath,StartMode,Type
            $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $(Get-ServiceStatus -Name $Driver.Name)
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
        Get-KernelDriver | Get-KnownVulnerableKernelDriver | ForEach-Object {

            $ServiceObjectResult = $_ | Select-Object Name,DisplayName,ImagePath,StartMode,Type
            $ServiceObjectResult | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $(Get-ServiceStatus -Name $_.Name)
            $ServiceObjectResult | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value $_.FileHash
            $ServiceObjectResult | Add-Member -MemberType "NoteProperty" -Name "Url" -Value $_.Url
            $AllResults += $ServiceObjectResult
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }
}