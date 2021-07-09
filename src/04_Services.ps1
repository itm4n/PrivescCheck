function Invoke-InstalledServicesCheck {
    <#
    .SYNOPSIS
    Enumerates non-default services

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    It uses the custom "Get-ServiceList" function to get a filtered list of services that are configured on the local machine. Then it returns each result in a custom PS object, indicating the name, display name, binary path, user and start mode of the service.
    
    .EXAMPLE
    PS C:\> Invoke-InstalledServicesCheck | ft

    Name    DisplayName  ImagePath                                           User        StartMode
    ----    -----------  ---------                                           ----        ---------
    VMTools VMware Tools "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" LocalSystem Automatic
    #>
    
    [CmdletBinding()] Param()

    Get-ServiceList -FilterLevel 3 | Select-Object -Property Name,DisplayName,ImagePath,User,StartMode
}

function Invoke-ServicesPermissionsRegistryCheck {
    <#
    .SYNOPSIS
    Checks the permissions of the service settings in the registry

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    The configuration of the services is maintained in the registry. Being able to modify these registry keys means being able to change the settings of a service. In addition, a complete machine reboot isn't necessary for these settings to be taken into account. Only the affected service needs to be restarted. 
    
    .EXAMPLE
    PS C:\> Invoke-ServicesPermissionsRegistryCheck 

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
    
    [CmdletBinding()] Param()
    
    # Get all services except the ones with an empty ImagePath or Drivers 
    $AllServices = Get-ServiceList -FilterLevel 2 
    Write-Verbose "Enumerating $($AllServices.Count) services..."

    foreach ($Service in $AllServices) {

        Get-ModifiableRegistryPath -Path $Service.RegistryPath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) } | Foreach-Object {

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
            $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $Service.RegistryKey
            $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
            $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($_.Permissions -join ", ")
            $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
            $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
            $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $UserCanStop
            $Result
        }
    }
}

function Invoke-ServicesUnquotedPathCheck {
    <#
    .SYNOPSIS
    Enumerates all the services with an unquoted path. For each one of them, enumerates paths that the current user can modify. Based on the original "Get-ServiceUnquoted" function from PowerUp. 

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    In my version of this function, I tried to eliminate as much false positives as possible. PowerUp tends to report "C:\" as exploitable whenever a program located in "C:\Program Files" is identified. The problem is that we cannot write "C:\program.exe" so the service wouldn't be exploitable. We can only create folders in "C:\" by default.
    
    .PARAMETER Info
    Use this option to return all services with an unquoted path containing spaces without checking if they are vulnerable.

    .EXAMPLE
    PS C:\> Invoke-ServicesUnquotedPathCheck

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
    
    [CmdletBinding()] Param(
        [switch]
        $Info = $false
    )

    # Get all services which have a non-empty ImagePath (exclude drivers as well)
    $Services = Get-ServiceList -FilterLevel 2
    Write-Verbose "Enumerating $($Services.Count) services..."
    
    # $PermissionsAddFile = @("WriteData/AddFile", "DeleteChild", "WriteDAC", "WriteOwner")
    # $PermissionsAddFolder = @("AppendData/AddSubdirectory", "DeleteChild", "WriteDAC", "WriteOwner")

    foreach ($Service in $Services) {

        $ImagePath = $Service.ImagePath.trim()

        if ($Info) {

            if (-not ([String]::IsNullOrEmpty($(Get-UnquotedPath -Path $ImagePath -Spaces)))) {
                $Service | Select-Object Name,DisplayName,User,ImagePath,StartMode
            }

            # If Info, return the result without checking if the path is vulnerable
            continue
        }

        Get-ExploitableUnquotedPath -Path $ImagePath | ForEach-Object {

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
            $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
            $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
            $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($_.Permissions -join ", ")
            $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
            $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
            $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $UserCanStop
            $Result
        }
    }
}

function Invoke-ServicesImagePermissionsCheck {
    <#
    .SYNOPSIS
    Enumerates all the services that have a modifiable binary (or argument)

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    FIrst, it enumerates the services thanks to the custom "Get-ServiceList" function. For each result, it checks the permissions of the ImagePath setting thanks to the "Get-ModifiablePath" function. Each result is returned in a custom PS object. 
    
    .EXAMPLE
    PS C:\> Invoke-ServicesImagePermissionsCheck

    Name              : VulneService
    ImagePath         : C:\APPS\service.exe
    User              : LocalSystem
    ModifiablePath    : C:\APPS\service.exe
    IdentityReference : NT AUTHORITY\Authenticated Users
    Permissions       : {Delete, WriteAttributes, Synchronize, ReadControl...}
    Status            : Unknown
    UserCanStart      : False
    UserCanStop       : False
    #>
    
    [CmdletBinding()] Param()
    
    $Services = Get-ServiceList -FilterLevel 2
    Write-Verbose "Enumerating $($Services.Count) services..."

    foreach ($Service in $Services) {

        $Service.ImagePath | Get-ModifiablePath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) } | Foreach-Object {
            
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
            $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
            $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
            $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($_.Permissions -join ", ")
            $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
            $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
            $Result | Add-Member -MemberType "NoteProperty" -Name "UserCanStop" -Value $UserCanStop
            $Result
        }
    }
}

function Invoke-ServicesPermissionsCheck {
    <#
    .SYNOPSIS
    Enumerates the services the current can modify through the service manager. In addition, it shows whether the service can be started/restarted. 
    
    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This is based on the original "Get-ModifiableService" from PowerUp.
    
    .EXAMPLE
    PS C:\> Invoke-ServicesPermissionsCheck
    
    Name           : DVWS
    ImagePath      : C:\DVWS\Vuln Service\service.exe
    User           : LocalSystem
    Status         : Stopped
    UserCanStart   : True
    UserCanStop    : True

    .LINK
    https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
    #>
    
    [CmdletBinding()] Param()

    # Get-ServiceList returns a list of custom Service objects. The properties of a custom Service 
    # object are: Name, DisplayName, User, ImagePath, StartMode, Type, RegsitryKey, RegistryPath.
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
            $Result
        }
    }
}

function Invoke-SCMPermissionsCheck {
    <#
    .SYNOPSIS
    Checks whether the permissions of the SCM allows the current user to perform privileged actions.
    
    .DESCRIPTION
    The SCM (Service Control Manager) has its own DACL, which is defined by the system. Though, it is possible to apply a custom one using the built-in "sc.exe" command line tool and a modified SDDL string for example. However, such manipulation is dangerous and is prone to errors. Therefore, the objective of this function is to check whether the current user as any modification rights on the SCM itself.
    
    .EXAMPLE
    PS C:\> Invoke-SCMPermissionsCheck

    AceType      : AccessAllowed
    AccessRights : AllAccess
    IdentitySid  : S-1-5-32-545
    IdentityName : BUILTIN\Users
    #>

    [CmdletBinding()] Param()

    $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
    $CurrentUserSids += $UserIdentity.User.Value

    Get-ServiceControlManagerDacl | Where-Object { $($_ | Select-Object -ExpandProperty "AceType") -match "AccessAllowed" } | ForEach-Object {

        $CurrentAce = $_

        $Permissions = [Enum]::GetValues($ServiceControlManagerAccessRightsEnum) | Where-Object {
            ($CurrentAce.AccessMask -band ($ServiceControlManagerAccessRightsEnum::$_)) -eq ($ServiceControlManagerAccessRightsEnum::$_)
        }

        $PermissionReference = @(
            $ServiceControlManagerAccessRightsEnum::CreateService, 
            $ServiceControlManagerAccessRightsEnum::ModifyBootConfig, 
            $ServiceControlManagerAccessRightsEnum::AllAccess, 
            $ServiceControlManagerAccessRightsEnum::GenericWrite
        )

        if (Compare-Object -ReferenceObject $Permissions -DifferenceObject $PermissionReference -IncludeEqual -ExcludeDifferent) {

            $IdentityReference = $($CurrentAce | Select-Object -ExpandProperty "SecurityIdentifier").ToString()

            if ($CurrentUserSids -contains $IdentityReference) {

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "AceType" -Value $($CurrentAce | Select-Object -ExpandProperty "AceType")
                $Result | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $($CurrentAce | Select-Object -ExpandProperty "AccessRights")
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentitySid" -Value $IdentityReference
                $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityName" -Value $(Convert-SidToName -Sid $IdentityReference)
                $Result
            }
        }
    }
}