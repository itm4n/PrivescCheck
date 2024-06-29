function Get-ServiceControlManagerDacl {
    <#
    .SYNOPSIS
    Helper - Get the DACL of the SCM (Service Control Manager)

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    The SCM (Service Control Manager) has its own DACL which defines which users/groups can connect / create services / enumerate services / etc. This function requests Read access to the SCM and queries this DACL. The DACL is returned as a Security Descriptor, which is a binary blob. Therefore, it is converted to a list of ACE objects, which can then be easily used by the caller.

    .EXAMPLE
    PS C:\> Get-ServiceControlManagerDacl

    AccessRights       : Connect
    BinaryLength       : 20
    AceQualifier       : AccessAllowed
    IsCallback         : False
    OpaqueLength       : 0
    AccessMask         : 1
    SecurityIdentifier : S-1-5-11
    AceType            : AccessAllowed
    AceFlags           : None
    IsInherited        : False
    InheritanceFlags   : None
    PropagationFlags   : None
    AuditFlags         : None
    ...

    .NOTES
    https://docs.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights
    #>

    [CmdletBinding()]
    param()

    $SERVICES_ACTIVE_DATABASE = "ServicesActive"
    $ServiceManagerHandle = $script:Advapi32::OpenSCManager($null, $SERVICES_ACTIVE_DATABASE, $script:ServiceControlManagerAccessRightEnum::GenericRead)
    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($ServiceManagerHandle) {

        $SizeNeeded = 0
        $null = $script:Advapi32::QueryServiceObjectSecurity($ServiceManagerHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref] $SizeNeeded)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        # 122 == The data area passed to a system call is too small
        if (($LastError -eq 122) -and ($SizeNeeded -gt 0)) {

            Write-Verbose "Size needed: $($SizeNeeded)"

            $BinarySecurityDescriptor = New-Object Byte[]($SizeNeeded)

            $Success = $script:Advapi32::QueryServiceObjectSecurity($ServiceManagerHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $SizeNeeded)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {

                $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0

                $Dacl = $RawSecurityDescriptor.DiscretionaryAcl

                if ($null -eq $Dacl) {
                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $script:ServiceControlManagerAccessRightEnum::AllAccess
                    # $Result | Add-Member -MemberType "NoteProperty" -Name "AccessMask" -Value AccessRights.value__
                    $Result | Add-Member -MemberType "NoteProperty" -Name "SecurityIdentifier" -Value "S-1-1-0"
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AceType" -Value "AccessAllowed"
                    $Result
                }
                else {
                    $Dacl | ForEach-Object {
                        Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value ($_.AccessMask -as $script:ServiceControlManagerAccessRightEnum) -PassThru
                    }
                }
            }

        }
        else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }

        $null = $script:Advapi32::CloseServiceHandle($ServiceManagerHandle)
    }
    else {
        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
    }
}

function Get-ServiceFromRegistry {
    <#
    .SYNOPSIS
    Extract the configuration of a service from the registry.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Services' configuration is stored in teh registry under "HKLM\SYSTEM\CurrentControlSet\Services". For each service, a subkey is created and contains all the information we need. So we can just query this key to get a service's configuration.

    .PARAMETER Name
    Name of a service.

    .EXAMPLE
    PS C:\> Get-ServiceFromRegistry -Name Spooler

    Name         : Spooler
    DisplayName  : @C:\WINDOWS\system32\spoolsv.exe,-1
    User         : LocalSystem
    ImagePath    : C:\WINDOWS\System32\spoolsv.exe
    StartMode    : Automatic
    Type         : Win32OwnProcess, InteractiveProcess
    RegistryKey  : HKLM\SYSTEM\CurrentControlSet\Services
    RegistryPath : HKLM\SYSTEM\CurrentControlSet\Services\Spooler
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $Name
    )

    $RegKeyServices = "HKLM\SYSTEM\CurrentControlSet\Services"
    $RegKey = Join-Path -Path $RegKeyServices -ChildPath $Name
    $RegItem = Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue
    if ($null -eq $RegItem) { return }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegItem.PSChildName
    $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value ([System.Environment]::ExpandEnvironmentVariables($RegItem.DisplayName))
    $Result | Add-Member -MemberType "NoteProperty" -Name "User" -Value $RegItem.ObjectName
    $Result | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $RegItem.ImagePath
    $Result | Add-Member -MemberType "NoteProperty" -Name "StartMode" -Value ($RegItem.Start -as $script:ServiceStartTypeEnum)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value ($RegItem.Type -as $script:ServiceTypeEnum)
    $Result | Add-Member -MemberType "NoteProperty" -Name "RegistryKey" -Value $RegKeyServices
    $Result | Add-Member -MemberType "NoteProperty" -Name "RegistryPath" -Value $RegKey
    $Result
}

function Test-IsKnownService {

    [OutputType([Boolean])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Object] $Service
    )

    $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")

    foreach ($SeparationCharacterSet in $SeparationCharacterSets) {

        $CandidatePaths = ($Service.ImagePath).Split($SeparationCharacterSet) | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.trim())) }

        foreach ($CandidatePath in $CandidatePaths) {

            $TempPath = $([System.Environment]::ExpandEnvironmentVariables($CandidatePath))

            $TempPathResolved = Resolve-Path -Path $TempPath -ErrorAction SilentlyContinue -ErrorVariable ErrorResolvePath
            if ($ErrorResolvePath) { continue }

            $File = Get-Item -Path $TempPathResolved -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItem
            if ($ErrorGetItem) { continue }

            if ($File -and (Test-IsMicrosoftFile -File $File)) { return $true }

            return $false
        }
    }

    return $false
}

function Get-ServiceList {
    <#
    .SYNOPSIS
    Helper - Enumerates services (based on the registry)

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This uses the registry to enumerate the services by looking for the subkeys of "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services". This allows any user to get information about all the services. So, even if non-privileged users can't access the details of a service through the Service Control Manager, they can do so simply by accessing the registry.

    .PARAMETER FilterLevel
    This parameter can be used to filter out the result returned by the function based on the
    following criteria:
        FilterLevel = 0 - No filtering
        FilterLevel = 1 - Exclude 'Services with empty ImagePath'
        FilterLevel = 2 - Exclude 'Services with empty ImagePath' + 'Drivers'
        FilterLevel = 3 - Exclude 'Services with empty ImagePath' + 'Drivers' + 'Known services'

    .EXAMPLE
    PS C:\> Get-ServiceList -FilterLevel 3

    Name         : VMTools
    DisplayName  : VMware Tools
    User         : LocalSystem
    ImagePath    : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
    StartMode    : Automatic
    Type         : Win32OwnProcess
    RegistryKey  : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMTools
    RegistryPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMTools

    .NOTES
    A service "Type" can be one of the following:
        KernelDriver = 1
        FileSystemDriver = 2
        Adapter = 4
        RecognizerDriver = 8
        Win32OwnProcess = 16
        Win32ShareProcess = 32
        InteractiveProcess = 256
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet(0,1,2,3)]
        [Int] $FilterLevel
    )

    begin {
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        if ($script:CachedServiceList.Count -eq 0) {

            # If the cached service list hasn't been initialized yet, enumerate all services and populate the
            # cache.

            $ServicesRegPath = "HKLM\SYSTEM\CurrentControlSet\Services"
            $RegAllServices = Get-ChildItem -Path "Registry::$($ServicesRegPath)" -ErrorAction SilentlyContinue

            $RegAllServices | ForEach-Object { [void] $script:CachedServiceList.Add((Get-ServiceFromRegistry -Name $_.PSChildName)) }
        }

        foreach ($ServiceItem in $script:CachedServiceList) {

            # FilterLevel = 0 - Add the service to the list and go to the next one
            if ($FilterLevel -eq 0) { $ServiceItem; continue }

            if ($ServiceItem.ImagePath -and (-not [String]::IsNullOrEmpty($ServiceItem.ImagePath.trim()))) {

                # FilterLevel = 1 - Add the service to the list of its ImagePath is not empty
                if ($FilterLevel -le 1) { $ServiceItem; continue }

                # Ignore services with no explicit type
                if ($null -eq $ServiceItem.Type) {
                    Write-Warning "Service $($ServiceItem.Name) has no type"
                    continue
                }

                $TypeMask = $script:ServiceTypeEnum::Win32OwnProcess -bor $script:ServiceTypeEnum::Win32ShareProcess -bor $script:ServiceTypeEnum::InteractiveProcess
                if (($ServiceItem.Type -band $TypeMask) -gt 0) {

                    # FilterLevel = 2 - Add the service to the list if it's not a driver
                    if ($FilterLevel -le 2) { $ServiceItem; continue }

                    if (-not (Test-IsKnownService -Service $ServiceItem)) {

                        # FilterLevel = 3 - Add the service if it's not a built-in Windows service
                        if ($FilterLevel -le 3) { $ServiceItem; continue }
                    }
                }
            }
        }
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Add-ServiceDacl {
    <#
    .SYNOPSIS
    Helper - Adds a Dacl field to a service object returned by Get-Service.

    Author: Matthew Graeber
    License: BSD 3-Clause

    .DESCRIPTION
    Takes one or more ServiceProcess.ServiceController objects on the pipeline and adds a Dacl field to each object. It does this by opening a handle with ReadControl for the service with using the GetServiceHandle Win32 API call and then uses QueryServiceObjectSecurity to retrieve a copy of the security descriptor for the service.

    @itm4n: I had to make some small changes to the original code because i don't import the Win32 API functions the same way it was done in PowerUp.

    .PARAMETER Name
    An array of one or more service names to add a service Dacl for. Passable on the pipeline.

    .EXAMPLE
    PS C:\> Get-Service | Add-ServiceDacl

    Add DACLs for every service the current user can read.

    .EXAMPLE
    PS C:\> Get-Service -Name VMTools | Add-ServiceDacl

    Add the Dacl to the VMTools service object.

    .OUTPUTS
    ServiceProcess.ServiceController

    .LINK
    https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
    #>

    [OutputType('ServiceProcess.ServiceController')]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('ServiceName')]
        [ValidateNotNullOrEmpty()]
        [String[]] $Name
    )

    begin {
        filter Local:Get-ServiceReadControlHandle {
            [OutputType([IntPtr])]
            param (
                [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
                [ValidateNotNullOrEmpty()]
                [ValidateScript({ $_ -as 'ServiceProcess.ServiceController' })]
                $Service
            )
            Add-Type -AssemblyName System.ServiceProcess # ServiceProcess is not loaded by default
            $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')
            $ReadControl = 0x00020000
            $RawHandle = $GetServiceHandle.Invoke($Service, @($ReadControl))
            $RawHandle
        }
    }

    process {
        foreach ($ServiceName in $Name) {

            $IndividualService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue -ErrorVariable GetServiceError
            if (-not $GetServiceError) {

                try {
                    $ServiceHandle = Get-ServiceReadControlHandle -Service $IndividualService
                }
                catch {
                    $ServiceHandle = $null
                }

                if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {
                    $SizeNeeded = 0

                    $Result = $script:Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref] $SizeNeeded)
                    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    # 122 == The data area passed to a system call is too small
                    if ((-not $Result) -and ($LastError -eq 122) -and ($SizeNeeded -gt 0)) {
                        $BinarySecurityDescriptor = New-Object Byte[]($SizeNeeded)

                        $Result = $script:Advapi32::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $SizeNeeded)
                        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Result) {

                            $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0

                            $RawDacl = $RawSecurityDescriptor.DiscretionaryAcl

                            # Check for NULL DACL first
                            if ($nul -eq $RawDacl) {
                                $Ace = New-Object -TypeName PSObject
                                $Ace | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $script:ServiceAccessRightEnum::GenericAll
                                # $Ace | Add-Member -MemberType "NoteProperty" -Name "AccessMask" -Value AccessRights.value__
                                $Ace | Add-Member -MemberType "NoteProperty" -Name "SecurityIdentifier" -Value (Convert-SidStringToSid -Sid "S-1-1-0")
                                $Ace | Add-Member -MemberType "NoteProperty" -Name "AceType" -Value "AccessAllowed"
                                $Dacl = @($Ace)
                            }
                            else {
                                $Dacl = $RawDacl | ForEach-Object {
                                    Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value ($_.AccessMask -as $script:ServiceAccessRightEnum) -PassThru
                                }
                            }

                            Add-Member -InputObject $IndividualService -MemberType NoteProperty -Name Dacl -Value $Dacl -PassThru
                        }
                    }

                    $null = $script:Advapi32::CloseServiceHandle($ServiceHandle)
                }
            }
        }
    }
}

function Test-ServiceDaclPermission {
    <#
    .SYNOPSIS
    Tests one or more passed services or service names against a given permission set, returning the service objects where the current user have the specified permissions.

    Author: @harmj0y, Matthew Graeber
    License: BSD 3-Clause

    .DESCRIPTION
    Takes a service Name or a ServiceProcess.ServiceController on the pipeline, and first adds a service Dacl to the service object with Add-ServiceDacl. All group SIDs for the current user are enumerated services where the user has some type of permission are filtered. The services are then filtered against a specified set of permissions, and services where the current user have the specified permissions are returned.

    .PARAMETER Name
    An array of one or more service names to test against the specified permission set.

    .PARAMETER Permissions
    A manual set of permission to test again. One of:'QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess'

    .PARAMETER PermissionSet
    A pre-defined permission set to test a specified service against. 'ChangeConfig', 'Restart', or 'AllAccess'.

    .OUTPUTS
    ServiceProcess.ServiceController

    .EXAMPLE
    PS C:\> Get-Service | Test-ServiceDaclPermission

    Return all service objects where the current user can modify the service configuration.

    .EXAMPLE
    PS C:\> Get-Service | Test-ServiceDaclPermission -PermissionSet 'Restart'

    Return all service objects that the current user can restart.

    .EXAMPLE
    PS C:\> Test-ServiceDaclPermission -Permissions 'Start' -Name 'VulnSVC'

    Return the VulnSVC object if the current user has start permissions.

    .LINK
    https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
    #>
    [OutputType('ServiceProcess.ServiceController')] param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String[]]
        [ValidateSet('QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', 'UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess')]
        $Permissions,

        [String]
        [ValidateSet('ChangeConfig', 'Restart', 'AllAccess')]
        $PermissionSet = 'ChangeConfig'
    )

    begin {
        $AccessMask = @{
            'QueryConfig'           = [UInt32]'0x00000001'
            'ChangeConfig'          = [UInt32]'0x00000002'
            'QueryStatus'           = [UInt32]'0x00000004'
            'EnumerateDependents'   = [UInt32]'0x00000008'
            'Start'                 = [UInt32]'0x00000010'
            'Stop'                  = [UInt32]'0x00000020'
            'PauseContinue'         = [UInt32]'0x00000040'
            'Interrogate'           = [UInt32]'0x00000080'
            'UserDefinedControl'    = [UInt32]'0x00000100'
            'Delete'                = [UInt32]'0x00010000'
            'ReadControl'           = [UInt32]'0x00020000'
            'WriteDac'              = [UInt32]'0x00040000'
            'WriteOwner'            = [UInt32]'0x00080000'
            'Synchronize'           = [UInt32]'0x00100000'
            'AccessSystemSecurity'  = [UInt32]'0x01000000'
            'GenericAll'            = [UInt32]'0x10000000'
            'GenericExecute'        = [UInt32]'0x20000000'
            'GenericWrite'          = [UInt32]'0x40000000'
            'GenericRead'           = [UInt32]'0x80000000'
            'AllAccess'             = [UInt32]'0x000F01FF'
        }

        $CheckAllPermissionsInSet = $false

        if ($PSBoundParameters['Permissions']) {
            $TargetPermissions = $Permissions
        }
        else {
            if ($PermissionSet -eq 'ChangeConfig') {
                $TargetPermissions = @('ChangeConfig', 'WriteDac', 'WriteOwner', 'GenericAll', ' GenericWrite', 'AllAccess')
            }
            elseif ($PermissionSet -eq 'Restart') {
                $TargetPermissions = @('Start', 'Stop')
                $CheckAllPermissionsInSet = $true # so we check all permissions && style
            }
            elseif ($PermissionSet -eq 'AllAccess') {
                $TargetPermissions = @('GenericAll', 'AllAccess')
            }
        }

        $CurrentUserSids = Get-CurrentUserSid
    }

    process {

        foreach ($IndividualService in $Name) {

            $TargetService = $IndividualService | Add-ServiceDacl

            # We might not be able to access the Service at all so we must check whether Add-ServiceDacl
            # returned something.
            if ($TargetService -and $TargetService.Dacl) {

                # Check all the Dacl objects of the current service
                foreach ($Ace in $TargetService.Dacl) {

                    $MatchingDaclFound = $false

                    # An ACE object contains two properties we want to check: a SID and a list of AccessRights. First,
                    # we want to check if the current Dacl SID is in the list of SIDs of the current user
                    if ($CurrentUserSids -contains $Ace.SecurityIdentifier) {

                        if ($CheckAllPermissionsInSet) {

                            # If a Permission Set was specified, we want to make sure that we have all the necessary access
                            # rights
                            $AllMatched = $true
                            foreach ($TargetPermission in $TargetPermissions) {
                                # check permissions && style
                                if (($Ace.AccessRights -band $AccessMask[$TargetPermission]) -ne $AccessMask[$TargetPermission]) {
                                    # Write-Verbose "Current user doesn't have '$TargetPermission' for $($TargetService.Name)"
                                    $AllMatched = $false
                                    break
                                }
                            }
                            if ($AllMatched) {
                                $TargetService | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $Ace.AccessRights
                                $TargetService | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $(Convert-SidToName -Sid $Ace.SecurityIdentifier)
                                $TargetService
                                $MatchingDaclFound = $true
                            }
                        }
                        else {

                            foreach ($TargetPermission in $TargetPermissions) {
                                # check permissions || style
                                if (($Ace.AceType -eq 'AccessAllowed') -and ($Ace.AccessRights -band $AccessMask[$TargetPermission]) -eq $AccessMask[$TargetPermission]) {
                                    $TargetService | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value $Ace.AccessRights
                                    $TargetService | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $(Convert-SidToName -Sid $Ace.SecurityIdentifier)
                                    $TargetService
                                    $MatchingDaclFound = $true
                                    break
                                }
                            }
                        }
                    }

                    if ($MatchingDaclFound) {
                        # As soon as we find a matching Dacl, we can stop searching
                        break
                    }
                }
            }
            else {
                Write-Verbose "Error enumerating the Dacl for service $IndividualService"
            }
        }
    }
}

function Resolve-DriverImagePath {

    [CmdletBinding()]
    param (
        [Object] $Service
    )

    if ($Service.ImagePath -match "^\\SystemRoot\\") {
        $Service.ImagePath -replace "\\SystemRoot",$env:SystemRoot
    }
    elseif ($Service.ImagePath -match "^System32\\") {
        Join-Path -Path $env:SystemRoot -ChildPath $Service.ImagePath
    }
    elseif ($Service.ImagePath -match "^\\\?\?\\") {
        $Service.ImagePath -replace "\\\?\?\\",""
    }
    else {
        $Service.ImagePath
    }
}

function Get-DriverList {

    [CmdletBinding()]
    param()

    if ($script:CachedDriverList.Count -eq 0) {

        # If the cached driver list hasn't been initialized yet, enumerate all drivers,
        # resolve their paths and populate the cache.

        Write-Verbose "Populating driver list cache..."

        $Services = Get-ServiceList -FilterLevel 1 | Where-Object { @('KernelDriver','FileSystemDriver','RecognizerDriver') -contains $_.Type }

        foreach ($Service in $Services) {

            $ImagePath = Resolve-DriverImagePath -Service $Service
            if (-not (Test-Path -Path $ImagePath)) { Write-Warning "Service: $($Service.Name) | Path not found: $($ImagePath)"; continue }

            $Service | Add-Member -MemberType "NoteProperty" -Name "ImagePathResolved" -Value $ImagePath

            [void] $script:CachedDriverList.Add($Service)
        }
    }

    $script:CachedDriverList | ForEach-Object { $_ }
}

function Get-VulnerableDriverHash {

    [CmdletBinding()]
    param ()

    $VulnerableDriverList = $script:VulnerableDrivers | ConvertFrom-Csv -Delimiter ";"
    if ($null -eq $VulnerableDriverList) { Write-Warning "Failed to get list of vulnerable drivers."; return }

    $VulnerableDriverList | ForEach-Object {
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Url" -Value "https://www.loldrivers.io/drivers/$($_.Id)"
        $Result | Add-Member -MemberType "NoteProperty" -Name "HashType" -Value $_.HashType
        $Result | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value ([string[]] ($_.Hash -split ","))
        $Result
    }
}

function Find-VulnerableDriver {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Object] $Service
    )

    begin {
        Write-Verbose "Initializing list of vulnerable driver hashes..."
        $VulnerableDriverHashes = Get-VulnerableDriverHash
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {

        $ResultHash = ""
        $ResultUrl = ""

        $FileHashMd5 = ""
        $FileHashSha1 = ""
        $FileHashSha256 = ""

        foreach ($VulnerableDriverHash in $VulnerableDriverHashes) {

            switch ($VulnerableDriverHash.HashType) {

                "Md5" {
                    if ([String]::IsNullOrEmpty($FileHashMd5)) { $FileHashMd5 = Get-FileHashHex -FilePath $Service.ImagePathResolved -Algorithm MD5 }
                    if ($VulnerableDriverHash.Hash -contains $FileHashMd5) {
                        $ResultHash = $FileHashMd5
                        $ResultUrl = $VulnerableDriverHash.Url
                    }
                    break
                }

                "Sha1" {
                    if ([String]::IsNullOrEmpty($FileHashSha1)) { $FileHashSha1 = Get-FileHashHex -FilePath $Service.ImagePathResolved -Algorithm SHA1 }
                    if ($VulnerableDriverHash.Hash -contains $FileHashSha1) {
                        $ResultHash = $FileHashSha1
                        $ResultUrl = $VulnerableDriverHash.Url
                    }
                    break
                }

                "Sha256" {
                    if ([String]::IsNullOrEmpty($FileHashSha256)) { $FileHashSha256 = Get-FileHashHex -FilePath $Service.ImagePathResolved -Algorithm SHA256 }
                    if ($VulnerableDriverHash.Hash -contains $FileHashSha256) {
                        $ResultHash = $FileHashSha256
                        $ResultUrl = $VulnerableDriverHash.Url
                    }
                    break
                }

                default {
                    Write-Warning "Empty or invalid hash type: '$($VulnerableDriverHash.HashType)' ($($VulnerableDriverHash.Url))"
                }
            }

            if (-not [String]::IsNullOrEmpty($ResultHash)) {
                $Result = $Service.PSObject.Copy()
                $Result | Add-Member -MemberType "NoteProperty" -Name "FileHash" -Value $ResultHash
                $Result | Add-Member -MemberType "NoteProperty" -Name "Url" -Value $ResultUrl
                $Result
                break
            }
        }
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}