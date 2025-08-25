function Get-ComClassEntryFromRegistry {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Guid] $Clsid
    )

    begin {
        $RootKey = "HKLM\SOFTWARE\Classes\CLSID"
        $FilteredComSubProperties = @( "InprocHandler", "InprocHandler32", "InprocServer", "InprocServer32", "LocalServer", "LocalServer32" )
        $IgnoredComSubProperties = @( "Instance", "PersistentHandler", "Shell", "PersistentAddinsRegistered", "MergedFolder", "TreatAs", "shellex", "ProgId" )
    }

    process {
        $ClassId = $Clsid.ToString()
        $ClassRegPath = "$($RootKey)\{$($ClassId)}"

        # Assume the input CLSID is correct and therefore that that the registry
        # path is correct as well. If it is not, we'll let Get-Item throw an
        # error. This will let us know that there is an issue upstream in the
        # code because there is no reason we would pass an invalid CLSID.
        $ClassProperties = Get-Item -Path "Registry::$($ClassRegPath)"
        if ($null -eq $ClassProperties) { continue }

        # There might be CLSID entries in the registry that do not have values or
        # sub-keys. We can filter those out by checking the "value count" and the
        # "sub key count". Note that the value count could also be "1" in case
        # the "(default)" value is set; we should ignore that case too.
        if (($ClassProperties.ValueCount -le 1) -and ($ClassProperties.SubKeyCount -eq 0)) {
            continue
        }

        # If the COM class has sub-properties, i.e. if the CLSID registry key has
        # sub-keys, list them.
        if ($ClassProperties.SubKeyCount -ne 0) {
            $ClassSubProperties = Get-ChildItem -Path "Registry::$($ClassRegPath)" -ErrorAction SilentlyContinue
        }
        else {
            $ClassSubProperties = $null
        }


        $ClassAppId = $ClassProperties | Get-ItemProperty -Name "AppId" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "AppId" | ForEach-Object { ([Guid] $_).Guid.ToUpper() }

        # Enumerate the COM class properties we are the most interested in.
        $ClassServerProperties = $ClassSubProperties | Where-Object { $FilteredComSubProperties -contains $_.PSChildName }

        if ($null -eq $ClassServerProperties) {
            # If we don't find the COM class properties we want, check whether the COM
            # class is "APPID hosted". If there is an AppId, we might find other
            # interesting things under the "AppID" registry key.
            if ($null -eq $ClassAppId) {
                # Determine whether the COM class is of interest to us by enumerating the
                # properties we are not interested in. If we find any, ignore it.
                $IgnoredSubProperties = $ClassSubProperties | Where-Object { $IgnoredComSubProperties -contains $_.PSChildName }
                if ($null -ne $IgnoredSubProperties) {
                    continue
                }

                # At this stage, there is probably still a few COM classes we don't know what
                # to do with. Ignore them.
                continue
            }
        }

        $ClassName = $ClassProperties | Get-ItemProperty -Name "(default)" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty "(default)"
        $ClassTypeLibId = $ClassSubProperties | Where-Object { "TypeLib" -eq $_.PSChildName } | Get-ItemProperty -Name "(default)" | Select-Object -ExpandProperty "(default)" | ForEach-Object { ([Guid] $_).Guid.ToUpper() }

        $ClassProgIds = [String[]] @()
        $ClassProgIds += $ClassSubProperties | Where-Object { "ProgID" -eq $_.PSChildName } | Get-ItemProperty -Name "(default)" | Select-Object -ExpandProperty "(default)"
        $ClassProgIds += $ClassSubProperties | Where-Object { "VersionIndependentProgID" -eq $_.PSChildName } | Get-ItemProperty -Name "(default)" | Select-Object -ExpandProperty "(default)"

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $ClassId
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $ClassName
        if ($null -ne $ClassAppId) { $Result | Add-Member -MemberType "NoteProperty" -Name "AppId" -Value $ClassAppId }
        if ($ClassProgIds.Count -gt 0) { $Result | Add-Member -MemberType "NoteProperty" -Name "ProgIds" -Value $ClassProgIds }
        if ($null -ne $ClassTypeLibId) { $Result | Add-Member -MemberType "NoteProperty" -Name "TypeLibId" -Value $ClassTypeLibId }
        $Result | Add-Member -MemberType "NoteProperty" -Name "RegPath" -Value $ClassRegPath

        if ($null -eq $ClassServerProperties) {
            # At this stage, if the COM class doesn't have any "server properties", it
            # should at least have an AppID, in which case we consider it is "AppId
            # hosted".
            if ($null -eq $ClassAppId) {
                Write-Error "COM class with ID $($ClassId) has no handler property / AppID | Properties: $(($ClassSubProperties | Select-Object -ExpandProperty "PSChildName") -join ",")"
            }
            $Result | Add-Member -MemberType "NoteProperty" -Name "HandlerType" -Value "AppIdHosted"
            $Result
        }
        else {
            # COM classes may have more than one handler type, so make sure we check all
            # of them.
            foreach ($ServerProperty in $ClassServerProperties) {

                $ServerData = $ServerProperty.GetValue($null, $null, "DoNotExpandEnvironmentNames")
                $ServerDataType = $null

                if ($ServerProperty.PSChildName -like "Inproc*") {
                    # The data contains the name or path of a DLL.
                    # $PathToAnalyze = $ServerData
                    $PathToAnalyze = [System.Environment]::ExpandEnvironmentVariables($ServerData)
                    # The following regex matches any string surrounded by double quotes, but not
                    # containing double quotes within it. This should match quoted paths such as
                    # "C:\windows\system32\combase.dll"
                    if ($ServerData -match "^`"[^`"]+`"`$") {
                        $PathToAnalyze = $PathToAnalyze.Trim('"')
                    }
                    if ([System.IO.Path]::IsPathRooted($PathToAnalyze)) {
                        $ServerDataType = "FilePath"
                    }
                    else {
                        $ServerDataType = "FileName"
                    }
                }
                elseif ($ServerProperty.PSChildName -like "Local*") {
                    # The data contains the path of an executable or a command line.
                    $ServerDataType = "CommandLine"
                }

                $ResultWithServerData = $Result.PSObject.Copy()
                $ResultWithServerData | Add-Member -MemberType "NoteProperty" -Name "HandlerType" -Value $ServerProperty.PSChildName
                $ResultWithServerData | Add-Member -MemberType "NoteProperty" -Name "HandlerRegPath" -Value $(Join-Path -Path $Result.RegPath -ChildPath $ResultWithServerData.HandlerType)
                $ResultWithServerData | Add-Member -MemberType "NoteProperty" -Name "HandlerDataType" -Value $ServerDataType
                $ResultWithServerData | Add-Member -MemberType "NoteProperty" -Name "HandlerData" -Value $ServerData
                $ResultWithServerData
            }
        }
    }
}

function Get-ComClassFromRegistry {
    <#
    .SYNOPSIS
    Helper - Enumerate registered COM classes through the registry

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet enumerates the registry keys under HKLM\SOFTWARE\Classes\CLSID to list registered COM classes. Depending on the configuration of each COM object, this cmdlet will return optional attributes, such as "AppId", "ProgIds", and "TypeLibId".

    .EXAMPLE
    PS C:\> Get-ComClassFromRegistry

    ...

    Id              : F8D253D9-89A4-4daa-87B6-1168369F0B21
    Name            : UpdateServiceManager Class
    AppId           : B366DEBE-645B-43A5-B865-DDD82C345492
    ProgIds         : {Microsoft.Update.ServiceManager.1, Microsoft.Update.ServiceManager}
    TypeLibId       : B596CC9F-56E5-419E-A622-E01BB457431E
    RegPath         : HKLM\SOFTWARE\Classes\CLSID\{F8D253D9-89A4-4daa-87B6-1168369F0B21}
    HandlerType     : InprocServer32
    HandlerRegPath  : HKLM\SOFTWARE\Classes\CLSID\{F8D253D9-89A4-4daa-87B6-1168369F0B21}\InprocServer32
    HandlerDataType : FilePath
    HandlerData     : C:\Windows\System32\wuapi.dll

    ...

    .LINK
    https://learn.microsoft.com/en-us/windows/win32/com/component-object-model--com--portal
    #>

    [CmdletBinding()]
    param ()

    begin {
        $RootKey = "HKLM\SOFTWARE\Classes\CLSID"
    }

    process {
        if (-not (Test-CachedData -Name "RegisteredComList")) {

            $RegisteredComList = @()

            # First, enumerate all CLSID registry key entries with a 'valid' name, i.e. a name
            # that can be parsed as a GUID.
            $ComClassRegistryClsid = @()
            $ClsidKeys = Get-ChildItem -Path "Registry::$($RootKey)" | Select-Object -ExpandProperty PSChildName
            foreach ($ClsidKey in $ClsidKeys) {
                try {
                    $ComClassRegistryClsid += [Guid] $ClsidKey
                }
                catch {
                    continue
                }
            }

            # Then, for each valid CLSID, enumerate the COM class properties.
            $ComClassRegistryClsid |
            Invoke-CommandMultithread -InitialSessionState $(Get-InitialSessionState) -Command "Get-ComClassEntryFromRegistry" -InputParameter "Clsid" |
            ForEach-Object {
                $RegisteredComList += $_
            }

            Set-CachedData -Name "RegisteredComList" -Data $RegisteredComList
        }

        Get-CachedData -Name "RegisteredComList"
    }
}

function Get-VolumeShadowCopyInformation {
    <#
    .SYNOPSIS
    Helper - Enumerates Shadow Copies

    Author: @SAERXCIT, @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Uses Win32 functions NtOpenDirectoryObject and NtQueryDirectoryObject (thanks @gentilkiwi for the method).
    Inspired from https://github.com/cube0x0/CVE-2021-36934 and https://gist.github.com/brianreitz/feb4e14bd45dd2e4394c225b17df5741.

    .EXAMPLE
    PS C:\>  Get-VolumeShadowCopyInformation | fl

    Volume : HarddiskVolumeShadowCopy1
    Path   : \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1

    Volume : HarddiskVolumeShadowCopy2
    Path   : \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
    #>

    [CmdletBinding()]
    param()

    process {
        $Devices = Get-NtObjectItem -Path "\Device"

        foreach ($Device in $Devices) {

            if (($Device.Type -eq "Device") -and ($Device.Name -like "*VolumeShadowCopy*")) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Volume" -Value $Device.Name
                $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $(Join-Path -Path "\\?\GLOBALROOT\Device\" -ChildPath $Device.Name)
                $Result
            }
        }
    }
}

function Get-UEFIStatus {
    <#
    .SYNOPSIS
    Helper - Gets the BIOS mode of the machine (Legacy / UEFI)

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Invokes the "GetFirmwareEnvironmentVariable()" function from the Windows API with dummy parameters. Indeed, the queried value doesn't matter, what matters is the last error code, which you can get by invoking "GetLastError()". If the return code is ERROR_INVALID_FUNCTION, this means that the function is not supported by the BIOS so it's LEGACY. Otherwise, the error code will indicate that it cannot find the requested variable, which means that the function is supported by the BIOS so it's UEFI.

    .EXAMPLE
    PS C:\> Get-UEFIStatus

    Name Status Description
    ---- ------ -----------
    UEFI   True BIOS mode is UEFI

    .NOTES
    https://github.com/xcat2/xcat-core/blob/master/xCAT-server/share/xcat/netboot/windows/detectefi.cpp
    https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariablea
    https://github.com/ChrisWarwick/GetUEFI/blob/master/GetFirmwareBIOSorUEFI.psm1
    #>

    [CmdletBinding()]
    param()

    $OsVersion = Get-WindowsVersionFromRegistry

    if (($OsVersion.Major -ge 10) -or (($OsVersion.Major -ge 6) -and ($OsVersion.Minor -ge 2))) {

        # Windows >= 8/2012

        $FirmwareType = Get-FirmwareType

        if ($FirmwareType -eq $script:FIRMWARE_TYPE::Bios) {
            $Status = $false
            $Description = "BIOS mode is Legacy."
        }
        elseif ($FirmwareType -eq $script:FIRMWARE_TYPE::Uefi) {
            $Status = $true
            $Description = "BIOS mode is UEFI."
        }
        else {
            $Description = "BIOS mode is unknown."
        }
    }
    elseif (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -eq 1)) {

        # Windows = 7/2008 R2

        $null = $script:Kernel32::GetFirmwareEnvironmentVariable("", "{00000000-0000-0000-0000-000000000000}", [IntPtr]::Zero, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if ($LastError -eq $script:SystemErrorCode::ERROR_INVALID_FUNCTION) {
            $Status = $false
            $Description = "BIOS mode is Legacy."
            Write-Verbose "GetFirmwareEnvironmentVariable - $(Format-Error $LastError)"
        }
        else {
            $Status = $true
            $Description = "BIOS mode is UEFI."
            Write-Verbose "GetFirmwareEnvironmentVariable - $(Format-Error $LastError)"
        }
    }
    else {
        $Description = "Cannot check BIOS mode."
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "UEFI"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result
}

function Get-SecureBootStatus {
    <#
    .SYNOPSIS
    Helper - Get the status of Secure Boot (enabled/disabled/unsupported)

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    In case of a UEFI BIOS, you can check whether 'Secure Boot' is enabled by looking at the 'UEFISecureBootEnabled' value of the following registry key: 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State'.

    .EXAMPLE
    PS C:\> Get-SecureBootStatus

    Key         : HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State
    Value       : UEFISecureBootEnabled
    Data        : 0
    Description : Secure Boot is disabled
    #>

    [CmdletBinding()]
    param()

    $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
    $RegValue = "UEFISecureBootEnabled"
    $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

    if ($null -ne $RegData) {
        if ($null -eq $RegData) {
            $Description = "Secure Boot is not supported."
        }
        else {
            $Description = "Secure Boot is $(if ($RegData -ne 1) { "not "})enabled."
        }
    }

    Write-Verbose "$($RegValue): $($Description)"

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
    $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
    $Result | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })
    $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $Result
}

function Get-MachineRole {

    [CmdletBinding()]
    param()

    begin {
        $FriendlyNames = @{
            "WinNT"    = "Workstation";
            "LanmanNT" = "Domain Controller";
            "ServerNT" = "Server";
        }
    }

    process {
        $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions"
        $RegValue = "ProductType"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue).$RegValue

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegData
        $Result | Add-Member -MemberType "NoteProperty" -Name "Role" -Value $(try { $FriendlyNames[$RegData] } catch { "" })
        $Result
    }
}

function Get-TpmDeviceInformation {
    <#
    .SYNOPSIS
    Helper - Collect various information about a TPM device

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet gathers almost the same information as the command "TpmTool.exe GetDeviceInformation". This was achieved mainly by reverse engineering TpmCoreProvisioning.dll. Therefore, the output of this command is not guaranteed to be 100% accurate.
    #>

    [CmdletBinding()]
    param ()

    begin {
        $TpmCoreProvisioningModulePresent = $false

        # Parameter for TpmIsLockedOut
        $IsLockedOut = 0
        # Parameters for TpmGetCapLockoutInfo
        $LockoutCounter = 0
        $MaxAuthFail = 0
        # Parameters for TpmGetDictionaryAttackParameters
        $DapMaxAuthFail = 0
        $DapLockoutInterval = 0
        $DapLockoutRecovery = 0

        $TpmCoreProvisioningModulePath = Resolve-ModulePath -Name "TpmCoreProvisioning"
        if ($null -ne $TpmCoreProvisioningModulePath) {
            $TpmCoreProvisioningModulePresent = $true
        }

        if ($TpmCoreProvisioningModulePresent) {
            $Result = New-Object -TypeName PSObject
        }
    }

    process {
        if (-not $TpmCoreProvisioningModulePresent) { return }

        $TpmDeviceInformation = [Activator]::CreateInstance($script:TPM_DEVICE_INFORMATION)

        $RetVal = $script:TpmCoreProvisioning::TpmGetDeviceInformation([ref] $TpmDeviceInformation)

        if ($RetVal -ne 0) {
            if ($RetVal -eq 0x800710DF) {
                $Result | Add-Member -MemberType "NoteProperty" -Name "TpmPresent" -Value $False
                Write-Warning "No TPM device found."
            }
            else {
                Write-Warning "TpmGetDeviceInformation KO 0x$("{0:X8}" -f $RetVal)"
            }
            return
        }

        $Result | Add-Member -MemberType "NoteProperty" -Name "TpmPresent" -Value $True

        if ($TpmDeviceInformation.TpmVersion -eq 0 -or $TpmDeviceInformation.TpmVersion -ge 3) {
            Write-Warning "Unknown TPM version: $($TpmDeviceInformation.TpmVersion)"
            return
        }

        # The flag 'IsInitialized' is always set to '1', and is not updated by the
        # function TpmGetDeviceInformation.
        $TpmDeviceInformation.IsInitialized = 1
        if ($TpmDeviceInformation.TpmVersion -eq 1) { $TpmDeviceInformationTpmVersion = "1.2" }
        if ($TpmDeviceInformation.TpmVersion -eq 2) { $TpmDeviceInformationTpmVersion = "2.0" }
        $TpmFirmwareVulnerability = $TpmDeviceInformation.TpmFirmwareVulnerability
        if ($TpmFirmwareVulnerability -eq 0) { $TpmFirmwareVulnerability = $script:TPM_VULNERABILITY::NONE }
        $TpmDeviceInformationManufacturerVersion = "$($TpmDeviceInformation.ManufacturerVersionMajor).$($TpmDeviceInformation.ManufacturerVersionMinor)"
        if ($TpmDeviceInformation.TpmVersion -eq 2) {
            $TpmDeviceInformationManufacturerVersion += ".$($TpmDeviceInformation.ManufacturerVersionSubMajor).$($TpmDeviceInformation.ManufacturerVersionSubMinor)"
        }
        $TpmDeviceInformationTpmErrataDate = ([DateTime]"01/01/$($TpmDeviceInformation.ErrataDateYear)").AddDays($TpmDeviceInformation.ErrataDateDayOfYear - 1)
        $TpmDeviceInformation.TpmFirmwareVulnerability = 1
        $Result | Add-Member -MemberType "NoteProperty" -Name "TpmVersion" -Value $TpmDeviceInformationTpmVersion
        $Result | Add-Member -MemberType "NoteProperty" -Name "ManufacturerId" -Value $TpmDeviceInformation.ManufacturerId
        $Result | Add-Member -MemberType "NoteProperty" -Name "ManufacturerDisplayName" -Value $TpmDeviceInformation.ManufacturerName
        $Result | Add-Member -MemberType "NoteProperty" -Name "ManufacturerVersion" -Value $TpmDeviceInformationManufacturerVersion
        $Result | Add-Member -MemberType "NoteProperty" -Name "PpiSpecVersion" -Value $TpmDeviceInformation.PpiSpecVersion
        $Result | Add-Member -MemberType "NoteProperty" -Name "IsInitialized" -Value $($TpmDeviceInformation.IsInitialized -as [Bool])
        $Result | Add-Member -MemberType "NoteProperty" -Name "ReadyForStorage" -Value $($TpmDeviceInformation.ReadyForStorage -as [Bool])
        $Result | Add-Member -MemberType "NoteProperty" -Name "ReadyForAttestation" -Value $($TpmDeviceInformation.ReadyForAttestation -as [Bool])
        $Result | Add-Member -MemberType "NoteProperty" -Name "IsCapableForAttestation" -Value $($TpmDeviceInformation.IsCapableForAttestation -as [Bool])
        $Result | Add-Member -MemberType "NoteProperty" -Name "ClearNeededToRecover" -Value $($TpmDeviceInformation.ClearNeededToRecover -as [Bool])
        $Result | Add-Member -MemberType "NoteProperty" -Name "ClearPossible" -Value $($TpmDeviceInformation.ClearPossible -as [Bool])
        $Result | Add-Member -MemberType "NoteProperty" -Name "TpmHasVulnerableFirmware" -Value $($TpmDeviceInformation.TpmHasVulnerableFirmware -as [Bool])
        $Result | Add-Member -MemberType "NoteProperty" -Name "TpmFirmwareVulnerability" -Value $TpmFirmwareVulnerability
        $Result | Add-Member -MemberType "NoteProperty" -Name "Pcr7BindingState" -Value $TpmDeviceInformation.Pcr7BindingState
        $Result | Add-Member -MemberType "NoteProperty" -Name "MaintenanceTaskComplete" -Value $($TpmDeviceInformation.MaintenanceTaskComplete -as [Bool])
        $Result | Add-Member -MemberType "NoteProperty" -Name "TpmSpecVersion" -Value $TpmDeviceInformation.TpmSpecVersionStr
        $Result | Add-Member -MemberType "NoteProperty" -Name "TpmErrataDate" -Value $TpmDeviceInformationTpmErrataDate
        $Result | Add-Member -MemberType "NoteProperty" -Name "PcClientVersion" -Value $TpmDeviceInformation.PcClientVersion

        if ($TpmDeviceInformation.TpmVersion -eq 1) {
            $Result | Add-Member -MemberType "NoteProperty" -Name "Tpm12SpecLevel" -Value $TpmDeviceInformation.Tpm12SpecLevel
            $Result | Add-Member -MemberType "NoteProperty" -Name "Tpm12SpecRevision" -Value $TpmDeviceInformation.Tpm12SpecRevision
        }

        $RetVal = $script:TpmCoreProvisioning::TpmIsLockedOut([ref] $IsLockedOut)
        if ($RetVal -ne 0) { Write-Warning "TpmIsLockedOut KO 0x$("{0:X8}" -f $RetVal)"; return }

        $Result | Add-Member -MemberType "NoteProperty" -Name "IsLockedOut" -Value $($IsLockedOut -as [Bool])

        $RetVal = $script:TpmCoreProvisioning::TpmGetCapLockoutInfo([ref] $LockoutCounter, [ref] $MaxAuthFail)
        if ($RetVal -ne 0) { Write-Warning "TpmGetDeviceInformation KO 0x$("{0:X8}" -f $RetVal)"; return }

        $Result | Add-Member -MemberType "NoteProperty" -Name "LockoutCounter" -Value $LockoutCounter

        $RetVal = $script:TpmCoreProvisioning::TpmGetDictionaryAttackParameters([ref] $DapMaxAuthFail, [ref] $DapLockoutInterval, [ref] $DapLockoutRecovery)
        if ($RetVal -ne 0) { Write-Warning "TpmGetDictionaryAttackParameters KO 0x$("{0:X8}" -f $RetVal)"; return }

        $Result | Add-Member -MemberType "NoteProperty" -Name "MaxAuthFail" -Value $DapMaxAuthFail
        $Result | Add-Member -MemberType "NoteProperty" -Name "LockoutInterval" -Value $DapLockoutInterval
        $Result | Add-Member -MemberType "NoteProperty" -Name "LockoutRecovery" -Value $DapLockoutRecovery
    }

    end {
        if ($TpmCoreProvisioningModulePresent) {
            $Result
        }
    }
}

function Get-TpmDeviceType {
    <#
    .SYNOPSIS
    Helper - Determine (or rather guess) a TPM type given a vendor ID

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet attempts to guess the type of a TPM given its vendor (or manufacturer) ID. For example, it is assumed that a TPM with the vendor ID 'IFX' (Infineon) is necessarily a discrete TPMs, while a TPM with the vendor ID 'IBM' is necessarily a virtual (or software) TPM. There are some nuances as well. For example, a TPM with the vendor ID 'INTC' could be either an integrated TPM, or a firmware TPM. Therefore, this cmdlet returns an integer representing a combination of flags defined in the enum 'TPM_DEVICE_TYPE'. If the TPM type cannot be determined, this cmdlet returns the special flag value 'Unknown'.

    .PARAMETER ManufacturerId
    A vendor ID attributed by the Trusted Computing Group (TCG) - See reference in the 'LINK' section.

    .LINK
    https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.06-Revision-0.96_pub.pdf
    #>

    [CmdletBinding()]
    param (
        [string] $ManufacturerId
    )

    begin {
        # Note: vendor IDs are represented by 4 bytes, or rather 4 ASCII chars.
        # IDs made of 3 characters are generally padded with a null byte, except
        # for 'NSM' and 'STM', which are padded with a space! Interestingly enough,
        # this is not defined by the TCG, but rather by the ID requestor (ie the
        # vendor).
        $DiscreteTpmVendorIds = @("ATML", "CSCO", "FLYS", "IFX", "NSG", "NSM ", "NTC", "NTZ", "SNS", "STM ")
        $IntegratedTpmVendorIds = @("BRCM", "INTC", "ROCC", "SMSC", "TXN")
        $FirmwareTpmVendorIds = @("AMD", "HISI", "HPE", "INTC", "LEN", "QCOM", "SECE", "SMSN")
        $VirtualTpmVendorIds = @("IBM", "GOOG", "MSFT")
        $TpmType = $script:TPM_DEVICE_TYPE::Unknown
    }

    process {
        if (-not [String]::IsNullOrEmpty($ManufacturerId)) {
            $TpmType = 0
            # Note: we need to check all the vendor ID lists because multiple TPM types
            # can be associated to a vendor ID. For example, a TPM with the vendor ID
            # 'INTC' (Intel) can be either an integrated TPM or a firmware TPM.
            if ($DiscreteTpmVendorIds -contains $ManufacturerId) { $TpmType += $script:TPM_DEVICE_TYPE::Discrete }
            if ($IntegratedTpmVendorIds -contains $ManufacturerId) { $TpmType += $script:TPM_DEVICE_TYPE::Integrated }
            if ($FirmwareTpmVendorIds -contains $ManufacturerId) { $TpmType += $script:TPM_DEVICE_TYPE::Firmware }
            if ($VirtualTpmVendorIds -contains $ManufacturerId) { $TpmType += $script:TPM_DEVICE_TYPE::Virtual }
            if ($TpmType -eq 0) { $script:TPM_DEVICE_TYPE::Unknown }
        }
    }

    end {
        $TpmType -as $script:TPM_DEVICE_TYPE
    }
}

function Get-SystemInformation {
    <#
    .SYNOPSIS
    Get basic software and hardware system information

    .DESCRIPTION
    This cmdlet collects system information similarly to what the internal function "WriteSystemInformation" in "TpmCoreProvisioning" does.

    .EXAMPLE
    C:\> Get-SystemInformation

    ProductName           : Windows 10 Pro
    BuildString           : 22621.1.amd64fre.ni_release.220506-1250
    BaseBoardManufacturer :
    BaseBoardProduct      :
    BiosMode              : Uefi
    BIOSReleaseDate       : 08/13/2024
    BIOSVendor            : EDK II
    BIOSVersion           : edk2-20240813-1.fc40
    SystemFamily          :
    SystemManufacturer    : QEMU
    SystemProductName     : Standard PC (Q35 + ICH9, 2009)
    SystemSKU             :
    #>

    [CmdletBinding()]
    param ()

    begin {
        $SoftwareRegKey = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $HardwareRegKey = "HKLM\HARDWARE\DESCRIPTION\System\BIOS"
    }

    process {
        $RegValue = "ProductName"
        $ProductName = (Get-ItemProperty -Path "Registry::$($SoftwareRegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $RegValue = "BuildLabEx"
        $BuildString = (Get-ItemProperty -Path "Registry::$($SoftwareRegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $RegValue = "BaseBoardManufacturer"
        $BaseBoardManufacturer = (Get-ItemProperty -Path "Registry::$($HardwareRegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $RegValue = "BaseBoardProduct"
        $BaseBoardProduct = (Get-ItemProperty -Path "Registry::$($HardwareRegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $BiosMode = Get-FirmwareType

        $RegValue = "BIOSReleaseDate"
        $BiosReleaseDate = (Get-ItemProperty -Path "Registry::$($HardwareRegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $RegValue = "BIOSVendor"
        $BiosVendor = (Get-ItemProperty -Path "Registry::$($HardwareRegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $RegValue = "BIOSVersion"
        $BiosVersion = (Get-ItemProperty -Path "Registry::$($HardwareRegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $RegValue = "SystemFamily"
        $SystemFamily = (Get-ItemProperty -Path "Registry::$($HardwareRegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $RegValue = "SystemManufacturer"
        $SystemManufacturer = (Get-ItemProperty -Path "Registry::$($HardwareRegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $RegValue = "SystemProductName"
        $SystemProductName = (Get-ItemProperty -Path "Registry::$($HardwareRegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $RegValue = "SystemSKU"
        $SystemSKU = (Get-ItemProperty -Path "Registry::$($HardwareRegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value $ProductName
        $Result | Add-Member -MemberType "NoteProperty" -Name "BuildString" -Value $BuildString
        $Result | Add-Member -MemberType "NoteProperty" -Name "BaseBoardManufacturer" -Value $BaseBoardManufacturer
        $Result | Add-Member -MemberType "NoteProperty" -Name "BaseBoardProduct" -Value $BaseBoardProduct
        $Result | Add-Member -MemberType "NoteProperty" -Name "BiosMode" -Value $BiosMode
        $Result | Add-Member -MemberType "NoteProperty" -Name "BiosReleaseDate" -Value $(Convert-DateToString -Date $BiosReleaseDate)
        $Result | Add-Member -MemberType "NoteProperty" -Name "BiosVendor" -Value $BiosVendor
        $Result | Add-Member -MemberType "NoteProperty" -Name "BiosVersion" -Value $BiosVersion
        $Result | Add-Member -MemberType "NoteProperty" -Name "SystemFamily" -Value $SystemFamily
        $Result | Add-Member -MemberType "NoteProperty" -Name "SystemManufacturer" -Value $SystemManufacturer
        $Result | Add-Member -MemberType "NoteProperty" -Name "SystemProductName" -Value $SystemProductName
        $Result | Add-Member -MemberType "NoteProperty" -Name "SystemSKU" -Value $SystemSKU
        $Result
    }
}

function Get-WindowsVersionFromRegistry {

    [CmdletBinding()]
    param()

    $RegKey = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    $RegItem = Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue

    if ($null -eq $RegItem) {
        [System.Environment]::OSVersion.Version
        return
    }

    $Major = $RegItem.CurrentMajorVersionNumber
    $Minor = $RegItem.CurrentMinorVersionNumber

    if ($null -eq $Major) { $Major = $RegItem.CurrentVersion.Split(".")[0] }
    if ($null -eq $Minor) { $Minor = $RegItem.CurrentVersion.Split(".")[1] }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Major" -Value ([UInt32] $Major)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Minor" -Value ([UInt32] $Minor)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Build" -Value ([UInt32] $RegItem.CurrentBuildNumber)
    $Result | Add-Member -MemberType "NoteProperty" -Name "Revision" -Value 0
    $Result | Add-Member -MemberType "NoteProperty" -Name "MajorRevision" -Value 0
    $Result | Add-Member -MemberType "NoteProperty" -Name "MinorRevision" -Value 0
    $Result | Add-Member -MemberType "NoteProperty" -Name "ReleaseId" -Value $RegItem.ReleaseId
    $Result | Add-Member -MemberType "NoteProperty" -Name "UBR" -Value $RegItem.UBR
    $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value $RegItem.ProductName
    $Result
}

function Get-ServiceFromRegistry {
    <#
    .SYNOPSIS
    Helper - Enumerates services (based on the registry)

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet uses the registry to enumerate the services in the registry key "HKLM\SYSTEM\CurrentControlSet\Services". This allows any user to get information about all the services. So, even if non-privileged users can't access the details of a service through the Service Control Manager, they can do so simply by accessing the registry.

    .PARAMETER FilterLevel
    This parameter can be used to filter out the result returned by the function based on the
    following criteria:
        FilterLevel = 0 - No filtering
        FilterLevel = 1 - Exclude 'Services with empty ImagePath'
        FilterLevel = 2 - Exclude 'Services with empty ImagePath' + 'Drivers'
        FilterLevel = 3 - Exclude 'Services with empty ImagePath' + 'Drivers' + 'Known services'

    .EXAMPLE
    PS C:\> Get-ServiceFromRegistry -FilterLevel 3

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
        [ValidateSet(0, 1, 2, 3)]
        [UInt32] $FilterLevel = 1
    )

    begin {
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection

        function Get-ServiceFromRegistryHelper {
            param (
                [Parameter(Mandatory = $true)]
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
            $Result | Add-Member -MemberType "NoteProperty" -Name "StartMode" -Value ($RegItem.Start -as $script:ServiceStartType)
            $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value ($RegItem.Type -as $script:ServiceType)
            $Result | Add-Member -MemberType "NoteProperty" -Name "RegistryKey" -Value $RegKeyServices
            $Result | Add-Member -MemberType "NoteProperty" -Name "RegistryPath" -Value $RegKey
            $Result
        }
    }

    process {

        if (-not (Test-CachedData -Name "ServiceList")) {

            $ServiceList = @()

            $ServicesRegPath = "HKLM\SYSTEM\CurrentControlSet\Services"
            $RegAllServices = Get-ChildItem -Path "Registry::$($ServicesRegPath)" -ErrorAction SilentlyContinue

            $RegAllServices | ForEach-Object {
                $ServiceList += $(Get-ServiceFromRegistryHelper -Name $_.PSChildName)
            }

            Set-CachedData -Name "ServiceList" -Data $ServiceList
        }

        $ServiceList = Get-CachedData -Name "ServiceList"

        foreach ($ServiceItem in $ServiceList) {

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

                $TypeMask = $script:ServiceType::Win32OwnProcess -bor $script:ServiceType::Win32ShareProcess -bor $script:ServiceType::InteractiveProcess
                if (($ServiceItem.Type -band $TypeMask) -gt 0) {

                    # FilterLevel = 2 - Add the service to the list if it's not a driver
                    if ($FilterLevel -le 2) { $ServiceItem; continue }

                    # Resolve the service's command line, return immediately if it fails.
                    $CommandLineResolved = [string[]] (Resolve-CommandLine -CommandLine $ServiceItem.ImagePath.trim())
                    if ($null -eq $CommandLineResolved) { $ServiceItem; continue }

                    $ExecutableFile = Get-Item -Path $CommandLineResolved[0] -ErrorAction SilentlyContinue
                    if ($null -eq $ExecutableFile) { $ServiceItem; continue }

                    # FilterLevel = 3 - Add the service if it's not a built-in Windows service
                    if (($FilterLevel -le 3) -and (-not $(Test-IsMicrosoftFile -File $ExecutableFile))) {
                        $ServiceItem; continue
                    }
                }
            }
        }
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Get-KernelDriver {

    [CmdletBinding()]
    param()

    if (-not (Test-CachedData -Name "DriverList")) {

        $DriverList = @()

        $Services = Get-ServiceFromRegistry -FilterLevel 1 | Where-Object { @('KernelDriver', 'FileSystemDriver', 'RecognizerDriver') -contains $_.Type }

        foreach ($Service in $Services) {

            $ImagePath = Resolve-KernelDriverImagePath -Service $Service
            if (-not (Test-Path -Path $ImagePath -ErrorAction SilentlyContinue)) { Write-Warning "Service: $($Service.Name) | Path not found: $($ImagePath)"; continue }

            $Service | Add-Member -MemberType "NoteProperty" -Name "ImagePathResolved" -Value $ImagePath

            $DriverList += $Service
        }

        Set-CachedData -Name "DriverList" -Data $DriverList
    }

    Get-CachedData -Name "DriverList"
}

function Get-NetworkAdapter {
    <#
    .SYNOPSIS
    List network adapters.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function leverages the Windows API (GetAdaptersAddresses) to list the network adapters.

    .PARAMETER All
    Specify this option to list all NDIS interfaces.

    .EXAMPLE
    PS C:\> Get-NetworkAdapter

    Name             : {B52615AE-995C-415B-9925-0C0815A81598}
    FriendlyName     : Ethernet0
    Type             : Ethernet
    Status           : Up
    ConnectionType   : Dedicated
    TunnelType       : None
    TxSpeed          : 1000000000
    RxSpeed          : 1000000000
    DnsSuffix        : localdomain
    Description      : Intel(R) 82574L Gigabit Network Connection
    PhysicalAddress  : 00:0c:29:1e:2b:00
    Flags            : DdnsEnabled, Dhcpv4Enabled, Ipv4Enabled, Ipv6Enabled
    IPv6             : fe:80::1:e9:ec:a:a7:a2:99:3f (/64)
    IPv4             : 192.168.140.130 (/24)
    Gateway          : 192.168.140.2
    DHCPv4Server     : 192.168.140.254
    DHCPv6Server     :
    DHCPv6IAID       : 100666409
    DHCPv6ClientDUID : 00:01:00:01:28:2e:96:5d:00:0c:29:1e:2b:00
    DnsServers       : 192.168.140.2
    WINSServers      : 192.168.140.2
    DnsSuffixList    :
    #>

    [CmdletBinding()]
    param(
        [switch] $All = $false
    )

    $InterfaceTypes = @{
        'Other'     = 1
        'Ethernet'  = 6
        'TokenRing' = 9
        'PPP'       = 23
        'Loopback'  = 24
        'ATM'       = 37
        'IEEE80211' = 71
        'Tunnel'    = 131
        'IEEE1394'  = 144
    }

    $InterfacesStatuses = @{
        'Up'             = 1
        'Down'           = 2
        'Testing'        = 3
        'Unknown'        = 4
        'Dormant'        = 5
        'NotPresent'     = 6
        'LowerLayerDown' = 7
    }

    $ConnectionTypes = @{
        'Dedicated' = 1
        'Passive'   = 2
        'Demand'    = 3
        'Maximum'   = 4
    }

    $TunnelTypes = @{
        'None'    = 0
        'Other'   = 1
        'Direct'  = 2
        '6to4'    = 11
        'ISATAP'  = 13
        'TEREDO'  = 14
        'IPHTTPS' = 15
    }

    $GAA_FLAG_INCLUDE_PREFIX = 0x0010
    $GAA_FLAG_INCLUDE_WINS_INFO = 0x0040
    $GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
    $GAA_FLAG_INCLUDE_ALL_INTERFACES = 0x0100

    $Family = 0 # AF_UNSPEC
    $Flags = $GAA_FLAG_INCLUDE_PREFIX -bor $GAA_FLAG_INCLUDE_WINS_INFO -bor $GAA_FLAG_INCLUDE_GATEWAYS
    if ($All) { $Flags = $Flags -bor $GAA_FLAG_INCLUDE_ALL_INTERFACES }
    $AdaptersSize = 0
    $Result = $script:Iphlpapi::GetAdaptersAddresses($Family, $Flags, [IntPtr]::Zero, [IntPtr]::Zero, [ref] $AdaptersSize)

    if ($AddressesSize -eq 0) {
        Write-Verbose "GetAdaptersAddresses KO - Error: $Result"
        return
    }

    Write-Verbose "GetAdaptersAddresses OK - Size: $AdaptersSize"

    $AdaptersPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($AdaptersSize)
    $Result = $script:Iphlpapi::GetAdaptersAddresses($Family, $Flags, [IntPtr]::Zero, $AdaptersPtr, [ref] $AdaptersSize)

    if ($Result -ne 0) {
        Write-Verbose "GetAdaptersAddresses KO - Error: $Result"
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($AdaptersSize)
        return
    }

    Write-Verbose "GetAdaptersAddresses OK"

    do {
        $Adapter = [System.Runtime.InteropServices.Marshal]::PtrToStructure($AdaptersPtr, [type] $script:IP_ADAPTER_ADDRESSES)

        # Interface type
        $InterfaceType = $InterfaceTypes.GetEnumerator() | Where-Object { $_.value -eq $Adapter.IfType } | ForEach-Object { $_.Name }

        # Status
        $InterfaceStatus = $InterfacesStatuses.GetEnumerator() | Where-Object { $_.value -eq $Adapter.OperStatus } | ForEach-Object { $_.Name }

        # Connection type
        $ConnectionType = $ConnectionTypes.GetEnumerator() | Where-Object { $_.value -eq $Adapter.ConnectionType } | ForEach-Object { $_.Name }

        # Tunnel type
        $TunnelType = $TunnelTypes.GetEnumerator() | Where-Object { $_.value -eq $Adapter.TunnelType } | ForEach-Object { $_.Name }

        # Friendly representation of the physical address
        $AdapterPhysicalAddress = ""
        if ($Adapter.PhysicalAddressLength -ne 0) {
            $AdapterPhysicalAddress = $(for ($i = 0; $i -lt $Adapter.PhysicalAddressLength; $i++) { "{0:x2}" -f $Adapter.PhysicalAddress[$i] }) -join ":"
        }

        # Unicast addresses
        $UnicastAddresses = @()
        $UnicastAddressPtr = $Adapter.FirstUnicastAddress
        while ($UnicastAddressPtr -ne [IntPtr]::Zero) {
            $UnicastAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($UnicastAddressPtr, [type] $script:IP_ADAPTER_UNICAST_ADDRESS_LH)
            $AddrObject = Convert-SocketAddressToObject -SocketAddress $UnicastAddress.Address
            $AddrObject.IPAddress = "$($AddrObject.IPAddress) (/$($UnicastAddress.OnLinkPrefixLength))"
            $UnicastAddresses += $AddrObject
            $UnicastAddressPtr = $UnicastAddress.Next
        }

        # DNS servers
        $DnsServerAddresses = @()
        $DnsServerAddressPtr = $Adapter.FirstDnsServerAddress
        while ($DnsServerAddressPtr -ne [IntPtr]::Zero) {
            $DnsServerAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($DnsServerAddressPtr, [type] $script:IP_ADAPTER_DNS_SERVER_ADDRESS_XP)
            $AddrObject = Convert-SocketAddressToObject -SocketAddress $DnsServerAddress.Address
            $DnsServerAddresses += $AddrObject
            $DnsServerAddressPtr = $DnsServerAddress.Next
        }

        # WINS server
        $WinsServerAddresses = @()
        $WinsServerAddressPtr = $Adapter.FirstWinsServerAddress
        while ($WinsServerAddressPtr -ne [IntPtr]::Zero) {
            $WinServerAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WinsServerAddressPtr, [type] $script:IP_ADAPTER_WINS_SERVER_ADDRESS_LH)
            $AddrObject = Convert-SocketAddressToObject -SocketAddress $WinServerAddress.Address
            $WinsServerAddresses += $AddrObject
            $WinsServerAddressPtr = $WinServerAddress.Next
        }

        # Gateway
        $GatewayAddresses = @()
        $GatewayAddressPtr = $Adapter.FirstGatewayAddress
        while ($GatewayAddressPtr -ne [IntPtr]::Zero) {
            $GatewayAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($GatewayAddressPtr, [type] $script:IP_ADAPTER_GATEWAY_ADDRESS_LH)
            $AddrObject = Convert-SocketAddressToObject -SocketAddress $GatewayAddress.Address
            $GatewayAddresses += $AddrObject
            $GatewayAddressPtr = $GatewayAddress.Next
        }

        # DNS suffix search list
        $DnsSuffixList = @()
        $DnsSuffixPtr = $Adapter.FirstDnsSuffix
        while ($DnsSuffixPtr -ne [IntPtr]::Zero) {
            $DnsSuffix = [System.Runtime.InteropServices.Marshal]::PtrToStructure($DnsSuffixPtr, [type] $script:IP_ADAPTER_DNS_SUFFIX)
            [string[]] $DnsSuffixList += $DnsSuffix.String
            $DnsSuffixPtr = $DnsSuffix.Next
        }

        # DHCPv4 server
        $Dhcpv4Server = Convert-SocketAddressToObject -SocketAddress $Adapter.Dhcpv4Server

        # DHCPv6 server
        $Dhcpv6Server = Convert-SocketAddressToObject -SocketAddress $Adapter.Dhcpv6Server
        $Dhcpv6ClientDuid = $(for ($i = 0; $i -lt $Adapter.Dhcpv6ClientDuidLength; $i++) { '{0:x2}' -f $Adapter.Dhcpv6ClientDuid[$i] }) -join ":"

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Adapter.AdapterName
        $Result | Add-Member -MemberType "NoteProperty" -Name "FriendlyName" -Value $Adapter.FriendlyName
        $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $InterfaceType
        $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $InterfaceStatus
        $Result | Add-Member -MemberType "NoteProperty" -Name "ConnectionType" -Value $ConnectionType
        $Result | Add-Member -MemberType "NoteProperty" -Name "TunnelType" -Value $TunnelType
        $Result | Add-Member -MemberType "NoteProperty" -Name "TxSpeed" -Value $Adapter.TransmitLinkSpeed
        $Result | Add-Member -MemberType "NoteProperty" -Name "RxSpeed" -Value $Adapter.ReceiveLinkSpeed
        $Result | Add-Member -MemberType "NoteProperty" -Name "DnsSuffix" -Value $Adapter.DnsSuffix
        $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Adapter.Description
        $Result | Add-Member -MemberType "NoteProperty" -Name "PhysicalAddress" -Value $AdapterPhysicalAddress
        $Result | Add-Member -MemberType "NoteProperty" -Name "Flags" -Value ($Adapter.Flags -as $script:IP_ADAPTER_FLAGS)
        $Result | Add-Member -MemberType "NoteProperty" -Name "IPv6" -Value (($UnicastAddresses | Where-Object { $_.Family -eq 23 } | ForEach-Object { $_.IPAddress }) -join ", ")
        $Result | Add-Member -MemberType "NoteProperty" -Name "IPv4" -Value (($UnicastAddresses | Where-Object { $_.Family -eq 2 } | ForEach-Object { $_.IPAddress }) -join ", ")
        $Result | Add-Member -MemberType "NoteProperty" -Name "Gateway" -Value (($GatewayAddresses | ForEach-Object { $_.IPAddress }) -join ", ")
        $Result | Add-Member -MemberType "NoteProperty" -Name "DHCPv4Server" -Value $Dhcpv4Server.IPAddress
        $Result | Add-Member -MemberType "NoteProperty" -Name "DHCPv6Server" -Value $Dhcpv6Server.IPAddress
        $Result | Add-Member -MemberType "NoteProperty" -Name "DHCPv6IAID" -Value $(if ($Adapter.Dhcpv6Iaid -ne 0) { $Adapter.Dhcpv6Iaid } else { $null })
        $Result | Add-Member -MemberType "NoteProperty" -Name "DHCPv6ClientDUID" -Value $Dhcpv6ClientDuid
        $Result | Add-Member -MemberType "NoteProperty" -Name "DnsServers" -Value (($DnsServerAddresses | ForEach-Object { $_.IPAddress }) -join ", ")
        $Result | Add-Member -MemberType "NoteProperty" -Name "WINSServers" -Value (($WinsServerAddresses | ForEach-Object { $_.IPAddress }) -join ", ")
        $Result | Add-Member -MemberType "NoteProperty" -Name "DNSSuffixList" -Value ($DnsSuffixList -join ", ")
        $Result

        [IntPtr] $AdaptersPtr = $Adapter.Next

    } while ($AdaptersPtr -ne [IntPtr]::Zero)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($AdaptersPtr)
}

function Get-WlanProfileList {
    <#
    .SYNOPSIS
    Enumerates the saved Wifi profiles.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet leverages the WLAN API to enumerate saved Wi-Fi profiles. WLAN profiles are stored as XML document. For each profile, the helper cmdlet 'Convert-WlanXmlProfile' is invoked in order to transform this XML document into a custom PS object that is easier to check. In case of a WPA2-PSK profile, the clear-text passphrase will be returned (if possible). In case of a 802.1x profile, detailed information will be returned, depending of the type of authentication.

    .EXAMPLE
    PS C:\> Get-WlanProfileList

    SSID           : wpa2-psk-ap
    ConnectionType : ESS (Infrastructure)
    ConnectionMode : manual
    Authentication : WPA2PSK
    Encryption     : AES
    PassPhrase     : ClearTextPassphraseHere
    Dot1X          : False

    SSID                          : ttls-ap
    ConnectionType                : ESS (Infrastructure)
    ConnectionMode                : auto
    Authentication                : WPA2
    Encryption                    : AES
    PassPhrase                    :
    Dot1X                         : True
    AuthenticationMode            : machineOrUser
    AuthenticationModeDescription : Use user credentials when a user is logged on, use machine credentials otherwise.
    EapTypeId                     : 21
    EapType                       : EAP-TTLS
    Eap                           : @{ServerValidationDisablePrompt=False; ServerValidationDisablePromptDescription=The user can be prompted for server validation.; ServerValidationNames=;
                                    TrustedRootCAs=8f43288ad272f3103b6fb1428485ea3014c0bcfe; TrustedRootCAsDescription=Microsoft Root Certificate Authority 2011}
    EapStr                        : ServerValidationDisablePrompt            : False
                                    ServerValidationDisablePromptDescription : The user can be prompted for server validation.
                                    ServerValidationNames                    :
                                    TrustedRootCAs                           : 8f43288ad272f3103b6fb1428485ea3014c0bcfe
                                    TrustedRootCAsDescription                : Microsoft Root Certificate Authority 2011
    #>

    [CmdletBinding()]
    param()

    try {

        [IntPtr] $ClientHandle = [IntPtr]::Zero
        [UInt32] $NegotiatedVersion = 0
        [UInt32] $ClientVersion = 2 # Client version for Windows Vista and Windows Server 2008
        $Result = $script:Wlanapi::WlanOpenHandle($ClientVersion, [IntPtr]::Zero, [ref] $NegotiatedVersion, [ref] $ClientHandle)
        if ($Result -ne 0) {
            Write-Warning "WlanOpenHandle - $(Format-Error $Result)"
            return
        }

        [IntPtr] $InterfaceListPtr = [IntPtr]::Zero
        $Result = $script:Wlanapi::WlanEnumInterfaces($ClientHandle, [IntPtr]::Zero, [ref] $InterfaceListPtr)
        if ($Result -ne 0) {
            Write-Warning "WlanEnumInterfaces - $(Format-Error $Result)"
            $script:Wlanapi::WlanCloseHandle($ClientHandle, [IntPtr]::Zero)
            return
        }

        $NumberOfInterfaces = [Runtime.InteropServices.Marshal]::ReadInt32($InterfaceListPtr)
        Write-Verbose "Number of WLAN interfaces: $($NumberOfInterfaces)"

        $WlanInterfaceInfoPtr = [IntPtr] ($InterfaceListPtr.ToInt64() + 8) # dwNumberOfItems + dwIndex

        for ($i = 0; $i -lt $NumberOfInterfaces; $i++) {

            $WlanInterfaceInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WlanInterfaceInfoPtr, [type] $script:WLAN_INTERFACE_INFO)

            [IntPtr] $ProfileListPtr = [IntPtr]::Zero
            $Result = $script:Wlanapi::WlanGetProfileList($ClientHandle, $WlanInterfaceInfo.InterfaceGuid, [IntPtr]::Zero, [ref] $ProfileListPtr)
            if ($Result -eq 0) {

                $NumberOfProfiles = [Runtime.InteropServices.Marshal]::ReadInt32($ProfileListPtr)
                Write-Verbose "Number of WLAN profiles: $($NumberOfProfiles)"

                $WlanProfileInfoPtr = [IntPtr] ($ProfileListPtr.ToInt64() + 8) # dwNumberOfItems + dwIndex

                for ($j = 0; $j -lt $NumberOfProfiles; $j++) {

                    $WlanProfileInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WlanProfileInfoPtr, [type] $script:WLAN_PROFILE_INFO)

                    [String] $ProfileXml = ""
                    [UInt32] $WlanProfileFlags = 4 # WLAN_PROFILE_GET_PLAINTEXT_KEY
                    [UInt32] $WlanProfileAccessFlags = 0
                    $Result = $script:Wlanapi::WlanGetProfile($ClientHandle, $WlanInterfaceInfo.InterfaceGuid, $WlanProfileInfo.ProfileName, [IntPtr]::Zero, [ref] $ProfileXml, [ref] $WlanProfileFlags, [ref] $WlanProfileAccessFlags)
                    if ($Result -eq 0) {
                        Convert-WlanXmlProfile -WlanProfile $ProfileXml
                    }
                    else {
                        Write-Warning "WlanGetProfile - $(Format-Error $Result)"
                    }

                    $WlanProfileInfoPtr = [IntPtr] ($WlanProfileInfoPtr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($WlanProfileInfo))
                }

                $script:Wlanapi::WlanFreeMemory($ProfileListPtr)
            }
            else {
                Write-Warning "WlanGetProfileList - $(Format-Error $Result)"
            }

            $WlanInterfaceInfoPtr = [IntPtr] ($WlanInterfaceInfoPtr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($WlanInterfaceInfo))
        }

        $null = $script:Wlanapi::WlanFreeMemory($InterfaceListPtr)
        $null = $script:Wlanapi::WlanCloseHandle($ClientHandle, [IntPtr]::Zero)
    }
    catch {
        # The Wlan API probably does not exist on this machine.
        if ($Error[0]) { Write-Warning $Error[0] }
    }
}

function Get-ComScheduledTask {
    <#
    .SYNOPSIS
    Helper - Enumerate registered scheduled tasks using COM.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet enumerates all registered scheduled tasks through the 'Schedule.Service' COM object. The result is not guaranteed to be exhaustive as the list of returned objects may differ depending on the current user's security context. Some scheduled tasks might require administrator privileges to be read.
    #>

    [CmdletBinding()]
    param ()

    begin {
        function Get-ComScheduledTaskHelper {
            param ([Object] $Service, [String] $Path)
            ($Folder = $Service.GetFolder($Path)).GetTasks(1)
            $Folder.GetFolders(0) | ForEach-Object {
                Get-ComScheduledTaskHelper -Service $Service -Path $(Join-Path -Path $Path -ChildPath $_.Name )
            }
        }
    }

    process {
        $ScheduleService = New-Object -ComObject("Schedule.Service")
        $ScheduleService.Connect()
        Get-ComScheduledTaskHelper -Path "\" -Service $ScheduleService
    }
}

function Get-RegisteredScheduledTask {
    <#
    .SYNOPSIS
    Helper - Enumerate registered scheduled tasks

    .DESCRIPTION
    This cmdlet lists all accessible scheduled tasks and extracts information about the principal it runs as, as well as the actions executed when the task is triggered.

    .EXAMPLE
    PS C:\> Get-RegisteredScheduledTask

    ...

    Name              : XblGameSaveTask
    Path              : \Microsoft\XblGameSave\XblGameSaveTask
    FilePath          : C:\WINDOWS\System32\Tasks\Microsoft\XblGameSave\XblGameSaveTask
    Enabled           : True
    RunAs             : @{Id=LocalSystem; UserId=S-1-5-18; User=NT AUTHORITY\SYSTEM; LogonType=; GroupId=; Group=; DisplayName=; RunLevel=; ProcessTokenSidType=; RequiredPrivileges=}
    ExecActions       : {@{Command=%windir%\System32\XblGameSaveTask.exe; Arguments=standby; WorkingDirectory=}}
    ComHandlerActions : {}
    SecurityInfo      : @{Owner=BUILTIN\Administrators; OwnerSid=S-1-5-32-544; Group=S-1-5-21-4024195226-107334468-2656468696-513; GroupSid=S-1-5-21-4024195226-107334468-2656468696-513; Dacl=System.Object[];
                        Sddl=O:BAG:S-1-5-21-4024195226-107334468-2656468696-513D:AI(A;ID;0x1f019f;;;BA)(A;ID;0x1f019f;;;SY)(A;ID;FR;;;AU)(A;ID;FR;;;LS)(A;ID;FR;;;NS)(A;ID;FA;;;BA)}

    ...

    .LINK
    https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema
    #>

    [CmdletBinding()]
    param ()

    process {

        if (-not (Test-CachedData -Name "ScheduledTaskList")) {

            $ScheduledTaskList = @()

            foreach ($ComTask in (Get-ComScheduledTask)) {

                $TaskXml = [xml] $ComTask.Xml

                $TaskPrincipals = @()
                $TaskXml.GetElementsByTagName("Principals").ChildNodes | ForEach-Object {

                    $TaskPrincipal = New-Object -TypeName PSObject
                    $TaskPrincipal | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $_.GetAttribute("id")
                    $TaskPrincipal | Add-Member -MemberType "NoteProperty" -Name "UserId" -Value $_.UserId
                    $TaskPrincipal | Add-Member -MemberType "NoteProperty" -Name "User" -Value (Convert-SidToName -Sid $_.UserId)
                    $TaskPrincipal | Add-Member -MemberType "NoteProperty" -Name "LogonType" -Value $_.LogonType
                    $TaskPrincipal | Add-Member -MemberType "NoteProperty" -Name "GroupId" -Value $_.GroupId
                    $TaskPrincipal | Add-Member -MemberType "NoteProperty" -Name "Group" -Value (Convert-SidToName -Sid $_.GroupId)
                    $TaskPrincipal | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value $_.DisplayName
                    $TaskPrincipal | Add-Member -MemberType "NoteProperty" -Name "RunLevel" -Value $_.RunLevel
                    $TaskPrincipal | Add-Member -MemberType "NoteProperty" -Name "ProcessTokenSidType" -Value $_.ProcessTokenSidType
                    $TaskPrincipal | Add-Member -MemberType "NoteProperty" -Name "RequiredPrivileges" -Value $_.RequiredPrivileges
                    $TaskPrincipals += $TaskPrincipal
                }

                $TaskActions = $TaskXml.GetElementsByTagName("Actions")
                $RunAsPrincipal = $TaskPrincipals | Where-Object { $_.Id -eq $TaskActions.GetAttribute("Context") }

                $ExecActions = @()
                $ComHandlerActions = @()

                $TaskActions.ChildNodes | ForEach-Object {

                    $Action = $_

                    switch ($Action.Name) {
                        "Exec" {
                            $ExecAction = New-Object -TypeName PSObject
                            $ExecAction | Add-Member -MemberType "NoteProperty" -Name "Command" -Value $Action.Command
                            $ExecAction | Add-Member -MemberType "NoteProperty" -Name "Arguments" -Value $Action.Arguments
                            $ExecAction | Add-Member -MemberType "NoteProperty" -Name "WorkingDirectory" -Value $Action.WorkingDirectory
                            $ExecActions += $ExecAction
                        }
                        "ComHandler" {
                            $ComHandlerAction = New-Object -TypeName PSObject
                            $ComHandlerAction | Add-Member -MemberType "NoteProperty" -Name "ClassId" -Value $Action.ClassId
                            $ComHandlerAction | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $Action.Data
                            $ComHandlerActions += $ComHandlerAction
                        }
                        "SendEmail" {
                            # We are not interested in this type of action.
                        }
                        "ShowMessage" {
                            # We are not interested in this type of action.
                        }
                    }
                }

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $ComTask.Name
                $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $ComTask.Path
                $Result | Add-Member -MemberType "NoteProperty" -Name "FilePath" -Value (Join-Path -Path $(Join-Path -Path $env:windir -ChildPath "System32\Tasks") -ChildPath $ComTask.Path)
                $Result | Add-Member -MemberType "NoteProperty" -Name "Enabled" -Value $ComTask.Enabled
                $Result | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value $RunAsPrincipal
                $Result | Add-Member -MemberType "NoteProperty" -Name "ExecActions" -Value $ExecActions
                $Result | Add-Member -MemberType "NoteProperty" -Name "ComHandlerActions" -Value $ComHandlerActions
                $Result | Add-Member -MemberType "NoteProperty" -Name "SecurityInfo" -Value (Get-ScheduledTaskSecurityInfo -Task $ComTask)
                $ScheduledTaskList += $Result
            }

            Set-CachedData -Name "ScheduledTaskList" -Data $ScheduledTaskList
        }

        Get-CachedData -Name "ScheduledTaskList"
    }
}

function Get-HotFixWithTimeout {
    <#
    .SYNOPSIS
    Helper - Get update history with a timeout in case it hangs.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    The Get-HotFix cmdlet can hang indefinitely. As an alternative, it is possible to invoke the Win32_QuickFixEngineering WMI class directly, but the result is the same. To address this issue, the class is instantiated in a separate Job, and a timeout is set. If the job doesn't complete before the timeout, an exception is thrown. It should be noted that the use of Get-CimInstance is preferred here because its invocation can be immediately cancelled, contrary to Get-WmiObject. Because Get-CimInstance is not supported in PSv2, a warning message is displayed in this case as a grace period of 2 minutes seems to be enforced when attempting to cancel the Get-WmiObject invocation.

    .PARAMETER Timeout
    Timeout value, in seconds.
    #>

    [CmdletBinding()]
    param (
        [UInt32] $Timeout = 10
    )

    process {
        if ($PSVersionTable.PSVersion.Major -gt 2) {
            $GetUpdateHistoryJob = Start-Job { Get-CimInstance -Class "Win32_QuickFixEngineering" -ErrorAction SilentlyContinue | Select-Object Description, HotFixID, InstalledBy, InstalledOn }
        }
        else {
            Write-Warning "PSv2 detected, timeout is not supported. Get-HotFixWithTimeout could hang for up to 2 minutes (+ timeout)."
            $GetUpdateHistoryJob = Start-Job { Get-WmiObject -Class "Win32_QuickFixEngineering" -ErrorAction SilentlyContinue | Select-Object Description, HotFixID, InstalledBy, InstalledOn }
        }

        if ($null -eq $GetUpdateHistoryJob) {
            throw "Failed to create job to retrieve hotfix history."
        }

        if (Wait-Job -Job $GetUpdateHistoryJob -Timeout $Timeout) {
            Receive-Job -Job $GetUpdateHistoryJob
        }
        else {
            Stop-Job -Job $GetUpdateHistoryJob -ErrorAction SilentlyContinue
            Remove-Job -Job $GetUpdateHistoryJob -Force -ErrorAction SilentlyContinue
            throw "Timed out waiting for hotfix history retrieval."
        }
    }
}
