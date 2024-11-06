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
        [Parameter(Mandatory=$true)]
        [string] $ManufacturerId
    )

    begin {
        $DiscreteTpmVendorIds = @("ATML","CSCO","FLYS","IFX","NSG","NSM","NTC","NTZ","SNS","STM")
        $IntegratedTpmVendorIds = @("BRCM","INTC","ROCC","SMSC","TXN")
        $FirmwareTpmVendorIds = @("AMD","HISI","HPE","INTC","LEN","QCOM","SECE","SMSN")
        $VirtualTpmVendorIds = @("IBM","GOOG","MSFT")
    }

    process {
        $TpmType = 0

        # Note: we need to check all the vendor ID lists because multiple TPM types
        # can be associated to a vendor ID. For example, a TPM with the vendor ID
        # 'INTC' (Intel) can be either an integrated TPM or a firmware TPM.
        if ($DiscreteTpmVendorIds -contains $ManufacturerId) { $TpmType += $script:TPM_DEVICE_TYPE::Discrete }
        if ($IntegratedTpmVendorIds -contains $ManufacturerId) { $TpmType += $script:TPM_DEVICE_TYPE::Integrated }
        if ($FirmwareTpmVendorIds -contains $ManufacturerId) { $TpmType += $script:TPM_DEVICE_TYPE::Firmware }
        if ($VirtualTpmVendorIds -contains $ManufacturerId) { $TpmType += $script:TPM_DEVICE_TYPE::Virtual }

        if ($TpmType -eq 0) { $TpmType += $script:TPM_DEVICE_TYPE::Unknown }

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
        $Result | Add-Member -MemberType "NoteProperty" -Name "BiosReleaseDate" -Value ([DateTime] $BiosReleaseDate)
        $Result | Add-Member -MemberType "NoteProperty" -Name "BiosVendor" -Value $BiosVendor
        $Result | Add-Member -MemberType "NoteProperty" -Name "BiosVersion" -Value $BiosVersion
        $Result | Add-Member -MemberType "NoteProperty" -Name "SystemFamily" -Value $SystemFamily
        $Result | Add-Member -MemberType "NoteProperty" -Name "SystemManufacturer" -Value $SystemManufacturer
        $Result | Add-Member -MemberType "NoteProperty" -Name "SystemProductName" -Value $SystemProductName
        $Result | Add-Member -MemberType "NoteProperty" -Name "SystemSKU" -Value $SystemSKU
        $Result
    }
}