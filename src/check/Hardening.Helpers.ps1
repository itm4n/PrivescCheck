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

    $OsVersion = Get-WindowsVersion

    # Windows >= 8/2012
    if (($OsVersion.Major -ge 10) -or (($OsVersion.Major -ge 6) -and ($OsVersion.Minor -ge 2))) {

        [UInt32] $FirmwareType = 0
        $Result = $script:Kernel32::GetFirmwareType([ref] $FirmwareType)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if ($Result -gt 0) {
            if ($FirmwareType -eq 1) {
                # FirmwareTypeBios = 1
                $Status = $false
                $Description = "BIOS mode is Legacy."
            }
            elseif ($FirmwareType -eq 2) {
                # FirmwareTypeUefi = 2
                $Status = $true
                $Description = "BIOS mode is UEFI."
            }
            else {
                $Description = "BIOS mode is unknown."
            }
        }
        else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }

    # Windows = 7/2008 R2
    }
    elseif (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -eq 1)) {

        $null = $script:Kernel32::GetFirmwareEnvironmentVariable("", "{00000000-0000-0000-0000-000000000000}", [IntPtr]::Zero, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        $ERROR_INVALID_FUNCTION = 1
        if ($LastError -eq $ERROR_INVALID_FUNCTION) {
            $Status = $false
            $Description = "BIOS mode is Legacy."
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }
        else {
            $Status = $true
            $Description = "BIOS mode is UEFI."
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
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
            "WinNT"     = "Workstation";
            "LanmanNT"  = "Domain Controller";
            "ServerNT"  = "Server";
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

function Get-BitLockerConfiguration {
    <#
    .SYNOPSIS
    Get the BitLocker startup authentication configuration.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet retrieves information about the authentication mode used by the BitLocker configuration from the 'HKLM\Software\Policies\Microsoft\FVE' key (e.g. 'TPM only', 'TPM+PIN', etc.).

    .EXAMPLE
    PS C:\> Get-BitLockerConfiguration

    Status             : @{Value=1; Description=BitLocker is enabled}
    UseTPM             : @{Value=1; Description=Require TPM (default)}
    UseAdvancedStartup : @{Value=0; Description=Do not require additional authentication at startup (default)}
    EnableBDEWithNoTPM : @{Value=0; Description=Do not allow BitLocker without a compatible TPM (default)}
    UseTPMPIN          : @{Value=0; Description=Do not allow startup PIN with TPM (default)}
    UseTPMKey          : @{Value=0; Description=Do not allow startup key with TPM (default)}
    UseTPMKeyPIN       : @{Value=0; Description=Do not allow startup key and PIN with TPM (default)}

    .LINK
    https://www.geoffchappell.com/studies/windows/win32/fveapi/policy/index.htm
    #>

    [CmdletBinding()]
    param()

    begin {
        # Default values for FVE parameters in HKLM\Software\Policies\Microsoft\FVE
        $FveConfig = @{
            UseAdvancedStartup = 0
            EnableBDEWithNoTPM = 0
            UseTPM = 1
            UseTPMPIN = 0
            UseTPMKey = 0
            UseTPMKeyPIN = 0
        }

        $FveUseAdvancedStartup = @(
            "Do not require additional authentication at startup (default)",
            "Require additional authentication at startup."
        )

        $FveEnableBDEWithNoTPM = @(
            "Do not allow BitLocker without a compatible TPM (default)",
            "Allow BitLocker without a compatible TPM"
        )

        $FveUseTPM = @(
            "Do not allow TPM",
            "Require TPM (default)",
            "Allow TPM"
        )

        $FveUseTPMPIN = @(
            "Do not allow startup PIN with TPM (default)",
            "Require startup PIN with TPM",
            "Allow startup PIN with TPM"
        )

        $FveUseTPMKey = @(
            "Do not allow startup key with TPM (default)",
            "Require startup key with TPM",
            "Allow startup key with TPM"
        )

        $FveUseTPMKeyPIN = @(
            "Do not allow startup key and PIN with TPM (default)",
            "Require startup key and PIN with TPM",
            "Allow startup key and PIN with TPM"
        )

        $FveConfigValues = @{
            UseAdvancedStartup = $FveUseAdvancedStartup
            EnableBDEWithNoTPM = $FveEnableBDEWithNoTPM
            UseTPM = $FveUseTPM
            UseTPMPIN = $FveUseTPMPIN
            UseTPMKey = $FveUseTPMKey
            UseTPMKeyPIN = $FveUseTPMKeyPIN
        }
    }

    process {

        $Result = New-Object -TypeName PSObject

        $RegKey = "HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus"
        $RegValue = "BootStatus"
        $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

        $BitLockerEnabled = $false

        if ($null -eq $RegData) {
            $StatusDescription = "BitLocker is not configured."
        }
        else {
            if ($RegData -ge 1) {
                $BitLockerEnabled = $true
                $StatusDescription = "BitLocker is enabled."
            }
            else {
                $StatusDescription = "BitLocker is not enabled."
            }
        }

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegData
        $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $StatusDescription
        $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Item

        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\FVE"

        $FveConfig.Clone().GetEnumerator() | ForEach-Object {
            $RegValue = $_.name
            $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
            if ($null -ne $RegData) {
                $FveConfig[$_.name] = $RegData
            }
        }

        if ($BitLockerEnabled) {
            foreach ($FveConfigItem in $FveConfig.GetEnumerator()) {

                $FveConfigValue = $FveConfigItem.name
                $FveConfigValueDescriptions = $FveConfigValues[$FveConfigValue]
                $IsValid = $true

                if (($FveConfigValue -eq "UseAdvancedStartup") -or ($FveConfigValue -eq "EnableBDEWithNoTPM")) {
                    if (($FveConfig[$FveConfigValue] -ne 0) -and ($FveConfig[$FveConfigValue] -ne 1)) {
                        $IsValid = $false
                    }
                }
                elseif (($FveConfigValue -eq "UseTPM") -or ($FveConfigValue -eq "UseTPMPIN") -or ($FveConfigValue -eq "UseTPMKey") -or ($FveConfigValue -eq "UseTPMKeyPIN")) {
                    if (($FveConfig[$FveConfigValue] -lt 0) -or ($FveConfig[$FveConfigValue] -gt 2)) {
                        $IsValid = $false
                    }
                }

                if (-not $IsValid) {
                    Write-Warning "Unexpected value for $($FveConfigValue): $($FveConfig[$FveConfigValue])"
                    continue
                }

                $Item = New-Object -TypeName PSObject
                $Item | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $($FveConfig[$FveConfigValue])
                $Item | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $($FveConfigValueDescriptions[$FveConfig[$FveConfigValue]])

                $Result | Add-Member -MemberType "NoteProperty" -Name $FveConfigValue -Value $Item
            }
        }

        $Result
    }
}

function Get-AppLockerPolicyFromRegistry {
    <#
    .SYNOPSIS
    Get the AppLocker policy from the registry, as an XML document.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet is an alternative for the official "Get-AppLockerPolicy" (PSv4+) that works in PSv2. It reads the registry and builds an XML representation of the AppLocker policy, similar to the output of "Get-AppLockerPolicy".
    #>

    [CmdletBinding()]
    param()

    begin {
        function Convert-EnforcementModeToString {
            param([UInt32] $EnforcementMode = 0)
            switch ($EnforcementMode) {
                0 { "NotConfigured" }
                1 { "Enabled" }
                2 { "ServicesOnly" }
            }
        }

        $RuleCollectionTypes = @( "Appx", "Dll", "Exe", "Msi", "Script" )
        $XmlWriterSettings = New-Object System.Xml.XmlWriterSettings
        $XmlWriterSettings.IndentChars = "  "
        $XmlWriterSettings.Indent = $true
        $XmlWriterSettings.OmitXmlDeclaration = $true
        $StringWriter = New-Object System.IO.StringWriter
        $XmlWriter = [System.Xml.XmlWriter]::Create($StringWriter, $XmlWriterSettings)
        $XmlWriter.WriteStartElement("AppLockerPolicy")
        $XmlWriter.WriteAttributeString("Version", "1")
    }

    process {
        foreach ($RuleCollectionType in $RuleCollectionTypes) {

            $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$($RuleCollectionType)"
            $Item = Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue
            if ($null -eq $Item) { continue }

            $EnforcementMode = Convert-EnforcementModeToString -EnforcementMode $Item.EnforcementMode

            $XmlWriter.WriteStartElement("RuleCollection")
            $XmlWriter.WriteAttributeString("Type", $RuleCollectionType)
            $XmlWriter.WriteAttributeString("EnforcementMode", $EnforcementMode)

            foreach ($ChildItem in $(Get-ChildItem -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue)) {

                $SubKeyName = $ChildItem.PSChildName

                $RegValue = "Value"
                $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)\$($SubKeyName)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
                $RuleXml = [System.Xml.XmlDocument] $RegData

                $RuleXml.WriteTo($XmlWriter)
            }

            $XmlWriter.WriteEndElement()
        }
    }

    end {
        $XmlWriter.WriteEndElement()
        $XmlWriter.Flush()
        $StringWriter.ToString()
        $XmlWriter.Close()
        $StringWriter.Close()
    }
}

function Get-AppLockerPolicyInternal {
    <#
    .SYNOPSIS
    Identify vulnerable AppLocker rules

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet parses the AppLocker configuration to identify rules that can be exploited to execute arbitrary files.

    .PARAMETER FilterLevel
    Filter rules based on their likelihood of exploitation (0 = all / no filter, 1 = low to high, 2 = medium and high, 3 = high only).
    #>

    [CmdletBinding()]
    param(
        [ValidateSet(0, 1, 2, 3)]
        [UInt32] $FilterLevel = 0
    )

    begin {
        $CurrentUserSids = Get-CurrentUserSid
        $Levels = @( "None", "Low", "Moderate", "High" )

        function Convert-AppLockerPath {
            param(
                [string] $Path
            )

            # AppLocker path variables
            # https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/applocker/understanding-the-path-rule-condition-in-applocker
            $VariableHashmap = @{
                "%WINDIR%"          = @( "%SystemRoot%" )
                "%SYSTEM32%"        = @( "%SystemDirectory%" )
                "%OSDRIVE%"         = @( "%SystemDrive%" )
                "%PROGRAMFILES%"    = @( "%ProgramFiles%", "%ProgramFiles(x86)%" )
            }

            $VariableFound = $false
            foreach ($Variable in $VariableHashmap.Keys) {
                if ($Path -like "$($Variable)*") {
                    $VariableFound = $true
                    foreach ($TranslatedVariable in $VariableHashmap[$Variable]) {
                        $Path -replace $Variable,$TranslatedVariable
                    }
                    break
                }
            }
            if (-not $VariableFound) { $Path }
        }

        function Convert-AppLockerConditionToString {
            param([object] $Condition, [string] $Type)
            switch ($Type) {
                "FilePublisher" {
                    $ConditionString = "Publisher='$($Condition.PublisherName)', Product='$($Condition.ProductName)', Binary='$($Condition.BinaryName)'"
                }
                "FilePath" {
                    $ConditionString = "Path='$($Condition.Path)'"
                }
                "FileHash" {
                    $ConditionString = "Alg='$($Condition.Type)', Hash='$($Condition.Data)', File='$($Condition.SourceFileName)', Length='$($Condition.SourceFileLength)'"
                }
                default {
                    Write-Warning "Unhandled condition type: $Type"
                }
            }
            $ConditionString
        }
    }

    process {

        if (([UInt32[]] $PSVersionTable.PSCompatibleVersions.Major) -contains 4) {
            $AppLockerPolicyXml = [xml] (Get-AppLockerPolicy -Effective -Xml)
        }
        else {
            Write-Warning "Incompatible PowerShell version detected, retrieving AppLocker policy from registry instead of using 'Get-AppLockerPolicy'..."
            $AppLockerPolicyXml = [xml] (Get-AppLockerPolicyFromRegistry)
        }

        foreach ($RuleCollection in $AppLockerPolicyXml.AppLockerPolicy.GetElementsByTagName("RuleCollection")) {

            # Type: Appx / Dll / Exe / Msi / Script
            # EnforcementMode: NotConfigured / Enabled / ServicesOnly

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "RuleCollectionType" -Value $RuleCollection.Type
            $Result | Add-Member -MemberType "NoteProperty" -Name "RuleCollectionEnforcementMode" -Value $RuleCollection.EnforcementMode

            if ($RuleCollection.EnforcementMode -eq "NotConfigured") {
                $Description = "No restriction is enforced for files of type '$($RuleCollection.Type)'."
                $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                $Result | Add-Member -MemberType "NoteProperty" -Name "Impact" -Value "High"
                $Result
                continue
            }

            $RuleTypes = @( "FilePublisher", "FilePath", "FileHash" )

            foreach ($RuleType in $RuleTypes) {

                $Rules = $RuleCollection.GetElementsByTagName("$($RuleType)Rule")

                foreach ($Rule in $Rules) {

                    if ($Rule.Action -eq "Deny") {
                        Write-Warning "Deny rule encountered and ignored: $($Rule.Name)"
                        continue
                    }

                    if ($CurrentUserSids -notcontains $Rule.UserOrGroupSid) {
                        Write-Verbose "This rule applies to a SID that is not ours ($($Rule.UserOrGroupSid)): $($Rule.Name)"
                        continue
                    }

                    $ResultRule = $Result.PsObject.Copy()
                    $ResultRule | Add-Member -MemberType "NoteProperty" -Name "RuleName" -Value $Rule.Name
                    $ResultRule | Add-Member -MemberType "NoteProperty" -Name "RuleDescription" -Value $Rule.Description
                    $ResultRule | Add-Member -MemberType "NoteProperty" -Name "RuleUserOrGroupSid" -Value $Rule.UserOrGroupSid
                    $ResultRule | Add-Member -MemberType "NoteProperty" -Name "RuleAction" -Value $Rule.Action

                    if ($Rule.Conditions) {
                        $Conditions = $Rule.Conditions.GetElementsByTagName("$($RuleType)Condition")
                    }

                    if ($Rule.Exceptions) {
                        $Exceptions = $Rule.Exceptions.GetElementsByTagName("$($RuleType)Condition")
                        $ExceptionListString = ($Exceptions | ForEach-Object { "$(Convert-AppLockerConditionToString -Condition $_ -Type $RuleType)" }) -join "; "
                    }
                    else {
                        $ExceptionListString = $null
                    }

                    foreach ($Condition in $Conditions) {

                        $ConditionString = Convert-AppLockerConditionToString -Condition $Condition -Type $RuleType
                        $Level = 0

                        switch ($RuleType) {

                            "FilePublisher" {
                                if (($Rule.Action -eq "Allow") -and ($Condition.PublisherName -eq "*")) {
                                    $Level = 1
                                    $Description = "This rule allows files from any publisher."
                                }
                                elseif (($Rule.Action -eq "Allow") -and (($Condition.ProductName -eq "*") -or ($Condition.BinaryName -eq "*"))) {
                                    $Level = 1
                                    $Description = "This rule allows any product or file from the publisher '$($Condition.PublisherName)'."
                                }
                            }

                            "FilePath" {
                                # Path is simply a wildcard?
                                if ($Condition.Path -eq "*") {
                                    $Level = 3
                                    $Description = "This rule allows any file."
                                }
                                # Path is a removable media?
                                elseif ($Condition.Path.StartsWith("%REMOVABLE%")) {
                                    $Level = 1
                                    $Description = "This rule allows files to be executed from a removable media (e.g., CD/DVD)."
                                }
                                # Path is a removable storage device?
                                elseif ($Condition.Path.StartsWith("%HOT%")) {
                                    $Level = 1
                                    $Description = "This rule allows files to be executed from a removable storage device (e.g., USB flash drive)."
                                }
                                # UNC path containing wildcards?
                                elseif ($Condition.Path.StartsWith("\\")) {
                                    # The following regex catches occurrences of "\\(foo)*(bar)\..."
                                    if ($Condition.Path -match "\\\\[^\\]*\*[^\\]*\\.*") {
                                        $Level = 1
                                        $Description = "This rule allows files to be executed from a network path with a hostname containing a wildcard."
                                    }
                                    elseif ($Condition.Path -match ".*\*.*") {
                                        $Level = 1
                                        $Description = "This rule allows files to be executed from a network path containing a wildcard, manual analysis is required."
                                    }
                                }
                                else {
                                    $CandidatePaths = [string[]] (Convert-AppLockerPath -Path $Condition.Path)
                                    foreach ($CandidatePath in $CandidatePaths) {
                                        if ([String]::IsNullOrEmpty($CandidatePath)) { continue }
                                        $CandidatePath = $([System.Environment]::ExpandEnvironmentVariables($CandidatePath))
                                        if ($CandidatePath.StartsWith("*")) {
                                            $Level = 3
                                            $Description = "This rule allows files to be executed from any location."
                                        }
                                        elseif ($CandidatePath.EndsWith("*")) {
                                            if (Test-IsSystemFolder -Path $CandidatePath.Trim("*")) {
                                                $Level = 2
                                                $Description = "This rule allows files to be executed from a system folder, and could therefore be vulnerable."
                                            }
                                            else {
                                                $ModifiablePaths = Get-ModifiablePath -Path $CandidatePath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                                                if ($ModifiablePaths) {
                                                    $Level = 3
                                                    $Description = "This rule allows files to be executed from a location where the current user has write access."
                                                }
                                            }
                                        }
                                        else {
                                            $ModifiablePaths = Get-ModifiablePath -Path $CandidatePath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
                                            if ($ModifiablePaths) {
                                                $Level = 3
                                                $Description = "This rule allows files to be executed from a location where the current user has write access."
                                            }
                                        }
                                    }
                                }
                            }

                            "FileHash" {
                                # Nothing to do here, secure by design???
                            }
                        }

                        if ($Level -ge $FilterLevel) {
                            if ($Rule.Exceptions) {
                                $Description = "$($Description) However, exceptions should be manually reviewed."
                            }
                            $ResultCondition = $ResultRule.PsObject.Copy()
                            $ResultCondition | Add-Member -MemberType "NoteProperty" -Name "RuleCondition" -Value $ConditionString
                            $ResultCondition | Add-Member -MemberType "NoteProperty" -Name "RuleExceptions" -Value $(if ($ExceptionListString) { $ExceptionListString } else { "(null)" })
                            $ResultCondition | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                            $ResultCondition | Add-Member -MemberType "NoteProperty" -Name "Level" -Value $Level
                            $ResultCondition | Add-Member -MemberType "NoteProperty" -Name "Risk" -Value $Levels[$Level]
                            $ResultCondition
                        }
                    }
                }
            }
        }
    }
}

function Get-EnforcedPowerShellExecutionPolicy {
    <#
    .SYNOPSIS
    Helper - Get the enforced PowerShell execution policy (when configured with a GPO)

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet retrieves the configuration of the PowerShell execution, when it is enforced with a GPO. If first checks the computer configuration, and returns it if found. Otherwise, it checks the the user configuration. If no execution policy is defined, this cmdlet returns null.

    .EXAMPLE
    PS C:\> Get-EnforcedPowerShellExecutionPolicy

    Policy          : Turn on Script Execution
    Key             : HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell
    EnableScripts   : 1
    ExecutionPolicy : RemoteSigned
    Description     : Local scripts can be executed. Scripts that originate from the Internet can be executed only if they are signed by a trusted publisher.
    #>

    [CmdletBinding()]
    param()

    begin {
        $RegKeys = @(
            "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell",
            "HKCU\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
        )
    }

    process {

        foreach ($RegKey in $RegKeys) {

            $RegValue = "EnableScripts"
            $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue
            if ($null -eq $RegData) {
                Write-Verbose "PowerShell execution policy not enforced in '$($RegKey)'."
                continue
            }

            $EnableScripts = [UInt32] $RegData

            $RegValue = "ExecutionPolicy"
            $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

            $ExecutionPolicy = $RegData

            if ($EnableScripts -eq 0) {
                $Description = "Script execution is disabled. The execution policy defaults to a per-machine preference setting."
            }
            else {
                switch ($ExecutionPolicy) {
                    "AllSigned" { $Description = "A PowerShell execution policy is enforced. It allows scripts to execute only if they are signed by a trusted publisher." }
                    "RemoteSigned" { $Description = "A PowerShell execution policy is enforced. It allows any local scripts to run. Scripts that originate from the Internet must be signed by a trusted publisher*;" }
                    "Unrestricted" { $Description = "A PowerShell execution policy is enforced. It allows all scripts to run." }
                    default { Write-Warning "Unexpected execution policy: $($ExecutionPolicy)" }
                }
            }

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Policy" -Value "Turn on Script Execution"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
            $Result | Add-Member -MemberType "NoteProperty" -Name "EnableScripts" -Value $EnableScripts
            $Result | Add-Member -MemberType "NoteProperty" -Name "ExecutionPolicy" -Value $ExecutionPolicy
            $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(if ($Description) { $Description } else { "(null)" })
            $Result

            # # A policy was found, so we can stop here. If it's defined in HKLM, it means
            # # that it's set in the computer configuration, which has precedence over the
            # # user configuration. Otherwise it's defined in the user configuration.
            break
        }
    }
}

function Get-AttackSurfaceReductionRule {
    <#
    .SYNOPSIS
    Helper - Get the ASR rules and their values

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet returns a list of all existing ASR rules, along with their values in the registry. If a rule is not defined, the 'Data' value is null.

    .EXAMPLE
    PS C:\> Get-AttackSurfaceReductionRule

    Rule        : Block executable files from running unless they meet a prevalence, age, or trusted list criterion
    Id          : 01443614-cd74-433a-b99e-2ecdc07bfc25
    State       :
    Description : Not configured (disabled)

    Rule        : Block Office applications from creating executable content
    Id          : 3b576869-a4ec-4529-8536-b80a7769e899
    State       : 2
    Description : Audit

    Rule        : Block Webshell creation for Servers
    Id          : a8f5898e-1dc8-49a9-9878-85004b8a61e6
    State       :
    Description : Not configured (disabled)

    .NOTES
    Computer Configuration > Policies > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > Attack Surface Reduction > Configure Attack Surface Reduction rules

    .LINK
    https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
    #>

    [CmdletBinding()]
    param()

    begin {
        $RuleIds = @{
            [Guid] "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
            [Guid] "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
            [Guid] "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
            [Guid] "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
            [Guid] "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
            [Guid] "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
            [Guid] "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
            [Guid] "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
            [Guid] "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
            [Guid] "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes"
            [Guid] "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
            [Guid] "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
            [Guid] "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
            [Guid] "33ddedf1-c6e0-47cb-833e-de6133960387" = "Block rebooting machine in Safe Mode (preview)"
            [Guid] "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
            [Guid] "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Block use of copied or impersonated system tools (preview)"
            [Guid] "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Block Webshell creation for Servers"
            [Guid] "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
            [Guid] "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
        }

        $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
    }

    process {

        foreach ($RuleId in $RuleIds.GetEnumerator()) {

            $RegValue = $RuleId.Name.ToString()
            $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -Name $RegValue -ErrorAction SilentlyContinue).$RegValue

            switch ($RegData) {
                $null { $Description = "Not configured (disabled)" }
                0 { $Description = "Disabled" }
                1 { $Description = "Block" }
                2 { $Description = "Audit" }
                6 { $Description = "Warn" }
                Default {
                    $Description = $null
                    Write-Warning "Unexpected value for ASR rule '$($RegValue)': $($RegData)"
                }
            }

            $Rule = New-Object -TypeName PSObject
            $Rule | Add-Member -MemberType "NoteProperty" -Name "Rule" -Value $RuleId.Value
            $Rule | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $RuleId.Name
            $Rule | Add-Member -MemberType "NoteProperty" -Name "State" -Value $RegData
            $Rule | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
            $Rule
        }
    }
}