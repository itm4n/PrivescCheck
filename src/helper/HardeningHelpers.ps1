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

    [CmdletBinding()] Param()

    $OsVersion = Get-WindowsVersion

    # Windows >= 8/2012
    if (($OsVersion.Major -ge 10) -or (($OsVersion.Major -ge 6) -and ($OsVersion.Minor -ge 2))) {

        [UInt32]$FirmwareType = 0
        $Result = $Kernel32::GetFirmwareType([ref]$FirmwareType)
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

        $null = $Kernel32::GetFirmwareEnvironmentVariable("", "{00000000-0000-0000-0000-000000000000}", [IntPtr]::Zero, 0)
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

    [CmdletBinding()] Param()

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

    [CmdletBinding()] Param()

    BEGIN {
        $FriendlyNames = @{
            "WinNT"     = "Workstation";
            "LanmanNT"  = "Domain Controller";
            "ServerNT"  = "Server";
        }
    }

    PROCESS {
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

    [CmdletBinding()] Param ()

    BEGIN {
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

    PROCESS {

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
    param ()
    
    begin {
        function Convert-EnforcementModeToString {
            param (
                [UInt32] $EnforcementMode = 0
            )
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
    param (
        [ValidateSet(0, 1, 2, 3)]
        [UInt32] $FilterLevel = 0
    )
    
    begin {
        $CurrentUserSids = Get-CurrentUserSids
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
            param (
                [object] $Condition,
                [string] $Type
            )
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
                                                if (Get-ModifiablePath -LiteralPaths $CandidatePath) {
                                                    $Level = 3
                                                    $Description = "This rule allows files to be executed from a location where the current user has write access."
                                                }
                                            }
                                        }
                                        else {
                                            $ModifiablePaths = Get-ModifiablePath -LiteralPaths $CandidatePath
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