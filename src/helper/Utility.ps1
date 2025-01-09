function Get-InitialSessionState {

    [OutputType([Management.Automation.Runspaces.InitialSessionState])]
    [CmdletBinding()]
    param ()

    process {
        if ($null -eq $script:GlobalVariable.InitialSessionState) {
            $script:GlobalVariable.InitialSessionState = New-InitialSessionState
        }

        return $script:GlobalVariable.InitialSessionState
    }
}

function Test-IsRunningInConsole {
    return $Host.Name -match "ConsoleHost"
}

function Test-IsMicrosoftFile {

    [OutputType([Boolean])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Object] $File
    )

    if ($File.VersionInfo.LegalCopyright -like "*Microsoft Corporation*") {
        return $true
    }

    return $false
}

function Test-IsCommonApplicationFile {

    [OutputType([Boolean])]
    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string] $Path
    )

    process {
        $script:GlobalConstant.CommonApplicationExtensions -contains ([System.IO.Path]::GetExtension($Path)).Replace('.', '')
    }
}

function Test-IsSystemFolder {

    [OutputType([Boolean])]
    [CmdletBinding()]
    param(
        [string] $Path
    )

    begin {
        $SystemPaths = @()
    }

    process {
        # Initialize system path list
        if ($SystemPaths.Count -eq 0) {
            [string[]] $SystemPaths += $env:windir
            [string[]] $SystemPaths += Join-Path -Path "$($env:windir)" -ChildPath "System"
            [string[]] $SystemPaths += Join-Path -Path "$($env:windir)" -ChildPath "System32"
            [string[]] $SystemPaths += Join-Path -Path "$($env:windir)" -ChildPath "Syswow64"
            [string[]] $SystemPaths += Join-Path -Path "$($env:windir)" -ChildPath "Sysnative"
            [string[]] $SystemPaths += $env:ProgramFiles
            [string[]] $SystemPaths += ${env:ProgramFiles(x86)}
            [string[]] $SystemPaths += $env:ProgramData
        }

        $SystemPaths -contains $Path.TrimEnd('\\')
    }
}

function Test-IsDomainJoined {

    [OutputType([Boolean])]
    [CmdletBinding()]
    param()

    $DomainInfo = Get-DomainInformation

    if ($DomainInfo.BufferType -eq $script:NETSETUP_JOIN_STATUS::NetSetupDomainName) {
        return $true
    }

    $DomainInfo = Get-DomainInformation -Azure

    if ($DomainInfo.JoinType -eq $script:DSREG_JOIN_TYPE::DSREG_DEVICE_JOIN) {
        return $true
    }

    return $false
}

function Convert-FiletimeToDatetime {
    [OutputType([DateTime])]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, Mandatory=$true)]
        [Object] # FILETIME
        $Filetime
    )

    [Int64] $Time = $Filetime.LowDateTime + $Filetime.HighDateTime * 0x100000000
    [DateTime]::FromFileTimeUtc($Time)
}

function Convert-EpochTimeToDateTime {
    [OutputType([DateTime])]
    [CmdletBinding()]
    param (
        [Parameter(Position = 1, Mandatory=$true)]
        [UInt32] $Seconds
    )

    $DateTime = [DateTime] '1970-01-01 00:00:00'
    $DateTime.AddSeconds($Seconds)
}

function Convert-DateToString {
    <#
    .SYNOPSIS
    Helper - Converts a DateTime object to a string representation

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    The output string is a simplified version of the ISO format: YYYY-MM-DD hh:mm:ss.

    .PARAMETER Date
    A System.DateTime object

    .EXAMPLE
    PS C:\> $Date = Get-Date; Convert-DateToString -Date $Date

    2020-01-16 - 10:26:11
    #>

    [OutputType([String])]
    [CmdletBinding()]
    param(
        [Object] $Date,
        [String] $DateString,
        [Switch] $IncludeTime
    )

    begin {
        if ($IncludeTime) {
            $DateFormat = "yyyy-MM-dd - HH:mm:ss"
        }
        else {
            $DateFormat = "yyyy-MM-dd"
        }
    }

    process {
        if (($null -eq $Date) -and ([string]::IsNullOrEmpty($DateString))) {
            Write-Warning "Cannot convert date, input object is null."
            return
        }

        if ([string]::IsNullOrEmpty($DateString)) {
            $Date = [DateTime] $Date
        }
        else {
            $Date = [DateTime] $DateString
        }

        $Date.ToString($DateFormat)
    }
}

function Convert-SidToName {
    <#
    .SYNOPSIS
    Helper - Converts a SID string to its corresponding username

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This helper function takes a user SID as an input parameter and returns the account name associated to this SID. If an account name cannot be found, nothing is returned.

    .PARAMETER Sid
    A user account SID, e.g.: S-1-5-18.

    .EXAMPLE
    An example
    PS C:\> Convert-SidToName -Sid S-1-5-18"

    NT AUTHORITY\SYSTEM
    #>

    [OutputType([String])]
    [CmdletBinding()]
    param(
        [String] $Sid
    )

    try {
        $SidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $SidObj.Translate([System.Security.Principal.NTAccount]) | Select-Object -ExpandProperty Value
    }
    catch {
        # In case of failure, return the SID.
        $Sid
    }
}

function Convert-CredentialBlobToString {

    [CmdletBinding()]
    param(
        [Parameter(Position = 1, Mandatory=$true)]
        [Object] $RawObject # CREDENTIAL
    )

    if (-not ($RawObject.CredentialBlobSize -eq 0)) {

        $TestFlags = 2 # IS_TEXT_UNICODE_STATISTICS
        $IsUnicode = $script:Advapi32::IsTextUnicode($RawObject.CredentialBlob, $RawObject.CredentialBlobSize, [ref] $TestFlags)

        if ($IsUnicode) {
            Write-Verbose "Encoding of input text is UNICODE"
            $Result = [Runtime.InteropServices.Marshal]::PtrToStringUni($RawObject.CredentialBlob, $RawObject.CredentialBlobSize / 2)
        }
        else {
            for ($i = 0; $i -lt $RawObject.CredentialBlobSize; $i++) {
                $BytePtr = [IntPtr] ($RawObject.CredentialBlob.ToInt64() + $i)
                $Byte = [Runtime.InteropServices.Marshal]::ReadByte($BytePtr)
                $Result += "{0:X2} " -f $Byte
            }
        }

        $Result
    }
}

function Convert-WlanXmlProfile {
    <#
    .SYNOPSIS
    Convert a WLAN XML profile to a custom PS object.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet takes a WLAN XML profile as an input, parses it, and return a custom object that contains the profile's key information, based on the type of authentication in use. For 802.1x profiles, it returns object(s) containing the detailed configuration. Only the main 802.1x authentication schemes are supported (see the 'Notes' section).

    .PARAMETER WlanProfile
    A string representing a WLAN profile as an XML document.

    .EXAMPLE
    PS C:\> Convert-WlanXmlProfile -WlanProfile $WlanProfile

    SSID           : wp2-access-point
    ConnectionType : ESS (Infrastructure)
    ConnectionMode : auto
    Authentication : WPA2PSK
    Encryption     : AES
    Dot1X          : False

    .EXAMPLE
    PS C:\> Convert-WlanXmlProfile -WlanProfile $WlanProfile

    SSID                  : eap-tls-access-point
    ConnectionType        : ESS (Infrastructure)
    ConnectionMode        : auto
    Authentication        : WPA2
    Encryption            : AES
    Dot1X                 : True
    AuthenticationModeRaw : user
    AuthenticationMode    : Use user credentials only.
    EapTypeId             : 13
    EapType               : EAP-TLS
    Eap                   : @{CredentialsSource=Certificate; ServerValidationDisablePrompt=True; ServerValidationDisablePromptComment=Authentication fails is the certificate is not trusted.; ServerValidationNames=; AcceptServerName=False; AcceptServerNameComment=The server name is not verified.; TrustedRootCAs=0563b8630d62d75abbc8ab1e4bdfb5a899b24d43; TrustedRootCAsComment=DigiCert Assured ID Root CA; PerformServerValidation=False; PerformServerValidationComment=Server validation is not performed.}

    .NOTES
    Supported EAP methods:
        Microsoft implements the following EAP methods: MS-EAP / MSCHAPv2 (26), TLS (13), PEAP (25), SIM (18), AKA (23), AKA' (50), TTLS (21), TEAP (55). In this function, we handle only TLS (13), PEAP (25), TTLS (21), and MSCHAPv2 (26).

    .LINK
    https://docs.microsoft.com/en-us/windows/win32/nativewifi/portal
    #>

    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string] $WlanProfile
    )

    begin {
        function ConvertTo-Boolean {
            param([object] $Text)
            if ($null -eq $Text) { Write-Warning "$($MyInvocation.MyCommand.Name) | Null input, assuming False"; return $False }
            if ($Text.GetType() -like "*XmlElement") { $Text = $(if ([string]::IsNullOrEmpty($Text.innerText)) { $Text } else { $Text.innerText }) }
            try { [System.Convert]::ToBoolean($Text) } catch { Write-Warning "Failed to convert to boolean: $($Text)" }
        }

        function Get-ConnectionTypeName {
            param([string] $ConnectionType)
            if ([string]::IsNullOrEmpty($ConnectionType)) { return }
            $Enumeration = @{ "ESS" = "Infrastructure" ; "IBSS" = "Ad-hoc" }
            try { $Enumeration[$ConnectionType] } catch { Write-Warning "Unknown connection type: $($ConnectionType)" }
        }

        function Get-EapTypeName {
            param([string] $MethodType)
            if ([string]::IsNullOrEmpty($MethodType)) { return }
            $Enumeration = @{ "13" = "EAP-TLS" ; "18" = "EAP-SIM" ; "21" = "EAP-TTLS" ; "23" = "EAP-AKA" ; "25" = "PEAP" ; "26" = "MS-EAP" ; "29" = "EAP-MSCHAP-V2" ; "50" = "EAP-AKA'" ; "55" = "TEAP" }
            try { $Enumeration[$MethodType] } catch { "Unknown" }
        }

        function Get-CertificateName {
            param([string] $Thumbprint)
            if ([string]::IsNullOrEmpty($Thumbprint)) { ""; return }
            $Certificate = Get-ChildItem "Cert:\LocalMachine\Root\$($Thumbprint.Replace(' ', ''))" -ErrorAction SilentlyContinue
            if ($null -eq $Certificate) { "Unknown Certificate"; return }
            ($Certificate.Subject.Split(',')[0]).Split('=')[1]
        }

        function Get-AuthModeDescription {
            param([string] $AuthMode)
            if ([string]::IsNullOrEmpty($AuthMode)) { return }
            $Enumeration = @{ "machineOrUser" = "Use user credentials when a user is logged on, use machine credentials otherwise." ; "machine" = "Use machine credentials only." ; "user" = "Use user credentials only." ; "guest" = "Use guest (empty) credentials only." }
            try { $Enumeration[$AuthMode] } catch { "Unknown" }
        }

        function Get-ServerValidationPromptDescription {
            param([boolean] $PromptDisabled)
            if ($PromptDisabled) { "Authentication fails is the certificate is not trusted." } else { "The user can be prompted for server validation." }
        }

        function Get-ServerValidationDescription {
            param([boolean] $PerformValidation)
            if ($PerformValidation) { "Server validation is performed." } else { "Server validation is not performed." }
        }

        function Get-AcceptServerNameDescription {
            param([boolean] $AcceptServerName)
            if ($AcceptServerName) { "The server name is verified." } else { "The server name is not verified." }
        }

        function Get-UseWinLogonCredentialsDescription {
            param([boolean] $UseWinLogonCredentials)
            if ($UseWinLogonCredentials) { "EAP MS-CHAPv2 obtains credentials from winlogon." } else { "EAP MS-CHAPv2 obtains credentials from the user." }
        }

        function Get-TrustedRootCA {
            param([System.Xml.XmlElement] $Node, [string] $Name)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $TrustedRootCAs = $Node.GetElementsByTagName($Name) | ForEach-Object { $_.InnerText.Replace(" ", "") }
            $TrustedRootCANames = $TrustedRootCAs | ForEach-Object { Get-CertificateName -Thumbprint $_ }
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Thumbprints" -Value ($TrustedRootCAs -join ", ")
            $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayNames" -Value ($TrustedRootCANames -join ", ")
            $Result
        }

        function Get-EapType {
            param([System.Xml.XmlElement] $Node)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $EapTypeId = $(if ([string]::IsNullOrEmpty($Node.Type.InnerText)) { $Node.Type } else { $Node.Type.InnerText })
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $EapTypeId
            $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value (Get-EapTypeName -MethodType $EapTypeId)
            $Result
        }

        function Get-EapTlsConfig {
            param([System.Xml.XmlElement] $Node)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $CredentialsSource = $(
                if ($null -ne $Node.EapType.CredentialsSource.SmartCard) { "SmartCard" }
                elseif ($null -ne $Node.EapType.CredentialsSource.CertificateStore) { "Certificate" }
            )
            $ServerValidationNode = $Node.EapType.ServerValidation
            $ServerValidationDisablePrompt = ConvertTo-Boolean -Text $ServerValidationNode.DisableUserPromptForServerValidation
            $AcceptServerName = ConvertTo-Boolean -Text $Node.EapType.AcceptServerName
            $PerformServerValidation = ConvertTo-Boolean -Text $Node.EapType.PerformServerValidation
            $TrustedRootCAs = Get-TrustedRootCA -Node $ServerValidationNode -Name "TrustedRootCA"
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "CredentialsSource" -Value $CredentialsSource
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePrompt" -Value $ServerValidationDisablePrompt
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePromptDescription" -Value (Get-ServerValidationPromptDescription -PromptDisabled $ServerValidationDisablePrompt)
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationNames" -Value $ServerValidationNode.ServerNames
            $Result | Add-Member -MemberType "NoteProperty" -Name "AcceptServerName" -Value $AcceptServerName
            $Result | Add-Member -MemberType "NoteProperty" -Name "AcceptServerNameDescription" -Value (Get-AcceptServerNameDescription -AcceptServerName $AcceptServerName)
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAs" -Value $TrustedRootCAs.Thumbprints
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAsDescription" -Value $TrustedRootCAs.DisplayNames
            $Result | Add-Member -MemberType "NoteProperty" -Name "PerformServerValidation" -Value $PerformServerValidation
            $Result | Add-Member -MemberType "NoteProperty" -Name "PerformServerValidationDescription" -Value (Get-ServerValidationDescription -PerformValidation $PerformServerValidation)
            $Result
        }

        function Get-EapTtlsConfig {
            param([System.Xml.XmlElement] $Node)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $ServerValidationNode = $Node.ServerValidation
            $ServerValidationDisablePrompt = ConvertTo-Boolean -Text $ServerValidationNode.DisablePrompt
            $TrustedRootCAs = Get-TrustedRootCA -Node $ServerValidationNode -Name "TrustedRootCAHash"
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePrompt" -Value $ServerValidationDisablePrompt
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePromptDescription" -Value (Get-ServerValidationPromptDescription -PromptDisabled $ServerValidationDisablePrompt)
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationNames" -Value $ServerValidationNode.ServerNames
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAs" -Value $TrustedRootCAs.Thumbprints
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAsDescription" -Value $TrustedRootCAs.DisplayNames
            $Result
        }

        function Get-EapPeapConfig {
            param([System.Xml.XmlElement] $Node)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $ServerValidationNode = $Node.EapType.ServerValidation
            $ServerValidationDisablePrompt = ConvertTo-Boolean -Text $ServerValidationNode.DisableUserPromptForServerValidation
            $TrustedRootCAs = Get-TrustedRootCA -Node $ServerValidationNode -Name "TrustedRootCA"
            $AcceptServerName = ConvertTo-Boolean -Text $Node.EapType.PeapExtensions.AcceptServerName
            $PerformServerValidation = ConvertTo-Boolean -Text $Node.EapType.PeapExtensions.PerformServerValidation
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePrompt" -Value $ServerValidationDisablePrompt
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePromptDescription" -Value (Get-ServerValidationPromptDescription -PromptDisabled $ServerValidationDisablePrompt)
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationNames" -Value $ServerValidationNode.ServerNames
            $Result | Add-Member -MemberType "NoteProperty" -Name "AcceptServerName" -Value $AcceptServerName
            $Result | Add-Member -MemberType "NoteProperty" -Name "AcceptServerNameDescription" -Value (Get-AcceptServerNameDescription -AcceptServerName $AcceptServerName)
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAs" -Value $TrustedRootCAs.Thumbprints
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAsDescription" -Value $TrustedRootCAs.DisplayNames
            $Result | Add-Member -MemberType "NoteProperty" -Name "PerformServerValidation" -Value $PerformServerValidation
            $Result | Add-Member -MemberType "NoteProperty" -Name "PerformServerValidationDescription" -Value (Get-ServerValidationDescription -PerformValidation $PerformServerValidation)
            $Result
        }

        function Get-EapMsChapv2Config {
            param([System.Xml.XmlElement] $Node)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $UseWinLogonCredentials = ConvertTo-Boolean -Text $Node.EapType.UseWinLogonCredentials
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "UseWinLogonCredentials" -Value $UseWinLogonCredentials
            $Result | Add-Member -MemberType "NoteProperty" -Name "UseWinLogonCredentialsDescription" -Value (Get-UseWinLogonCredentialsDescription -UseWinLogonCredentials $UseWinLogonCredentials)
            $Result
        }

        function Get-EapConfig {
            param([System.Xml.XmlElement] $Node, [string] $Type)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            switch ($Type) {
                "13" {
                    Get-EapTlsConfig -Node $Node.Eap
                }
                "21" {
                    Get-EapTtlsConfig -Node $Node.EapTtls
                }
                "25" {
                    Get-EapPeapConfig -Node $Node.Eap
                }
                "26" {
                    Get-EapMsChapv2Config -Node $Node.Eap
                }
                default {
                    Write-Warning "$($MyInvocation.MyCommand.Name) | Unsupported EAP type: $($Type)"
                }
            }
        }
    }

    process {
        if ([string]::IsNullOrEmpty($WlanProfile)) { Write-Warning "$($MyInvocation.MyCommand.Name) | Failed to get content: $($ProfileFileItem.FullName)"; return }
        try { $XmlFile = [xml] $WlanProfile } catch { Write-Warning "$($MyInvocation.MyCommand.Name) | Failed to parse XML: $($ProfileFileItem.FullName)"; return }

        $WifiProfiles = $XmlFile.GetElementsByTagName("WLANProfile")

        foreach ($WifiProfile in $WifiProfiles) {

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "SSID" -Value $WifiProfile.SSIDConfig.SSID.name
            $Result | Add-Member -MemberType "NoteProperty" -Name "ConnectionType" -Value "$($WifiProfile.connectionType) ($(Get-ConnectionTypeName -ConnectionType $WifiProfile.connectionType))"
            $Result | Add-Member -MemberType "NoteProperty" -Name "ConnectionMode" -Value $(if (($WifiProfile.connectionType -eq "ESS") -and ([string]::IsNullOrEmpty($WifiProfile.connectionMode))) { "auto" } else { $WifiProfile.connectionMode })

            $SecurityConfig = $WifiProfile.MSM.security
            if ($null -eq $SecurityConfig) { Write-Warning "SSID: '$($Result.SSID)' | 'Security' node not found."; return }
            $UseDot1X = ConvertTo-Boolean -Text $SecurityConfig.authEncryption.useOneX

            $Result | Add-Member -MemberType "NoteProperty" -Name "Authentication" -Value $SecurityConfig.authEncryption.authentication
            $Result | Add-Member -MemberType "NoteProperty" -Name "Encryption" -Value $SecurityConfig.authEncryption.encryption
            $Result | Add-Member -MemberType "NoteProperty" -Name "PassPhrase" -Value $SecurityConfig.sharedKey.keyMaterial
            $Result | Add-Member -MemberType "NoteProperty" -Name "Dot1X" -Value $UseDot1X

            # If 802.1x is not used, we can return the profile straight away.
            if (-not $UseDot1X) { $Result; return }

            # The OneX node holds the 802.1x configuration. When 'useOneX' is set to true, this node must
            # be present in the 'WLANProfile' XML document. All the information regarding the 802.1x
            # configuration can be found within this node.
            $OneXNode = $SecurityConfig.OneX
            if ($null -eq $OneXNode) { Write-Warning "SSID: '$($Result.SSID)' | 'OneX' node not found."; return }
            $AuthenticationMode = $(if ([string]::IsNullOrEmpty($OneXNode.authMode)) { "machineOrUser" } else { $OneXNode.authMode })

            $Result | Add-Member -MemberType "NoteProperty" -Name "AuthenticationMode" -Value $AuthenticationMode
            $Result | Add-Member -MemberType "NoteProperty" -Name "AuthenticationModeDescription" -Value (Get-AuthModeDescription -AuthMode $AuthenticationMode)

            # Get EAP type from the EapMethod element.
            $EapType = Get-EapType -Node $OneXNode.EAPConfig.EapHostConfig.EapMethod
            if ($null -eq $EapType) { Write-Warning "SSID: '$($Result.SSID)' | EAP type not found."; return }

            $Result | Add-Member -MemberType "NoteProperty" -Name "EapTypeId" -Value $EapType.Id
            $Result | Add-Member -MemberType "NoteProperty" -Name "EapType" -Value $EapType.Name

            # The 802.1x configuration can be stored either in "clear" text or as a binary blob. We only
            # handle the case the configuration is stored in "clear" text. Otherwise, the ignore the Wi-Fi
            # profile and print a warning message.
            $ConfigNode = $OneXNode.EAPConfig.EapHostConfig.Config
            if ($null -eq $ConfigNode) { Write-Warning "SSID: '$($Result.SSID)' | 'Config' node not found."; return }

            $EapConfig = Get-EapConfig -Node $ConfigNode -Type $EapType.Id
            if ($null -eq $EapConfig) { Write-Warning "SSID: '$($Result.SSID)' | Failed to parse EAP configuration."; return }

            $Result | Add-Member -MemberType "NoteProperty" -Name "Eap" -Value $EapConfig
            $Result | Add-Member -MemberType "NoteProperty" -Name "EapStr" -Value ($EapConfig | Format-List | Out-String).Trim()

            # In some cases, there is an additional EAP layer. This may happen when, for example, the initial
            # EAP layer is PEAP, and then MS-CHAPv2 is used to authenticate the user. In this case, we parse
            # the next 'Eap' node, and add the configuration to the object. Otherwise, we simply return the
            # the result object and stop there.
            if ($null -eq $ConfigNode.Eap.EapType.Eap) {
                Write-Verbose "SSID: '$($Result.SSID)' | There is no inner EAP configuration."
                $Result
                return
            }

            $InnerEapType = Get-EapType -Node $ConfigNode.Eap.EapType.Eap
            if ($null -eq $InnerEapType) { Write-Warning "SSID: '$($Result.SSID)' | Inner EAP type not found."; return }

            $Result | Add-Member -MemberType "NoteProperty" -Name "InnerEapTypeId" -Value $InnerEapType.Id
            $Result | Add-Member -MemberType "NoteProperty" -Name "InnerEapType" -Value $InnerEapType.Name

            $InnerEapConfig = Get-EapConfig -Node $ConfigNode.Eap.EapType -Type $InnerEapType.Id
            if ($null -eq $InnerEapConfig) { Write-Warning "SSID: '$($Result.SSID)' | Failed to parse inner EAP configuration."; return }

            $Result | Add-Member -MemberType "NoteProperty" -Name "InnerEap" -Value $InnerEapConfig
            $Result | Add-Member -MemberType "NoteProperty" -Name "InnerEapStr" -Value ($InnerEapConfig | Format-List | Out-String).Trim()

            $Result
        }
    }
}

function Get-FirstExistingParentFolderPath {

    [CmdletBinding()]
    param (
        [String] $Path
    )

    try {
        $ParentPath = Split-Path $Path -Parent
        if ($ParentPath -and $(Test-Path -Path $ParentPath -ErrorAction SilentlyContinue)) {
            Resolve-Path -Path $ParentPath | Select-Object -ExpandProperty "Path" | Convert-Path
        }
        else {
            Get-FirstExistingParentFolderPath -Path $ParentPath
        }
    }
    catch {
        $null = $_
    }
}

function Get-UnattendSensitiveData {
    <#
    .SYNOPSIS
    Helper - Extract sensitive data from an "unattend" XML file

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Unattend files are XML documents which may contain cleartext passwords if they are not properly sanitized. Most of the time, "Password" fields will be replaced by the generic "*SENSITIVE*DATA*DELETED*" mention but sometimes, the original value remains and is either present in its plaintext form or base64-encoded form. If a non-empty password field is found and if it's not equal to the default "*SENSITIVE*DATA*DELETED*", this function will return the corresponding set of credentials: domain, username and (decoded) password.

    .PARAMETER Path
    The Path of the "unattend.xml" file to parse

    .EXAMPLE
    PS C:\> Get-UnattendSensitiveData -Path C:\Windows\Panther\Unattend.xml

    Type         Domain      Username      Password
    ----         ------      --------      --------
    Credentials  contoso.com Administrator Password1
    LocalAccount N/A         John          Password1
    AutoLogon    .           Administrator P@ssw0rd

    .NOTES
    A password can be stored in three formats:

    1) Simple string

        <Password>Password</Password>

    2) XML node + plain value

        <Password>
            <Value>Password</Value>
            <PlainText>true</PlainText>
        </Password>

    3) XML node + base64-encoded value

        <Password>
            <Value>UABhAHMAcwB3AG8AcgBkAA==</Value>
            <PlainText>false</PlainText>
        </Password>

    /!\ UNICODE encoding!
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [String] $Path
    )

    function Get-DecodedPassword {

        [CmdletBinding()]
        param(
            [Object] $XmlNode
        )

        if ($XmlNode.GetType().Name -eq "string") {
            $XmlNode
        }
        else {
            if ($XmlNode) {
                if ($XmlNode.PlainText -eq "false") {
                    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($XmlNode.Value))
                }
                else {
                    $XmlNode.Value
                }
            }
        }
    }

    [xml] $Xml = Get-Content -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetContentError

    if (-not $GetContentError) {

        $Xml.GetElementsByTagName("Credentials") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_.Password

            if ((-not [String]::IsNullOrEmpty($Password)) -and (-not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Credentials"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $_.Domain
                $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Username
                $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Result
            }
        }

        $Xml.GetElementsByTagName("LocalAccount") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_.Password

            if ((-not [String]::IsNullOrEmpty($Password)) -and (-not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "LocalAccount"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value "N/A"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Name
                $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Result
            }
        }

        $Xml.GetElementsByTagName("AutoLogon") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_.Password

            if ((-not [String]::IsNullOrEmpty($Password)) -and (-not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "AutoLogon"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $_.Domain
                $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Username
                $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Result
            }
        }

        $Xml.GetElementsByTagName("AdministratorPassword") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_

            if ((-not [String]::IsNullOrEmpty($Password)) -and (-not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "AdministratorPassword"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value "N/A"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value "N/A"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Result
            }
        }
    }
}

function Get-FileHashHex {
    <#
    .SYNOPSIS
    Compute the hash of a file given its path.

    Author: @itm4n
    Credit: @jaredcatkinson
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet is a simplified version of 'Get-FileHash', which is not available in PSv2.

    .PARAMETER FilePath
    The path of the file for which we want to compute the hash.

    .PARAMETER Algorithm
    A hash algorithm: md5, sha1, or sha256

    .EXAMPLE
    PS C:\> Get-FileHashHex -FilePath "C:\Windows\System32\drivers\RTCore64.sys"
    01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd

    PS C:\> Get-FileHashHex -FilePath "C:\Windows\System32\drivers\RTCore64.sys" -Algorithm sha1
    f6f11ad2cd2b0cf95ed42324876bee1d83e01775

    PS C:\> Get-FileHashHex -FilePath "C:\Windows\System32\drivers\RTCore64.sys" -Algorithm md5
    2d8e4f38b36c334d0a32a7324832501d

    .NOTES
    Credit goes to https://github.com/jaredcatkinson for the code.

    .LINK
    https://gist.github.com/jaredcatkinson/7d561b553a04501238f8e4f061f112b7
    #>#

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,

        [ValidateSet("MD5", "SHA1", "SHA256")]
        [string] $Algorithm = "SHA256"
    )

    try {
        $FileStream = [System.IO.File]::OpenRead($FilePath)
        $HashAlg = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
        $Hash = [byte[]] $HashAlg.ComputeHash($FileStream)
        [System.BitConverter]::ToString($Hash).Replace("-","").ToLower()
    }
    catch {
        Write-Warning "Failed to get hash of '$($FilePath)': $($_.Exception.Message.Trim())"
    }
}

function Get-KnownVulnerableKernelDriverList {

    [CmdletBinding()]
    param ()

    $VulnerableDriverList = $script:GlobalConstant.VulnerableDrivers | ConvertFrom-Csv -Delimiter ";"
    if ($null -eq $VulnerableDriverList) { Write-Warning "Failed to get list of vulnerable drivers."; return }

    $VulnerableDriverList | ForEach-Object {
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Url" -Value "https://www.loldrivers.io/drivers/$($_.Id)"
        $Result | Add-Member -MemberType "NoteProperty" -Name "HashType" -Value $_.HashType
        $Result | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value ([string[]] ($_.Hash -split ","))
        $Result
    }
}

function Resolve-CommandLine {

    [OutputType([String[]])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String] $CommandLine
    )

    process {
        $CommandLineResolved = [System.Environment]::ExpandEnvironmentVariables($CommandLine)

        # Is it a quoted path, i.e. a string surrounded by quotes, without quotes inside?
        # -> regex = ^"([^"])+"$
        if ($CommandLineResolved -match "^`"([^`"])+`"`$") {
            # This is a file path, return input after trimming double quotes
            return [String[]] $CommandLineResolved.Trim('"')
        }

        # Is it an unquoted path, without spaces?
        # -> regex = ^[^",^ ,^\t]+$
        if ($CommandLineResolved -match "^[^`",^ ,^\t]+`$") {
            # This a file path, return input as is.
            return [String[]] $CommandLineResolved
        }

        # Is it a command line in which the path of the executable is quoted?
        # -> regex = ^".+[ ,\t].*$
        if ($CommandLineResolved -match "^`".+\s.+" -and $CommandLineResolved) {
            return [String[]] (ConvertTo-ArgumentList -CommandLine $CommandLineResolved)
        }

        $Arguments = [String[]] (ConvertTo-ArgumentList -CommandLine $CommandLineResolved)
        if ($Arguments.Length -eq 0) {
            Write-Warning "Resolve-CommandLine failed for input: $($CommandLine)"
            return $null
        }

        if (-not [System.IO.Path]::IsPathRooted($Arguments[0])) {
            $PathResolved = Resolve-ModulePath -Name $Arguments[0]
            if (-not [String]::IsNullOrEmpty($PathResolved)) { $Arguments[0] = $PathResolved }
        }

        if (Test-Path -Path $Arguments[0] -ErrorAction SilentlyContinue) {
            # If arg0 is a valid file path, command line parsing worked, we can stop there.
            return $Arguments
        }

        for ($i = $Arguments.Length - 1; $i -ge 0; $i--) {
            $PathToAnalyze = $Arguments[0..$i] -join " "
            if (Test-Path -Path $PathToAnalyze -ErrorAction SilentlyContinue) {
                $Result = @()
                $Result += $PathToAnalyze
                if ($i -lt ($Arguments.Length - 1)) {
                    $Result += $Arguments[$($i + 1)..$($Arguments.Length - 1)]
                }
                return [String[]] $Result
            }
        }

        Write-Warning "Resolve-CommandLine failed for input: $($CommandLine)"
    }
}

function Resolve-KernelDriverImagePath {

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