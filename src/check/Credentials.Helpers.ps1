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

function Get-VaultCredential {
    <#
    .SYNOPSIS
    Helper - Enumerates Windows Credentials

    .DESCRIPTION
    Invokes the Windows API to enumerate the credentials that are stored in the user's vault (Windows Credentials).

    .PARAMETER Filtered
    If True, only entries with a readable (i.e. non-empty) password are returned.

    .EXAMPLE
    PS C:\> Get-VaultCredential -Filtered

    TargetName : LegacyGeneric:target=https://github.com/
    UserName   : user@example.com
    Comment    :
    Type       : 1 - GENERIC
    Persist    : 2 - LOCAL_MACHINE
    Flags      : 0
    Credential : ***
    #>

    [CmdletBinding()]
    param(
        [Switch] $Filtered = $false
    )

    # CRED_ENUMERATE_ALL_CREDENTIALS = 0x1
    $Count = 0;
    $CredentialsPtr = [IntPtr]::Zero
    $Success = $script:Advapi32::CredEnumerate([IntPtr]::Zero, 1, [ref] $Count, [ref] $CredentialsPtr)
    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($Success) {

        Write-Verbose "CredEnumerate() OK - Count: $($Count)"

        # CredEnumerate() returns an array of $Count PCREDENTIAL pointers, so we need to iterate this array
        # in order to get each PCREDENTIAL pointer. Then we can use this pointer to convert a blob of
        # unmanaged memory to a CREDENTIAL object.

        for ($i = 0; $i -lt $Count; $i++) {

            $CredentialPtrOffset = [IntPtr] ($CredentialsPtr.ToInt64() + [IntPtr]::Size * $i)
            $CredentialPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($CredentialPtrOffset)
            $Cred = [System.Runtime.InteropServices.Marshal]::PtrToStructure($CredentialPtr, [type] $script:CREDENTIAL)
            $CredStr = Convert-CredentialBlobToString $Cred

            if ((-not $Filtered) -or ($Filtered -and (-not [String]::IsNullOrEmpty($CredStr)))) {

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "TargetName" -Value $Cred.TargetName
                $Result | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $Cred.UserName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Comment" -Value $Cred.Comment
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "$($Cred.Type -as $script:CRED_TYPE)"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Persist" -Value "$($Cred.Persist -as $script:CRED_PERSIST)"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Flags" -Value "0x$($Cred.Flags.ToString('X8'))"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Credential" -Value $CredStr
                $Result
            }
        }

        $script:Advapi32::CredFree($CredentialsPtr)
    }
    else {
        # If there is no saved credentials, CredEnumerate sets the last error to ERROR_NOT_FOUND but this
        # doesn't mean that the function really failed. The same thing applies for the error code
        # ERROR_NO_SUCH_LOGON_SESSION.
        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
    }
}

function Get-VaultList {

    [CmdletBinding()]
    param(
        [Switch]
        $Filtered = $false
    )

    function Get-VaultNameFromGuid {
        [CmdletBinding()]
        param(
            [Guid] $VaultGuid
        )

        $VaultSchemaEnum = @{
            ([Guid] '2F1A6504-0641-44CF-8BB5-3612D865F2E5') = 'Windows Secure Note'
            ([Guid] '3CCD5499-87A8-4B10-A215-608888DD3B55') = 'Windows Web Password Credential'
            ([Guid] '154E23D0-C644-4E6F-8CE6-5069272F999F') = 'Windows Credential Picker Protector'
            ([Guid] '4BF4C442-9B8A-41A0-B380-DD4A704DDB28') = 'Web Credentials'
            ([Guid] '77BC582B-F0A6-4E15-4E80-61736B6F3B29') = 'Windows Credentials'
            ([Guid] 'E69D7838-91B5-4FC9-89D5-230D4D4CC2BC') = 'Windows Domain Certificate Credential'
            ([Guid] '3E0E35BE-1B77-43E7-B873-AED901B6275B') = 'Windows Domain Password Credential'
            ([Guid] '3C886FF3-2669-4AA2-A8FB-3F6759A77548') = 'Windows Extended Credential'
        }

        $VaultSchemaEnum[$VaultGuid]
    }

    # Highly inspired from "Get-VaultCredential.ps1", credit goes to Matthew Graeber
    # https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Get-VaultCredential.ps1
    function Get-VaultItemElementValue {
        [OutputType([Boolean])]
        [OutputType([Int16])]
        [OutputType([Int32])]
        [OutputType([String])]
        [CmdletBinding()]
        param(
            [IntPtr] $VaultItemElementPtr
        )

        if ($VaultItemElementPtr -eq [IntPtr]::Zero) {
            return
        }

        $VaultItemDataHeader = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemElementPtr, [type] $script:VAULT_ITEM_DATA_HEADER)
        $VaultItemDataValuePtr = [IntPtr] ($VaultItemElementPtr.ToInt64() + 16)

        switch ($VaultItemDataHeader.Type) {

            # ElementType_Boolean
            0x00 {
                [Bool] [Runtime.InteropServices.Marshal]::ReadByte($VaultItemDataValuePtr)
            }

            # ElementType_Short
            0x01 {
                [Runtime.InteropServices.Marshal]::ReadInt16($VaultItemDataValuePtr)
            }

            # ElementType_UnsignedShort
            0x02 {
                [Runtime.InteropServices.Marshal]::ReadInt16($VaultItemDataValuePtr)
            }

            # ElementType_Integer
            0x03 {
                [Runtime.InteropServices.Marshal]::ReadInt32($VaultItemDataValuePtr)
            }

            # ElementType_UnsignedInteger
            0x04 {
                [Runtime.InteropServices.Marshal]::ReadInt32($VaultItemDataValuePtr)
            }

            # ElementType_Double
            0x05 {
                [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemDataValuePtr, [Type] [Double])
            }

            # ElementType_Guid
            0x06 {
                [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemDataValuePtr, [Type] [Guid])
            }

            # ElementType_String
            0x07 {
                $StringPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($VaultItemDataValuePtr)
                [Runtime.InteropServices.Marshal]::PtrToStringUni($StringPtr)
            }

            # ElementType_ByteArray
            0x08 {

            }

            # ElementType_TimeStamp
            0x09 {

            }

            # ElementType_ProtectedArray
            0x0a {

            }

            # ElementType_Attribute
            0x0b {

            }

            # ElementType_Sid
            0x0c {
                $SidPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($VaultItemDataValuePtr)
                $SidObject = [Security.Principal.SecurityIdentifier] ($SidPtr)
                $SidObject.Value
            }

            # ElementType_Max
            0x0d {

            }
        }
    }

    $VaultsCount = 0
    $VaultGuids = [IntPtr]::Zero
    $Result = $script:Vaultcli::VaultEnumerateVaults(0, [ref] $VaultsCount, [ref] $VaultGuids)

    if ($Result -eq 0) {

        Write-Verbose "VaultEnumerateVaults() OK - Count: $($VaultsCount)"

        for ($i = 0; $i -lt $VaultsCount; $i++) {

            $VaultGuidPtr = [IntPtr] ($VaultGuids.ToInt64() + ($i * [Runtime.InteropServices.Marshal]::SizeOf([Type] [Guid])))
            $VaultGuid = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultGuidPtr, [type] [Guid])
            $VaultName = Get-VaultNameFromGuid -VaultGuid $VaultGuid

            Write-Verbose "Vault: $($VaultGuid) - $($VaultName)"

            $VaultHandle = [IntPtr]::Zero
            $Result = $script:Vaultcli::VaultOpenVault($VaultGuidPtr, 0, [ref] $VaultHandle)

            if ($Result -eq 0) {

                Write-Verbose "VaultOpenVault() OK - Vault Handle: 0x$($VaultHandle.ToString('X8'))"

                $VaultItemsCount = 0
                $ItemsPtr = [IntPtr]::Zero
                $Result = $script:Vaultcli::VaultEnumerateItems($VaultHandle, 0x0200, [ref] $VaultItemsCount, [ref] $ItemsPtr)

                $VaultItemPtr = $ItemsPtr

                if ($Result -eq 0) {

                    Write-Verbose "VaultEnumerateItems() OK - Items Count: $($VaultItemsCount)"

                    $OSVersion = Get-WindowsVersion

                    try {

                        for ($j = 0; $j -lt $VaultItemsCount; $j++) {

                            if ($OSVersion.Major -le 6 -and $OSVersion.Minor -le 1) {
                                # Windows 7
                                $VaultItemType = [type] $script:VAULT_ITEM_7
                            }
                            else {
                                # Windows 8+
                                $VaultItemType = [type] $script:VAULT_ITEM_8
                            }

                            $VaultItem = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemPtr, [type] $VaultItemType)

                            if ($OSVersion.Major -le 6 -and $OSVersion.Minor -le 1) {
                                # Windows 7
                                $PasswordItemPtr = [IntPtr]::Zero
                                $Result = $script:Vaultcli::VaultGetItem7($VaultHandle, [ref] $VaultItem.SchemaId, $VaultItem.Resource, $VaultItem.Identity, [IntPtr]::Zero, 0, [ref] $PasswordItemPtr)
                            }
                            else {
                                # Windows 8+
                                $PasswordItemPtr = [IntPtr]::Zero
                                $Result = $script:Vaultcli::VaultGetItem8($VaultHandle, [ref] $VaultItem.SchemaId, $VaultItem.Resource, $VaultItem.Identity, $VaultItem.PackageSid, [IntPtr]::Zero, 0, [ref] $PasswordItemPtr)
                            }

                            if ($Result -eq 0) {

                                Write-Verbose "VaultGetItem() OK - ItemPtr: 0x$($PasswordItemPtr.ToString('X8'))"
                                $PasswordItem = [Runtime.InteropServices.Marshal]::PtrToStructure($PasswordItemPtr, [Type] $VaultItemType)
                                $Password = Get-VaultItemElementValue -VaultItemElementPtr $PasswordItem.Authenticator
                                $script:Vaultcli::VaultFree($PasswordItemPtr) | Out-Null

                            }
                            else {
                                Write-Verbose "VaultGetItem() failed - Err: 0x$($Result.ToString('X8'))"
                            }

                            if ((-not $Filtered) -or ($Filtered -and (-not [String]::IsNullOrEmpty($Password)))) {

                                $Result = New-Object -TypeName PSObject
                                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $VaultName
                                $Result | Add-Member -MemberType "NoteProperty" -Name "TargetName" -Value $(Get-VaultItemElementValue -VaultItemElementPtr $VaultItem.Resource)
                                $Result | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $(Get-VaultItemElementValue -VaultItemElementPtr $VaultItem.Identity)
                                $Result | Add-Member -MemberType "NoteProperty" -Name "Credential" -Value $Password
                                $Result | Add-Member -MemberType "NoteProperty" -Name "LastWritten" -Value $(Convert-FiletimeToDatetime $VaultItem.LastWritten)
                                $Result
                            }

                            $VaultItemPtr = [IntPtr] ($VaultItemPtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([Type] $VaultItemType))
                        }
                    }
                    catch [Exception] {
                        Write-Verbose $_.Exception.Message
                    }
                }
                else {
                    Write-Verbose "VaultEnumerateItems() failed - Err: 0x$($Result.ToString('X8'))"
                }

                $script:Vaultcli::VaultCloseVault([ref] $VaultHandle) | Out-Null
            }
            else {
                Write-Verbose "VaultOpenVault() failed - Err: 0x$($Result.ToString('X8'))"
            }
        }
    }
    else {
        Write-Verbose "VaultEnumerateVaults() failed - Err: 0x$($Result.ToString('X8'))"
    }
}

function Get-ShadowCopy {
    <#
    .SYNOPSIS
    Helper - Enumerates Shadow Copies

    Author: @SAERXCIT, @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Uses Win32 functions NtOpenDirectoryObject and NtQueryDirectoryObject (thanks @gentilkiwi for the method).
    Inspired from https://github.com/cube0x0/CVE-2021-36934 and https://gist.github.com/brianreitz/feb4e14bd45dd2e4394c225b17df5741.

    .EXAMPLE
    PS C:\>  Get-ShadowCopy | fl

    Volume : HarddiskVolumeShadowCopy1
    Path   : \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1

    Volume : HarddiskVolumeShadowCopy2
    Path   : \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2
    #>

    [CmdletBinding()]
    param()

    $ObjectName = "\Device"
    $ObjectNameBuffer = [Activator]::CreateInstance($script:UNICODE_STRING)
    $script:Ntdll::RtlInitUnicodeString([ref] $ObjectNameBuffer, $ObjectName) | Out-Null

    $ObjectAttributes = [Activator]::CreateInstance($script:OBJECT_ATTRIBUTES)
    $ObjectAttributes.Length = $script:OBJECT_ATTRIBUTES::GetSize()
    $ObjectAttributes.RootDirectory = [IntPtr]::Zero
    $ObjectAttributes.Attributes = $OBJ_ATTRIBUTE::OBJ_CASE_INSENSITIVE
    $ObjectAttributes.ObjectName = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($script:UNICODE_STRING::GetSize())
    [System.Runtime.InteropServices.Marshal]::StructureToPtr($ObjectNameBuffer, $ObjectAttributes.ObjectName, $true)

    $ObjectAttributes.SecurityDescriptor = [IntPtr]::Zero
    $ObjectAttributes.SecurityQualityOfService = [IntPtr]::Zero

    $ObjectHandle = [IntPtr]::Zero

    $Status = $script:Ntdll::NtOpenDirectoryObject([ref] $ObjectHandle, 3, [ref] $ObjectAttributes)

    if ($Status -ne 0) {
        $LastError = $script:Ntdll::RtlNtStatusToDosError($Status)
        Write-Verbose "NtOpenDirectoryObject - $([ComponentModel.Win32Exception] $LastError)"
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ObjectAttributes.ObjectName) | Out-Null
        return
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ObjectAttributes.ObjectName) | Out-Null

    $BufferSize = 1024
    $Buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufferSize)

    [uint32] $Context = 0
    [uint32] $Length = 0

    while ($true) {

        $Status = $script:Ntdll::NtQueryDirectoryObject($ObjectHandle, $Buffer, $BufferSize, $true, $Context -eq 0, [ref] $Context, [ref] $Length)

        if ($Status -ne 0) { break }

        $ObjectDirectoryInformation = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Buffer, [type] $script:OBJECT_DIRECTORY_INFORMATION)
        $TypeName = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ObjectDirectoryInformation.TypeName.Buffer)
        $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($ObjectDirectoryInformation.Name.Buffer)

        if ($TypeName -eq "Device" -and $Name -like "*VolumeShadowCopy*") {
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Volume" -Value $Name
            $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $(Join-Path -Path "\\?\GLOBALROOT\Device\" -ChildPath $Name)
            $Result
        }
    }

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($Buffer) | Out-Null
}

function Find-WmiCcmNaaCredential {
    <#
    .SYNOPSIS
    Search for NAA credentials in the WMI database.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet attempts to find SCCM Network Access Account credential blobs in the raw WMI data file 'OBJECTS.DATA'.

    .PARAMETER Path
    The path of the WMI data file to parse. If null, the default system path is used.

    .EXAMPLE
    PS C:\> Find-WmiCcmNaaCredential | Format-List

    NetworkAccessUsername : <PolicySecret Version="1"><![CDATA[0601000001000000D08...]]></PolicySecret>
    NetworkAccessPassword : <PolicySecret Version="1"><![CDATA[0601000001000000D08...]]></PolicySecret>

    .NOTES
    https://posts.specterops.io/the-phantom-credentials-of-sccm-why-the-naa-wont-die-332ac7aa1ab9
    #>

    [CmdletBinding()]
    param(
        [string] $Path
    )

    begin {
        $SanityCheck = $true

        if ([string]::IsNullOrEmpty($Path)) {
            $Path = Join-Path -Path $env:windir -ChildPath "System32\wbem\Repository\OBJECTS.DATA"
        }

        if (-not (Test-Path -Path $Path)) {
            Write-Warning "File not found: $($Path)"
            $SanityCheck = $false
        }

        $BasePattern = "CCM_NetworkAccessAccount"
        $PolicyPatternBegin = "<PolicySecret"
        $PolicyPatternEnd = "</PolicySecret>"

        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {

        if (-not $SanityCheck) { return }

        $Candidates = Select-String -Path $Path -Pattern "$($BasePattern)`0`0$($PolicyPatternBegin)"
        if ($null -eq $Candidates) { return }

        foreach ($Candidate in $Candidates) {

            # Find the offset of the XML start tag, and create a substring starting from
            # this offset, to the end of the line.
            $Line = $Candidate.Line
            $Offset = $Line.IndexOf($BasePattern) + $BasePattern.Length + 2
            $Line = $Line.SubString($Offset, $Line.Length - $Offset)

            # Find all occurrences of the XML start tag. For each one, find the XML end tag
            # and extract a substring containing the PolicySecret entry.
            $Offset = 0
            $PolicySecrets = @()
            while (($Offset = $Line.IndexOf($PolicyPatternBegin, $Offset)) -ge 0) {

                $EndIndex = $Line.IndexOf($PolicyPatternEnd, $Offset)
                if ($EndIndex -lt 0) {
                    Write-Warning "Failed to find pattern '$($PolicyPatternEnd)'."
                    break
                }

                $Length = $EndIndex + $PolicyPatternEnd.Length - $Offset
                $Substring = $Line.SubString($Offset, $Length)
                [string[]] $PolicySecrets += $Substring

                $Offset += $PolicyPatternBegin.Length
            }

            if ($PolicySecrets.Count -ne 2) {
                Write-Warning "PolicySecret count should be 2, but was $($PolicySecrets.Count)."
                break
            }

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "NetworkAccessUsername" -Value $PolicySecrets[1]
            $Result | Add-Member -MemberType "NoteProperty" -Name "NetworkAccessPassword" -Value $PolicySecrets[0]
            $Result
        }
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Find-SccmCacheFileCredential {
    <#
    .SYNOPSIS
    Helper - Find potentially hard coded credentials in SCCM cache files.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function first retrieves a list of potentially interesting files from the SCCM cache folders, and tries to find potentially hard coded credentials or secrets. For binary files, it simply determines whether there is a potential match, without returning anything to avoid messing up with the terminal output. For text files (incl. scripts), it returns all matching results.
    #>

    [CmdletBinding()]
    param()

    begin {
        $Keywords = @( "password", "SecureString", "secret", "pwd", "token", "username" )
        $CredentialSearchPattern = "($($Keywords -join '|'))"

        function Get-MatchedKeyword {
            param([string] $InputMatched)
            $KeywordMatched = $null
            foreach ($Keyword in $Keywords) {
                $KeywordMatch = $InputMatched | Select-String -Pattern $Keyword
                if ($null -ne $KeywordMatch) {
                    $KeywordMatched = $Keyword
                    break
                }
            }
            return $KeywordMatched
        }
    }

    process {

        $SccmCacheFolders = Get-SccmCacheFoldersFromRegistry

        foreach ($SccmCacheFolder in $SccmCacheFolders) {

            if ([string]::IsNullOrEmpty($SccmCacheFolder.Path)) { continue }

            $SccmCacheFiles = Get-SccmCacheFile -Path $SccmCacheFolder.Path

            foreach ($SccmCacheFile in $SccmCacheFiles) {

                if ([string]::IsNullOrEmpty($SccmCacheFile.Path)) { continue }

                $FileItem = Get-Item -Path $SccmCacheFile.Path -ErrorAction SilentlyContinue
                if ($null -eq $FileItem) { continue }

                if ($SccmCacheFile.Type -eq "Binary") {

                    # For binary files, just check whether the target file matches at least
                    # once, without returning anything.

                    # Ignore files that are larger than 100 MB to avoid spending too much
                    # time on the search.

                    if ($FileItem.Length -gt 100000000) {
                        Write-Warning "File '$($SccmCacheFile.Path) is too big, ignoring."
                        continue
                    }

                    $TempMatch = Get-Content -Path $SccmCacheFile.Path | Select-String -Pattern $CredentialSearchPattern
                    if ($null -ne $TempMatch) {

                        $Result = $SccmCacheFile.PSObject.Copy()
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Match" -Value "(binary file matches)"
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Keyword" -Value (Get-MatchedKeyword -InputMatched $TempMatch.Line)
                        $Result
                    }
                }
                elseif (($SccmCacheFile.Type -eq "Script") -or ($SccmCacheFile.Type -eq "Text")) {

                    # For script files and misc text files, return all matches of the pattern.

                    $TempMatch = Get-Content -Path $SccmCacheFile.Path | Select-String -Pattern $CredentialSearchPattern -AllMatches
                    if ($null -ne $TempMatch) {
                        Write-Verbose "File '$($SccmCacheFile.Path)' matches pattern."
                        foreach ($Match in $TempMatch) {

                            $Result = $SccmCacheFile.PSObject.Copy()
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Match" -Value "Line $($Match.LineNumber): $($Match.Line.Trim())"
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Keyword" -Value (Get-MatchedKeyword -InputMatched $TempMatch.Line)
                            $Result
                        }
                    }
                }
                else {
                    throw "Unhandled file type: $($SccmCacheFile.Type)"
                }
            }
        }
    }
}