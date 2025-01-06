function Get-CurrentUserSid {

    [CmdletBinding()]
    param()

    if ($null -eq $script:GlobalCache.CurrentUserSids) {
        Write-Verbose "Initializing cache: CurrentUserSids"
        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $script:GlobalCache.CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $script:GlobalCache.CurrentUserSids += $UserIdentity.User.Value
    }

    $script:GlobalCache.CurrentUserSids
}

function Get-CurrentUserDenySid {

    [CmdletBinding()]
    param()

    if ($null -eq $script:GlobalCache.CurrentUserDenySids) {
        Write-Verbose "Initializing cache: CurrentUserDenySids"
        $script:GlobalCache.CurrentUserDenySids = [string[]](Get-TokenInformationGroup -InformationClass Groups | Where-Object { $_.Attributes.Equals("UseForDenyOnly") } | Select-Object -ExpandProperty SID)
        if ($null -eq $script:GlobalCache.CurrentUserDenySids) {
            $script:GlobalCache.CurrentUserDenySids = @()
        }
    }

    $script:GlobalCache.CurrentUserDenySids
}

function Get-InstalledApplication {
    <#
    .SYNOPSIS
    Helper - Enumerates the installed applications

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This looks for applications installed in the common "Program Files" and "Program Files (x86)" folders. It also enumerates installed applications thanks to the registry by looking for all the subkeys in "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall".

    .PARAMETER Filtered
    If True, only non-default applications are returned. Otherwise, all the applications are returned. The filter is base on a list of known applications which are known to be installed by default (e.g.: "Windows Defender").

    .EXAMPLE
    PS C:\> Get-InstalledApplication -Filtered

    Mode                LastWriteTime     Length Name
    ----                -------------     ------ ----
    d----        29/11/2019     10:51            Npcap
    d----        29/11/2019     10:51            Wireshark
    #>

    [CmdletBinding()]
    param(
        [switch] $Filtered = $false
    )

    begin {
        $IgnoredPrograms = @( "Common Files", "Internet Explorer", "ModifiableWindowsApps", "PackageManagement", "Windows Defender", "Windows Defender Advanced Threat Protection", "Windows Mail", "Windows Media Player", "Windows Multimedia Platform", "Windows NT", "Windows Photo Viewer", "Windows Portable Devices", "Windows Security", "WindowsPowerShell", "Microsoft.NET", "Windows Portable Devices", "dotnet", "MSBuild", "Intel", "Reference Assemblies" )
    }

    process {
        $InstalledPrograms = @()
        $InstalledPrograms += Get-ChildItem -Path $(Join-Path -Path $env:SystemDrive -ChildPath "Program Files (x86)") -ErrorAction SilentlyContinue | Where-Object { $_ -is [System.IO.DirectoryInfo] }
        $InstalledPrograms += Get-ChildItem -Path $(Join-Path -Path $env:SystemDrive -ChildPath "Program Files") -ErrorAction SilentlyContinue | Where-Object { $_ -is [System.IO.DirectoryInfo] }

        $InstalledProgramsRegKeys = @()
        $InstalledProgramsRegKeys += Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue
        $InstalledProgramsRegKeys += Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue

        foreach ($InstalledProgramsRegKey in $InstalledProgramsRegKeys) {

            $InstallLocation = [System.Environment]::ExpandEnvironmentVariables($InstalledProgramsRegKey.GetValue("InstallLocation"))
            if ([String]::IsNullOrEmpty($InstallLocation)) { continue }
            if (-not (Test-Path -Path $InstallLocation -ErrorAction SilentlyContinue)) { continue }

            $InstallLocation = $InstallLocation.Trim('\')

            $FileItem = Get-Item -Path $InstallLocation -ErrorAction SilentlyContinue
            if ($null -eq $FileItem) { continue }
            if ($FileItem -isnot [System.IO.DirectoryInfo]) { continue }

            $InstalledPrograms += $FileItem
        }

        foreach ($InstalledProgram in $($InstalledPrograms | Sort-Object -Property "FullName" -Unique)) {

            # Make sure we skip empty paths.
            if ([string]::IsNullOrEmpty($InstalledProgram.FullName)) { continue }

            # Make sure we don't treat system paths such as 'C:\Windows\System32' as
            # application folders.
            if (Test-IsSystemFolder -Path $InstalledProgram.FullName) { continue }

            # If the 'Filtered' switch is used, only return non-default application
            # folder entries.
            if ($Filtered -and ($IgnoredPrograms -contains $InstalledProgram.Name)) { continue }

            # Keep only the folder name and full path.
            $InstalledProgram | Select-Object -Property Name,FullName
        }
    }
}

function Get-SccmCacheFolderFromRegistry {
    <#
    .SYNOPSIS
    Helper - Enumerate SCCM cache folders using the registry.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function lists the values of the registry key 'HKLM\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution', checks if their data contains the path of an SCCM cache folder, and finally returns all valid paths
    #>

    [CmdletBinding()]
    param()

    begin {
        $SoftwareDistributionKey = "HKLM\SOFTWARE\Microsoft\SMS\Mobile Client\Software Distribution"
    }

    process {
        $SoftwareDistributionKeyItem = Get-Item -Path "Registry::$($SoftwareDistributionKey)" -ErrorAction SilentlyContinue
        if ($null -eq $SoftwareDistributionKeyItem) { return }

        foreach ($Value in $($SoftwareDistributionKeyItem | Select-Object -ExpandProperty Property)) {

            # Filer out values that don't contain an SCCM cache folder path.
            $Data = (Get-ItemProperty -Path "Registry::$($SoftwareDistributionKey)" -Name $Value).$Value
            if ($Data -notlike "*ccmcache*") { continue }

            # Only return folders that exist.
            $FolderItem = Get-Item -Path "$($Data)" -ErrorAction SilentlyContinue
            if ($null -eq $FolderItem) { continue }

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $Value
            $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Data
            $Result
        }
    }
}

function Get-SccmCacheFile {
    <#
    .SYNOPSIS
    Helper - Enumerate application files in SCCM cache folders.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function first retrieves a list of SCCM cache folders, and, for each path, lists files recursively. It then returns all paths corresponding to a script or executable.
    #>

    [CmdletBinding()]
    param(
        [string] $Path
    )

    begin {
        $ScriptFileExtensions = @( "bat", "cmd", "ps1", "vbe", "vbs", "wsf", "wsh" )
        $ScriptPathRegex = ".*\.($($ScriptFileExtensions -join '|'))$"

        $BinFileExtensions = @( "exe", "dll", "msi" )
        $BinFilePathRegex = ".*\.($($BinFileExtensions -join '|'))$"

        $TextFileExtensions = @( "reg", "cfg", "txt" )
        $TextFilePathRegex = ".*\.($($TextFileExtensions -join '|'))$"
    }

    process {

        foreach ($FileItem in $(Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue)) {

            if ($FileItem -is [System.IO.DirectoryInfo]) { continue }

            if ($FileItem.FullName -match $ScriptPathRegex) {
                $FileType = "Script"
            }
            elseif ($FileItem.FullName -match $BinFilePathRegex) {
                $FileType = "Binary"
            }
            elseif ($FileItem.FullName -match $TextFilePathRegex) {
                $FileType = "Text"
            }
            else {
                continue
            }

            $RelativePath = Resolve-PathRelativeTo -From $Path -To $FileItem.FullName

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $FileType
            $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $FileItem.FullName
            $Result | Add-Member -MemberType "NoteProperty" -Name "RelativePath" -Value $RelativePath
            $Result
        }
    }
}

function Get-CredentialItem {
    <#
    .SYNOPSIS
    Helper - Enumerates Windows Credentials

    .DESCRIPTION
    Invokes the Windows API to enumerate the credentials that are stored in the user's vault (Windows Credentials).

    .PARAMETER Filtered
    If True, only entries with a readable (i.e. non-empty) password are returned.

    .EXAMPLE
    PS C:\> Get-CredentialItem -Filtered

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
        Write-Verbose "CredEnumerate - $(Format-Error $LastError)"
    }
}

function Get-VaultItem {

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

                    $OSVersion = Get-WindowsVersionFromRegistry

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

function Get-SccmNetworkAccessAccountCredential {
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
    PS C:\> Get-SccmNetworkAccessAccountCredential | Format-List

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

        if (-not (Test-Path -Path $Path -ErrorAction SilentlyContinue)) {
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

function Get-SccmCacheFileCredential {
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

        $SccmCacheFolders = Get-SccmCacheFolderFromRegistry

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

function Get-RemoteDesktopUserSession {
    <#
    .SYNOPSIS
    List the sessions of the currently logged-on users through the WTS API.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet simply invokes the WTSEnumerateSessionsEx API to enumerate the sessions of the logged-on users. This API returns a list of TS_SESSION_INFO_1W structures containing the sessions info.

    .EXAMPLE
    PS C:\> Get-RemoteDesktopUserSession

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
        Write-Verbose "WTSEnumerateSessionsEx - $(Format-Error $LastError)"
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
        Write-Verbose "WTSFreeMemoryEx - $(Format-Error $LastError)"
        return
    }
}

function Get-KnownVulnerableKernelDriver {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Object] $Service
    )

    begin {
        Write-Verbose "Initializing list of vulnerable driver hashes..."
        $VulnerableDriverHashes = Get-KnownVulnerableKernelDriverList
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

function Get-RpcRange {
    <#
    .SYNOPSIS
    Helper - Dynamically identifies the range of randomized RPC ports from a list of ports.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function is a helper for the Invoke-TcpEndpointCheck function. Windows uses a set of RPC ports that are randomly allocated in the range 49152-65535 by default. If we want to filter out these listening ports we must first figure out this set of ports. The aim of this function is to guess this range using basic statistics on a given array of port numbers. We can quite reliably identify the RPC port set because they are concentrated in a very small range. It's not 100% reliable but it will do the job most of the time.

    .PARAMETER Ports
    An array of port numbers

    .EXAMPLE
    PS C:\> Get-RpcRange -Ports $Ports

    MinPort MaxPort
    ------- -------
    49664   49672
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Int[]] $Ports
    )

    function Get-Statistic {
        [CmdletBinding()]
        param(
            [Int[]] $Ports,
            [Int] $MinPort,
            [Int] $MaxPort,
            [Int] $Span
        )

        $Stats = @()
        For ($i = $MinPort; $i -lt $MaxPort; $i += $Span) {
            $Counter = 0
            foreach ($Port in $Ports) {
                if (($Port -ge $i) -and ($Port -lt ($i + $Span))) {
                    $Counter += 1
                }
            }
            $RangeStats = New-Object -TypeName PSObject
            $RangeStats | Add-Member -MemberType "NoteProperty" -Name "MinPort" -Value $i
            $RangeStats | Add-Member -MemberType "NoteProperty" -Name "MaxPort" -Value ($i + $Span)
            $RangeStats | Add-Member -MemberType "NoteProperty" -Name "PortsInRange" -Value $Counter
            $Stats += $RangeStats
        }
        $Stats
    }

    # We split the range 49152-65536 into blocks of size 32 and then, we take the block which has
    # greater number of ports in it.
    $Stats = Get-Statistic -Ports $Ports -MinPort 49152 -MaxPort 65536 -Span 32

    $MaxStat = $null
    foreach ($Stat in $Stats) {
        if ($Stat.PortsInRange -gt $MaxStat.PortsInRange) {
            $MaxStat = $Stat
        }
    }

    For ($i = 0; $i -lt 8; $i++) {
        $Span = ($MaxStat.MaxPort - $MaxStat.MinPort) / 2
        $NewStats = Get-Statistic -Ports $Ports -MinPort $MaxStat.MinPort -MaxPort $MaxStat.MaxPort -Span $Span
        if ($NewStats) {
            if ($NewStats[0].PortsInRange -eq 0) {
                $MaxStat = $NewStats[1]
            }
            elseif ($NewStats[1].PortsInRange -eq 0) {
                $MaxStat = $NewStats[0]
            }
            else {
                break
            }
        }
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "MinPort" -Value $MaxStat.MinPort
    $Result | Add-Member -MemberType "NoteProperty" -Name "MaxPort" -Value $MaxStat.MaxPort
    $Result
}

function Get-NetworkEndpoint {
    <#
    .SYNOPSIS
    Get a list of listening ports (TCP/UDP)

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    It uses the 'GetExtendedTcpTable' and 'GetExtendedUdpTable' functions of the Windows API to list the TCP/UDP endpoints on the local machine. It handles both IPv4 and IPv6. For each entry in the table, a custom PS object is returned, indicating the IP version (IPv4/IPv6), the protocol (TCP/UDP), the local address (e.g.: "0.0.0.0:445"), the state, the PID of the associated process and the name of the process. The name of the process is retrieved through a call to "Get-Process -PID <PID>".

    .EXAMPLE
    PS C:\> Get-NetworkEndpoint | ft

    IP   Proto LocalAddress LocalPort Endpoint         State       PID Name
    --   ----- ------------ --------- --------         -----       --- ----
    IPv4 TCP   0.0.0.0            135 0.0.0.0:135      LISTENING  1216 svchost
    IPv4 TCP   0.0.0.0            445 0.0.0.0:445      LISTENING     4 System
    IPv4 TCP   0.0.0.0           5040 0.0.0.0:5040     LISTENING  8580 svchost
    IPv4 TCP   0.0.0.0          49664 0.0.0.0:49664    LISTENING   984 lsass
    IPv4 TCP   0.0.0.0          49665 0.0.0.0:49665    LISTENING   892 wininit
    IPv4 TCP   0.0.0.0          49666 0.0.0.0:49666    LISTENING  1852 svchost
    IPv4 TCP   0.0.0.0          49667 0.0.0.0:49667    LISTENING  1860 svchost
    IPv4 TCP   0.0.0.0          49668 0.0.0.0:49668    LISTENING  2972 svchost
    IPv4 TCP   0.0.0.0          49669 0.0.0.0:49669    LISTENING  4480 spoolsv
    IPv4 TCP   0.0.0.0          49670 0.0.0.0:49670    LISTENING   964 services

    .EXAMPLE
    PS C:\> Get-NetworkEndpoint -UDP -IPv6 | ft

    IP   Proto LocalAddress LocalPort Endpoint    State  PID Name
    --   ----- ------------ --------- --------    -----  --- ----
    IPv6 UDP   ::                 500 [::]:500    N/A   5000 svchost
    IPv6 UDP   ::                3702 [::]:3702   N/A   4128 dasHost
    IPv6 UDP   ::                3702 [::]:3702   N/A   4128 dasHost
    IPv6 UDP   ::                4500 [::]:4500   N/A   5000 svchost
    IPv6 UDP   ::               62212 [::]:62212  N/A   4128 dasHost
    IPv6 UDP   ::1               1900 [::1]:1900  N/A   5860 svchost
    IPv6 UDP   ::1              63168 [::1]:63168 N/A   5860 svchost
    #>

    [CmdletBinding()]
    param(
        # IPv4 by default
        [Switch] $IPv6 = $false,
        # TCP by default
        [Switch] $UDP = $false
    )

    $AF_INET6 = 23
    $AF_INET = 2

    if ($IPv6) {
        $IpVersion = $AF_INET6
    }
    else {
        $IpVersion = $AF_INET
    }

    if ($UDP) {
        $UDP_TABLE_OWNER_PID = 1
        [Int] $BufSize = 0
        $Result = $script:Iphlpapi::GetExtendedUdpTable([IntPtr]::Zero, [ref] $BufSize, $true, $IpVersion, $UDP_TABLE_OWNER_PID, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }
    else {
        $TCP_TABLE_OWNER_PID_LISTENER = 3
        [Int] $BufSize = 0
        $Result = $script:Iphlpapi::GetExtendedTcpTable([IntPtr]::Zero, [ref] $BufSize, $true, $IpVersion, $TCP_TABLE_OWNER_PID_LISTENER, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }

    if ($Result -eq 122) {

        Write-Verbose "GetExtendedProtoTable() OK - Size: $BufSize"

        [IntPtr] $TablePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufSize)

        if ($UDP) {
            $Result = $script:Iphlpapi::GetExtendedUdpTable($TablePtr, [ref] $BufSize, $true, $IpVersion, $UDP_TABLE_OWNER_PID, 0)
        }
        else {
            $Result = $script:Iphlpapi::GetExtendedTcpTable($TablePtr, [ref] $BufSize, $true, $IpVersion, $TCP_TABLE_OWNER_PID_LISTENER, 0)
        }

        if ($Result -eq 0) {

            if ($UDP) {
                if ($IpVersion -eq $AF_INET) {
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $script:MIB_UDPTABLE_OWNER_PID)
                }
                elseif ($IpVersion -eq $AF_INET6) {
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $script:MIB_UDP6TABLE_OWNER_PID)
                }
            }
            else {
                if ($IpVersion -eq $AF_INET) {
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $script:MIB_TCPTABLE_OWNER_PID)
                }
                elseif ($IpVersion -eq $AF_INET6) {
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $script:MIB_TCP6TABLE_OWNER_PID)
                }
            }

            $NumEntries = $Table.NumEntries

            Write-Verbose "GetExtendedProtoTable() OK - NumEntries: $NumEntries"

            $Offset = [IntPtr] ($TablePtr.ToInt64() + 4)

            For ($i = 0; $i -lt $NumEntries; $i++) {

                if ($UDP) {
                    if ($IpVersion -eq $AF_INET) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $script:MIB_UDPROW_OWNER_PID)
                        $LocalAddr = (New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr)).IPAddressToString
                    }
                    elseif ($IpVersion -eq $AF_INET6) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $script:MIB_UDP6ROW_OWNER_PID)
                        $LocalAddr = New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr, $TableEntry.LocalScopeId)
                    }
                }
                else {
                    if ($IpVersion -eq $AF_INET) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $script:MIB_TCPROW_OWNER_PID)
                        $LocalAddr = (New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr)).IPAddressToString
                    }
                    elseif ($IpVersion -eq $AF_INET6) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $script:MIB_TCP6ROW_OWNER_PID)
                        $LocalAddr = New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr, [Int64] $TableEntry.LocalScopeId)
                    }
                }

                $LocalPort = $TableEntry.LocalPort[0] * 0x100 + $TableEntry.LocalPort[1]
                $ProcessId = $TableEntry.OwningPid

                if ($IpVersion -eq $AF_INET) {
                    $LocalAddress = "$($LocalAddr):$($LocalPort)"
                }
                elseif ($IpVersion -eq $AF_INET6) {
                    # IPv6.ToString doesn't work in PSv2 for some reason
                    try { $LocalAddress = "[$($LocalAddr)]:$($LocalPort)" } catch { $LocalAddress = "????:$($LocalPort)" }
                }

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "IP" -Value $(if ($IpVersion -eq $AF_INET) { "IPv4" } else { "IPv6" } )
                $Result | Add-Member -MemberType "NoteProperty" -Name "Proto" -Value $(if ($UDP) { "UDP" } else { "TCP" } )
                $Result | Add-Member -MemberType "NoteProperty" -Name "LocalAddress" -Value $LocalAddr
                $Result | Add-Member -MemberType "NoteProperty" -Name "LocalPort" -Value $LocalPort
                $Result | Add-Member -MemberType "NoteProperty" -Name "Endpoint" -Value $LocalAddress
                $Result | Add-Member -MemberType "NoteProperty" -Name "State" -Value $(if ($UDP) { "N/A" } else { "LISTENING" } )
                $Result | Add-Member -MemberType "NoteProperty" -Name "PID" -Value $ProcessId
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value (Get-Process -PID $ProcessId -ErrorAction SilentlyContinue).ProcessName
                $Result

                $Offset = [IntPtr] ($Offset.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($TableEntry))
            }

        }
        else {
            Write-Verbose "GetExtended***Table - $(Format-Error $LastError)"
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TablePtr)

    }
    else {
        Write-Verbose "GetExtended***Table - $(Format-Error $LastError)"
    }
}