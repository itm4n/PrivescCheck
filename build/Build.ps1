function Invoke-Build {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("PrivescCheck")]
        [String] $Name,

        [Switch] $NoNewSeed,

        [Switch] $NoNewKey
    )

    begin {

        $SanityCheck = $true

        if (-not (Test-Path -Path "build")) {
            Write-Message Error "Build folder not found."
            $SanityCheck = $false
        }

        $BuildProfilesJson = Get-FileContent -Type "build" -FileName "BuildProfiles.json" | Out-String | ConvertFrom-Json
        if ($null -eq $BuildProfilesJson) {
            Write-Message Error "Failed to read build profile file."
            $SanityCheck = $false
        }

        $RootPath = Split-Path -Path (Split-Path -Path $PSCommandPath -Parent) -Parent

        $WordList = Get-FileContent -Type "data" -FileName "WordList.txt" | Where-Object { -not [String]::IsNullOrEmpty($_) }
        if ($null -eq $WordList) {
            Write-Message Error "Failed to retrieve word list."
            $SanityCheck = $false
        }

        if ($NoNewSeed) {
            $Seed = Get-FileContent -Type "build" -FileName "Seed.txt" -ErrorAction SilentlyContinue | Out-String
            if ([String]::IsNullOrEmpty($Seed)) {
                Write-Message Error "Failed to read seed from file."
                $SanityCheck = $false
            }
            else {
                $Seed = [Int32]::Parse($Seed)
                Write-Message Info "Using seed: $($Seed)"
            }
        }
        else {
            $Seed = Get-RandomInt
            Write-Message Info "Generated seed: $($Seed)"
            Set-FileContent -Type "build" -FileName "Seed.txt" -Content "$($Seed)"
        }

        if ($NoNewKey) {
            $EncryptionKeyHexString = Get-FileContent -Type "build" -FileName "EncryptionKey.txt" -ErrorAction SilentlyContinue | Out-String
            if ([String]::IsNullOrEmpty($EncryptionKeyHexString)) {
                Write-Message Error "Failed to read encryption key from file."
                $SanityCheck = $false
            }
            else {
                $EncryptionKeyHexString = $EncryptionKeyHexString.Trim()
                Write-Message Info "Using encryption key: $($EncryptionKeyHexString)"
                $EncryptionKey = New-Object -TypeName Byte[] -ArgumentList ($EncryptionKeyHexString.Length / 2)
                for ($i = 0; $i -lt ($EncryptionKeyHexString.Length / 2); $i++) {
                    $EncryptionKey[$i] = [Convert]::ToByte($EncryptionKeyHexString.Substring($i * 2, 2), 16)
                }
            }
        }
        else {
            $EncryptionKey = New-RandomByteArray -Size 32
            $EncryptionKeyHexString = [System.BitConverter]::ToString($EncryptionKey).ToLower() -replace '-',''
            Write-Message Info "Generated encryption key: $($EncryptionKeyHexString)"
            Set-FileContent -Type "build" -FileName "EncryptionKey.txt" -Content "$($EncryptionKeyHexString)"
        }

        # https://learn.microsoft.com/en-us/dotnet/api/system.platformid
        $CurrentPlatform = [System.Environment]::OSVersion.Platform
        $TestModuleImport = $CurrentPlatform -eq "Win32NT"
        if ($TestModuleImport -eq $false) {
            Write-Message Warning "Unsupported platform for module import testing: $($CurrentPlatform)"
        }
    }

    process {

        if (-not $SanityCheck) { return }

        $BuildProfileObject = $BuildProfilesJson.Profiles | Where-Object { $_.Name -eq $Name }
        if ($null -eq $BuildProfileObject) {
            Write-Message Error "No build profile found for name: $($Name)"
            return
        }

        $ScriptFilename = "$($BuildProfileObject.Name).ps1"
        $ScriptPath = Join-Path -Path $RootPath -ChildPath "dist\$($ScriptFilename)"
        $ScriptContent = ""
        $ErrorCount = 0
        $Modules = @()

        Write-Message Info "Building script '$($ScriptFilename)'..."

        foreach ($IncludeId in $BuildProfileObject.Includes) {

            $IncludeObject = $BuildProfilesJson.Includes | Where-Object { $_.Id -eq $IncludeId }
            if ($null -eq $IncludeObject) {
                Write-Message Error "No include found for ID: $($IncludeId)"
                return
            }

            $CurrentSeed = $Seed

            foreach ($FileId in $IncludeObject.Files) {

                $FileObject = $BuildProfilesJson.Files | Where-Object { $_.Id -eq $FileId }
                if ($null -eq $FileObject) {
                    Write-Message Error "No file found for ID: $($FileId)"
                    return
                }

                $ModulePath = Join-Path -Path $RootPath -ChildPath $FileObject.Path
                $ModuleItem = Get-Item -Path $ModulePath -ErrorAction SilentlyContinue
                if ($null -eq $ModuleItem) {
                    Write-Message Error "Failed to open file '$($ModulePath)'."
                    return
                }

                $ModuleFilename = $ModuleItem.Name

                # Pick a random name for the current module
                $RandomName = [String] (Get-Random -InputObject $WordList -Count 1 -SetSeed $CurrentSeed)
                $WordList = $WordList | Where-Object { $_ -ne $RandomName }
                $CurrentSeed = Get-RandomInt -Seed $CurrentSeed

                $ModuleName = $RandomName.ToLower()
                $ModuleName = ([regex] $ModuleName[0].ToString()).Replace($ModuleName, $ModuleName[0].ToString().ToUpper(), 1)

                $Modules += $ModuleName

                $ScriptBlock = Get-Content -Path $ModulePath | Out-String

                foreach ($MatchAndReplace in $FileObject.MatchAndReplace) {

                    $DataToReplace = Get-FileContent -Type "data" -FileName $MatchAndReplace.DataFile | Out-String
                    if ($null -eq $DataToReplace) {
                        Write-Message Error "Failed to retrieve data file content: $($MatchAndReplace.DataFile)"
                        return
                    }

                    $DataToReplaceBlob = ConvertTo-EmbeddedTextBlob -Text $DataToReplace
                    if ($null -eq $DataToReplace) {
                        Write-Message Error "Failed to encode data file content: $($MatchAndReplace.DataFile)"
                        return
                    }

                    $ScriptBlock = $ScriptBlock -replace "{{$($MatchAndReplace.Tag)}}", $DataToReplaceBlob

                    $DataToReplaceSize = [Math]::Round($DataToReplace.Length / 1024, 2)
                    $DataToReplaceBlobSize = [Math]::Round($DataToReplaceBlob.Length / 1024, 2)

                    Write-Message Info "Embedded data file '$($MatchAndReplace.DataFile)' into '$($ModuleFilename)' (orig=$($DataToReplaceSize) KB, blob=$($DataToReplaceBlobSize) KB)."
                }

                # Is the script block detected by AMSI after stripping the comments?
                # Note: if the script block is caught by AMSI, an exception is triggered, so we go
                # directly to the "catch" block. Otherwise, it means that the module was successfully
                # loaded.
                $ScriptBlock = Remove-CommentFromScriptBlock -ScriptBlock $ScriptBlock

                if ($TestModuleImport) {
                    try {
                        & $ExecutionContext.InvokeCommand.NewScriptBlock($ScriptBlock)
                        Write-Message Info "File '$($ModuleFilename)' (name: '$($ModuleName)') was loaded successfully."
                    }
                    catch {
                        if ($_.FullyQualifiedErrorId -like "ScriptContainedMaliciousContent*") {
                            # Exception triggered because of AMSI.
                            $ErrorCount += 1
                            Write-Message Error "Malicious content detected in module '$($ModuleFilename)' (name: '$($ModuleName)'): $($_.Exception.Message.Trim())"
                        }
                        elseif ($_.FullyQualifiedErrorId -eq "CommandNotFoundException") {
                            # Exception triggered because a non-existing command is invoked. This is expected
                            # in certain files.
                            if (@("New-Enum", "New-StructureField", "New-Function") -notcontains $_.TargetObject) {
                                $ErrorCount += 1
                                Write-Message Error "Unexpected error while importing module '$($ModuleFilename)' (name: '$($ModuleName)'): $($_.Exception.Message.Trim())"
                            }
                            else {
                                Write-Message Info "File '$($ModuleFilename)' (name: '$($ModuleName)') was not loaded successfully (expected)."
                            }
                        }
                        else {
                            # Other unexpected exception
                            $ErrorCount += 1
                            Write-Message Error "Unexpected error while importing module '$($ModuleFilename)' (name: '$($ModuleName)'): $($_.Exception.Message.Trim())"
                        }
                    }
                }

                if ($FileObject.Compression -eq $true) {
                    $ScriptEncoded = ConvertTo-Gzip -InputText $ScriptBlock
                }
                else {
                    $ScriptEncoded = [Text.Encoding]::UTF8.GetBytes($ScriptBlock)
                }

                $ScriptEncoded = ConvertTo-AesEncrypted -InputBuffer $ScriptEncoded -Key $EncryptionKey
                $ScriptEncoded = [System.Convert]::ToBase64String($ScriptEncoded)
                $ScriptContent += "`$$($ModuleName) = `"$($ScriptEncoded)`"`r`n"
            }
        }

        if ($ErrorCount -eq 0) {
            Write-Message Success "Build successful, writing result to file '$($ScriptPath)'..."
            $ScriptContent += "`r`n$(Get-ScriptLoader -Modules $Modules -EncodedKey ([System.Convert]::ToBase64String($EncryptionKey)))"
            $ScriptContent | Out-File -FilePath $ScriptPath -Encoding ascii
            Write-Message Info "File hash: $((Get-FileHash -Path $ScriptPath).Hash.ToLower())"
        }
        else {
            Write-Message Error "Build failed, check the build logs for more information."
        }
    }
}

function Write-Message {

    [CmdletBinding()]
    param(
        [Parameter(Position=0, Mandatory=$true)]
        [ValidateSet("Success", "Info", "Warning", "Error")]
        [String] $Type,

        [Parameter(Position=1, Mandatory=$true)]
        [String] $Message
    )

    switch ($Type) {
        "Info"      { $Symbol = "[*]"; $Color = "Blue" }
        "Success"   { $Symbol = "[+]"; $Color = "Green" }
        "Warning"   { $Symbol = "[!]"; $Color = "Yellow" }
        "Error"     { $Symbol = "[-]"; $Color = "Red" }
        default     { throw "Unknown message type: $($Type)" }
    }

    Write-Host -NoNewline -ForegroundColor "$Color" "$($Symbol) "
    Write-Host "$Message"
}

function Get-RandomInt {

    [OutputType([Int32])]
    [CmdletBinding()]
    param (
        [Int32] $Seed,
        [Int32] $Min,
        [Int32] $Max
    )

    if ($PSBoundParameters['Seed']) {
        $Rand = New-Object -TypeName "System.Random" -ArgumentList $Seed
    }
    else {
        $Rand = New-Object -TypeName "System.Random"
    }

    if ($PSBoundParameters['Min'] -and $PSBoundParameters['Max']) {
        return $Rand.Next($Min, $Max)
    }

    if ($PSBoundParameters['Max']) {
        return $Rand.Next($Max)
    }

    return $Rand.Next()
}

function Get-FilePath {

    [OutputType([String])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("build", "data")]
        [String] $Type,

        [Parameter(Mandatory = $true)]
        [String] $FileName
    )

    # The script path is 'C:\...\PrivescCheck\build\Build.ps1'

    # Get the parent folder path: 'C:\...\PrivescCheck\build'
    $RootFolderPath = Split-Path -Path $PSCommandPath -Parent

    # Get the parent folder path: 'C:\...\PrivescCheck'
    $RootFolderPath = Split-Path -Path $RootFolderPath -Parent

    # Get the data folder path: 'C:\...\PrivescCheck\data'
    $FilePath = Join-Path -Path $RootFolderPath -ChildPath $Type

    # Get the data file path: 'C:\...\PrivescCheck\data\$FileName'
    $FilePath = Join-Path -Path $FilePath -ChildPath $FileName

    return $FilePath
}

function Get-FileContent {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $Type,

        [Parameter(Mandatory = $true)]
        [String] $FileName
    )

    $FilePath = Get-FilePath -Type $Type -FileName $FileName
    Get-Content -Path $FilePath -Encoding Ascii
}

function Set-FileContent {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $Type,

        [Parameter(Mandatory = $true)]
        [String] $FileName,

        [Parameter(Mandatory = $true)]
        [String] $Content
    )

    $FilePath = Get-FilePath -Type $Type -FileName $FileName
    $Content | Set-Content -Path $FilePath -Encoding Ascii
}

function Get-LolDriverJson {

    [CmdletBinding()]
    param ()

    begin {
        $LolDriversJsonUrl = "https://www.loldrivers.io/api/drivers.json"
        $ResultCounter = 0
        $KnownVulnerableSampleCounter = 0
    }

    process {
        try {
            $LolDriversJsonFile = (New-Object Net.WebClient).DownloadString($LolDriversJsonUrl)
        }
        catch {
            Write-Message Error "[LOLDRIVERS] Failed to download $($LolDriversJsonUrl): $($_.Exception.Message)"
            return
        }

        # ISSUE: ConvertFrom-Json cannot be used to parse the JSON file in PS 5.1
        # because the "Sections" dictionary may contain section names that are
        # considered duplicates, such as "INIT" and "init". This is due to the fact
        # that ConvertFrom-Json treats strings in a case insensitive way, whereas JSON
        # does not. There is a solution for that in PS 7+, with the "-AsHashtable"
        # switch.
        #
        # SOLUTION: For PS 5.1, we can use a .Net trick instead (see resource link
        # below).
        #
        # LINKS:
        # https://github.com/PowerShell/PowerShell/issues/3705
        # https://github.com/PowerShell/PowerShell/issues/3705#issuecomment-350022987

        $LolDrivers = $null

        if ($PSVersionTable.PSVersion.Major -ge 7) {
            try {
                $LolDrivers = $LolDriversJsonFile | ConvertFrom-Json -AsHashtable
            }
            catch {
                Write-Message Error "[LOLDRIVERS] Failed to deserialize JSON file (ConvertFrom-Json): $($_.Exception.Message)"
                return
            }
        }
        else {
            # We need to load an external assembly. This won't work if the code is executed
            # with PowerShell Core.
            try {
                $null = [System.Reflection.Assembly]::LoadWithPartialName("System.Web.Extensions")
                # Create a JavaScriptSerializer object that can handle 134217728 characters
                # (i.e. 256 MB file of Unicode characters). The default value is 2097152
                # characters (i.e. 4 MB file of Unicode characters). At the time of writing
                # The size of the LOL drivers JSON file is roughly 30 MB.
                $JavaScriptSerializer = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer -Property @{ MaxJsonLength = 134217728 }
                $LolDrivers = [Object[]] ($JavaScriptSerializer.DeserializeObject($LolDriversJsonFile))
            }
            catch {
                Write-Message Error "[LOLDRIVERS] Failed to deserialize JSON file (JavaScriptSerializer): $($_.Exception.Message)"
                return
            }
        }

        if ($null -eq $LolDrivers) {
            Write-Message Error "[LOLDRIVERS] Failed to parse LOL driver JSON file. A suitable JSON deserializer was probably not found."
            return
        }

        Write-Message Info "[LOLDRIVERS] The database contains $($LolDrivers.Count) driver records."

        # At this stage, we get an array of objects representing the LOL drivers.
        # Example:
        #
        # Key                    Value
        # ---                    -----
        # Id                     2a6a38ca-f2e6-456e-9ccf-db59d8c80c9e
        # Tags                   {nvflash.sys}
        # Verified               TRUE
        # Author                 Michael Haag
        # Created                2023-07-22
        # MitreID                T1068
        # CVE                    {}
        # Category               vulnerable driver
        # Commands               {[Command, ], [Description, Confirmed vulnerable driver from Microsoft Block List], [OperatingSystem, Windows], [Privileges, kernel]...}
        # Resources              {https://gist.github.com/mgraeber-rc/1bde6a2a83237f17b463d051d32e802c}
        # Detection              {System.Collections.Generic.Dictionary`2[System.String,System.Object]}
        # Acknowledgement        {[Handle, ], [Person, ]}
        # KnownVulnerableSamples {System.Collections.Generic.Dictionary`2[System.String,System.Object]}

        # We are only interested in "vulnerable drivers", let's filter them based on
        # the value of the "Category" field.
        $VulnerableLolDrivers = [Hashtable[]] ($LolDrivers | Where-Object { $_.Category -eq "vulnerable driver" })
        if (($null -eq $VulnerableLolDrivers) -or ($VulnerableLolDrivers.Count -eq 0)) {
            Write-Message Error "[LOLDRIVERS] The list of known vulnerable drivers is empty. An issue must have occurred during parsing."
            return
        }

        Write-Message Info "[LOLDRIVERS] The database contains $($VulnerableLolDrivers.Count) known vulnerable driver records."

        foreach ($VulnerableLolDriver in $VulnerableLolDrivers) {
            if ($VulnerableLolDriver.ContainsKey("KnownVulnerableSamples")) {
                $KnownVulnerableSampleCounter += ([Object[]] $VulnerableLolDriver['KnownVulnerableSamples']).Count
            }
        }

        Write-Message Info "[LOLDRIVERS] The database contains $($KnownVulnerableSampleCounter) known vulnerable driver samples."

        foreach ($VulnerableLolDriver in $VulnerableLolDrivers) {

            if (-not $VulnerableLolDriver.ContainsKey("Id")) {
                Write-Message Warning "[LOLDRIVERS] Driver entry does not have an ID, ignoring..."
                continue
            }

            if (-not $VulnerableLolDriver.ContainsKey("KnownVulnerableSamples")) {
                Write-Message Warning "[LOLDRIVERS] Driver with ID $($VulnerableLolDriver['Id']) does not have a 'KnownVulnerableSamples' property, ignoring..."
                continue
            }

            $KnownVulnerableSamples = [Hashtable[]] ($VulnerableLolDriver['KnownVulnerableSamples'])
            if (($null -eq $KnownVulnerableSamples) -or ($KnownVulnerableSamples.Count -eq 0)) {
                Write-Message Warning "[LOLDRIVERS] Driver with ID $($VulnerableLolDriver['Id']) does not has an empty 'KnownVulnerableSamples' list, ignoring..."
                continue
            }

            foreach ($KnownVulnerableSample in $KnownVulnerableSamples) {

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $VulnerableLolDriver['Id']

                # A "known vulnerable sample" is represented in the following format.
                #
                # Key               Value
                # ---               -----
                # Authentihash      {[MD5, 7221126b272047b7ced2189f8a4bd484], [SHA1, 0cb5fc2ee1ba75e5b8ed06f92d4edaf08b136333], [SHA256, 4ae065383a4ef5564a515d12adf18427f8d74cc15140edb95e5e2a51ca44fe42]}
                # Company
                # Copyright
                # CreationTimestamp 2014-08-01 20:05:10
                # Date
                # Description
                # ExportedFunctions
                # FileVersion
                # Filename
                # ImportedFunctions {ZwOpenSection, RtlInitUnicodeString, ZwUnmapViewOfSection, IofCompleteRequest...}
                # Imports           {ntoskrnl.exe, HAL.dll}
                # InternalName
                # MD5               ba86e444ae837476e7ccdd06f8867795
                # MachineType       I386
                # MagicHeader       50 45 0 0
                # OriginalFilename
                # PDBPath
                # Product
                # ProductVersion
                # Publisher
                # RichPEHeaderHash  {[MD5, e13d58791de2d0a78a75e7aa5895f01c], [SHA1, b01e89baeba99bf6936438515a7908c0e67e1904], [SHA256, 8c7a52aca95ef6b480d3aa8b2fc87809f8761197b6a2df4bae7a34da6664f6c6]}
                # SHA1              b9c3f4dcc7463cbec84b808d880194bbc304ccd0
                # SHA256            9368e51ec98e2ad20893a5fc21e6a8b20c5bee158d5c49ca58649cff84db9d68
                # Sections          {[.text, System.Collections.Generic.Dictionary`2[System.String,System.Object]], [.rdata, System.Collections.Generic.Dictionary`2[System.String,System.Object]], [.data, System.Collections....
                # Signature
                # Signatures        {System.Collections.Generic.Dictionary`2[System.String,System.Object]}
                # Imphash           528ac7a1e034801d1f20238971c6ec19
                # LoadsDespiteHVCI  FALSE

                # Try to extract the sample file's name.
                $SampleFilename = ""
                if ($KnownVulnerableSample.ContainsKey("OriginalFilename")) {
                    # Extract from 'OriginalFilename' field first.
                    $SampleOriginalFilename = [String] $KnownVulnerableSample['OriginalFilename']
                    if (-not [String]::IsNullOrEmpty($SampleOriginalFilename)) {
                        $SampleFilename = $SampleOriginalFilename
                    }
                    else {
                        if ($KnownVulnerableSample.ContainsKey("Filename")) {
                            # Extract from 'Filename' field first if 'OriginalFilename' is empty.
                            $SampleFilenameAttr = [String] $KnownVulnerableSample['Filename']
                            if (-not [String]::IsNullOrEmpty($SampleFilenameAttr)) {
                                $SampleFilename = $SampleFilenameAttr
                            }
                            else {
                                if ($VulnerableLolDriver.ContainsKey("Tags")) {
                                    # Extract from driver's Tags if 'Filename' is empty.
                                    $VulnerableDriverTags = [String[]] $VulnerableLolDriver['Tags']
                                    if ($VulnerableDriverTags.Count -gt 0) {
                                        $SampleFilename = $VulnerableDriverTags[0]
                                    }
                                }
                            }
                        }
                    }
                }

                if ([String]::IsNullOrEmpty($SampleFilename)) {
                    Write-Message Warning "[LOLDRIVERS] Sample with driver ID $($VulnerableLolDriver['Id']) does not have a filename."
                }

                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $SampleFilename

                # Try to extract the sample file's version.
                if ($KnownVulnerableSample.ContainsKey("FileVersion")) {
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Version" -Value $KnownVulnerableSample['FileVersion']
                }

                # Try to extract the sample file's hashes.
                foreach ($HashAlg in @("MD5", "SHA1", "SHA256")) {
                    if ($KnownVulnerableSample.ContainsKey($HashAlg)) {
                        $Result | Add-Member -MemberType "NoteProperty" -Name $HashAlg -Value $KnownVulnerableSample[$HashAlg]
                    }
                }

                # Try to extract the sample file's authenticode hashes.
                if ($KnownVulnerableSample.ContainsKey("Authentihash")) {
                    $SampleAuthenticodeHashes = $KnownVulnerableSample['Authentihash']
                    foreach ($HashAlg in @("SHA1", "SHA256")) {
                        if ($SampleAuthenticodeHashes.ContainsKey($HashAlg)) {
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Authenticode$($HashAlg)" -Value $SampleAuthenticodeHashes[$HashAlg]
                        }
                    }
                }
                # else {
                #     Write-Message Warning "[LOLDRIVERS] Sample with driver ID $($VulnerableLolDriver['Id']) does not contain an 'Authentihash' property."
                # }

                # Try to extract the sample file's TBS certificate hashes.
                $SampleTbsMD5 = [String[]] @()
                $SampleTbsSHA1 = [String[]] @()
                $SampleTbsSHA256 = [String[]] @()
                $SampleTbsSHA384 = [String[]] @()

                if ($KnownVulnerableSample.ContainsKey("Signatures")) {

                    $SampleSignatures = [Hashtable[]] $KnownVulnerableSample['Signatures']

                    foreach ($SampleSignature in $SampleSignatures) {

                        if ($SampleSignature.ContainsKey("Certificates")) {

                            $SampleCertificates = [Hashtable[]] $SampleSignature['Certificates']

                            foreach ($SampleCertificate in $SampleCertificates) {

                                # Sample certificate object:
                                #
                                # Name                           Value
                                # ----                           -----
                                # SignatureAlgorithmOID          1.2.840.113549.1.1.5
                                # Signature                      03099b8f79ef7f5930aaef68b5fae3091dbb4f82065d375fa6529f168dea1c9209446ef56deb587c30e8f9698d23730b126f47a9ae3911f82ab19bb01ac38eeb599600adce0c4db2d031a6085c2a7afce27a1d574ca865...
                                # ValidTo                        2020-12-30 23:59:59
                                # ValidFrom                      2012-12-21 00:00:00
                                # IsCertificateAuthority         True
                                # Version                        3
                                # CertificateType                CA
                                # Subject                        C=US, O=Symantec Corporation, CN=Symantec Time Stamping Services CA , G2
                                # SerialNumber                   7e93ebfb7cc64e59ea4b9a77d406fc3b
                                # IsCodeSigning                  False
                                # TBS                            {[MD5, d0785ad36e427c92b19f6826ab1e8020], [SHA1, 365b7a9c21bd9373e49052c3e7b3e4646ddd4d43], [SHA256, c2abb7484da91a658548de089d52436175fdb760a1387d225611dc0613a1e2ff], [SHA38...
                                # IsCA                           True

                                if ($SampleCertificate.ContainsKey("TBS")) {

                                    $ToBeSignedSignatures = [Hashtable] $SampleCertificate['TBS']

                                    foreach ($HashAlg in @("MD5", "SHA1", "SHA256", "SHA384")) {
                                        if ($ToBeSignedSignatures.ContainsKey($HashAlg)) {
                                            switch ($HashAlg) {
                                                "MD5"    { $SampleTbsMD5 += $ToBeSignedSignatures['MD5'] }
                                                "SHA1"   { $SampleTbsSHA1 += $ToBeSignedSignatures['SHA1'] }
                                                "SHA256" { $SampleTbsSHA256 += $ToBeSignedSignatures['SHA256'] }
                                                "SHA384" { $SampleTbsSHA384 += $ToBeSignedSignatures['SHA384'] }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    $Result | Add-Member -MemberType "NoteProperty" -Name "TbsMD5" -Value ($SampleTbsMD5 -join ",")
                    $Result | Add-Member -MemberType "NoteProperty" -Name "TbsSHA1" -Value ($SampleTbsSHA1 -join ",")
                    $Result | Add-Member -MemberType "NoteProperty" -Name "TbsSHA256" -Value ($SampleTbsSHA256 -join ",")
                    $Result | Add-Member -MemberType "NoteProperty" -Name "TbsSHA384" -Value ($SampleTbsSHA384 -join ",")
                }
                # else {
                #     Write-Message Warning "[LOLDRIVERS] Sample with driver ID $($VulnerableLolDriver['Id']) does not have a 'Signatures' property."
                # }

                $Result
                $ResultCounter += 1
            }
        }
    }

    end {
        Write-Message Info "[LOLDRIVERS] Parsed $($ResultCounter)/$($KnownVulnerableSampleCounter) known vulnerable driver samples."
    }
}

function Get-LolDriver {

    [CmdletBinding()]
    param ()

    $LolDriversUrl = "https://www.loldrivers.io/api/drivers.csv"
    $LolDrivers = ""

    try {
        $LolDrivers = (New-Object Net.WebClient).DownloadString($LolDriversUrl)
    }
    catch {
        Write-Message Error "Net.WebClient exception: $($_.Exception.Message)"
        return
    }

    $LolDrivers = ConvertFrom-Csv -InputObject $LolDrivers
    Write-Message Success "Successfully downloaded LOL driver list from $($LolDriversUrl) (count=$($LolDrivers.Count))"

    $VulnerableLolDrivers = $LolDrivers | Where-Object { $_.Category -like "*vulnerable*" }
    Write-Message Info "Filtered list on 'vulnerable' drivers (count=$($VulnerableLolDrivers.Count))"

    foreach ($VulnerableLolDriver in $VulnerableLolDrivers) {

        # Keep the UUID for future reference in the LOL drivers database.
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $VulnerableLolDriver.Id

        # Extract all the valid hashes from the data
        $HashesMd5 = [String[]] ($VulnerableLolDriver.KnownVulnerableSamples_MD5 -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -eq 32 })
        $HashesSha1 = [String[]] ($VulnerableLolDriver.KnownVulnerableSamples_SHA1 -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -eq 40 })
        $HashesSha256 = [String[]] ($VulnerableLolDriver.KnownVulnerableSamples_SHA256 -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -eq 64 })
        $AuthenticodeHashesSha1 = [String[]] ($VulnerableLolDriver.KnownVulnerableSamples_Authentihash_SHA1 -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -eq 40 })
        $AuthenticodeHashesSha256 = [String[]] ($VulnerableLolDriver.KnownVulnerableSamples_Authentihash_SHA256 -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -eq 64 })

        # Find the hash list that has the most values
        $HashesMax = (@($HashesMd5.Count, $HashesSha1.Count, $HashesSha256.Count, $AuthenticodeHashesSha1.Count, $AuthenticodeHashesSha256.Count) | Measure-Object -Maximum).Maximum

        if ($HashesMax -eq 0) {
            Write-Message Warning "No hash found for entry with ID: $($VulnerableLolDriver.Id)"
            continue
        }

        # Keep the hash list that has the most values, prioritize the shortest hashes
        # to minimize the total space they will take in the final script.
        # If no file hash is found, fall back to Authenticode hash.
        if ($HashesMd5.Count -eq $HashesMax) {
            $Result | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value ($HashesMd5 -join ",")
        }
        elseif ($HashesSha1.Count -eq $HashesMax) {
            $Result | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value ($HashesSha1 -join ",")
        }
        elseif ($HashesSha256.Count -eq $HashesMax) {
            $Result | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value ($HashesSha256 -join ",")
        }
        elseif ($AuthenticodeHashesSha1.Count -eq $HashesMax) {
            $Result | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value ($AuthenticodeHashesSha1 -join ",")
        }
        elseif ($AuthenticodeHashesSha256.Count -eq $HashesMax) {
            $Result | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value ($AuthenticodeHashesSha256 -join ",")
        }

        $Result
    }
}

function Update-WordList {

    [CmdletBinding()]
    param (
        [UInt32] $WordLength = 10
    )

    begin {
        $WordListUrl = "https://raw.githubusercontent.com/CBHue/PyFuscation/master/wordList.txt"
    }

    process {
        try {
            $WordList = (New-Object Net.WebClient).DownloadString($WordListUrl)
        }
        catch {
            Write-Message Warning "[Update-WordList] Failed to download word list: $($_.Exception.Message.Trim())"
            return
        }

        if ([String]::IsNullOrEmpty($WordList)) {
            Write-Message Warning "[Update-WordList] Word list is empty, aborting..."
            return
        }

        $WordList = [String[]] ($WordList -split "`n" | ForEach-Object { $_.Trim() })
        Write-Message Info "Downloaded word list (count=$($WordList.Count))."

        if ($WordList.Count -lt 10000) {
            Write-Message Warning "[Update-WordList] Word list is too small, aborting..."
            return
        }

        $WordListFiltered = [String[]] ($WordList | Where-Object { (-not [string]::IsNullOrEmpty($_)) -and ($_.Length -eq $WordLength) -and ($_.ToLower() -match "^[a-z]+$") })
        Write-Message Info "Filtered word list (count=$($WordListFiltered.Count))."

        if ($WordListFiltered.Count -lt 1000) {
            Write-Warning "[Update-WordList] Filtered word list is too small, aborting..."
            return
        }

        $LocalWordListContent = Get-FileContent -Type "data" -FileName "WordList.txt" -ErrorAction SilentlyContinue | Out-String

        if (-not [String]::IsNullOrEmpty($LocalWordListContent)) {

            $LocalWordList = [String[]] ($LocalWordListContent.Split("`n") | Where-Object { -not [String]::IsNullOrEmpty($_) })

            Write-Message Info "Found local word list (count=$($LocalWordList.Count))."

            if ($LocalWordList.Count -eq $WordListFiltered.Count) {
                Write-Message Success "Word list is already up-to-date."
                return
            }
        }

        $WordListOutput = $WordListFiltered -join "`n"
        Set-FileContent -Type "data" -FileName "WordList.txt" -Content $WordListOutput

        Write-Message Success "Updated word list file."
    }
}

function Update-LolDriverFile {

    [CmdletBinding()]
    param ()

    begin {
        $VulnerableDriversFileName = "VulnerableDriverSamples.csv"
    }

    process {
        # Retrieve and process LOL driver list from the LOL drivers website.
        $LolDrivers = [Object[]] (Get-LolDriverJson)
        if ($null -eq $LolDrivers) { return }

        # Retrieve our local and processed version of the LOL driver list.
        $LocalLolDriversContent = Get-FileContent -Type "data" -FileName $VulnerableDriversFileName -ErrorAction SilentlyContinue | Out-String

        if (-not [String]::IsNullOrEmpty($LocalLolDriversContent)) {

            $LocalLolDriversContentSize = [Math]::Round($LocalLolDriversContent.Length / 1024, 2)
            $LocalLolDrivers = $LocalLolDriversContent | ConvertFrom-Csv

            Write-Message Info "Found local LOL driver sample list (size=$($LocalLolDriversContentSize) KB, count=$($LocalLolDrivers.Count))."

            # Compare the two lists. If they are equal, we don't need to update our local file.
            $Comparison = Compare-Object -ReferenceObject $LocalLolDrivers -DifferenceObject $LolDrivers -Property Id
            if ($null -eq $Comparison) {

                Write-Message Success "LOL driver sample list is already up-to-date."
                return
            }
        }

        Write-Message Info "LOL driver sample list needs to be created or updated..."

        # Convert the list to CSV and write to file.
        $LolDriversCsv = $LolDrivers | ConvertTo-Csv -Delimiter "," -NoTypeInformation | Out-String
        Set-FileContent -Type "data" -FileName $VulnerableDriversFileName -Content $LolDriversCsv

        $LolDriversCsvSize = [Math]::Round($LolDriversCsv.Length / 1024, 2)

        Write-Message Success "Updated LOL driver sample list file (size=$($LolDriversCsvSize) KB, count=$($LolDrivers.Count)): $($VulnerableDriversFileName)"
    }
}

function Get-ScriptLoader {

    [OutputType([String])]
    param (
        [String[]] $Modules,
        [String] $EncodedKey
    )

    $LoaderBlock = @"
@({{MODULE_LIST}}) | ForEach-Object {
    `$dec = [Convert]::FromBase64String(`$_)
    `$aes = [Security.Cryptography.Aes]::Create()
    `$outbuf = New-Object Byte[] (`$dec.Length - `$aes.IV.Length)
    `$aes.Key = [Convert]::FromBase64String("{{ENCODED_KEY}}")
    `$aes.IV = `$dec[0..(`$aes.IV.Length - 1)]
    `$rc = (New-Object Security.Cryptography.CryptoStream (New-Object IO.MemoryStream (, `$dec[`$aes.IV.Length..(`$dec.Length - 1)])), (`$aes.CreateDecryptor()), ([Security.Cryptography.CryptoStreamMode]::Read)).Read(`$outbuf, 0, `$outbuf.Length)
    try {
        `$sb = `$ExecutionContext.InvokeCommand.NewScriptBlock((ConvertFrom-Gzip -InputBuffer `$outbuf[0..(`$rc - 1)]))
    } catch {
        `$sb = `$ExecutionContext.InvokeCommand.NewScriptBlock(([Text.Encoding]::UTF8.GetString(`$outbuf[0..(`$rc - 1)])))
    }
    . `$sb
}
"@

    $ModuleList = ($Modules | ForEach-Object { "`$$($_)" }) -join ','
    $LoaderBlockResult = $LoaderBlock
    $LoaderBlockResult = $LoaderBlockResult -replace "{{MODULE_LIST}}", $ModuleList
    $LoaderBlockResult = $LoaderBlockResult -replace "{{ENCODED_KEY}}", $EncodedKey

    return $LoaderBlockResult
}

function Remove-CommentFromScriptBlock {

    [OutputType([String])]
    [CmdletBinding()]
    param(
        [String] $ScriptBlock
    )

    $IsCommentBlock = $False
    $Output = ""

    ForEach ($Line in $ScriptBlock.Split("`n")) {
        if ($Line -like "*<#*") {
            $IsCommentBlock = $True
        }

        if ((-not $IsCommentBlock) -and ($Line -match "^\s*#.*")) {
            continue
        }

        if (-not $IsCommentBlock) {
            $Output += "$Line`n"
        }

        if ($Line -like "*#>*") {
            $IsCommentBlock = $False
        }
    }

    $Output
}

function ConvertTo-EmbeddedTextBlob {
    [OutputType([String])]
    param([String] $Text)
    $Compressed = ConvertTo-Gzip -InputText $Text
    [System.Convert]::ToBase64String($Compressed)
}

function ConvertTo-Gzip {

    [CmdletBinding()]
    param (
        [string] $InputText
    )

    process {
        [System.Text.Encoding] $Encoding = [System.Text.Encoding]::UTF8
        [byte[]] $InputTextEncoded = $Encoding.GetBytes($InputText)
        [System.IO.MemoryStream] $MemoryStream = New-Object System.IO.MemoryStream
        $GzipStream = New-Object System.IO.Compression.GzipStream $MemoryStream, ([System.IO.Compression.CompressionMode]::Compress)
        $GzipStream.Write($InputTextEncoded, 0, $InputTextEncoded.Length)
        $GzipStream.Close()
        $MemoryStream.Close()
        $MemoryStream.ToArray()
    }
}

function New-RandomByteArray {

    [OutputType([Byte[]])]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateSet(16, 32)]
        [UInt32] $Size
    )

    # https://gist.github.com/lennybacon/9fcce97f84d1b760e8da0e9d0738536a
    $Random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $Buffer = New-Object Byte[] $Size
    $Random.GetBytes($Buffer)
    return $Buffer
}

function ConvertTo-AesEncrypted {

    [OutputType([Byte[]])]
    param (
        [Parameter(Mandatory=$true)]
        [Byte[]] $InputBuffer,
        [Parameter(Mandatory=$true)]
        [Byte[]] $Key
    )

    # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes
    $AesAlg = [System.Security.Cryptography.Aes]::Create()

    $AesAlg.Key = $Key
    # Fixe IV is bad, but we are not doing real cryptography, just obfuscation.
    $AesAlg.IV = [Byte[]] @(0xde, 0xad, 0xbe, 0xef, 0x8b, 0xad, 0xf0, 0x0d, 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xfe, 0xed)

    $Encryptor = $AesAlg.CreateEncryptor()
    $MemoryStream = New-Object IO.MemoryStream
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream $MemoryStream, $Encryptor, ([System.Security.Cryptography.CryptoStreamMode]::Write)
    $CryptoStream.Write($InputBuffer, 0, $InputBuffer.Length)
    $CryptoStream.FlushFinalBlock()
    $Encrypted = $MemoryStream.ToArray()
    $MemoryStream.Close()
    $CryptoStream.Close()

    return $AesAlg.IV + $Encrypted
}

function ConvertFrom-AesEncrypted {

    [OutputType([Byte[]])]
    param (
        [Parameter(Mandatory=$true)]
        [Byte[]] $InputBuffer,
        [Parameter(Mandatory=$true)]
        [Byte[]] $Key
    )

    # https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes
    $AesAlg = [System.Security.Cryptography.Aes]::Create()

    $IV = $InputBuffer[0..($AesAlg.IV.Length - 1)]
    $Encrypted = $InputBuffer[$AesAlg.IV.Length..($InputBuffer.Length - 1)]
    $Buffer = New-Object Byte[] ($InputBuffer.Length - $AesAlg.IV.Length)

    $AesAlg.Key = $Key
    $AesAlg.IV = $IV

    $Decryptor = $AesAlg.CreateDecryptor()
    $MemoryStream = New-Object IO.MemoryStream (, $Encrypted)
    $CryptoStream = New-Object System.Security.Cryptography.CryptoStream $MemoryStream, $Decryptor, ([System.Security.Cryptography.CryptoStreamMode]::Read)
    $ReadCount = $CryptoStream.Read($Buffer, 0, $Buffer.Length)
    $CryptoStream.Close()
    $MemoryStream.Close()

    return $Buffer[0..($ReadCount - 1)]
}