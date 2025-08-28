function Invoke-Build {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("PrivescCheck", "PointAndPrint")]
        [String] $Name,

        [Switch] $NoNewSeed
    )

    begin {

        $SanityCheck = $true

        if (-not (Test-Path -Path "build")) {
            Write-Message -Type Error "Build folder not found."
            $SanityCheck = $false
        }

        $BuildProfilesJson = Get-FileContent -Type "build" -FileName "BuildProfiles.json" | Out-String | ConvertFrom-Json
        if ($null -eq $BuildProfilesJson) {
            Write-Message -Type Error "Failed to read build profile file."
            $SanityCheck = $false
        }

        $ScriptHeader = "#Requires -Version 2`r`n`r`n"
        $RootPath = Split-Path -Path (Split-Path -Path $PSCommandPath -Parent) -Parent

        $WordList = Get-FileContent -Type "data" -FileName "WordList.txt" | Where-Object { -not [String]::IsNullOrEmpty($_) }
        if ($null -eq $WordList) {
            Write-Message -Type Error "Failed to retrieve word list."
            $SanityCheck = $false
        }

        if ($NoNewSeed) {
            $Seed = Get-FileContent -Type "build" -FileName "Seed.txt" -ErrorAction SilentlyContinue | Out-String
            if ([String]::IsNullOrEmpty($Seed)) {
                Write-Message -Type Error -Message "Failed to read seed from file."
                $SanityCheck = $false
            }
            else {
                $Seed = [Int32]::Parse($Seed)
                Write-Message -Message "Using seed: $($Seed)"
            }
        }
        else {
            $Seed = Get-RandomInt
            Write-Message -Message "Generated seed: $($Seed)"
            Set-FileContent -Type "build" -FileName "Seed.txt" -Content "$($Seed)"
        }

        # https://learn.microsoft.com/en-us/dotnet/api/system.platformid
        $CurrentPlatform = [System.Environment]::OSVersion.Platform
        $TestModuleImport = $CurrentPlatform -eq "Win32NT"
        if ($TestModuleImport -eq $false) {
            Write-Message -Type Warning -Message "Unsupported platform for module import testing: $($CurrentPlatform)"
        }
    }

    process {

        if (-not $SanityCheck) { return }

        $BuildProfileObject = $BuildProfilesJson.Profiles | Where-Object { $_.Name -eq $Name }
        if ($null -eq $BuildProfileObject) {
            Write-Message -Type Error -Message "No build profile found for name: $($Name)"
            return
        }

        $ScriptFilename = "$($BuildProfileObject.Name).ps1"
        $ScriptPath = Join-Path -Path $RootPath -ChildPath "release\$($ScriptFilename)"
        $ScriptContent = "$($ScriptHeader)"
        $ErrorCount = 0
        $Modules = @()

        Write-Message "Building script '$($ScriptFilename)'..."

        foreach ($IncludeId in $BuildProfileObject.Includes) {

            $IncludeObject = $BuildProfilesJson.Includes | Where-Object { $_.Id -eq $IncludeId }
            if ($null -eq $IncludeObject) {
                Write-Message -Type Error -Message "No include found for ID: $($IncludeId)"
                return
            }

            $CurrentSeed = $Seed

            foreach ($FileId in $IncludeObject.Files) {

                $FileObject = $BuildProfilesJson.Files | Where-Object { $_.Id -eq $FileId }
                if ($null -eq $FileObject) {
                    Write-Message -Type Error -Message "No file found for ID: $($FileId)"
                    return
                }

                $ModulePath = Join-Path -Path $RootPath -ChildPath $FileObject.Path
                $ModuleItem = Get-Item -Path $ModulePath -ErrorAction SilentlyContinue
                if ($null -eq $ModuleItem) {
                    Write-Message -Type Error "Failed to open file '$($ModulePath)'."
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
                        Write-Message -Type Error "Failed to retrieve data file content: $($MatchAndReplace.DataFile)"
                        return
                    }

                    $DataToReplace = ConvertTo-EmbeddedTextBlob -Text $DataToReplace
                    if ($null -eq $DataToReplace) {
                        Write-Message -Type Error "Failed to encode data file content: $($MatchAndReplace.DataFile)"
                        return
                    }

                    $ScriptBlock = $ScriptBlock -replace "{{$($MatchAndReplace.Tag)}}", $DataToReplace

                    Write-Message "Embedded data file '$($MatchAndReplace.DataFile)' into '$($ModuleFilename)'"
                }

                # Is the script block detected by AMSI after stripping the comments?
                # Note: if the script block is caught by AMSI, an exception is triggered, so we go
                # directly to the "catch" block. Otherwise, it means that the module was successfully
                # loaded.
                $ScriptBlock = Remove-CommentFromScriptBlock -ScriptBlock $ScriptBlock

                if ($TestModuleImport) {
                    try {
                        $ScriptBlock | Invoke-Expression
                        Write-Message "File '$($ModuleFilename)' (name: '$($ModuleName)') was loaded successfully."
                    }
                    catch {
                        $ErrorCount += 1
                        Write-Message -Type Error "Failed to load file '$($ModuleFilename)' (name: '$($ModuleName)'): $($_.Exception.Message.Trim())"
                    }
                }

                if ($FileObject.Compression -eq $true) {
                    $ScriptEncoded = ConvertTo-Gzip -InputText $ScriptBlock
                }
                else {
                    $ScriptEncoded = [Text.Encoding]::UTF8.GetBytes($ScriptBlock)
                }

                $ScriptEncoded = [System.Convert]::ToBase64String($ScriptEncoded)
                $ScriptContent += "`$$($ModuleName) = `"$($ScriptEncoded)`"`r`n"
            }
        }

        if ($ErrorCount -eq 0) {

            Write-Message -Type Success "Build successful, writing result to file '$($ScriptPath)'..."
            $ScriptContent += "`r`n$(Get-ScriptLoader -Modules $Modules)"
            $ScriptContent | Out-File -FilePath $ScriptPath -Encoding ascii

            if ($BuildProfileName -eq "PrivescCheck") {

                # If the output script is PrivescCheck.ps1, copy the result at the root of the
                # project as well.
                $ScriptPath = Join-Path -Path $RootPath -ChildPath "$($ScriptFilename)"
                Write-Message -Type Info "Copying result to file '$($ScriptPath)'..."
                $ScriptContent | Out-File -FilePath $ScriptPath -Encoding ascii
            }
        }
    }
}

function Write-Message {

    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String] $Message,
        [ValidateSet("Success", "Info", "Warning", "Error")]
        [String] $Type
    )

    $Symbol = "[*]"; $Color = "Blue"

    switch ($Type) {
        "Success" {
            $Symbol = "[+]"; $Color = "Green"
        }
        "Warning" {
            $Symbol = "[!]"; $Color = "Yellow"
        }
        "Error" {
            $Symbol = "[-]"; $Color = "Red"
        }
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

function Get-LolDriver {

    [CmdletBinding()]
    param ()

    $LolDriversUrl = "https://www.loldrivers.io/api/drivers.csv"
    $LolDrivers = ""
    try {
        $LolDrivers = (New-Object Net.WebClient).DownloadString($LolDriversUrl)
    }
    catch {
        Write-Message -Type Error -Message "Net.WebClient exception: $($_.Exception.Message)"
        return
    }

    $LolDrivers = ConvertFrom-Csv -InputObject $LolDrivers
    Write-Message -Type Success -Message "Successfully downloaded LOL driver list from $($LolDriversUrl) (count=$($LolDrivers.Count))"

    $LolDriversVulnerable = $LolDrivers | Where-Object { $_.Category -like "*vulnerable*" }
    Write-Message -Message "Filtered list on 'vulnerable' drivers (count=$($LolDriversVulnerable.Count))"

    $LolDrivers = @()
    $LolDriversVulnerable | ForEach-Object {

        # Keep the UUID for future reference in the LOL drivers database.
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $_.Id

        # Extract all the valid hashes from the data
        $HashesMd5 = [string[]] ($_.KnownVulnerableSamples_MD5 -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -eq 32 })
        $HashesSha1 = [string[]] ($_.KnownVulnerableSamples_SHA1 -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -eq 40 })
        $HashesSha256 = [string[]] ($_.KnownVulnerableSamples_SHA256 -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -eq 64 })

        if (($HashesMd5.Count -eq 0) -and ($HashesSha1.Count -eq 0) -and ($HashesSha256.Count -eq 0)) {
            Write-Message -Type Warning -Message "No hash found for entry with ID: $($_.Id)"
            continue
        }

        # Find the hash list that has the most values
        $HashesMax = (@($HashesMd5.Count, $HashesSha1.Count, $HashesSha256.Count) | Measure-Object -Maximum).Maximum

        # Keep the hash list that has the most values, prioritize the shortest hashes
        # to minimize the total space they will take in the final script.
        if ($HashesMd5.Count -eq $HashesMax) {
            $Result | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value ($HashesMd5 -join ",")
        }
        elseif ($HashesSha1.Count -eq $HashesMax) {
            $Result | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value ($HashesSha1 -join ",")
        }
        elseif ($HashesSha256.Count -eq $HashesMax) {
            $Result | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value ($HashesSha256 -join ",")
        }

        $Result
    }
}

function Update-LolDriverList {

    [CmdletBinding()]
    param ()

    $VulnerableDriversFileName = "VulnerableDrivers.csv"

    # Retrieve and process LOL driver list from the LOL drivers website.
    $LolDrivers = Get-LolDriver
    if ($null -eq $LolDrivers) {
        Write-Message -Type Error -Message "Failed to retrieve or parse remote LOL driver list."
        return
    }

    # Retrieve our local and processed version of the LOL driver list.
    $LocalLolDriversContent = Get-FileContent -Type "data" -FileName $VulnerableDriversFileName -ErrorAction SilentlyContinue | Out-String
    if ($null -ne $LocalLolDriversContent) {
        $LocalLolDrivers = $LocalLolDriversContent | ConvertFrom-Csv
        Write-Message -Message "Parsed local LOL driver list (count=$($LocalLolDrivers.Count))"
        # Compare the two lists. If they are equal, we don't need to update our local file.
        $Comparison = Compare-Object -ReferenceObject $LocalLolDrivers -DifferenceObject $LolDrivers -Property Id,Hash
        if ($null -eq $Comparison) {
            Write-Message -Type Success -Message "The local copy of the LOL driver list is already up-to-date."
            return
        }
    }

    Write-Message -Message "The local copy of the LOL driver list needs to be created or updated..."

    # Convert the list to CSV and write to file.
    $LolDriversCsv = $LolDrivers | ConvertTo-Csv -Delimiter "," -NoTypeInformation | Out-String
    Set-FileContent -Type "data" -FileName $VulnerableDriversFileName -Content $LolDriversCsv

    Write-Message -Type Success -Message "LOL driver list file created or updated: $($VulnerableDriversFileName)"
}

function Update-WordList {

    [CmdletBinding()]
    param (
        [UInt32] $WordLength = 8
    )

    $WordListUrl = "https://raw.githubusercontent.com/CBHue/PyFuscation/master/wordList.txt"
    $WordList = (New-Object Net.WebClient).DownloadString($WordListUrl)

    if ($null -eq $WordList) {
        throw "Word list is empty"
    }

    $WordList = $WordList -split "`n" | ForEach-Object { $_.Trim() }
    $WordList = $WordList | Where-Object { (-not [string]::IsNullOrEmpty($_)) -and ($_.Length -eq $WordLength) -and ($_.ToLower() -match "^[a-z]+$") }

    Set-FileContent -Type "data" -FileName "WordList.txt" -Content ($WordList | Out-String)
}

function Get-ScriptLoader {

    [CmdletBinding()]
    param(
        [string[]] $Modules
    )

    begin {
        $LoaderBlock = @"
`$Modules = @({{MODULE_LIST}})
`$Modules | ForEach-Object {
    `$Decoded = [System.Convert]::FromBase64String(`$_)
    if (`$_ -like "H4s*") {
        `$Decoded = ConvertFrom-Gzip -Bytes `$Decoded
    }
    else {
        `$Decoded = [Text.Encoding]::UTF8.GetString(`$Decoded)
    }
    `$ScriptBlock = `$ExecutionContext.InvokeCommand.NewScriptBlock(`$Decoded)
    . `$ScriptBlock
    Remove-Variable -Name "Decoded"
    Remove-Variable -Name "ScriptBlock"
}
Remove-Variable -Name "Modules"
@({{MODULE_STR_LIST}}) | ForEach-Object { Remove-Variable -Name `$_ }
"@
    }

    process {
        $ModuleList = ($Modules | ForEach-Object { "`$$($_)" }) -join ','
        $ModuleStrList = ($Modules | ForEach-Object { "`"$($_)`"" }) -join ','
        ($LoaderBlock -replace "{{MODULE_LIST}}", $ModuleList) -replace "{{MODULE_STR_LIST}}", $ModuleStrList
    }
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