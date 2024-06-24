function Invoke-Build {

    [CmdletBinding()]
    param(
        [string] $Name,
        [switch] $NoRandomNames
    )

    begin {
        $BuildProfileCore = @(
            "src\core\Compression.ps1",
            "src\core\Reflection.ps1",
            "src\core\WinApi.Enum.ps1",
            "src\core\WinApi.Struct.ps1",
            "src\core\WinApi.Wrappers.ps1",
            "src\core\WinApi.ps1"
        )

        $BuildProfilePrivescCheck = $BuildProfileCore + @(
            "src\check\Helpers.ps1",
            "src\check\Globals.ps1",
            "src\check\Main.ps1",
            "src\check\User.ps1",
            "src\check\Services.Helpers.ps1",
            "src\check\Services.ps1",
            "src\check\Applications.ps1",
            "src\check\ScheduledTasks.ps1",
            "src\check\Hardening.Helpers.ps1",
            "src\check\Hardening.ps1",
            "src\check\Configuration.Helpers.ps1",
            "src\check\Configuration.ps1",
            "src\check\Network.ps1",
            "src\check\Updates.ps1",
            "src\check\Credentials.Helpers.ps1",
            "src\check\Credentials.ps1",
            "src\check\Misc.ps1",
            "src\check\Msi.Helpers.ps1"
        )

        $BuildProfilePointAndPrint = $BuildProfileCore + @(
            "src\exploit\PointAndPrint.ps1"
        )

        $SanityCheck = $true

        $BuildProfiles = @{
            "PrivescCheck" = $BuildProfilePrivescCheck
            "PointAndPrint" = $BuildProfilePointAndPrint
        }

        if ($Name -and (-not ($BuildProfiles.Keys -contains $Name))) {
            Write-Message -Type Error "Build profile '$($Name)' not found."
            $SanityCheck = $false
        }

        if (-not (Test-Path -Path "build")) {
            Write-Message -Type Error "Build folder not found."
            $SanityCheck = $false
        }

        if ($SanityCheck) {
            $ScriptHeader = "#Requires -Version 2`r`n`r`n"
            $RootPath = Split-Path -Path (Split-Path -Path $PSCommandPath -Parent) -Parent
            if ($NoRandomNames) {
                Write-Message -Type Warning "Random name disabled."
            }
            else {
                $Wordlist = Get-Wordlist -WordLength 10
            }

            $LolDrivers = Get-LolDriverList

            $CheckCsvFilePath = Split-Path -Path $PSCommandPath -Parent
            $CheckCsvFilePath = Join-Path -Path $CheckCsvFilePath -ChildPath "Checks.csv"
            $CheckCsv = Get-Content -Path $CheckCsvFilePath -Encoding Ascii | Out-String
            $CheckCsvBlob = ConvertTo-EmbeddedTextBlob -Text $CheckCsv
        }
    }

    process {

        if (-not $SanityCheck) { return }

        foreach ($BuildProfileName in $BuildProfiles.Keys) {

            if ($Name -and ($BuildProfileName -ne $Name)) { continue }

            $BuildProfile = $BuildProfiles[$BuildProfileName]
            $ScriptFilename = "$($BuildProfileName).ps1"
            $ScriptPath = Join-Path -Path $RootPath -ChildPath "release\$($ScriptFilename)"
            $ScriptContent = "$($ScriptHeader)"
            $ErrorCount = 0
            $Modules = @()

            Write-Message "Building script '$($ScriptFilename)'..."

            foreach ($ModuleRelativePath in $BuildProfile) {

                $ModulePath = Join-Path -Path $RootPath -ChildPath $ModuleRelativePath
                $ModuleItem = Get-Item -Path $ModulePath -ErrorAction SilentlyContinue

                if ($null -eq $ModuleItem) {
                    Write-Message -Type Error "Failed to open file '$($ModulePath)'."
                    $ErrorCount += 1
                    break
                }

                $ModuleFilename = $ModuleItem.Name

                if ($null -ne $Wordlist) {
                    # Pick a random name from the wordlist.
                    $RandomName = Get-Random -InputObject $Wordlist -Count 1
                    $Wordlist = $Wordlist | Where-Object { $_ -ne $RandomName }
                    $ModuleName = $RandomName.ToLower()
                    $ModuleName = ([regex] $ModuleName[0].ToString()).Replace($ModuleName, $ModuleName[0].ToString().ToUpper(), 1)
                }
                else {
                    # Otherwise use the filename as the module name.
                    $ModuleFilenameSplit = $ModuleFilename.Split('.')
                    $ModuleName = ($ModuleFilenameSplit[0..($ModuleFilenameSplit.Count-2)] -join '.') -replace '\.',''
                }

                [string[]] $Modules += $ModuleName

                $ScriptBlock = Get-Content -Path $ModulePath | Out-String
                $CompressScriptBlock = $true

                if ($ModuleFilename -like "Globals*") {

                    if ($null -ne $LolDrivers) {
                        # Populate vulnerable driver list.
                        $LolDriversCsv = $LolDrivers | ConvertTo-Csv -Delimiter ";" | Out-String
                        $ScriptBlock = $ScriptBlock -replace "VULNERABLE_DRIVERS",$LolDriversCsv
                        Write-Message "Driver list written to '$($ModuleFilename)'."
                    }
                    else {
                        Write-Message -Type Warning "Known vulnerable driver CSV is null."
                    }

                    if ($null -ne $CheckCsvBlob) {
                        # Populate check list as an encoded blob.
                        $ScriptBlock = $ScriptBlock -replace "CHECK_CSV_BLOB",$CheckCsvBlob
                        Write-Message "Check list written to '$($ModuleFilename)'."
                    }
                    else {
                        Write-Message -Type Warning "Check CSV text blob is null."
                    }
                }

                if ($ModuleFilename -like "Compression*") {

                    $CompressScriptBlock = $false
                }

                # Is the script block detected by AMSI after stripping the comments?
                # Note: if the script block is caught by AMSI, an exception is triggered, so we go
                # directly to the "catch" block. Otherwise, it means that the module was successfully
                # loaded.
                $ScriptBlock = Remove-CommentsFromScriptBlock -ScriptBlock $ScriptBlock
                try {
                    $ScriptBlock | Invoke-Expression
                }
                catch {
                    $ErrorCount += 1
                    Write-Message -Type Error "$($_.Exception.Message.Trim())"
                }

                Write-Message "File '$($ModuleFilename)' (name: '$($ModuleName)') was loaded successfully."

                if ($CompressScriptBlock) {
                    $ScriptEncoded = ConvertTo-Gzip -InputText $ScriptBlock
                }
                else {
                    $ScriptEncoded = [Text.Encoding]::UTF8.GetBytes($ScriptBlock)
                }

                $ScriptEncoded = [System.Convert]::ToBase64String($ScriptEncoded)
                $ScriptContent += "`$$($ModuleName) = `"$($ScriptEncoded)`"`r`n"
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
}

function Write-Message {

    [CmdletBinding()]
    param(
        [Parameter(Position=0,Mandatory=$true)]
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

function ConvertTo-EmbeddedTextBlob {
    param([String] $Text)
    $Compressed = ConvertTo-Gzip -InputText $Text
    [System.Convert]::ToBase64String($Compressed)
}

function Get-AssetFileContent {

    [CmdletBinding()]
    param(
        [OutputType([String])]
        [Parameter(Mandatory=$true)]
        [ValidateSet("WordList", "KnownVulnerableDriverList")]
        [string] $Name
    )

    begin {
        $ExpirationDelayInDays = 30
        switch ($Name) {
            "WordList" {
                $Filename = "wordlist.txt"
                $FileUrl = "https://raw.githubusercontent.com/CBHue/PyFuscation/master/wordList.txt"
            }
            "KnownVulnerableDriverList" {
                $Filename = "vulnerable_drivers.csv"
                $FileUrl = "https://www.loldrivers.io/api/drivers.csv"
            }
        }
        $BuildPath = Split-Path -Path $PSCommandPath -Parent
        $FilePath = Join-Path -Path $BuildPath -ChildPath "cache"
        $FilePath = Join-Path -Path $FilePath -ChildPath "$($Filename)"
    }

    process {
        $DownloadFile = $true
        $CachedFile = Get-Item -Path $FilePath -ErrorAction SilentlyContinue
        if ($null -ne $CachedFile) {
            $TimeSpan = New-TimeSpan -Start $CachedFile.CreationTime -End $(Get-Date)
            if ($TimeSpan.TotalDays -gt $ExpirationDelayInDays) {
                # Cached file expired, so delete it.
                Remove-Item -Path $FilePath -Force
            }
            else {
                # Cached file has not expired yet, use it.
                $DownloadFile = $false
            }
        }

        if ($DownloadFile) {
            try {
                # Download the file.
                $FileContent = (New-Object Net.WebClient).DownloadString($FileUrl)
                Write-Message "File '$($Filename)' downloaded from: $($FileUrl)"
                # Save the file to the local cache folder.
                $FileContent | Out-File -FilePath $FilePath -Encoding ASCII
                Write-Message "File '$($Filename)' saved to: $($FilePath)"
            }
            catch {
                Write-Message -Type Error "Failed to download file '$($Filename)' from $($FileUrl)."
            }
        }

        Write-Message "Retrieved file '$($Filename)' from local cache."
        Get-Content -LiteralPath $FilePath | Out-String
    }
}

function Get-Wordlist {

    [CmdletBinding()]
    param (
        [UInt32] $WordLength = 8
    )

    $Wordlist = Get-AssetFileContent -Name "WordList"
    if ($null -ne $Wordlist) {
        $Wordlist = $Wordlist -split "`n" | ForEach-Object { $_.Trim() }
        $Wordlist | Where-Object { (-not [string]::IsNullOrEmpty($_)) -and ($_.length -eq $WordLength) -and ($_.ToLower() -match "^[a-z]+$") }
    }
}

function Get-LolDriverList {

    [CmdletBinding()]
    param ()

    $LolDriversCsv = Get-AssetFileContent -Name "KnownVulnerableDriverList"

    try { $LolDrivers = ConvertFrom-Csv -InputObject $LolDriversCsv }
    catch { Write-Message -Type Warning "Failed to parse CSV file: $($_.Exception.Message.Trim())"; return }

    Write-Message "Number of drivers in the list: $($LolDrivers.Count)"

    $LolDriversVulnerable = $LolDrivers | Where-Object { $_.Category -like "*vulnerable*" }
    Write-Message "Number of vulnerable drivers: $($LolDriversVulnerable.Count)"

    $LolDriversVulnerable | ForEach-Object {

        # Keep the UUID for future reference in the LOL drivers database.
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $_.Id

        # Extract all the valid hashes from the data
        $HashesMd5 = [string[]] ($_.KnownVulnerableSamples_MD5 -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -eq 32 })
        $HashesSha1 = [string[]] ($_.KnownVulnerableSamples_SHA1 -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -eq 40 })
        $HashesSha256 = [string[]] ($_.KnownVulnerableSamples_SHA256 -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -eq 64 })

        # Find the hash list that has the most values
        $HashesMax = (@($HashesMd5.Count, $HashesSha1.Count, $HashesSha256.Count) | Measure-Object -Maximum).Maximum

        # Keep the hash list that has the most values, prioritize the shortest hashes
        # to minimize the total space they will take in the final script.
        if ($HashesMd5.Count -eq $HashesMax) {
            $Result | Add-Member -MemberType "NoteProperty" -Name "HashType" -Value "Md5"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value ($HashesMd5 -join ",")
        }
        elseif ($HashesSha1.Count -eq $HashesMax) {
            $Result | Add-Member -MemberType "NoteProperty" -Name "HashType" -Value "Sha1"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value ($HashesSha1 -join ",")
        }
        elseif ($HashesSha256.Count -eq $HashesMax) {
            $Result | Add-Member -MemberType "NoteProperty" -Name "HashType" -Value "Sha256"
            $Result | Add-Member -MemberType "NoteProperty" -Name "Hash" -Value ($HashesSha256 -join ",")
        }

        $Result
    }
}

function Get-ScriptLoader {

    [CmdletBinding()]
    param(
        [string[]] $Modules
    )

    begin {
        $LoaderBlock = @"
`$Modules = @(MODULE_LIST)
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
}
"@
    }

    process {
        $LoaderBlock -replace "MODULE_LIST",$(($Modules | ForEach-Object { "`$$($_)" }) -join ',')
    }
}

function Remove-CommentsFromScriptBlock {

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