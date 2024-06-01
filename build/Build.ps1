function Invoke-Build {

    [CmdletBinding()] param(
        [string] $Name
    )

    begin {
        $BuildProfileCore = @(
            "src\core\Reflection.ps1",
            "src\core\WinApiEnum.ps1",
            "src\core\WinApiStruct.ps1",
            "src\core\WinApi.ps1"
        )

        $BuildProfilePrivescCheck = $BuildProfileCore + @(
            "src\helper\Helpers.ps1",
            "src\helper\WinApiHelpers.ps1",
            "src\helper\ServiceHelpers.ps1",
            "src\helper\HardeningHelpers.ps1",
            "src\helper\CredentialHelpers.ps1",
            "src\helper\ConfigurationHelpers.ps1",
            "src\helper\MsiHelpers.ps1",
            "src\check\Globals.ps1",
            "src\check\Main.ps1",
            "src\check\User.ps1",
            "src\check\Services.ps1",
            "src\check\Applications.ps1",
            "src\check\ScheduledTasks.ps1",
            "src\check\Hardening.ps1",
            "src\check\Configuration.ps1",
            "src\check\Network.ps1",
            "src\check\Updates.ps1",
            "src\check\Credentials.ps1",
            "src\check\Misc.ps1"
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

        if ($SanityCheck) {
            $ScriptHeader = "#Requires -Version 2`r`n`r`n"
            $RootPath = Split-Path -Path (Split-Path -Path $PSCommandPath -Parent) -Parent
            $Wordlist = Get-Wordlist -WordLength 10
            $LolDrivers = Get-LolDrivers
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
                    $ModuleName = ([regex]$ModuleName[0].ToString()).Replace($ModuleName, $ModuleName[0].ToString().ToUpper(), 1)
                }
                else {
                    # Otherwise use the module name from the file name.
                    $ModuleNameSplit = ($ModuleFilename.Split('.')[0]).Split('_')
                    $ModuleName = $ModuleNameSplit[1..($ModuleNameSplit.Count-1)] -join '_'
                }

                [string[]] $Modules += $ModuleName

                try {
                    $ScriptBlock = Get-Content -Path $ModulePath | Out-String

                    # Populate vulnerable driver list.
                    if ($ModuleFilename -like "*globals*") {

                        Write-Message "Populating file '$($ModuleFilename)' with list of vulnerable drivers..."
                        
                        if ($null -ne $LolDrivers) {

                            $LolDriversCsv = $LolDrivers | ConvertTo-Csv -Delimiter ";" | Out-String
                            Write-Message "Driver list exported as CSV."
                            $ScriptBlock = $ScriptBlock -replace "VULNERABLE_DRIVERS",$LolDriversCsv
                            Write-Message "Driver list written to '$($ModuleFilename)'."
                        }
                    }

                    # Is the script block detected by AMSI after stripping the comments?
                    # Note: if the script block is caught by AMSI, an exception is triggered, so we go
                    # directly to the "catch" block. Otherwise, it means that the module was sucessfully 
                    # loaded.
                    $ScriptBlock = Remove-CommentsFromScriptBlock -ScriptBlock $ScriptBlock
                    $ScriptBlock | Invoke-Expression

                    Write-Message "File '$($ModuleFilename)' (name: '$($ModuleName)') was loaded successfully."

                    $ScriptCompressed = ConvertTo-Gzip -InputText $ScriptBlock
                    $ScriptCompressedEncoded = [System.Convert]::ToBase64String($ScriptCompressed)
                    $ScriptContent += "`$$($ModuleName) = `"$($ScriptCompressedEncoded)`"`r`n"
                }
                catch {
                    $ErrorCount += 1
                    Write-Message -Type Error "$($_.Exception.Message.Trim())"
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
}

function Write-Message {

    [CmdletBinding()] param(
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

function Get-Wordlist {

    [CmdletBinding()]
    param (
        [UInt32] $WordLength = 8
    )
    
    begin {
        $WordlistUrl = "https://raw.githubusercontent.com/CBHue/PyFuscation/master/wordList.txt"
    }
    
    process {
        try {
            $Wordlist = (New-Object Net.WebClient).DownloadString($WordlistUrl)
            Write-Message "Wordlist downloaded from: $($WordlistUrl)"
            $Wordlist = $Wordlist -split "`n"
            $Wordlist = $Wordlist | Where-Object { (-not [string]::IsNullOrEmpty($_)) -and ($_.length -eq $WordLength) -and ($_.ToLower() -match "^[a-z]+$") }
            Write-Message "Number of items in wordlist after filtering (word size=$($WordLength)): $($Wordlist.Count)"
            $Wordlist
        }
        catch {
            Write-Message -Type Warning "Failed to download wordlist."
        }
    }
}

function Get-LolDrivers {

    [CmdletBinding()] param()

    $LolDriversUrl = 'https://www.loldrivers.io/api/drivers.csv'
    $WebClient = New-Object -TypeName 'System.Net.WebClient'
    
    try { $LolDriversCsv = $WebClient.DownloadString($LolDriversUrl) }
    catch { Write-Message -Type Warning "Failed to download CSV file from loldrivers.io: $($_.Exception.Message.Trim())"; return }

    Write-Message "Driver list downloaded from: $($LolDriversUrl)"

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
    param (
        [string[]] $Modules
    )
    
    begin {
        $LoaderBlock = @"
function ConvertFrom-Gzip {
    [CmdletBinding()] param([byte[]] `$Bytes)
    `$is = New-Object IO.MemoryStream(, `$Bytes)
    `$gs = New-Object IO.Compression.GzipStream `$is, ([IO.Compression.CompressionMode]::Decompress)
    `$sr = New-Object IO.StreamReader(`$gs)
    `$sbd = `$sr.ReadToEnd()
    `$sr.Close()
    `$gs.Close()
    `$is.Close()
    `$sbd
}

`$Modules = @(MODULE_LIST)
`$Modules | ForEach-Object {
    `$Decoded = [System.Convert]::FromBase64String(`$_)
    ConvertFrom-Gzip -Bytes `$Decoded | Invoke-Expression
}
"@
    }
    
    process {
        $LoaderBlock -replace "MODULE_LIST",$(($Modules | ForEach-Object { "`$$($_)" }) -join ',')
    }
}

function Remove-CommentsFromScriptBlock {

    [CmdletBinding()] param(
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
    
    begin {
        [System.Text.Encoding] $Encoding = [System.Text.Encoding]::UTF8
    }
    
    process {
        [byte[]] $InputTextEncoded = $Encoding.GetBytes($InputText)
        [System.IO.MemoryStream] $MemoryStream = New-Object System.IO.MemoryStream
        $GzipStream = New-Object System.IO.Compression.GzipStream $MemoryStream, ([System.IO.Compression.CompressionMode]::Compress)
        $GzipStream.Write($InputTextEncoded, 0, $InputTextEncoded.Length)
        $GzipStream.Close()
        $MemoryStream.Close()
        $MemoryStream.ToArray()
    }
}