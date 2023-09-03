<#
Usage:
    - powershell -ep bypass -c ". .\Build.ps1; Invoke-Build"

Notes:
    - [2021-11-28] Cortex XDR detected the loader. I had to split the base64 decoding and the GZip decompressing into two separate functions.
    - [2021-11-28] Cortex XDR detects repeated calls to "Invoke-Expression" as a malicious behavior. So, rather than calling "Invoke-Expression" on each script block, I now reconstruct the entire script and I call "Invoke-Expression" on the final result. Default AMSI seems to be OK with that as well.
    - [2023-07-02] ESET seems to use a signature-based detection. Using randomly-generated variable names for the modules could do the trick here.
#>

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

function Convert-ToBase64CompressedScriptBlock {

    [CmdletBinding()] param(
        [String] $ScriptBlock
    )

    # Script block as String to Byte array
    [System.Text.Encoding] $Encoding = [System.Text.Encoding]::UTF8
    [Byte[]] $ScriptBlockEncoded = $Encoding.GetBytes($ScriptBlock)

    # Compress Byte array (gzip)
    [System.IO.MemoryStream] $MemoryStream = New-Object System.IO.MemoryStream
    $GzipStream = New-Object System.IO.Compression.GzipStream $MemoryStream, ([System.IO.Compression.CompressionMode]::Compress)
    $GzipStream.Write($ScriptBlockEncoded, 0, $ScriptBlockEncoded.Length)
    $GzipStream.Close()
    $MemoryStream.Close()
    $ScriptBlockCompressed = $MemoryStream.ToArray()

    # Byte array to Base64
    [System.Convert]::ToBase64String($ScriptBlockCompressed)
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

function Convert-FromBase64CompressedScriptBlock {

    [CmdletBinding()] param(
        [String] $ScriptBlock
    )

    # Base64 to Byte array of compressed data
    $ScriptBlockCompressed = [System.Convert]::FromBase64String($ScriptBlock)

    # Decompress data
    $InputStream = New-Object System.IO.MemoryStream(, $ScriptBlockCompressed)
    $MemoryStream = New-Object System.IO.MemoryStream
    $GzipStream = New-Object System.IO.Compression.GzipStream $InputStream, ([System.IO.Compression.CompressionMode]::Decompress)
    $GzipStream.CopyTo($MemoryStream)
    $GzipStream.Close()
    $MemoryStream.Close()
    $InputStream.Close()
    [Byte[]] $ScriptBlockEncoded = $MemoryStream.ToArray()

    # Byte array to String
    [System.Text.Encoding] $Encoding = [System.Text.Encoding]::UTF8
    $Encoding.GetString($ScriptBlockEncoded) | Out-String
}

function Invoke-Build {

    [CmdletBinding()] param()

    $ErrorCount = 0
    $ScriptOutput = "#Requires -Version 2`n`n"
    $OutputFile = "PrivescCheck.ps1"
    $WordlistUrl = "https://raw.githubusercontent.com/CBHue/PyFuscation/master/wordList.txt"
    $WordLen = 10
    $UseRandomNames = $true

    Write-Message "Build starts. Output file: $($OutputFile)"
    
    $Modules = New-Object System.Collections.ArrayList

    try {
        $Wordlist = (New-Object Net.WebClient).DownloadString($WordlistUrl)
        Write-Message "Wordlist downloaded from: $($WordlistUrl)"
        $Wordlist = $Wordlist -split "`n"
        $Wordlist = $Wordlist | Where-Object { (-not [string]::IsNullOrEmpty($_)) -and ($_.length -eq $WordLen) -and ($_.ToLower() -match "^[a-z]+$") }
        Write-Message -Type Success "Number of items in wordlist after filtering (word size=$($WordLen)): $($Wordlist.Count)"
    }
    catch {
        Write-Message -Type Warning "Failed to download wordlist, fall back to module names."
        $UseRandomNames = $false
    }
    
    Get-ChildItem -Path ".\src\*" | ForEach-Object {
    
        $ModulePath = $_.FullName
        $ModuleFilename = $_.Name
    
        try {
            if ($UseRandomNames) {
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
    
            [void] $Modules.Add($ModuleName)
    
            # Read script block from module file
            $ScriptBlock = Get-Content -Path $ModulePath | Out-String

            # Special case of the file containing the global variables. We need to insert the 
            # vulnerable driver list.
            if ($ModuleFilename -like "*global*") {
                Write-Message "Populating file '$($ModuleFilename)' with list of vulnerable drivers..."
                $LolDrivers = Get-LolDrivers
                if ($null -ne $LolDrivers) {
                    try {
                        $LolDriversCsv = $LolDrivers | ConvertTo-Csv -Delimiter ";" | Out-String
                        Write-Message "Driver list exported as CSV."
                        $ScriptBlock = $ScriptBlock -replace "VULNERABLE_DRIVERS",$LolDriversCsv
                        Write-Message -Type Success "Driver list written to '$($ModuleFilename)'."
                    }
                    catch {
                        Write-Message -Type Error "Failed to populate driver list: $($_.Exception.Message.Trim())"
                    }
                }
            }
    
            # Strip out comments
            $ScriptBlock = Remove-CommentsFromScriptBlock -ScriptBlock $ScriptBlock
    
            # Is the script block detected by AMSI after stripping the comments?
            # Note: if the script block is caught by AMSI, an exception is triggered, so we go
            # directly to the "catch" block. Otherwise, it means that the module was sucessfully 
            # loaded.
            $ScriptBlock | Invoke-Expression
    
            Write-Message "File '$($ModuleFilename)' (name: '$($ModuleName)') was loaded successfully."
    
            # Compress and Base64 encode script block
            $ScriptBlockBase64 = Convert-ToBase64CompressedScriptBlock -ScriptBlock $ScriptBlock
    
            # Store each compressed block in a string variable
            $ScriptOutput += "`$$($ModuleName) = `"$($ScriptBlockBase64)`"`n"
        }
        catch [Exception] {
            $ErrorCount += 1
            Write-Message -Type Error "Failed to load file $($ModuleFilename): $($_.Exception.Message.Trim())"
        }
    }
    
    # if no error, write the loader
    if ($ErrorCount -eq 0) {
    
        $LoaderBlock = @"
function Convert-FromBase64ToGzip {
    [CmdletBinding()] param([string] `$String)
    [Convert]::FromBase64String(`$String)
}
    
function Convert-FromGzipToText {
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

`$Modules = @($( ($Modules | ForEach-Object { "`$$($_)" }) -join ','))
`$Modules | ForEach-Object {
    `$Decoded = Convert-FromBase64ToGzip -String `$_
    Convert-FromGzipToText -Bytes `$Decoded | Invoke-Expression
}
"@
    
        $ScriptOutput += "`n$($LoaderBlock)"
    }
    
    # If no error, write the script to the file
    if ($ErrorCount -eq 0) {
        Write-Message -Type Success "Build complete!"
        $ScriptOutput | Out-File -FilePath $OutputFile -Encoding ascii
        Write-Message "Script written to file '$($OutputFile)'."
    }
}