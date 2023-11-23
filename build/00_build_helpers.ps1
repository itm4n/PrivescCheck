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
            $UseRandomNames = $false
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
