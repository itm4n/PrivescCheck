<#
Usage:
    - powershell -ep bypass -c ".\Build.ps1"

Notes:
    - [2021-11-28] Cortex XDR detected the loader. I had to split the base64 decoding and the GZip decompressing into two separate functions.
    - [2021-11-28] Cortex XDR detects repeated calls to "Invoke-Expression" as a malicious behavior. So, rather than calling "Invoke-Expression" on each script block, I now reconstruct the entire script and I call "Invoke-Expression" on the final result. Default AMSI seems to be OK with that as well.
#>

$ErrorsCount = 0
$ScriptOutput = "#Requires -Version 2`r`n`r`n"
$OutputFile = "PrivescCheck.ps1"

$Modules = New-Object System.Collections.ArrayList

function Convert-ToBase64CompressedScriptBlock {

    [CmdletBinding()] param(
        [String]
        $ScriptBlock
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
        [String]
        $ScriptBlock
    )

    $IsComment = $False
    $Output = ""

    ForEach ($Line in $ScriptBlock.Split("`n")) {
        if ($Line -like "*<#*") {
            $IsComment = $True
        }

        if (-not $IsComment) {
            $Output += "$Line`n"
        }

        if ($Line -like "*#>*") {
            $IsComment = $False
        }
    }

    $Output
}

function Convert-FromBase64CompressedScriptBlock {

    [CmdletBinding()] param(
        [String]
        $ScriptBlock
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

Get-ChildItem -Path ".\src\*" | ForEach-Object {

    $ModulePath = $_.FullName
    $ModuleFilename = $_.Name

    try {
        . $ModulePath
        Write-Host -ForegroundColor Green "[OK] " -NoNewline
        Write-Host "Loaded module file $ModuleFilename"

        $ModuleName = ($ModuleFilename.Split('.')[0]).Split('_')[1]

        [void] $Modules.Add($ModuleName)

        # Read script block from module file
        $ScriptBlock = Get-Content -Path $ModulePath | Out-String

        # Strip out comments
        $ScriptBlock = Remove-CommentsFromScriptBlock -ScriptBlock $ScriptBlock

        # Compress and Base64 encode script block
        $ScriptBlockBase64 = Convert-ToBase64CompressedScriptBlock -ScriptBlock $ScriptBlock

        $ScriptOutput += "# ------------------------------------`r`n"
        $ScriptOutput += "# Module $ModuleName`r`n"
        $ScriptOutput += "# ------------------------------------`r`n"
        $ScriptOutput += "`$ScriptBlock$($ModuleName) = `"$($ScriptBlockBase64)`"`r`n`r`n"
    }
    catch [Exception] {
        $ErrorsCount += 1
        Write-Host -ForegroundColor Red "[KO] " -NoNewline
        Write-Host "Failed to load module file $ModuleFilename"
        Write-Host -ForegroundColor Red "[ERROR]" $_.Exception.Message.Trim()
    }
}

# if no error, write the loader
if ($ErrorsCount -eq 0) {

    $LoaderBlock = @"
# ------------------------------------`
# Loader
# ------------------------------------
function Convert-FromBase64ToGzip {
    [CmdletBinding()] param(
        [string] `$String
    )
    [Convert]::FromBase64String(`$String)
}

function Convert-FromGzipToText {
    [CmdletBinding()] param(
        [byte[]] `$Bytes
    )
    `$is = New-Object IO.MemoryStream(, `$Bytes)
    `$gs = New-Object IO.Compression.GzipStream `$is, ([IO.Compression.CompressionMode]::Decompress)
    `$sr = New-Object IO.StreamReader(`$gs)
    `$sbd = `$sr.ReadToEnd()
    `$sr.Close()
    `$gs.Close()
    `$is.Close()
    `$sbd
}

`$AllScript = ""
`$Modules = @($( ($Modules | ForEach-Object { "`$ScriptBlock$($_)" }) -join ','))
`$Modules | ForEach-Object {
    `$Decoded = Convert-FromBase64ToGzip -String `$_
    `$Decompressed = Convert-FromGzipToText -Bytes `$Decoded
    `$AllScript += `$Decompressed
    `$ModulesDecoded += `$Decompressed
}

`$AllScript | Invoke-Expression
"@

    $ScriptOutput += "`r`n`r`n$($LoaderBlock)`r`n`r`n"
}

# If no error, write the script to the file
if ($ErrorsCount -eq 0) {

    Write-Host -ForegroundColor Green "[OK] " -NoNewline
    Write-Host "Build complete!"

    $ScriptOutput | Out-File -FilePath $OutputFile -Encoding ascii
    Write-Host -ForegroundColor Green "[OK] " -NoNewline
    Write-Host "Script written to file $OutputFile"
}