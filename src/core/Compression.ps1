function ConvertFrom-Gzip {
    [CmdletBinding()]
    param([byte[]] $Bytes)
    $is = New-Object IO.MemoryStream(, $Bytes)
    $gs = New-Object IO.Compression.GzipStream $is, ([IO.Compression.CompressionMode]::Decompress)
    $sr = New-Object IO.StreamReader($gs)
    $sbd = $sr.ReadToEnd()
    $sr.Close()
    $gs.Close()
    $is.Close()
    $sbd
}