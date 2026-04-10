function ConvertFrom-Gzip {
    [CmdletBinding()]
    param ([Byte[]] $InputBuffer)
    $is = New-Object IO.MemoryStream(, $InputBuffer)
    $gs = New-Object IO.Compression.GzipStream $is, ([IO.Compression.CompressionMode]::Decompress)
    $sr = New-Object IO.StreamReader($gs)
    $sbd = $sr.ReadToEnd()
    $sr.Close()
    $gs.Close()
    $is.Close()
    $sbd
}