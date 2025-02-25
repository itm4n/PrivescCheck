# Changelog

## 2025-02-25

### Added

- Function for checking scheduled task permissions.

### Modified

- The helper 'Get-ObjectAccessRight' was updated to handle scheduled task objects.
- Improved error handling when opening kernel object handles.

### Fixed

- The helper 'Get-ObjectAccessRight' helper did not check for invalid handles, which resulted in undefined behaviors.

## 2025-02-19

### Modified

- Update existing scheduled task checks so that they use the new helper 'Get-RegisteredScheduledTask'.

### Removed

- Previous helper ('Get-ScheduledTaskList') for enumerating scheduled tasks was removed.

## 2025-02-18

### Added

- Wrapper for converting an SDDL to a security descriptor object.
- Helper for obtaining security information about a registered scheduled task.
- New helper for obtaining information about registered scheduled tasks.

### Modified

- Update 'Get-ScheduledTaskList' to include hidden tasks.

## 2025-02-15

### Added

- Check for VNC server passwords.
- Check for IPv6 configuration.
- Check for Credential Delegation.

## 2025-02-13

### Added

- PowerShell security feature check.

### Removed

- PowerShell execution policy check.
- PowerShell Transcription check.

## 2025-01-10

### Added

- Helper function for enumerating all processes and threads.
- Check for process and thread permissions.

### Changed

- Merge and refactor hive file permission checks (CVE-2021-36934).

## 2025-01-09

### Changed

- Rename helper function 'Get-ModificationRight' to 'Get-ObjectAccessRight', and make it even more generic so that it can be used to check any access right, not just modification rights (which is still the default).
- The helper function 'Get-ObjectAccessRight' now handles access right checks for the Service Control Manager.

### Removed

- The cmdlet 'Get-ModifiableService' was replaced by the more generic helper function 'Get-ModificationRight'.
- The helper function 'Convert-NameToSid' embedded within 'Get-ModificationRight' was removed as it is no longer needed.
- The helper function 'Get-ModifiableRegistryPath' was replaced by 'Get-ObjectAccessRight'.
- The helper function 'Test-ServiceDiscretionaryAccessControlList' was replaced by 'Get-ObjectAccessRight'.
- The helper function 'Get-ServiceDiscretionaryAccessControlList' was replaced by 'Get-ObjectAccessRight'.
- The helper function 'Convert-SidStringToSid' is not used and was therefore removed.

## 2025-01-08

### Added

- Wrapper function for querying an object's security information in a generic way.
- Implement a generic way of analyzing an object's DACL.

### Changed

- Refactor file, directory, registry key ACL check.

## 2025-01-06

### Changed

- Add multithreading to root folder permissions check.
- Update check result output (and include execution time).
- Add check type information to check banner (console output).

## 2025-01-04

### Added

- Add a Windows API wrapper ('Get-ServiceStatus') for querying a service's status.

### Changed

- Replaced use of 'Get-Service' for obtaining a service's current status with the new wrapper cmdlet 'Get-ServiceStatus'.

## 2025-01-01

### Changed

- Refactor service access and DACL check, and merge Service Control Manager check.

## 2024-12-31

### Changed

- Improve standard Windows error handling (using a dedicated 'Format-Error' helper function).

## 2024-12-28

### Added

- Add a helper function for opening services.

### Changed

- Add multithreading to application file permissions check.
- Refactor application folder enumeration.

## 2024-12-27

### Added

- Support for multithreading.

### Changed

- Add multithreading to COM class registry path permission check.
- Add multithreading to COM class image file permission check.
- Add multithreading to MSI enumeration.

## 2024-12-25

### Added

- Benchmark option to measure the time taken by each check.

## 2024-12-24

### Added

- Check for the configuration of the default local administrator account.
- Helper function to obtain information about local user accounts.

### Changed

- Check "Invoke-StartupApplicationPermissionCheck" refactored to remove duplicate code.
- Helper functions "Get-UnquotedPath" and "Get-ExploitableUnquotedPath" merged and refactored.

### Removed

- Helper function "Test-IsKnownService" (replaced by "Resolve-CommandLine" + "Test-IsMicrosoftFile").

## 2024-12-06

### Added

- Check for name resolution protocol configuration.

## 2024-12-05

### Added

- Helper function for collecting information about firewall profiles.
- Check for disabled firewall on each network profile.
- Check for registered AMSI providers.

## 2024-11-27

### Changed

- The web proxy auto-configuration check was refactored to include WPAD settings.

## 2024-11-21

### Added

- New wrapper cmdlets for obtaining (Azure) domain information.

### Changed

- The "Test-IsDomainJoined" cmdlet was modified so that it now relies on (Azure) domain information, which is more reliable than "NetWkstaGetInfo".

### Removed

- The wrapper cmdlet for "NetWkstaGetInfo" was removed since it's no longer used.

## 2024-11-19

### Added

- The "Server SPN target name validation level" is now reported in the SMB configuration check.

## 2024-11-06

### Added

- New wrapper cmdlet for the GetFirmwareType API.
- New helper cmdlet "Get-SystemInformation" for collecting system information.

### Changed

- The system information check is now enriched with the data returned by the new "Get-SystemInformation" helper function.
- The cmdlet "Get-UEFIStatus" now uses the new "Get-FirmwareType" helper function.

## 2024-10-31

### Added

- Check for TPM device information. The aim is to provide the same information as the output of the command 'TpmTool.exe GetDeviceInformation' in the form of a PowerShell object.

### Changed

- Update BitLocker check to adapt severity and description based on the presence of a TPM (and its type).

## 2024-10-30

### Changed

- Update Point and Print configuration check to be more accurate.

## 2024-09-22

### Added

- Check for 'DisableLUAInRepair' registry value which disables the UAC prompt for Windows Installer repair actions.

## 2024-06-29

### Added

- Check for permissions of folders located at the root of a 'fixed' drive.

## 2024-06-26

### Changed

- Complete refactoring of the helper function Get-ModifiablePath.

## 2024-06-25

### Added

- Check for COM servers with a missing module.

### Changed

- Reintroduce the leaked handle check.
- Handle service image path as a command line to prevent false positives when checking file permissions.

## 2024-06-24

### Added

- Check for COM registry permissions.
- Helper function for resolving module paths.
- Check for COM module file permissions.
- Check for COM ghost DLLs.

## 2024-06-22

### Added

- Check for user privileges granted through GPOs.

### Changed

- LAPS check performed only if machine is domain-joined.
- Domain membership tested using the Windows API NetWkstaGetInfo rather than the registry.
- Asset files used when "building" the script can now be cached.
- Check list saved in separate file and embedded in script at build time.

## 2024-06-20

### Fixed

- Improper sorting of NAA credential occurrences resulting in data loss.

## 2024-06-11

### Added

- SMB server and client configuration check (SMBv1, signing)

## 2024-06-10

### Added

- List Windows Defender Exploit Guard ASR rules.

### Changed

- Defender exclusions can now be obtained through event logs as well.

## 2024-06-02

### Removed

- Last startup time using tick count.
- Redundant startup application info check
- Redundant hotfix info check
- Redundant service unquoted path info check

## 2024-06-01

### Added

- Check have an addition attribute named "Risky", that allows them to be disabled when there is a high risk of triggering EDR.
- Registry key paths and values are now returned in the output of the Point and Print check.

### Changed

- Checks now have a "Type" (Base, Extended, Audit, Experimental), rather than multiple boolean flags.
- Rework the README, and provide additional information regarding check types.
- Rework the output of the MSI Custom Actions check to make it more readable.

### Fixed

- Prevent system folders from being returned when obtaining a list of installed applications.

## 2024-05-28

### Added

- Check for PowerShell execution policy enforced with GPO.

## 2024-05-27

### Added

- Check for SCCM cache folders.
- Check for hard coded credentials in the SCCM cache folders.
- Check for proxy auto config URL (proxy.pac)

### Removed

- The previous version of the SCCM cache folder check was pretty much useless, so it was removed.

## 2024-05-24

### Added

- Check to report whether an AppLocker policy is enforced.

## 2024-05-23

### Fixed

- False negative in WSUS check when Windows Update features are turned off.

## 2024-03-11

### Added

- Check for dangerous default file extension associations (e.g. '.bat').

## 2024-03-06

### Fixed

- Windows update history is no longer obtained through the registry. This method was not reliable enough.
- Errors were not properly handled during third-party kernel enumeration.

## 2024-03-05

### Changed

- Add test ID to output CSV file.

## 2024-02-20

### Updated

- In the LAPS check, the configuration of both LAPS legacy and LAPSv2 is now enumerated.

## 2023-12-25

### Added

- Check for cached MSI files that run potentially unsafe Custom Actions.

## 2023-12-19

### Added

- Check for AppLocker rules that can be exploited to execute arbitrary code.

### Fixed

- Removed code analyzer decorators because they are not compatible with PSv2.

## 2023-12-07

### Changed

- Complete refactor of the Credential Guard check to remove the dependency on the Get-ComputerInfo cmdlet, which is only available in PS > v5.1. Instead, the WMI database is directly queried, in addition to the registry settings.
- Added decorators to suppress warnings on unused variables that define Windows structures.

## 2023-12-06

### Fixed

- The Point and Print check now also reports the "InForest" setting, that can be used as an alternative to "ServerList".
- Another attempt at figuring out the vulnerable (Package) Point and Print configurations...

### Changed

- Improved readability of application permissions check by expanding the array of file system rights.

## 2023-12-05

### Fixed

- In the HTML report, all cells containing raw output results are now scrollable.
- Fixed result discrepancies caused by NTFS filesystem redirection when running from a 32-bit PowerShell.

## 2023-12-03

### Added

- Check for SCCM Network Access Account credentials.

### Changed

- Updated build script to create a copy of 'PrivescCheck.ps1' at the root of the project.

## 2023-11-22

### Fixed

- Restored PSv2 compatibility regarding severity level enumeration.

## 2023-09-03

### Changed

- Improved result header.
- Improved BIOS mode + Secure Boot check.
- The modifiable application check now displays a warning when a system folder is detected, rather than searching it recursively.

## 2023-08-20

### Changed

- All the check descriptions were update to follow a more generic phrasing.
- Updated the style of the ASCII and HTML reports.

## 2023-08-19

### Changed

- The BitLocker check now returns something only if the configuration is vulnerable.
- Move AD domain helpers to the global Helper file.
- The LAPS check now returns something only if the configuration is vulnerable.
- The UAC check now returns something only if the configuration is vulnerable.
- Results are now sorted by severity in the short report.
- The Credential Guard check now returns something only if the configuration is vulnerable.
- The AlwaysInstallElevated check was refactored.
- The Point and Print config check was refactored.
- The WLAN profile check was refactored.
- The Airstrike attack check was refactored.
- The Driver Co-installer check now returns something only if the configuration is vulnerable.
- The LSA protection check now returns something only if the configuration is vulnerable.
- The BIOS mode check now returns something only if the configuration is vulnerable.
- The user privilege check now returns only exploitable privileges.

### Removed

- The "compliance" aspect was completely removed.

## 2023-08-14

### Changed

- Reworked the script output using unicode characters.
- Replaced the categories with main techniques from the Mitre Att&ck framework.

### Removed

- Removed the check "types" ("info"/"vuln") as this information was redundant with the severity.

## 2023-08-13

### Fixed

- Fixed a false negative that caused Credential Guard to be reported as not being running. This could occur when Windows enabled it by default because the machine meets all the hardware and software requirements.

## 2023-07-22

### Changed

- Only one hash type is stored for each driver in the LOL drivers database to reduce the size of the final script.

### Fixed

- Fixed an latent issue that could cause module names to overlap in the final script.

## 2023-07-18

### Fixed

- Fixed a regression causing false negatives in `Invoke-ServiceUnquotedPathCheck` (see issue #48).

## 2023-07-10

### Added

- Add a check for vulnerable drivers based on the list provided by loldrivers.io.

### Changed

- Restructure the source code.
- Improved enumeration of leaked handles for better compatibility with PSv2.
- Check random module names with a regex to ensure they contain only a-z letters.

## 2023-07-02

### Changed

- The "build" script now generates random variable names for the modules. To do so, it downloads the word list from the "PyFuscation" project. If it cannot download the list, it falls back to using the filename instead.

## 2023-07-01

### Changed

- The "PrintNightmare" check was fully renamed as "Point and Print configuration", which is more accurate. The code was also completely refactored. The tests that are implemented for the different variants of the exploit should also be more reliable.

## 2023-06-28

### Fixed

- Two of the registry keys in the Point & Print configuration check were incorrect.

## 2023-06-18

### Added

- Updated the BitLocker check to report the startup authentication mode (TPM only, TPM+PIN, etc.).
- A helper function was added to extract the BitLocker status and configuration.

## 2023-05-23

### Added

- The DLL "SprintCSP.dll" was added to the list of phantom DLLs that can be hijacked (service "StorSvc").
- For each phantom DLL, a link to the (original?) source describing its discovery and exploitation is now provided.

### Changed

- A check's compliance result is no longer a Boolean. It is now represented as a String ("True", "False", "N/A").
- In HTML reports, the "Compliance" result is handled similarly to "Severity" levels, using a label.

## 2023-02-18

### Added

- Services > Invoke-ThirdPartyDriverCheck, for enumerating third-party drivers.

## 2023-02-18

### Changed

- Modified the Process access rights enumeration to bypass Cortex AMSI detection (AMSI rule flagging the string "CreateThread" as malicious).
- Changed the configuration of the Vault "cred" and "list" checks to enable them only in "Extended" mode to bypass Cortex behavioral detection.
- Updated the help text of the main Invoke-PrivescCheck cmdlet as suggested in PR #45.

### Fixed

- The WinLogon credential check now ensures that the password values are not empty.

## 2023-01-29

### Fixed

- The info check now shows the correct product name when running on Windows 11.

## 2022-11-07

### Fixed

- Getting the name of a process (based on its PID) could fail when enumerating network endpoints. These errors are now silently ignored.

## 2022-11-06

### Added

- Misc > Invoke-ExploitableLeakedHandlesCheck

### Changed

- Added a cache for user group SIDs and deny SIDs. Deny SIDs in particular caused a significant overhead in Get-ModifiablePath. The performance gain is substantial.
- The dates in the hotfix list are now displayed in ISO format to avoid confusion.

### Fixed

- Get-HotFixList missed some update packages because the regular expression used to browse the registry was incorrect.

## 2022-10-30

### Changed

- The builder now removes all the comments, thus lowering the chance of detection by AMSI.

## 2022-10-02

### Fixed

- Incorrect handling of deny-only groups in file ACL checks.
- Issue with Metasploit caused by the presence of a null byte in the output.

## 2022-08-14

### Changed

- Second try to supporting deny-only SIDs when checking DACLs (Get-ModificationRight).

## 2022-08-07

### Changed

- DACL checking is now done in a dedicated cmdlet (Get-ModificationRight) which can currently handle objects of types "File", "Directory" and "Registry Key".
- The Get-ModifiablePath and Get-ModifiableRegistryPath cmdlets now use the generic Get-ModificationRight cmdlet.
- Deny ACEs are now taken into account when checking DACLs.

## 2022-06-08

### Added

- The value of the 'DisableWindowsUpdateAccess' setting is now reported in the WSUS check.

### Fixed

- System PATH parsing improved to ensure we do not check empty paths

## 2022-04-07

### Added

- Explicit output types where possible

### Changed

- Rewrite the Builder and the Loader
- Rename "Write-PrivescCheckAsciiReport" to "Show-PrivescCheckAsciiReport"

### Removed

- Trailing spaces in the entire code (code cleanup)
- Empty catch blocks

## 2022-03-13

### Added

- Network > Get-WlanProfileList, a helper function that retrieves the list of saved Wi-Fi profiles through the Windows API
- Network > Convert-WlanXmlProfile, a helper function that converts a WLAN XML profile to a custom PS object
- Network > Invoke-AirstrikeAttackCheck, check whether a workstation would be vulnerable to the Airstrike attack

### Changed

- Network > Invoke-WlanProfileCheck, this check now detects potential issues in 802.1x Wi-Fi profiles

## 2022-03-10

### Fixed

- A typo in the Print Nightmare check following the previous code refactoring

## 2022-03-08

### Changed

- Refactored and improved Config > Invoke-PrintNightmareCheck
- Refactored registry key checks

## 2022-02-18

### Added

- Misc > Invoke-UserSessionCheck

## 2022-02-13

### Added

- Config > Invoke-HardenedUNCPathCheck (@mr_mitm, @itm4n)

## 2022-01-13

### Added

- Misc > Invoke-DefenderExclusionCheck

## 2021-09-13

### Added

- Config > Invoke-DriverCoInstallerCheck (@SAERXCIT)

## 2021-08-17

### Added

- Creds > Invoke-HiveFileShadowCopyPermissionCheck (@SAERXCIT)

## 2021-07-23

### Added

- Config > Invoke-PrintNightmareCheck

## 2021-07-09

### Added

- XML output report format

## 2021-06-20

### Added

- Misc > Invoke-NamedPipePermissionCheck (experimental)

## 2021-06-18

### Added

- Network > Invoke-NetworkAdapterCheck

## 2021-06-16

### Added

- Invoke-UserCheck now retrieves more information about the current Token

## 2021-06-13

### Added

- User > Invoke-UserRestrictedSidCheck in case of WRITE RESTRICTED Tokens

### Changed

- Group enumeration is now generic
- All privileges are now listed and the check is now considered "INFO"

## 2021-06-01

### Changed

- Group enumeration is now done using the Windows API

## 2021-05-28

### Added

- A "Build" tool to slightly obfuscate the script

### Changed

- Complete code refactor
- PrivescCheck no longer relies on compiled C# code (back to original PowerUp method)
- Code is now structured and split in "category" files
- LSA Protection and Credential Guard are now separate checks

### Fixed

- Fixed minor bugs

## 2021-04-06

### Added

- Services > Invoke-ServiceControlManagerPermissionCheck

## 2020-10-29

### Added

- Scheduled Tasks > Invoke-ScheduledTaskUnquotedPathCheck

### Changed

- Refactored the report generation feature
- Refactored scheduled tasks check

## 2020-10-28

### Added

- A 'RunIfAdmin' mode. Some checks are now run even if the script is executed as an administrator.
- A severity level for each check

## 2020-10-27

### Added

- Config > Invoke-SccmCacheFolderVulnCheck

## 2020-10-07

### Added

- Additional custom checks can now be added as plugins
- A "silent" mode (only the final vulnerability report is displayed)
- Config > Invoke-SccmCacheFolderCheck
- Some report generation functions (HTML, CSV)

## 2020-10-06

### Added

- Apps > Invoke-ApplicationsOnStartupVulnCheck

## 2020-10-04

### Added

- Credentials > PowerShell History

## 2020-09-13

### Added

- basic vulnerability report

## 2020-09-04

### Added

- Misc > Invoke-EndpointProtectionCheck

## 2020-07-22

### Added

- Fixed a false positive: 'C:' resolves to the current directory
- Fixed a false positive: scheduled tasks running as the current user
- Hardening > Invoke-BitLockerCheck

## 2020-07-17

### Added

- Refactored Main function

## 2020-07-16

### Added

- Helper > Convert-SidToName
- Misc > Invoke-HotfixCheck
- Applications > Invoke-ProgramDataPermissionCheck

## 2020-04-09

### Added

- DLL Hijacking > Invoke-HijackableDllCheck
- Applications > Invoke-ScheduledTasksCheck

## 2020-04-08

### Added

- Misc > Invoke-UserHomeFolderCheck
- Programs > Invoke-StartupApplicationPermissionCheck
- Registry > Invoke-WsusConfigurationCheck
- User > Invoke-UserEnvironmentCheck
- Updated Credentials > Invoke-CredentialFileCheck

## 2020-03-21

### Added

- Handled exception in "Network > Invoke-WlanProfileCheck" when dealing with servers

## 2020-03-12

### Added

- Network > Invoke-WlanProfileCheck

## 2020-02-14

### Added

- Credentials > Invoke-VaultListCredentialCheck

### Changed

- Renamed Credentials > Invoke-CredentialManagerCheck -> Invoke-VaultCredentialCheck

## 2020-02-09

### Added

- Credentials > Invoke-GPPCredentialCheck

## 2020-01-30

### Added

- Credentials > Invoke-CredentialManagerCheck

## 2020-01-29

### Added

- Fixed bug Helper > Get-ModifiablePath (error handling in Split-Path)

## 2020-01-20

### Added

- Fixed bug User > Invoke-UserGroupCheck (don't translate SIDs like "S-1-5.*")

## 2020-01-17

### Added

- Helper > Get-UEFIStatus
- Helper > Get-SecureBootStatus
- Helper > Get-CredentialGuardStatus
- Helper > Get-LsaRunAsPPLStatus
- Registry > Invoke-LsaProtectionsCheck
- Helper > Get-UnattendSensitiveData
- Credentials > Invoke-UnattendFileCredentialCheck

### Changed

- Merged Sensitive Files with Credentials

## 2020-01-16

### Added

- Moved "Invoke-PrivescCheck.ps1" from "Pentest-Tools" to a dedicated repo.
- User > Invoke-UserCheck
- User > Invoke-UserGroupCheck
- User > Invoke-UserPrivilegeCheck
- Services > Invoke-InstalledServiceCheck
- Services > Invoke-ServicePermissionCheck
- Services > Invoke-ServiceRegistryPermissionCheck
- Services > Invoke-ServiceImagePermissionCheck
- Services > Invoke-ServiceUnquotedPathCheck
- Dll Hijacking > Invoke-DllHijackingCheck
- Sensitive Files > Invoke-SamBackupFilesCheck
- Programs > Invoke-InstalledApplicationCheck
- Programs > Invoke-InstalledApplicationPermissionCheck
- Programs > Invoke-RunningProcessCheck
- Credentials > Invoke-WinLogonCredentialCheck
- Credentials > Invoke-CredentialFileCheck
- Registry > Invoke-UserAccountControlCheck
- Registry > Invoke-LapsCheck
- Registry > Invoke-PowershellTranscriptionCheck
- Registry > Invoke-RegistryAlwaysInstallElevatedCheck
- Network > Invoke-TcpEndpointCheck
- Network > Invoke-UdpEndpointCheck
- Misc > Invoke-WindowsUpdateCheck
- Misc > Invoke-SystemInformationCheck
- Misc > Invoke-LocalAdminGroupCheck
- Misc > Invoke-MachineRoleCheck
- Misc > Invoke-SystemStartupHistoryCheck
- Misc > Invoke-SystemStartupCheck
- Misc > Invoke-SystemDriveCheck