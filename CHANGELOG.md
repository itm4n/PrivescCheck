# Changelog

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

- Second try to supporting deny-only SIDs when checking DACLs (Get-AclModificationRights).

## 2022-08-07

### Changed

- DACL checking is now done in a dedicated cmdlet (Get-AclModificationRights) which can currently handle objects of types "File", "Directory" and "Registry Key".
- The Get-ModifiablePath and Get-ModifiableRegistryPath cmdlets now use the generic Get-AclModificationRights cmdlet.
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

- Network > Invoke-WlanProfilesCheck, this check now detects potential issues in 802.1x Wi-Fi profiles

## 2022-03-10

### Fixed

- A typo in the Print Nightmare check following the previous code refactoring

## 2022-03-08

### Changed

- Refactored and improved Config > Invoke-PrintNightmareCheck
- Refactored registry key checks

## 2022-02-18

### Added

- Misc > Invoke-UserSessionListCheck

## 2022-02-13

### Added

- Config > Invoke-HardenedUNCPathCheck (@mr_mitm, @itm4n)

## 2022-01-13

### Added

- Misc > Invoke-DefenderExclusionsCheck

## 2021-09-13

### Added

- Config > Invoke-DriverCoInstallersCheck (@SAERXCIT)

## 2021-08-17

### Added

- Creds > Invoke-SensitiveHiveShadowCopyCheck (@SAERXCIT)

## 2021-07-23

### Added

- Config > Invoke-PrintNightmareCheck

## 2021-07-09

### Added

- XML output report format

## 2021-06-20

### Added

- Misc > Invoke-NamedPipePermissionsCheck (experimental)

## 2021-06-18

### Added

- Network > Invoke-NetworkAdaptersCheck

## 2021-06-16

### Added

- Invoke-UserCheck now retrieves more information about the current Token

## 2021-06-13

### Added

- User > Invoke-UserRestrictedSidsCheck in case of WRITE RESTRICTED Tokens

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

- Services > Invoke-SCMPermissionsCheck

## 2020-10-29

### Added

- Scheduled Tasks > Invoke-ScheduledTasksUnquotedPathCheck

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
- Hardening > Invoke-BitlockerCheck

## 2020-07-17

### Added

- Refactored Main function

## 2020-07-16

### Added

- Helper > Convert-SidToName
- Misc > Invoke-HotfixCheck
- Applications > Invoke-ProgramDataCheck

## 2020-04-09

### Added

- DLL Hijacking > Invoke-HijackableDllsCheck
- Applications > Invoke-ScheduledTasksCheck

## 2020-04-08

### Added

- Misc > Invoke-UsersHomeFolderCheck
- Programs > Invoke-ApplicationsOnStartupCheck
- Registry > Invoke-WsusConfigCheck
- User > Invoke-UserEnvCheck
- Updated Credentials > Invoke-CredentialFilesCheck

## 2020-03-21

### Added

- Handled exception in "Network > Invoke-WlanProfilesCheck" when dealing with servers

## 2020-03-12

### Added

- Network > Invoke-WlanProfilesCheck

## 2020-02-14

### Added

- Credentials > Invoke-VaultListCheck

### Changed

- Renamed Credentials > Invoke-CredentialManagerCheck -> Invoke-VaultCredCheck

## 2020-02-09

### Added

- Credentials > Invoke-GPPPasswordCheck

## 2020-01-30

### Added

- Credentials > Invoke-CredentialManagerCheck

## 2020-01-29

### Added

- Fixed bug Helper > Get-ModifiablePath (error handling in Split-Path)

## 2020-01-20

### Added

- Fixed bug User > Invoke-UserGroupsCheck (don't translate SIDs like "S-1-5.*")

## 2020-01-17

### Added

- Helper > Get-UEFIStatus
- Helper > Get-SecureBootStatus
- Helper > Get-CredentialGuardStatus
- Helper > Get-LsaRunAsPPLStatus
- Registry > Invoke-LsaProtectionsCheck
- Helper > Get-UnattendSensitiveData
- Credentials > Invoke-UnattendFilesCheck

### Changed

- Merged Sensitive Files with Credentials

## 2020-01-16

### Added

- Moved "Invoke-PrivescCheck.ps1" from "Pentest-Tools" to a dedicated repo.
- User > Invoke-UserCheck
- User > Invoke-UserGroupsCheck
- User > Invoke-UserPrivilegesCheck
- Services > Invoke-InstalledServicesCheck
- Services > Invoke-ServicesPermissionsCheck
- Services > Invoke-ServicesPermissionsRegistryCheck
- Services > Invoke-ServicesImagePermissionsCheck
- Services > Invoke-ServicesUnquotedPathCheck
- Dll Hijacking > Invoke-DllHijackingCheck
- Sensitive Files > Invoke-SamBackupFilesCheck
- Programs > Invoke-InstalledProgramsCheck
- Programs > Invoke-ModifiableProgramsCheck
- Programs > Invoke-RunningProcessCheck
- Credentials > Invoke-WinlogonCheck
- Credentials > Invoke-CredentialFilesCheck
- Registry > Invoke-UacCheck
- Registry > Invoke-LapsCheck
- Registry > Invoke-PowershellTranscriptionCheck
- Registry > Invoke-RegistryAlwaysInstallElevatedCheck
- Network > Invoke-TcpEndpointsCheck
- Network > Invoke-UdpEndpointsCheck
- Misc > Invoke-WindowsUpdateCheck
- Misc > Invoke-SystemInfoCheck
- Misc > Invoke-LocalAdminGroupCheck
- Misc > Invoke-MachineRoleCheck
- Misc > Invoke-SystemStartupHistoryCheck
- Misc > Invoke-SystemStartupCheck
- Misc > Invoke-SystemDrivesCheck