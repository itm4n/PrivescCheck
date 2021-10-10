function Get-SecurityBaseline {
    <#
    .SYNOPSIS
    Get a security baseline based on a Windows profile. This works only with registry keys.
    
    Author: @SAERXCIT, @itm4n
    License: BSD 3-Clause

    .PARAMETER Profile
    Name of the Windows profile (Windows10, ...)
    #>

    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("Windows10")]
        [string]
        $Profile
    )

    $BaselineWindows10 = @"
"Category", "Description", "Key", "Value", "Type", "Default", "Expected"
"BitLocker", "Enable BitLocker drive encryption", "HKLM\SYSTEM\CurrentControlSet\Control\BitLockerStatus", "BootStatus", "REG_DWORD", "0", "1"
"BitLocker", "Enable advanced BitLocker setup", "HKLM\SOFTWARE\Policies\Microsoft\FVE", "UseAdvancedStartup", "REG_DWORD", "", "1"
"BitLocker", "Allow BitLocker without a compatible TPM", "HKLM\SOFTWARE\Policies\Microsoft\FVE", "EnableBDEWithNoTPM", "REG_DWORD", "", "0"
"BitLocker", "Allow BitLocker with a compatible TPM", "HKLM\SOFTWARE\Policies\Microsoft\FVE", "UseTPM", "REG_DWORD", "", "0"
"BitLocker", "Allow BitLocker with a compatible TPM and a startup PIN", "HKLM\SOFTWARE\Policies\Microsoft\FVE", "UseTPMPIN", "REG_DWORD", "", "1"
"BitLocker", "Allow BitLocker with a compatible TPM and a startup key", "HKLM\SOFTWARE\Policies\Microsoft\FVE", "UseTPMKey", "REG_DWORD", "", "0"
"BitLocker", "Allow BitLocker with a compatible TPM and a startup key and PIN", "HKLM\SOFTWARE\Policies\Microsoft\FVE", "UseTPMKeyPIN", "REG_DWORD", "", "0"
"BitLocker", "Disable new DMA devices when this computer is locked", "HKLM\SOFTWARE\Policies\Microsoft\FVE", "DisableExternalDMAUnderLock", "REG_DWORD", "", "1"
"BitLocker", "Do not allow write access to devices configured in another organization", "HKLM\SOFTWARE\Policies\Microsoft\FVE", "RDVDenyCrossOrg", "REG_DWORD", "", "0"
"BitLocker", "Allow enhanced PINs for startup", "HKLM\SOFTWARE\Policies\Microsoft\FVE", "UseEnhancedPin" , "REG_DWORD", "", "1"
"BitLocker", "Deny write access to removable drives not protected by BitLocker", "HKLM\SYSTEM\CurrentControlSet\Policies\Microsoft\FVE", "RDVDenyWriteAccess", "REG_DWORD", "", "1"
"Authentication", "Enable enhanced anti-spoofing for Windows Hello face authentication", "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures", "EnhancedAntiSpoofing", "REG_DWORD", "", "1"
"Authentication", "Remote host allows delegation of non-exportable credentials", "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation", "AllowProtectedCreds", "REG_DWORD", "", "1"
"Authentication", "Disable convenience PIN sign-in", "HKLM\SOFTWARE\Policies\Microsoft\Windows\System", "AllowDomainPINLogon", "REG_DWORD", "", "0"
"Authentication", "Do not enumerate local users on domain-joined computers", "HKLM\SOFTWARE\Policies\Microsoft\Windows\System", "EnumerateLocalUsers", "REG_DWORD", "0", "0"
"Authentication", "Limit local account use of blank passwords to console logon only", "HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "LimitBlankPasswordUse", "REG_DWORD", "1", "1"
"Authentication", "Define LAN Manager authentication level", "HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", "REG_DWORD", "", "5"
"Authentication", "Do not store LAN Manager hash value on next password change", "HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash", "REG_DWORD", "1", "1"
"Authentication", "Do not allow anonymous enumeration of SAM accounts and shares", "HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymous", "REG_DWORD", "0", "1"
"Authentication", "Do not allow anonymous enumeration of SAM account", "HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM", "REG_DWORD", "1", "1"
"Authentication", "Restrict clients allowed to make remote calls to SAM", "HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictRemoteSAM", "REG_SZ", "", "O:BAG:BAD:(A;;RC;;;BA)"
"Authentication", "Do not allow LocalSystem NULL session fallback", "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "allownullsessionfallback", "REG_DWORD", "0", "0"
"Authentication", "Set minimum session security for NTLM SSP based (including secure RPC) clients", "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NTLMMinClientSec", "REG_DWORD", "", "537395200"
"Authentication", "Set minimum session security for NTLM SSP based (including secure RPC) servers", "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0", "NTLMMinServerSec", "REG_DWORD", "", "537395200"
"Authentication", "Prevent WDigest credentials from being stored in memory", "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential", "REG_DWORD", "0", "0"
"User Account Control", "Do not enumerate administrator accounts on elevation", "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI", "EnumerateAdministrators", "REG_DWORD", "", "0"
"User Account Control", "Define the behavior of the elevation prompt for administrators", "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", "REG_DWORD", "5", "2"
"User Account Control", "Define the behavior of the elevation prompt for users", "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorUser", "REG_DWORD", "3", "0"
"User Account Control", "Detect application installations and prompt for elevation", "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableInstallerDetection", "REG_DWORD", "1", "1"
"User Account Control", "Run all administrators in Admin Approval Mode", "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", "REG_DWORD", "1", "1"
"User Account Control", "Only elevate UIAccess applications that are installed in secure locations", "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableSecureUIAPaths", "REG_DWORD", "1", "1"
"User Account Control", "Virtualize file and registry write failures to per-user locations", "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableVirtualization", "REG_DWORD", "1", "1"
"User Account Control", "Use Admin Approval Mode for the built-in Administrator account", "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "FilterAdministratorToken", "REG_DWORD", "0", "1"
"User Account Control", "Enable UAC remote restrictions", "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "LocalAccountTokenFilterPolicy", "REG_DWORD", "1", "0"
"User Account Control", "Disable always install with elevated privileges", "SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", "REG_DWORD", "", "0"
"User Account Control", "Allow user control over installs", "SOFTWARE\Policies\Microsoft\Windows\Installer", "EnableUserControl", "REG_DWORD", "", "0"
"Windows Defender", "Block potentially unwanted software", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender", "PUAProtection", "REG_DWORD", "", "1"
"Windows Defender", "Select cloud protection level", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine", "MpCloudBlockLevel", "REG_DWORD", "", "2"
"Windows Defender", "Scan downloaded files and attachments", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableIOAVProtection", "REG_DWORD", "", "0"
"Windows Defender", "Turn on real-time protection", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", "REG_DWORD", "", "0"
"Windows Defender", "Scan removable drives", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan", "DisableRemovableDriveScanning", "REG_DWORD", "", "0"
"Windows Defender", "Configure the 'Block at First Sight' feature", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "DisableBlockAtFirstSeen", "REG_DWORD", "", "0"
"Windows Defender", "Join Microsoft MAPS", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SpynetReporting", "REG_DWORD", "", "2"
"Windows Defender", "Send file samples when further analysis is required", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "SubmitSamplesConsent", "REG_DWORD", "", "1"
"Windows Defender", "Enable Attack Surface Reduction rules", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR", "ExploitGuard_ASR_Rules", "REG_DWORD", "", "1"
"Windows Defender", "Block Office communication application from creating child processes", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "26190899-1602-49e8-8b27-eb1d0a1ce869", "REG_DWORD", "", "1"
"Windows Defender", "Block Office applications from creating executable content", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "3b576869-a4ec-4529-8536-b80a7769e899", "REG_DWORD", "", "1"
"Windows Defender", "Block execution of potentially obfuscated scripts", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "5beb7efe-fd9a-4556-801d-275e5ffc04cc", "REG_DWORD", "", "1"
"Windows Defender", "Block Office applications from injecting code into other processes", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "REG_DWORD", "", "1"
"Windows Defender", "Block Adobe Reader from creating child processes", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "REG_DWORD", "", "1"
"Windows Defender", "Block Win32 API calls from Office macro", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B", "REG_DWORD", "", "1"
"Windows Defender", "Block credential stealing from the Windows local security authority subsystem (lsass.exe)", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "REG_DWORD", "", "1"
"Windows Defender", "Block untrusted and unsigned processes that run from USB", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "REG_DWORD", "", "1"
"Windows Defender", "Block executable content from email client and webmail", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "REG_DWORD", "", "1"
"Windows Defender", "Use advanced protection against ransomware", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "c1db55ab-c21a-4637-bb3f-a12568109d35", "REG_DWORD", "", "1"
"Windows Defender", "Block JavaScript or VBScript from launching downloaded executable content", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "d3e037e1-3eb8-44c8-a917-57927947596d", "REG_DWORD", "", "1"
"Windows Defender", "Block all Office applications from creating child processes", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "REG_DWORD", "", "1"
"Windows Defender", "Block persistence through WMI event subscription", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "e6db77e5-3df2-4cf1-b95a-636979351e5b", "REG_DWORD", "", "1"
"Windows Defender", "Prevent users and apps from accessing dangerous websites", "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection", "EnableNetworkProtection", "REG_DWORD", "0", "1"
"Windows Defender", "Turn on Windows Defender SmartScreen ", "HKLM\SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", "REG_DWORD", "", "1"
"Windows Defender", "Configure Windows Defender SmartScreen behavior", "HKLM\SOFTWARE\Policies\Microsoft\Windows\System", "ShellSmartScreenLevel", "REG_SZ", "", "Block"
"Firewall", "Domain profile: block inbound connections", "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile", "DefaultInboundAction", "REG_DWORD", "", "1"
"Firewall", "Domain profile: allow outbound connections", "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile", "DefaultOutboundAction", "REG_DWORD", "", "0"
"Firewall", "Domain profile: disable notifications", "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile", "DisableNotifications", "REG_DWORD", "", "1"
"Firewall", "Domain profile: enable firewall", "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile", "EnableFirewall", "REG_DWORD", "", "1"
"Firewall", "Private profile: block inbound connections", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile", "DefaultInboundAction", "REG_DWORD", "", "1"
"Firewall", "Private profile: allow outbound connections", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile", "DefaultOutboundAction", "REG_DWORD", "", "0"
"Firewall", "Private profile: disable notifications", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile", "DisableNotifications", "REG_DWORD", "", "1"
"Firewall", "Private profile: enable firewall", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile", "EnableFirewall", "REG_DWORD", "", "1"
"Firewall", "Public profile: do not apply local connection security rules", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile", "AllowLocalIPsecPolicyMerge", "REG_DWORD", "", "0"
"Firewall", "Public profile: do not apply local firewall rules", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile", "AllowLocalPolicyMerge", "REG_DWORD", "", "0"
"Firewall", "Public profile: block inbound connections", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile", "DefaultInboundAction", "REG_DWORD", "", "1"
"Firewall", "Public profile: allow outbound connections", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile", "DefaultOutboundAction", "REG_DWORD", "", "0"
"Firewall", "Public profile: disable notifications", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile", "DisableNotifications", "REG_DWORD", "", "1"
"Firewall", "Public profile: enable firewall", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile", "EnableFirewall", "REG_DWORD", "", "1"
"Network", "Do not allow Windows to automatically connect to suggested open hotspots", "HKLM\Software\Microsoft\WcmSvc\wifinetworkmanager\config", "AutoConnectAllowedOEM", "REG_DWORD", "", "0"
"Network", "Disable IPv4 source routing", "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "DisableIPSourceRouting", "REG_DWORD", "", "2"
"Network", "Disable ICMP redirects", "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters", "EnableICMPRedirect", "REG_DWORD", "", "0"
"Network", "Disable IPv6 source routing", "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisableIPSourceRouting", "REG_DWORD", "", "2"
"Network Connections", "Turn off Internet download for Web publishing and online ordering wizards", "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoWebServices", "REG_DWORD", "", "1"
"Network Connections", "Configure CredSSP encryption oracle remediation protection", "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters", "AllowEncryptionOracle", "REG_DWORD", "", "0"
"Network Connections", "Turn off downloading of print drivers over HTTP", "HKLM\Software\Policies\Microsoft\Windows NT\Printers", "DisableWebPnPDownload", "REG_DWORD", "", "1"
"Network Connections", "Disable SMB insecure guest logons", "HKLM\Software\Policies\Microsoft\Windows\LanmanWorkstation", "AllowInsecureGuestAuth", "REG_DWORD", "", "0"
"Network Connections", "Prohibit use of Internet Connection Sharing on your DNS domain network", "HKLM\Software\Policies\Microsoft\Windows\Network Connections", "NC_ShowSharedAccessUI", "REG_DWORD", "", "0"
"Network Connections", "Configure hardened UNC paths: NETLOGON", "HKLM\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths", "\\*\NETLOGON", "REG_SZ", "", "RequireIntegrity=1,RequireMutualAuthentication=1"
"Network Connections", "Configure hardened UNC paths: SYSVOL", "HKLM\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths", "\\*\SYSVOL", "REG_SZ", "", "RequireIntegrity=1,RequireMutualAuthentication=1"
"Network Connections", "Prohibit connection to non-domain networks when connected to domain authenticated network", "HKLM\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy", "fBlockNonDomain", "REG_DWORD", "", "1"
"Network Connections", "Force SMB server signing", "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "requiresecuritysignature", "REG_DWORD", "", "1"
"Network Connections", "Restrict anonymous access to Named Pipes and Shares", "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RestrictNullSessAccess", "REG_DWORD", "", "1"
"Network Connections", "Disable SMBv1", "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", "REG_DWORD", "", "0"
"Network Connections", "Do not send unencrypted password to third-party SMB servers", "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters", "EnablePlainTextPassword", "REG_DWORD", "", "0"
"Network Connections", "Force SMB client signing", "HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature", "REG_DWORD", "", "1"
"Network Connections", "Enable LDAP client signing", "HKLM\System\CurrentControlSet\Services\LDAP", "LDAPClientIntegrity", "REG_DWORD", "", "1"
"Network Connections", "Disable MrxSmb10 service", "HKLM\SYSTEM\CurrentControlSet\Services\MrxSmb10", "Start", "REG_DWORD", "", "4"
"Network Connections", "Set NetBIOS node type as P-node", "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters", "NodeType", "REG_DWORD", "", "2"
"Network Connections", "Allow the computer to ignore NetBIOS name release requests", "HKLM\SYSTEM\CurrentControlSet\Services\Netbt\Parameters", "NoNameReleaseOnDemand", "REG_DWORD", "", "1"
"Network Connections", "Always digitally encrypt or sign secure channel data ", "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters", "requiresignorseal", "REG_DWORD", "", "1"
"Network Connections", "Require strong session key", "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters", "requirestrongkey", "REG_DWORD", "", "1"
"Network Connections", "Digitally encrypt secure channel data (when possible)", "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters", "sealsecurechannel", "REG_DWORD", "", "1"
"Network Connections", "Digitally sign secure channel data (when possible)", "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters", "signsecurechannel", "REG_DWORD", "", "1"
"Remote Access", "RPC: Allow only authenticated RPC Clients to connect to RPC Servers ", "HKLM\Software\Policies\Microsoft\Windows NT\Rpc", RestrictRemoteClients", "REG_DWORD", "", "1"
"Remote Access", "RDP: Do not allow passwords to be saved", "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services", DisablePasswordSaving", "REG_DWORD", "1", "1"
"Remote Access", "RDP: Turn off remote assistance", "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services", fAllowToGetHelp", "REG_DWORD", "", "0"
"Remote Access", "RDP: Do not allow drive redirection", "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services", fDisableCdm", "REG_DWORD", "", "1"
"Remote Access", "RDP: Require secure RPC communication", "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services", fEncryptRPCTraffic", "REG_DWORD", "", "1"
"Remote Access", "RDP: Always prompt for password upon connection", "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services", fPromptForPassword", "REG_DWORD", "", "1"
"Remote Access", "RDP: Set minimum encryption level to high", "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services", MinEncryptionLevel", "REG_DWORD", "", "3"
"Remote Access", "WinRM: Disable client basic authentication", "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client", AllowBasic", "REG_DWORD", "0", "0"
"Remote Access", "WinRM: Enable client digest authentication", "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client", AllowDigest", "REG_DWORD", "0", "0"
"Remote Access", "WinRM: Disallow client unecrypted traffic", "HKLM\Software\Policies\Microsoft\Windows\WinRM\Client", AllowUnencryptedTraffic", "REG_DWORD", "0", "0"
"Remote Access", "WinRM: Disallow server basic authentication", "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service", AllowBasic", "REG_DWORD", "0", "0"
"Remote Access", "WinRM: Disallow server unencrypted traffic", "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service", AllowUnencryptedTraffic", "REG_DWORD", "0", "0"
"Remote Access", "WinRM: Disallow WinRM from storing RunAs credentials", "HKLM\Software\Policies\Microsoft\Windows\WinRM\Service", DisableRunAs", "REG_DWORD", "0", "1"
"Cloud Content", "Do not suggest third-party content in Windows spotlight", "HKCU\Software\Policies\Microsoft\Windows\CloudContent", "DisableThirdPartySuggestions", "REG_DWORD", "0", "1"
"Cloud Content", "Allow Microsoft accounts to be optional", "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System", "MSAOptional", "REG_DWORD", "0", "1"
"Cloud Content", "Turn off Microsoft consumer experiences", "HKLM\Software\Policies\Microsoft\Windows\CloudContent", "DisableWindowsConsumerFeatures", "REG_DWORD", "0", "1"
"Lock Screen", "Turn off toast notifications on the lock screen", "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications", "NoToastApplicationNotificationOnLockScreen", "REG_DWORD", "0", "1"
"Lock Screen", "Set machine inactivity limit", "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System", "InactivityTimeoutSecs", "REG_DWORD", "", "900"
"Lock Screen", "Disable interaction with applications using voice control while the screen is locked", "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy", "LetAppsActivateWithVoiceAboveLock", "REG_DWORD", "0", "2"
"Lock Screen", "Prevents a camera from being invoked on the lock screen", "HKLM\Software\Policies\Microsoft\Windows\Personalization", "NoLockScreenCamera", "REG_DWORD", "0", "1"
"Lock Screen", "Disable slide show on the lock screen", "HKLM\Software\Policies\Microsoft\Windows\Personalization", "NoLockScreenSlideshow", "REG_DWORD", "", "1"
"Virtualization Based Security", "Enable System Guard Secure Launch", "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "ConfigureSystemGuardLaunch", "REG_DWORD", "", "1"
"Virtualization Based Security", "Turn On Virtualization Based Security", "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "EnableVirtualizationBasedSecurity", "REG_DWORD", "0", "1"
"Virtualization Based Security", "Require UEFI Memory Attributes Table", "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "HVCIMATRequired", "REG_DWORD", "", "1"
"Virtualization Based Security", "Configure Virtualization Based Protection of Code Integrity", "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "HypervisorEnforcedCodeIntegrity", "REG_DWORD", "", "1"
"Virtualization Based Security", "Enable  Credential Guard ", "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "LsaCfgFlags", "REG_DWORD", "", "1"
"Virtualization Based Security", "Select Platform Security Level", "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard", "RequirePlatformSecurityFeatures", "REG_DWORD", "", "1"
"Session Management", "Configure Smart card removal behavior", "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "ScRemoveOption", "REG_DWORD", "0", "1"
"Session Management", "Do not automatically sign in and lock the last interactive user after the system restarts ", "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableAutomaticRestartSignOn", "REG_DWORD", "0", "1"
"Session Management", "Require a password when a computer wakes (plugged in)", "HKLM\Software\Policies\Microsoft\Power\PowerSettings\5CA83367-6E45-459F-A27B-476B1D01C936", "ACSettingIndex", "REG_DWORD", "1", "1"
"Session Management", "Require a password when a computer wakes (on battery)", "HKLM\Software\Policies\Microsoft\Power\PowerSettings\5CA83367-6E45-459F-A27B-476B1D01C936", "DCSettingIndex", "REG_DWORD", "1", "1"
"Session Management", "Disallow standby states (S1-S3) when sleeping (plugged in)", "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab", "ACSettingIndex", "REG_DWORD", "1", "0"
"Session Management", "Disallow standby states (S1-S3) when sleeping (on battery)", "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\abfc2519-3608-4c2a-94ea-171b0ed546ab", "DCSettingIndex", "REG_DWORD", "1", "0"
"Removable Devices", "Do not execute any autorun commands", "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoAutorun", "REG_DWORD", "0", "1"
"Removable Devices", "Turn off Autoplay", "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", "REG_DWORD", "", "255"
"Removable Devices", "Prevent installation of devices using drivers that match these device setup classes", "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions", "DenyDeviceClasses", "REG_DWORD", "0", "1"
"Removable Devices", "Prevent installation of devices using drivers that match these device setup classes (already installed)", "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions", "DenyDeviceClassesRetroactive", "REG_DWORD", "0", "1"
"Removable Devices", "Prevent installation of devices using drivers for these device setup classes", "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses", "1", "REG_SZ", "", "{d48179be-ec20-11d1-b6b8-00c04fa372a7}"
"Removable Devices", "Disallow Autoplay for non-volume devices", "HKLM\Software\Policies\Microsoft\Windows\Explorer", "NoAutoplayfornonVolume", "REG_DWORD", "0", "1"
"Kernel Protection", "Block all external DMA-capable devices", "HKLM\Software\Policies\Microsoft\Windows\Kernel DMA Protection", "DeviceEnumerationPolicy", "REG_DWORD", "", "0"
"Kernel Protection", "Enable Structured Exception Handling Overwrite Protection (SEHOP)", "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel", "DisableExceptionChainValidation", "REG_DWORD", "", "0"
"Kernel Protection", "Configure the Boot-Start Driver Initialization Policy", "HKLM\SYSTEM\CurrentControlSet\Policies\EarlyLaunch", "DriverLoadPolicy", "REG_DWORD", "", "3"
"Logging", "Specify the maximum log file size (KB)", "HKLM\Software\Policies\Microsoft\Windows\EventLog\Application", "MaxSize", "REG_DWORD", "", "32768"
"Logging", "Specify the maximum log file size (KB)", "HKLM\Software\Policies\Microsoft\Windows\EventLog\Security", "MaxSize", "REG_DWORD", "", "196608"
"Logging", "Specify the maximum log file size (KB)", "HKLM\Software\Policies\Microsoft\Windows\EventLog\System", "MaxSize", "REG_DWORD", "", "32768"
"Logging", "Turn on PowerShell Script Block Logging", "HKLM\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging", "REG_DWORD", "", "1"
"Logging", "Log dropped packets", "HKLM\Domain: Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging", "LogDroppedPackets", "REG_DWORD", "", "1"
"Logging", "Domain: Specify the maximum log file size (KB)", "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging", "LogFileSize", "REG_DWORD", "", "16384"
"Logging", "Domain: Log successful packets", "HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging", "LogSuccessfulConnections", "REG_DWORD", "", "1"
"Logging", "Private: Log dropped packets", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging", "LogDroppedPackets", "REG_DWORD", "", "1"
"Logging", "Private: Specify the maximum log file size (KB)", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging", "LogFileSize", "REG_DWORD", "", "16384"
"Logging", "Private: Log successful packets", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging", "LogSuccessfulConnections", "REG_DWORD", "", "1"
"Logging", "Public: Log dropped packets", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging", "LogDroppedPackets", "REG_DWORD", "", "1"
"Logging", "Public: Specify the maximum log file size (KB)", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging", "LogFileSize", "REG_DWORD", "", "16384"
"Logging", "Public: Log successful packets", "HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging", "LogSuccessfulConnections", "REG_DWORD", "", "1"
"Logging", "Force audit policy subcategory settings to override audit policy category settings.", "HKLM\System\CurrentControlSet\Control\Lsa", "SCENoApplyLegacyAuditPolicy", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Users cannot change 'User name and passwords on forms' or 'prompt me to save passwords'. ", "HKCU\Software\Policies\Microsoft\Internet Explorer\Control Panel", "FormSuggest Passwords", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Turn off the auto-complete feature for user names and passwords on forms", "HKCU\Software\Policies\Microsoft\Internet Explorer\Main", "FormSuggest Passwords", "REG_SZ", "", "no"
"Edge & Internet Explorer", "Do not prompt me to save passwords", "HKCU\Software\Policies\Microsoft\Internet Explorer\Main", "FormSuggest PW Ask", "REG_SZ", "", "no"
"Edge & Internet Explorer", "Remove 'Run this time' button for outdated ActiveX controls in Internet Explorer", "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ext", "RunThisTimeEnabled", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Turn on blocking of outdated ActiveX controls for Internet Explorer", "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Ext", "VersionCheckEnabled", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Check for signatures on downloaded programs", "HKLM\Software\Policies\Microsoft\Internet Explorer\Download", "CheckExeSignatures", "REG_SZ", "", "yes"
"Edge & Internet Explorer", "Disallow software to run or install if the signature is invalid", "HKLM\Software\Policies\Microsoft\Internet Explorer\Download", "RunInvalidSignatures", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Prevent downloading of enclosures from RSS feeds", "HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds", "DisableEnclosureDownload", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Do not allow ActiveX controls to run in Protected Mode when Enhanced Protected Mode is enabled", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main", "DisableEPMCompat", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Turn on Enhanced Protected Mode", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main", "Isolation", "REG_SZ", "", "PMEM"
"Edge & Internet Explorer", "Turn on 64-bit tab processes when running in Enhanced Protected Mode", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main", "Isolation64Bit", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "MK Protocol Security Restriction", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL", "(Reserved)", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "MK Protocol Security Restriction", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL", "explorer.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "MK Protocol Security Restriction", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL", "iexplore.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Consistent Mime Handling", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING", "(Reserved)", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Consistent Mime Handling", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING", "explorer.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Consistent Mime Handling", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING", "iexplore.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Mime Sniffing Safety Feature", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING", "(Reserved)", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Mime Sniffing Safety Feature", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING", "explorer.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Mime Sniffing Safety Feature", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING", "iexplore.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Restrict ActiveX Install", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL", "(Reserved)", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Restrict ActiveX Install", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL", "explorer.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Restrict ActiveX Install", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL", "iexplore.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Restrict File Download", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD", "(Reserved)", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Restrict File Download", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD", "explorer.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Restrict File Download", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD", "iexplore.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Configure Notification bar for IE processes", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND", "(Reserved)", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Configure Notification bar for IE processes", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND", "explorer.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Configure Notification bar for IE processes", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND", "iexplore.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Scripted Window Security Restrictions", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS", "(Reserved)", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Scripted Window Security Restrictions", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS", "explorer.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Scripted Window Security Restrictions", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS", "iexplore.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Protection From Zone Elevation", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION", "(Reserved)", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Protection From Zone Elevation", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION", "explorer.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Protection From Zone Elevation", "HKLM\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION", "iexplore.exe", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Select SmartScreen Filter mode", "HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter", "EnabledV9", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Prevent bypassing SmartScreen Filter warnings", "HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter", "PreventOverride", "REG_DWORD", "0", "1"
"Edge & Internet Explorer", "Prevent bypassing SmartScreen Filter warnings about files that are not commonly downloaded from the Internet", "HKLM\Software\Policies\Microsoft\Internet Explorer\PhishingFilter", "PreventOverrideAppRepUnknown", "REG_DWORD", "0", "1"
"Edge & Internet Explorer", "Turn off Crash Detection", "HKLM\Software\Policies\Microsoft\Internet Explorer\Restrictions", "NoCrashDetection", "REG_DWORD", "1", "1"
"Edge & Internet Explorer", "Turn on the Security Settings Check feature", "HKLM\Software\Policies\Microsoft\Internet Explorer\Security", "DisableSecuritySettingsCheck", "REG_DWORD", "0", "0"
"Edge & Internet Explorer", "Prevent per-user installation of ActiveX controls", "HKLM\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX", "BlockNonAdminActiveXInstall", "REG_DWORD", "0", "1"
"Edge & Internet Explorer", "Prevent certificate error overrides", "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Internet Settings", "PreventCertErrorOverrides", "REG_DWORD", "0", "1"
"Edge & Internet Explorer", "Disable  Password Manager", "HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main", "FormSuggest Passwords", "REG_SZ", "", "no"
"Edge & Internet Explorer", "Turn on Windows Defender SmartScreen", "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter", "EnabledV9", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Prevent bypassing Windows Defender SmartScreen prompts for sites", "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter", "PreventOverride", "REG_DWORD", "0", "1"
"Edge & Internet Explorer", "Prevent bypassing Windows Defender SmartScreen prompts for files", "HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter", "PreventOverrideAppRepUnknown", "REG_DWORD", "0", "1"
"Edge & Internet Explorer", "Check for server certificate revocation", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "CertificateRevocation", "REG_DWORD", "0", "1"
"Edge & Internet Explorer", "Allow fallback to SSL 3.0 (Internet Explorer)", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "EnableSSL3Fallback", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Prevent ignoring certificate errors", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "PreventIgnoreCertErrors", "REG_DWORD", "0", "1"
"Edge & Internet Explorer", "Configure Secure Protocol combinations", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "SecureProtocols", "REG_DWORD", "", "2560"
"Edge & Internet Explorer", "Security Zones: Use only machine settings", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "Security_HKLM_only", "REG_DWORD", "0", "1"
"Edge & Internet Explorer", "Security Zones: Do not allow users to change policies", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "Security_options_edit", "REG_DWORD", "0", "1"
"Edge & Internet Explorer", "Security Zones: Do not allow users to add/delete sites", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "Security_zones_map_edit", "REG_DWORD", "0", "1"
"Edge & Internet Explorer", "Turn on certificate address mismatch warning", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "WarnOnBadCertRecving", "REG_DWORD", "0", "1"
"Edge & Internet Explorer", "Disable Java in all zones", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\0", "1C00", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Disable Java in all zones", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1", "1C00", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Disable Java in all zones", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2", "1C00", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Turn on SmartScreen Filter scan", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\3", "2301", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Disable Java in all zones", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4", "1C00", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Turn on SmartScreen Filter scan", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4", "2301", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Intranet Sites: Exclude all network paths (UNCs)", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap", "UNCAsIntranet", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Disable Java in all zones", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0", "1C00", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Run antimalware programs against ActiveX controls", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0", "270C", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Initialize and script ActiveX controls not marked as safe", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1", "1201", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable Java in all zones", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1", "1C00", "REG_DWORD", "", "65536"
"Edge & Internet Explorer", "Run antimalware programs against ActiveX controls", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1", "270C", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Initialize and script ActiveX controls not marked as safe", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2", "1201", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable Java in all zones", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2", "1C00", "REG_DWORD", "", "65536"
"Edge & Internet Explorer", "Run antimalware programs against ActiveX controls", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2", "270C", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Do not download signed ActiveX controls", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1001", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Do not download unsigned ActiveX controls", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1004", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Initialize and script ActiveX controls not marked as safe", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1201", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable Internet Explorer web browser control", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1206", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable scriptlets", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1209", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Only allow approved domains to use ActiveX controls without prompt", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "120b", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Only allow approved domains to use the TDC ActiveX control", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "120c", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable access data sources across domains", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1406", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable paste operations via script", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1407", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Turn on Cross-Site Scripting (XSS) Filter", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1409", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Disallow VBScript to run in Internet Explorer", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "140C", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable Userdata persistence", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1606", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Do not navigate windows and frames across different domains", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1607", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Do not include local directory path when uploading files to a server", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "160A", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disallow drag and drop or copy and paste files", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1802", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable launching applications and files in an IFRAME", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1804", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Prompt before launching programs and unsafe files", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1806", "REG_DWORD", "", "1"
"Edge & Internet Explorer", "Use Pop-up Blocker", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1809", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Prompt for user name and password", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1A00", "REG_DWORD", "", "65536"
"Edge & Internet Explorer", "Disable Java in all zones", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "1C00", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Disable signed .NET Framework-reliant components ", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "2001", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable unsigned .NET Framework-reliant components ", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "2004", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Web sites in less privileged Web content zones cannot navigate into this zone", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "2101", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disallow script-initiated windows without size or position constraints", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "2102", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable status bar updates via script", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "2103", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Block not user-initiated file downloads", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "2200", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Use SmartScreen Filter", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "2301", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Disable loading of XAML files ", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "2402", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Turn on Protected Mode", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "2500", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Disable dragging of content from different domains within a window", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "2708", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable dragging of content from different domains across windows", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "2709", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Run antimalware programs against ActiveX controls", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3", "270C", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Do not download signed ActiveX controls", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1001", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Do not download unsigned ActiveX controls", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1004", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Do not run ActiveX controls and plugins", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1200", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Initialize and script ActiveX controls not marked as safe", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1201", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable Internet Explorer web browser control", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1206", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable scriptlets", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1209", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Only allow approved domains to use ActiveX controls without prompt", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "120b", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Only allow approved domains to use the TDC ActiveX control", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "120c", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable active scripting", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1400", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Diable scripting of Java applets", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1402", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Script ActiveX controls not marked safe for scripting", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1405", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Do not access data sources across domains", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1406", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable paste operations via script", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1407", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Turn on Cross-Site Scripting (XSS) Filter", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1409", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Disallow VBScript to run in Internet Explorer", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "140C", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable Userdata persistence", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1606", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Do not navigate windows and frames across different domains", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1607", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable META REFRESH", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1608", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Do not include local directory path when uploading files to a server", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "160A", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable drag and drop or copy and paste files", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1802", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable file downloads", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1803", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Do not launch applications and files in an IFRAME", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1804", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Do not launch programs and unsafe files", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1806", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Use Pop-up Blocker", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1809", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Configure anonymous logon", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1A00", "REG_DWORD", "", "196608"
"Edge & Internet Explorer", "Disable Java in all zones", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "1C00", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Disable Binary and Script Behaviors", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "2000", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Do not run .NET Framework-reliant components signed with Authenticode", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "2001", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Do not run .NET Framework-reliant components not signed with Authenticode", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "2004", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Web sites in less privileged Web content zones cannot navigate into this zone", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "2101", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disallow script-initiated windows without size or position constraints", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "2102", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable status bar updates via script", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "2103", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable automatic prompting for file downloads", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "2200", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Use SmartScreen Filter", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "2301", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Disallow loading of XAML files ", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "2402", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Turn on Protected Mode", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "2500", "REG_DWORD", "", "0"
"Edge & Internet Explorer", "Disable dragging of content from different domains within a window", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "2708", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Disable dragging of content from different domains across windows", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "2709", "REG_DWORD", "", "3"
"Edge & Internet Explorer", "Run antimalware programs against ActiveX controls", "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4", "270C", "REG_DWORD", "", "0"
"@
    switch ($Profile) {
        Windows10 { $BaselineWindows10 }
    }
}

function Invoke-BaselineRegistryCheck {
    <#
    .SYNOPSIS
    Checks each item of a security baseline subset. The subset is determined based on the provided category.
    
    Author: @SAERXCIT, @itm4n
    License: BSD 3-Clause

    .PARAMETER Category
    The catefory of security checks (e.g.: "BitLocker", "Authentication", "Windows Defender", etc.).
    #>

    [CmdletBinding()] Param(
        [Parameter(Mandatory=$true)]
        [string]
        $Category
    )

    # TODO: Determine profile dynamically base on machine role and Windows version
    $ProfileName = "Windows10"

    # Get baseline and filter on category
    $BaselineCsv = Get-SecurityBaseline -Profile $ProfileName | ConvertFrom-Csv -ErrorAction Stop
    $Baseline = [object[]] ($BaselineCsv | Where-Object { $_.Category -eq $Category } | Select-Object -Property * -ExcludeProperty Category)

    if (-not $Baseline) { throw "Baseline is null" }

    foreach ($BaselineItem in $Baseline) {

        switch ($BaselineItem.Type) {
            "REG_DWORD" {
                $BaselineItem.Expected = [UInt32] $BaselineItem.Expected
                if ([string]::IsNullOrEmpty($BaselineItem.Default)) { $BaselineItem.Default = $null } else { $BaselineItem.Default = [UInt32] $BaselineItem.Default }
            }
            "REG_SZ" {
                $BaselineItem.Expected = [string] $BaselineItem.Expected
                $BaselineItem.Default = [string] $BaselineItem.Default
            }
            default {
                throw "Unhandled registry type value"
            }
        }
        
        $Item = Get-ItemProperty -Path "Registry::$($BaselineItem.Key)" -Name $BaselineItem.Value -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItemProperty

        if ($ErrorGetItemProperty) {
            # Key or value does not exist, therefore assume default value.
            $ValueToCheck = $BaselineItem.Default
        }
        else {
            # Value exists, check if the data is equal to what is expected.
            $ValueToCheck = $Item.$($BaselineItem.Value)
        }

        $BaselineItem | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $ValueToCheck
        $BaselineItem | Add-Member -MemberType "NoteProperty" -Name "Compliant" -Value $($ValueToCheck -eq $BaselineItem.Expected)
        $BaselineItem
    }
}