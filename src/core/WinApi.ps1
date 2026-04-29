$FunctionDefinitions = @(
    (New-Function advapi32 OpenSCManager ([IntPtr]) @([String], [String], [UInt32]) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError -EntryPoint OpenSCManager),
    (New-Function advapi32 OpenService ([IntPtr]) @([IntPtr], [String], [UInt32]) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError -EntryPoint OpenServiceW),
    (New-Function advapi32 QueryServiceStatusEx ([Bool]) @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -SetLastError -EntryPoint QueryServiceStatusEx),
    (New-Function advapi32 CloseServiceHandle ([Bool]) @([IntPtr]) -SetLastError -EntryPoint CloseServiceHandle),
    (New-Function advapi32 OpenProcessToken ([Bool]) @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) -SetLastError -EntryPoint OpenProcessToken),
    (New-Function advapi32 GetTokenInformation ([Bool]) @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -SetLastError -EntryPoint GetTokenInformation),
    (New-Function advapi32 LookupAccountSid ([Bool]) @([String], [IntPtr], [System.Text.StringBuilder], [UInt32].MakeByRefType(), [System.Text.StringBuilder], [UInt32].MakeByRefType(), [Int].MakeByRefType()) -SetLastError -EntryPoint LookupAccountSid),
    (New-Function advapi32 LookupPrivilegeName ([Int]) @([String], $script:LUID.MakeByRefType(), [System.Text.StringBuilder], [UInt32].MakeByRefType()) -SetLastError -EntryPoint LookupPrivilegeNameW),
    (New-Function advapi32 CredEnumerate ([Bool]) @([IntPtr], [UInt32], [UInt32].MakeByRefType(), [IntPtr].MakeByRefType()) -SetLastError -EntryPoint CredEnumerate),
    (New-Function advapi32 CredFree ([void]) @([IntPtr]) -EntryPoint CredFree),
    (New-Function advapi32 IsTextUnicode ([Bool]) @([IntPtr], [UInt32], [UInt32].MakeByRefType()) -EntryPoint IsTextUnicode),
    (New-Function advapi32 ConvertSidToStringSidW ([Bool]) @([IntPtr], [IntPtr].MakeByRefType()) -SetLastError -EntryPoint ConvertSidToStringSidW),
    (New-Function advapi32 IsTokenRestricted ([Bool]) @([IntPtr]) -SetLastError -EntryPoint IsTokenRestricted),
    (New-Function advapi32 GetSecurityInfo ([UInt32]) @([IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType()) -SetLastError -EntryPoint GetSecurityInfo),
    (New-Function advapi32 ConvertSecurityDescriptorToStringSecurityDescriptor ([Bool]) @([IntPtr], [UInt32], [UInt32], [String].MakeByRefType(), [UInt32].MakeByRefType()) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError -EntryPoint ConvertSecurityDescriptorToStringSecurityDescriptorW),
    (New-Function advapi32 ConvertStringSecurityDescriptorToSecurityDescriptor ([Bool]) @([String], [UInt32], [IntPtr].MakeByRefType(), [UInt32].MakeByRefType()) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError -EntryPoint ConvertStringSecurityDescriptorToSecurityDescriptorW),
    (New-Function advapi32 GetSidSubAuthority ([IntPtr]) @([IntPtr], [UInt32]) -SetLastError -EntryPoint GetSidSubAuthority),
    (New-Function advapi32 GetSidSubAuthorityCount ([IntPtr]) @([IntPtr]) -SetLastError -EntryPoint GetSidSubAuthorityCount),
    (New-Function advapi32 RegOpenKeyEx ([UInt32]) @([IntPtr], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError -EntryPoint RegOpenKeyExW),

    (New-Function crypt32 CryptQueryObject ([Bool]) @([UInt32], [IntPtr], [UInt32], [UInt32], [UInt32], [UInt32].MakeByRefType(), [UInt32].MakeByRefType(), [UInt32].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType()) -SetLastError -EntryPoint CryptQueryObject),
    (New-Function crypt32 CertCloseStore ([Bool]) @([IntPtr], [UInt32]) -SetLastError -EntryPoint CertCloseStore),
    (New-Function crypt32 CryptMsgClose ([Bool]) @([IntPtr]) -SetLastError -EntryPoint CryptMsgClose),
    (New-Function crypt32 CertFreeCertificateContext ([Bool]) @([IntPtr]) -SetLastError -EntryPoint CertFreeCertificateContext),
    (New-Function crypt32 CertNameToStrW ([UInt32]) @([UInt32], $script:CRYPTOAPI_BLOB.MakeByRefType(), [UInt32], [System.Text.StringBuilder], [UInt32]) -EntryPoint CertNameToStrW),
    (New-Function crypt32 CryptFindOIDInfo ([IntPtr]) @([UInt32], [String], [UInt32]) -EntryPoint CryptFindOIDInfo -Charset Ansi),
    (New-Function crypt32 CertGetCertificateContextProperty ([Bool]) @([IntPtr], [UInt32], [IntPtr], [UInt32].MakeByRefType()) -SetLastError -EntryPoint CertGetCertificateContextProperty),
    (New-Function crypt32 CertGetEnhancedKeyUsage ([Bool]) @([IntPtr], [UInt32], [IntPtr], [UInt32].MakeByRefType()) -SetLastError -EntryPoint CertGetEnhancedKeyUsage),

    (New-Function firewallapi FWOpenPolicyStore ([Void]) @([UInt32], [IntPtr], $script:FW_STORE_TYPE, $script:FW_POLICY_ACCESS_RIGHT, [UInt32], [IntPtr].MakeByRefType()) -EntryPoint FWOpenPolicyStore),
    (New-Function firewallapi FWClosePolicyStore ([UInt32]) @([IntPtr]) -EntryPoint FWClosePolicyStore),
    (New-Function firewallapi FWGetConfig2 ([Void]) @([IntPtr], $script:FW_PROFILE_CONFIG, $script:FW_PROFILE_TYPE, $script:FW_CONFIG_FLAGS, [IntPtr], [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) -EntryPoint FWGetConfig2),

    (New-Function fveapi FveOpenVolumeW ([Int32]) @([String], [Bool], [IntPtr].MakeByRefType()) -EntryPoint FveOpenVolumeW -Charset Unicode),
    (New-Function fveapi FveCloseVolume ([Int32]) @([IntPtr]) -EntryPoint FveCloseVolume),
    (New-Function fveapi FveGetStatus ([Int32]) @([IntPtr], $script:FVE_STATUS_V8.MakeByRefType()) -EntryPoint FveGetStatus -Charset None),

    (New-Function iphlpapi GetAdaptersAddresses ([UInt32]) @([UInt32], [UInt32], [IntPtr], [IntPtr], [UInt32].MakeByRefType()) -EntryPoint GetAdaptersAddresses),
    (New-Function iphlpapi GetExtendedTcpTable ([UInt32]) @([IntPtr], [UInt32].MakeByRefType(), [Bool], [UInt32], $script:TCP_TABLE_CLASS, [UInt32]) -SetLastError -EntryPoint GetExtendedTcpTable),
    (New-Function iphlpapi GetExtendedUdpTable ([UInt32]) @([IntPtr], [UInt32].MakeByRefType(), [Bool], [UInt32], $script:UDP_TABLE_CLASS , [UInt32]) -SetLastError -EntryPoint GetExtendedUdpTable),

    (New-Function kernel32 ("Create"+"File") ([IntPtr]) @([String], [UInt32], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr]) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError -EntryPoint ("Create"+"File"+"W")),
    (New-Function kernel32 ("Get"+"Current"+"Process") ([IntPtr]) @() -EntryPoint ("Get"+"Current"+"Process")),
    (New-Function kernel32 ("Open"+"Process") ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError -EntryPoint ("Open"+"Process")),
    (New-Function kernel32 ("Open"+"Thread") ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError -EntryPoint ("Open"+"Thread")),
    (New-Function kernel32 ("Get"+"Process"+"Id") ([UInt32]) @([IntPtr]) -SetLastError -EntryPoint ("Get"+"Process"+"Id")),
    (New-Function kernel32 ("Get"+"Thread"+"Id") ([UInt32]) @([IntPtr]) -SetLastError -EntryPoint ("Get"+"Thread"+"Id")),
    (New-Function kernel32 ("Duplicate"+"Handle") ([IntPtr]) @([IntPtr], [IntPtr], [IntPtr], [IntPtr].MakeByRefType(), [UInt32], [Bool], [UInt32]) -SetLastError -EntryPoint ("Duplicate"+"Handle")),
    (New-Function kernel32 ("Close"+"Handle") ([Bool]) @([IntPtr]) -SetLastError -EntryPoint ("Close"+"Handle")),
    (New-Function kernel32 ("Get"+"Firmware"+"Environment"+"Variable") ([UInt32]) @([String], [String], [IntPtr], [UInt32]) -SetLastError -EntryPoint ("Get"+"Firmware"+"Environment"+"Variable")),
    (New-Function kernel32 ("Get"+"Firmware"+"Type") ([Bool]) @([UInt32].MakeByRefType()) -SetLastError -EntryPoint ("Get"+"Firmware"+"Type")),
    (New-Function kernel32 ("Local"+"Free") ([IntPtr]) @([IntPtr]) -EntryPoint ("Local"+"Free")),
    (New-Function kernel32 ("Query"+"DosDevice") ([UInt32]) @([String], [IntPtr], [UInt32]) -SetLastError -EntryPoint ("Query"+"DosDevice"+"W")),
    (New-Function kernel32 ("Wow64"+"Disable"+"Wow64"+"Fs"+"Redirection") ([Bool]) @([IntPtr].MakeByRefType()) ([Runtime.InteropServices.CallingConvention]::Winapi) -SetLastError -EntryPoint ("Wow64"+"Disable"+"Wow64"+"Fs"+"Redirection")),
    (New-Function kernel32 ("Wow64"+"Revert"+"Wow64"+"Fs"+"Redirection") ([Bool]) @([IntPtr]) -SetLastError -EntryPoint ("Wow64"+"Revert"+"Wow64"+"Fs"+"Redirection")),
    (New-Function kernel32 ("Load"+"Library") ([IntPtr]) @([String]) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError -EntryPoint ("Load"+"Library"+"W")),
    (New-Function kernel32 ("Free"+"Library") ([Bool]) @([IntPtr]) -SetLastError -EntryPoint ("Free"+"Library")),
    (New-Function kernel32 ("Search"+"Path"+"W") ([UInt32]) @([IntPtr], [String], [String], [UInt32], [System.Text.StringBuilder], [IntPtr]) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError -EntryPoint ("Search"+"Path"+"W")),
    (New-Function kernel32 ("Get"+"Proc"+"Address") ([IntPtr]) @([IntPtr], [String]) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Ansi) -SetLastError -EntryPoint ("Get"+"Proc"+"Address")),

    (New-Function ncrypt NCryptOpenStorageProvider ([Int32]) @([UIntPtr].MakeByRefType(), [String], [UInt32]) -Charset Unicode -EntryPoint NCryptOpenStorageProvider),
    (New-Function ncrypt NCryptOpenKey ([Int32]) @([UIntPtr], [UIntPtr].MakeByRefType(), [String], [UInt32], [UInt32]) -Charset Unicode -EntryPoint NCryptOpenKey),
    (New-Function ncrypt NCryptGetProperty ([Int32]) @([UIntPtr], [String], [IntPtr], [UInt32], [UInt32].MakeByRefType(), [UInt32]) -Charset Unicode -EntryPoint NCryptGetProperty),
    (New-Function ncrypt NCryptFreeObject ([Int32]) @([UIntPtr]) -EntryPoint NCryptFreeObject),

    (New-Function netapi32 NetGetJoinInformation ([UInt32]) @([IntPtr], [IntPtr].MakeByRefType(), $script:NETSETUP_JOIN_STATUS.MakeByRefType()) -Charset Unicode -EntryPoint NetGetJoinInformation),
    (New-Function netapi32 NetGetAadJoinInformation ([Int32]) @([String], [IntPtr].MakeByRefType()) -Charset Unicode -EntryPoint NetGetAadJoinInformation),
    (New-Function netapi32 NetUserEnum ([UInt32]) @([IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType(), [UInt32], [UInt32].MakeByRefType(), [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) -EntryPoint NetUserEnum),
    (New-Function netapi32 NetApiBufferFree ([UInt32]) @([IntPtr]) -EntryPoint NetApiBufferFree),
    (New-Function netapi32 NetFreeAadJoinInformation ([Void]) @([IntPtr]) -EntryPoint NetFreeAadJoinInformation),

    (New-Function ntdll RtlNtStatusToDosError ([UInt32]) @([Int32]) -EntryPoint RtlNtStatusToDosError),
    (New-Function ntdll RtlInitUnicodeString ([IntPtr]) @($script:UNICODE_STRING.MakeByRefType(), [String]) -EntryPoint RtlInitUnicodeString),
    (New-Function ntdll NtQueryObject ([Int32]) @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -EntryPoint NtQueryObject),
    (New-Function ntdll NtOpenDirectoryObject ([Int32]) @([IntPtr].MakeByRefType(), [UInt32], $script:OBJECT_ATTRIBUTES.MakeByRefType()) -EntryPoint NtOpenDirectoryObject),
    (New-Function ntdll NtQueryDirectoryObject ([Int32]) @([IntPtr], [IntPtr], [UInt32], [Bool], [Bool], [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) -EntryPoint NtQueryDirectoryObject),
    (New-Function ntdll NtOpenSymbolicLinkObject ([Int32]) @([IntPtr].MakeByRefType(), [UInt32], $script:OBJECT_ATTRIBUTES.MakeByRefType()) -EntryPoint NtOpenSymbolicLinkObject),
    (New-Function ntdll NtQuerySymbolicLinkObject ([Int32]) @([IntPtr], $script:UNICODE_STRING.MakeByRefType(), [UInt32].MakeByRefType()) -EntryPoint NtQuerySymbolicLinkObject),
    (New-Function ntdll NtQuerySystemInformation ([Int32]) @([UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -EntryPoint NtQuerySystemInformation),
    (New-Function ntdll NtClose ([Int32]) @([IntPtr]) -EntryPoint NtClose),

    (New-Function shell32 CommandLineToArgvW ([IntPtr]) @([String], [Int32].MakeByRefType()) -SetLastError -Charset Unicode -EntryPoint CommandLineToArgvW),

    (New-Function shlwapi AssocQueryStringW ([Int32]) @($script:ASSOCF, $script:ASSOCSTR, [String], [IntPtr], [System.Text.StringBuilder], [UInt32].MakeByRefType()) -Charset Unicode -EntryPoint AssocQueryStringW),
    (New-Function shlwapi PathRelativePathTo ([Bool]) @([System.Text.StringBuilder], [String], [UInt32], [String], [UInt32]) -Charset Unicode -EntryPoint PathRelativePathToW),

    (New-Function TpmCoreProvisioning TpmGetDeviceInformation ([Int32]) @($script:TPM_DEVICE_INFORMATION.MakeByRefType()) -EntryPoint TpmGetDeviceInformation),
    (New-Function TpmCoreProvisioning TpmGetCapLockoutInfo ([Int32]) @([UInt32].MakeByRefType(), [UInt32].MakeByRefType()) -EntryPoint TpmGetCapLockoutInfo),
    (New-Function TpmCoreProvisioning TpmIsLockedOut ([Int32]) @([Byte].MakeByRefType()) -EntryPoint TpmIsLockedOut),
    (New-Function TpmCoreProvisioning TpmGetDictionaryAttackParameters ([Int32]) @([UInt32].MakeByRefType(), [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) -EntryPoint TpmGetDictionaryAttackParameters),

    (New-Function vaultcli VaultEnumerateVaults ([UInt32]) @([UInt32], [UInt32].MakeByRefType(), [IntPtr].MakeByRefType()) -EntryPoint VaultEnumerateVaults),
    (New-Function vaultcli VaultOpenVault ([UInt32]) @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) -Entrypoint VaultOpenVault),
    (New-Function vaultcli VaultEnumerateItems ([UInt32]) @([IntPtr], [UInt32], [UInt32].MakeByRefType(), [IntPtr].MakeByRefType()) -EntryPoint VaultEnumerateItems),
    (New-Function vaultcli VaultGetItem7 ([UInt32]) @([IntPtr], [Guid].MakeByRefType(), [IntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr].MakeByRefType()) -EntryPoint VaultGetItem),
    (New-Function vaultcli VaultGetItem8 ([UInt32]) @([IntPtr], [Guid].MakeByRefType(), [IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr].MakeByRefType()) -EntryPoint VaultGetItem),
    (New-Function vaultcli VaultFree ([UInt32]) @([IntPtr]) -EntryPoint VaultFree),
    (New-Function vaultcli VaultCloseVault ([UInt32]) @([IntPtr].MakeByRefType()) -EntryPoint VaultCloseVault),

    (New-Function wlanapi WlanOpenHandle ([UInt32]) @([UInt32], [IntPtr], [UInt32].MakeByRefType(), [IntPtr].MakeByRefType()) -EntryPoint WlanOpenHandle),
    (New-Function wlanapi WlanCloseHandle ([UInt32]) @([IntPtr], [IntPtr]) -EntryPoint WlanCloseHandle),
    (New-Function wlanapi WlanEnumInterfaces ([UInt32]) @([IntPtr], [IntPtr], [IntPtr].MakeByRefType()) -EntryPoint WlanEnumInterfaces),
    (New-Function wlanapi WlanFreeMemory ([Void]) @([IntPtr]) -EntryPoint WlanFreeMemory),
    (New-Function wlanapi WlanGetProfileList ([UInt32]) @([IntPtr], [Guid], [IntPtr], [IntPtr].MakeByRefType()) -EntryPoint WlanGetProfileList),
    (New-Function wlanapi WlanGetProfile ([UInt32]) @([IntPtr], [Guid], [String], [IntPtr], [String].MakeByRefType(), [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) -EntryPoint WlanGetProfile),

    (New-Function wtsapi32 WTSEnumerateSessionsEx ([Bool]) @([IntPtr], [UInt32].MakeByRefType(), [UInt32], [IntPtr].MakeByRefType(), [UInt32].MakeByRefType()) -SetLastError -EntryPoint WTSEnumerateSessionsExW),
    (New-Function wtsapi32 WTSFreeMemoryEx ([Bool]) @([UInt32], [IntPtr], [UInt32]) -SetLastError -EntryPoint WTSFreeMemoryExW)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'WinApiModule.NativeMethods'
$script:Advapi32 = $Types['advapi32']
$script:Crypt32  = $Types['crypt32']
$script:Iphlpapi = $Types['iphlpapi']
$script:FirewallApi = $Types['firewallapi']
$script:FveApi = $Types['fveapi']
$script:Kernel32 = $Types['kernel32']
$script:Ncrypt   = $Types['ncrypt']
$script:Netapi32 = $Types['netapi32']
$script:Ntdll    = $Types['ntdll']
$script:Shell32  = $Types['shell32']
$script:Shlwapi  = $Types['shlwapi']
$script:TpmCoreProvisioning = $Types['TpmCoreProvisioning']
$script:Vaultcli = $Types['vaultcli']
$script:Winspool = $Types['winspool']
$script:Wlanapi  = $Types['wlanapi']
$script:Wtsapi32 = $Types['wtsapi32']
Remove-Variable -Name "Types"
Remove-Variable -Name "FunctionDefinitions"