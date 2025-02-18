$script:SeverityLevel = New-Enum $Module WinApiModule.SeverityLevel UInt32 @{
    None                                = 0
    Low                                 = 1
    Medium                              = 2
    High                                = 3
}

$script:SystemErrorCode = New-Enum $Module WinApiModule.SystemErrorCode UInt32 @{
    ERROR_SUCCESS                       = 0
    ERROR_INVALID_FUNCTION              = 1
    ERROR_INSUFFICIENT_BUFFER           = 122
    ERROR_ENVVAR_NOT_FOUND              = 203
}

$script:FileShareMode = New-Enum $Module WinApiModule.FileShareMode UInt32 @{
    None                                = 0x00000000
    Read                                = 0x00000001
    Write                               = 0x00000002
    Delete                              = 0x00000004
} -BitField

$script:FileAccessRight = New-Enum $Module WinApiModule.FileAccessRight UInt32 @{
    ReadData                            = 0x00000001
    WriteData                           = 0x00000002
    AppendData                          = 0x00000004
    ReadExtendedAttributes              = 0x00000008
    WriteExtendedAttributes             = 0x00000010
    Execute                             = 0x00000020
    ReadAttributes                      = 0x00000080
    WriteAttributes                     = 0x00000100
    Delete                              = 0x00010000
    ReadControl                         = 0x00020000
    WriteDac                            = 0x00040000
    WriteOwner                          = 0x00080000
    Synchronize                         = 0x00100000
    AccessSystemSecurity                = 0x01000000
    AllAccess                           = 0x001f01ff
    GenericRead                         = 0x00120089 # FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_READ_EA | STANDARD_RIGHTS_READ | SYNCHRONIZE
    GenericWrite                        = 0x00120116 # FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_EA | STANDARD_RIGHTS_WRITE | SYNCHRONIZE
    GenericExecute                      = 0x001200a0 # FILE_EXECUTE | FILE_READ_ATTRIBUTES | STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE
} -BitField

$script:DirectoryAccessRight = New-Enum $Module WinApiModule.DirectoryAccessRight UInt32 @{
    ListDirectory                       = 0x00000001
    AddFile                             = 0x00000002
    AddSubdirectory                     = 0x00000004
    ReadExtendedAttributes              = 0x00000008
    WriteExtendedAttributes             = 0x00000010
    Traverse                            = 0x00000020
    DeleteChild                         = 0x00000040
    ReadAttributes                      = 0x00000080
    WriteAttributes                     = 0x00000100
    Delete                              = 0x00010000
    ReadControl                         = 0x00020000
    WriteDac                            = 0x00040000
    WriteOwner                          = 0x00080000
    Synchronize                         = 0x00100000
    AccessSystemSecurity                = 0x01000000
    AllAccess                           = 0x000f000f
    GenericRead                         = 0x00120089
    GenericWrite                        = 0x00120116
    GenericExecute                      = 0x001200a0
}

$script:RegistryKeyAccessRight = New-Enum $Module WinApiModule.RegistryKeyAccessRight UInt32 @{
    QueryValue                          = 0x00000001
    SetValue                            = 0x00000002
    CreateSubKey                        = 0x00000004
    EnumerateSubKeys                    = 0x00000008
    Notify                              = 0x00000010
    CreateLink                          = 0x00000020
    Delete                              = 0x00010000
    ReadControl                         = 0x00020000
    WriteDac                            = 0x00040000
    WriteOwner                          = 0x00080000
    AllAccess                           = 0x000f003f
    GenericRead                         = 0x00020019 # STANDARD_RIGHTS_READ | KEY_NOTIFY | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE
    GenericWrite                        = 0x00020006 # STANDARD_RIGHTS_WRITE | KEY_SET_VALUE | KEY_CREATE_SUB_KEY
}

$script:ServiceAccessRight = New-Enum $Module WinApiModule.ServiceAccessRight UInt32 @{
    QueryConfig                         = 0x00000001
    ChangeConfig                        = 0x00000002
    QueryStatus                         = 0x00000004
    EnumerateDependents                 = 0x00000008
    Start                               = 0x00000010
    Stop                                = 0x00000020
    PauseContinue                       = 0x00000040
    Interrogate                         = 0x00000080
    UserDefinedControl                  = 0x00000100
    Delete                              = 0x00010000
    ReadControl                         = 0x00020000
    WriteDac                            = 0x00040000
    WriteOwner                          = 0x00080000
    Synchronize                         = 0x00100000
    AccessSystemSecurity                = 0x01000000
    AllAccess                           = 0x000f01ff
    GenericRead                         = 0x0002008d # STANDARD_RIGHTS_READ | SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS
    GenericWrite                        = 0x00020002 # STANDARD_RIGHTS_WRITE | SERVICE_CHANGE_CONFIG
    GenericExecute                      = 0x00020170 # STANDARD_RIGHTS_EXECUTE | SERVICE_START | SERVICE_STOP | SERVICE_PAUSE_CONTINUE | SERVICE_USER_DEFINED_CONTROL
} -BitField

$script:ServiceControlManagerAccessRight = New-Enum $Module WinApiModule.ServiceControlManagerAccessRight UInt32 @{
    Connect                             = 0x00000001
    CreateService                       = 0x00000002
    EnumerateService                    = 0x00000004
    Lock                                = 0x00000008
    QueryLockStatus                     = 0x00000010
    ModifyBootConfig                    = 0x00000020
    ReadControl                         = 0x00020000
    WriteDac                            = 0x00040000
    WriteOwner                          = 0x00080000
    AllAccess                           = 0x000f003f
    GenericRead                         = 0x00020014 # STANDARD_RIGHTS_READ | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS
    GenericWrite                        = 0x00020022 # STANDARD_RIGHTS_WRITE | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_MODIFY_BOOT_CONFIG
    GenericExecute                      = 0x00020009 # STANDARD_RIGHTS_EXECUTE | SC_MANAGER_CONNECT | SC_MANAGER_LOCK
} -BitField

# Note: Cortex XDR detects the keyword 'CreateThread'. To work around this issue,
# native access right names are used for process-specific access rights.
$script:ProcessAccessRight = New-Enum $Module WinApiModule.ProcessAccessRight UInt32 @{
    TERMINATE                           = 0x00000001 # Process specific access right: TERMINATE
    CREATE_THREAD                       = 0x00000002 # Process specific access right: CREATE_THREAD
    SET_SESSIONID                       = 0x00000004 # Process specific access right: SET_SESSIONID
    VM_OPERATION                        = 0x00000008 # Process specific access right: VM_OPERATION
    VM_READ                             = 0x00000010 # Process specific access right: VM_READ
    VM_WRITE                            = 0x00000020 # Process specific access right: VM_WRITE
    DUP_HANDLE                          = 0x00000040 # Process specific access right: DUP_HANDLE
    CREATE_PROCESS                      = 0x00000080 # Process specific access right: CREATE_PROCESS
    SET_QUOTA                           = 0x00000100 # Process specific access right: SET_QUOTA
    SET_INFORMATION                     = 0x00000200 # Process specific access right: SET_INFORMATION
    QUERY_INFORMATION                   = 0x00000400 # Process specific access right: QUERY_INFORMATION
    SUSPEND_RESUME                      = 0x00000800 # Process specific access right: SUSPEND_RESUME
    QUERY_LIMITED_INFORMATION           = 0x00001000 # Process specific access right: QUERY_LIMITED_INFORMATION
    SET_LIMITED_INFORMATION             = 0x00002000 # Process specific access right: SET_LIMITED_INFORMATION
    Delete                              = 0x00010000 # Standard access right: DELETE
    ReadControl                         = 0x00020000 # Standard access right: READ_CONTROL
    WriteDac                            = 0x00040000 # Standard access right: WRITE_DAC
    WriteOwner                          = 0x00080000 # Standard access right: WRITE_OWNER
    Synchronize                         = 0x00100000 # Standard access right: SYNCHRONIZE
    AllAccess                           = 0x001fffff # STANDARD_RIGHTS_REQUIRED (0x000F0000L) | SYNCHRONIZE (0x00100000L) | 0xFFFF
} -BitField

$script:ThreadAccessRight = New-Enum $Module WinApiModule.ThreadAccessRight UInt32 @{
    Terminate                           = 0x00000001
    SuspendResume                       = 0x00000002
    GetContext                          = 0x00000008
    SetContext                          = 0x00000010
    SetInformation                      = 0x00000020
    QueryInformation                    = 0x00000040
    SetThreadToken                      = 0x00000080
    Impersonate                         = 0x00000100
    DirectImpersonation                 = 0x00000200
    SetLimitedInformation               = 0x00000400
    QueryLimitedInformation             = 0x00000800
    Delete                              = 0x00010000
    ReadControl                         = 0x00020000
    WriteDac                            = 0x00040000
    WriteOwner                          = 0x00080000
    Synchronize                         = 0x00100000
    AllAccess                           = 0x001fffff # STANDARD_RIGHTS_REQUIRED (0x000F0000L) | SYNCHRONIZE (0x00100000L) | 0xFFFF
} -BitField

$script:TokenAccessRight = New-Enum $Module WinApiModule.TokenAccessRight UInt32 @{
    AssignPrimary                       = 0x00000001
    Duplicate                           = 0x00000002
    Impersonate                         = 0x00000004
    Query                               = 0x00000008
    QuerySource                         = 0x00000010
    AdjustPrivileges                    = 0x00000020
    AdjustGroups                        = 0x00000040
    AdjustDefault                       = 0x00000080
    AdjustSessionId                     = 0x00000100
    Read                                = 0x00020008
    Write                               = 0x000200e0
    Execute                             = 0x00020000
    TrustConstraintMask                 = 0x00020018
    AccessPseudoHandle                  = 0x00000018
    AllAccessP                          = 0x000f00ff
    AllAccess                           = 0x000f01ff
} -BitField

$script:ServiceType = New-Enum $Module WinApiModule.ServiceType UInt32 @{
    KernelDriver                        = 0x00000001
    FileSystemDriver                    = 0x00000002
    Adapter                             = 0x00000004
    RecognizerDriver                    = 0x00000008
    Driver                              = 0x0000000b
    Win32OwnProcess                     = 0x00000010
    Win32ShareProcess                   = 0x00000020
    Win32                               = 0x00000030
    UserService                         = 0x00000040
    UserOwnProcess                      = 0x00000050
    UserShareProcess                    = 0x00000060
    UserServiceInstance                 = 0x00000080
    InteractiveProcess                  = 0x00000100
    PkgService                          = 0x00000200
    All                                 = 0x000003ff
} -BitField

$script:ServiceStartType = New-Enum $Module WinApiModule.ServiceStartType UInt32 @{
    Boot                                = 0
    System                              = 1
    Automatic                           = 2
    Manual                              = 3
    Disabled                            = 4
}

$script:ThreadState = New-Enum $Module WinApiModule.ThreadState UInt32 @{
    Initialized                         = 0
    Ready                               = 1
    Running                             = 2
    Standby                             = 3
    Terminated                          = 4
    Wait                                = 5
    Transition                          = 6
    Unknown                             = 7
}

$script:ServiceState = New-Enum $Module WinApiModule.ServiceState UInt32 @{
    Stopped                             = 1
    StartPending                        = 2
    StopPending                         = 3
    Running                             = 4
    ContinuePending                     = 5
    PausePending                        = 6
    Paused                              = 7
}

$script:SecurityInformation = New-Enum $Module WinApiModule.SecurityInformation Int32 @{
    Owner                               = 0x00000001
    Group                               = 0x00000002
    Dacl                                = 0x00000004
    Sacl                                = 0x00000008
    Label                               = 0x00000010
    Attribute                           = 0x00000020
    Scope                               = 0x00000040
    ProcessTrustLabel                   = 0x00000080
    AccessFilter                        = 0x00000100
    Backup                              = 0x00010000
    ProtectedDacl                       = 0x80000000
    ProtectedSacl                       = 0x40000000
    UnprotectedDacl                     = 0x20000000
    UnprotectedSacl                     = 0x10000000
} -BitField

$script:SID_NAME_USE = New-Enum $Module WinApiModule.SID_NAME_USE UInt32 @{
    User                                = 1
    Group                               = 2
    Domain                              = 3
    Alias                               = 4
    WellKnownGroup                      = 5
    DeletedAccount                      = 6
    Invalid                             = 7
    Unknown                             = 8
    Computer                            = 9
    Label                               = 10
    LogonSession                        = 11
}

$script:TOKEN_INFORMATION_CLASS = New-Enum $Module WinApiModule.TOKEN_INFORMATION_CLASS UInt32 @{
    TokenUser                           = 1
    TokenGroups                         = 2
    TokenPrivileges                     = 3
    TokenOwner                          = 4
    TokenPrimaryGroup                   = 5
    TokenDefaultDacl                    = 6
    TokenSource                         = 7
    TokenType                           = 8
    TokenImpersonationLevel             = 9
    TokenStatistics                     = 10
    TokenRestrictedSids                 = 11
    TokenSessionId                      = 12
    TokenGroupsAndPrivileges            = 13
    TokenSessionReference               = 14
    TokenSandBoxInert                   = 15
    TokenAuditPolicy                    = 16
    TokenOrigin                         = 17
    TokenElevationType                  = 18
    TokenLinkedToken                    = 19
    TokenElevation                      = 20
    TokenHasRestrictions                = 21
    TokenAccessInformation              = 22
    TokenVirtualizationAllowed          = 23
    TokenVirtualizationEnabled          = 24
    TokenIntegrityLevel                 = 25
    TokenUIAccess                       = 26
    TokenMandatoryPolicy                = 27
    TokenLogonSid                       = 28
    TokenIsAppContainer                 = 29
    TokenCapabilities                   = 30
    TokenAppContainerSid                = 31
    TokenAppContainerNumber             = 32
    TokenUserClaimAttributes            = 33
    TokenDeviceClaimAttributes          = 34
    TokenRestrictedUserClaimAttributes  = 35
    TokenRestrictedDeviceClaimAttributes = 36
    TokenDeviceGroups                   = 37
    TokenRestrictedDeviceGroups         = 38
    TokenSecurityAttributes             = 39
    TokenIsRestricted                   = 40
    TokenProcessTrustLevel              = 41
    TokenPrivateNameSpace               = 42
    TokenSingletonAttributes            = 43
    TokenBnoIsolation                   = 44
    TokenChildProcessFlags              = 45
    TokenIsLessPrivilegedAppContainer   = 46
    TokenIsSandboxed                    = 47
    TokenIsAppSilo                      = 48
    TokenLoggingInformation             = 49
    MaxTokenInfoClass                   = 50
}

$script:TOKEN_TYPE = New-Enum $Module WinApiModule.TOKEN_TYPE UInt32 @{
    TokenPrimary                        = 1
    TokenImpersonation                  = 2
}

$script:SECURITY_IMPERSONATION_LEVEL = New-Enum $Module WinApiModule.SECURITY_IMPERSONATION_LEVEL UInt32 @{
    SecurityAnonymous                   = 1
    SecurityIdentification              = 2
    SecurityImpersonation               = 3
    SecurityDelegation                  = 4
}

$script:TCP_TABLE_CLASS = New-Enum $Module WinApiModule.TCP_TABLE_CLASS UInt32 @{
    TCP_TABLE_BASIC_LISTENER            = 0
    TCP_TABLE_BASIC_CONNECTIONS         = 1
    TCP_TABLE_BASIC_ALL                 = 2
    TCP_TABLE_OWNER_PID_LISTENER        = 3
    TCP_TABLE_OWNER_PID_CONNECTIONS     = 4
    TCP_TABLE_OWNER_PID_ALL             = 5
    TCP_TABLE_OWNER_MODULE_LISTENER     = 6
    TCP_TABLE_OWNER_MODULE_CONNECTIONS  = 7
    TCP_TABLE_OWNER_MODULE_ALL          = 8
}

$script:UDP_TABLE_CLASS = New-Enum $Module WinApiModule.UDP_TABLE_CLASS UInt32 @{
    UDP_TABLE_BASIC                     = 0
    UDP_TABLE_OWNER_PID                 = 1
    UDP_TABLE_OWNER_MODULE              = 2
}

$script:WLAN_INTERFACE_STATE = New-Enum $Module WinApiModule.WLAN_INTERFACE_STATE UInt32 @{
    NotReady                            = 0
    Connected                           = 1
    AdHocNetworkFormed                  = 2
    Disconnecting                       = 3
    Disconnected                        = 4
    Associating                         = 5
    Discovering                         = 6
    Authenticating                      = 7
}

$script:ADS_USER_FLAGS = New-Enum $Module WinApiModule.ADS_USER_FLAGS UInt32 @{
    Script                              = 0x00000001
    AccountDisable                      = 0x00000002
    HomedirRequired                     = 0x00000008
    Lockout                             = 0x00000010
    PasswdNotreqd                       = 0x00000020
    PasswdCantChange                    = 0x00000040
    EncryptedTextPasswordAllowed        = 0x00000080
    TempDuplicateAccount                = 0x00000100
    NormalAccount                       = 0x00000200
    InterDomainTrustAccount             = 0x00000800
    WorkstationTrustAccount             = 0x00001000
    ServerTrustAccount                  = 0x00002000
    DontExpirePasswd                    = 0x00010000
    MnsLogonAccount                     = 0x00020000
    SmartCardRequired                   = 0x00040000
    TrustedForDelegation                = 0x00080000
    NotDelegated                        = 0x00100000
    UseDesKeyOnly                       = 0x00200000
    DontRequirePreAuth                  = 0x00400000
    PasswordExpired                     = 0x00800000
    TrustedToAuthenticateForDelegation  = 0x01000000
} -BitField

$script:GROUP_TYPE_FLAGS = New-Enum $Module WinApiModule.GROUP_TYPE_FLAGS Int32 @{
    BuiltinLocalGroup                   = 0x00000001
    AccountGroup                        = 0x00000002
    ResourceGroup                       = 0x00000004
    UniversalGroup                      = 0x00000008
    AppBasicGroup                       = 0x00000010
    AppQueryGroup                       = 0x00000020
    SecurityEnabled                     = 0x80000000
} -BitField

$script:CRED_TYPE = New-Enum $Module WinApiModule.CRED_TYPE UInt32 @{
    Generic                             = 1
    DomainPassword                      = 2
    DomainCertificate                   = 3
    DomainVisiblePassword               = 4
    GenericCertificate                  = 5
    DomainExtended                      = 6
    Maximum                             = 7
    MaximumEx                           = 0x03ef
}

$script:CRED_PERSIST = New-Enum $Module WinApiModule.CRED_PERSIST UInt32 @{
    Session                             = 1
    LocalMachine                        = 2
    Enterprise                          = 3
}

# Custom enum, does not actually exist
$script:IP_ADAPTER_FLAGS = New-Enum $Module WinApiModule.IP_ADAPTER_FLAGS UInt32 @{
    DdnsEnabled                         = 0x00000001
    RegisterAdapterSuffix               = 0x00000002
    Dhcpv4Enabled                       = 0x00000004
    ReceiveOnly                         = 0x00000008
    NoMulticast                         = 0x00000010
    Ipv6OtherStatefulConfig             = 0x00000020
    NetBiosOverTcpIpEnabled             = 0x00000040
    Ipv4Enabled                         = 0x00000080
    Ipv6Enabled                         = 0x00000100
    Ipv6ManagedAddressConfigurationSupported = 0x00000200
} -BitField

$script:WTS_CONNECTSTATE_CLASS = New-Enum $Module WinApiModule.WTS_CONNECTSTATE_CLASS UInt32 @{
    Active                              = 0
    Connected                           = 1
    ConnectQuery                        = 2
    Shadow                              = 3
    Disconnected                        = 4
    Idle                                = 5
    Listen                              = 6
    Reset                               = 7
    Down                                = 8
    Init                                = 9
}

$script:APD_FILE_COPY_FLAGS = New-Enum $Module WinApiModule.APD_FILE_COPY_FLAGS UInt32 @{
    APD_STRICT_UPGRADE                  = 0x00000001
    APD_STRICT_DOWNGRADE                = 0x00000002
    APD_COPY_ALL_FILES                  = 0x00000004
    APD_COPY_NEW_FILES                  = 0x00000008
    APD_COPY_FROM_DIRECTORY             = 0x00000010
    APD_DONT_COPY_FILES_TO_CLUSTER      = 0x00001000
    APD_COPY_TO_ALL_SPOOLERS            = 0x00002000
    APD_INSTALL_WARNED_DRIVER           = 0x00008000
    APD_RETURN_BLOCKING_STATUS_CODE     = 0x00010000
} -BitField

$script:ASSOCF = New-Enum $Module WinApiModule.ASSOCF UInt32 @{
    ASSOCF_NONE                         = 0x00000000
    ASSOCF_INIT_NOREMAPCLSID            = 0x00000001
    ASSOCF_INIT_BYEXENAME               = 0x00000002
    ASSOCF_OPEN_BYEXENAME               = 0x00000002
    ASSOCF_INIT_DEFAULTTOSTAR           = 0x00000004
    ASSOCF_INIT_DEFAULTTOFOLDER         = 0x00000008
    ASSOCF_NOUSERSETTINGS               = 0x00000010
    ASSOCF_NOTRUNCATE                   = 0x00000020
    ASSOCF_VERIFY                       = 0x00000040
    ASSOCF_REMAPRUNDLL                  = 0x00000080
    ASSOCF_NOFIXUPS                     = 0x00000100
    ASSOCF_IGNOREBASECLASS              = 0x00000200
    ASSOCF_INIT_IGNOREUNKNOWN           = 0x00000400
    ASSOCF_INIT_FIXED_PROGID            = 0x00000800
    ASSOCF_IS_PROTOCOL                  = 0x00001000
    ASSOCF_INIT_FOR_FILE                = 0x00002000
} -BitField

$script:ASSOCSTR = New-Enum $Module WinApiModule.ASSOCSTR UInt32 @{
    ASSOCSTR_COMMAND                    = 1
    ASSOCSTR_EXECUTABLE                 = 2
    ASSOCSTR_FRIENDLYDOCNAME            = 3
    ASSOCSTR_FRIENDLYAPPNAME            = 4
    ASSOCSTR_NOOPEN                     = 5
    ASSOCSTR_SHELLNEWVALUE              = 6
    ASSOCSTR_DDECOMMAND                 = 7
    ASSOCSTR_DDEIFEXEC                  = 8
    ASSOCSTR_DDEAPPLICATION             = 9
    ASSOCSTR_DDETOPIC                   = 10
    ASSOCSTR_INFOTIP                    = 11
    ASSOCSTR_QUICKTIP                   = 12
    ASSOCSTR_TILEINFO                   = 13
    ASSOCSTR_CONTENTTYPE                = 14
    ASSOCSTR_DEFAULTICON                = 15
    ASSOCSTR_SHELLEXTENSION             = 16
    ASSOCSTR_DROPTARGET                 = 17
    ASSOCSTR_DELEGATEEXECUTE            = 18
    ASSOCSTR_SUPPORTED_URI_PROTOCOLS    = 19
    ASSOCSTR_PROGID                     = 20
    ASSOCSTR_APPID                      = 21
    ASSOCSTR_APPPUBLISHER               = 22
    ASSOCSTR_APPICONREFERENCE           = 23
    ASSOCSTR_MAX                        = 24
}

# The following enum is not documented. It was crafted by reverse engineering
# the internal function 'WriteTPMDeviceInformation' of the module TpmCoreProvisioning.dll.
$script:TPM_VULNERABILITY = New-Enum $Module WinApiModule.TPM_VULNERABILITY UInt64 @{
    ADV170012_IFX_ROCA_RIEMANN                                      = 0x00000001 # ADV170012 - IFX ROCA/Riemann
    ADV190024_ECDSA_KEY_GENERATION_TPM_FAIL                         = 0x00000002 # ADV190024 - ECDSA key generation (tpm.FAIL)
    TPM2_ACTIVATE_CREDENTIAL_SPURIOUS_TPM_RC_BINDING_ERROR          = 0x00000004 # TPM2_ActivateCredential - spurious TPM_RC_BINDING error
    TPM2_GET_TEST_RESULT_TPM_ENTERS_FAILURE_MODE                    = 0x00000008 # TPM2_GetTestResult - TPM enters failure mode
    TPM2_CREATE_PRIMARY_ECC_KEY_GENERATION_TPM_ENTERS_FAILURE_MODE  = 0x00000010 # TPM2_CreatePrimary - ECC key generation - TPM enters failure mode
    NONE                                                            = 0x10000000
} -BitField

# The following enum does not really exist in the Windows API. Its purpose is
# to easily represent a TPM device type.
$script:TPM_DEVICE_TYPE = New-Enum $Module WinApiModule.TPM_DEVICE_TYPE UInt32 @{
    Discrete                            = 0x00000001
    Integrated                          = 0x00000002
    Firmware                            = 0x00000004
    Software                            = 0x00000008
    Virtual                             = 0x00000010
    Unknown                             = 0x00100000
} -BitField

$script:FIRMWARE_TYPE = New-Enum $Module WinApiModule.FIRMWARE_TYPE UInt32 @{
    Unknown                             = 0
    Bios                                = 1
    Uefi                                = 2
    Max                                 = 3
}

$script:NETSETUP_JOIN_STATUS = New-Enum $Module WinApiModule.NETSETUP_JOIN_STATUS UInt32 @{
    NetSetupUnknownStatus               = 0
    NetSetupUnjoined                    = 1
    NetSetupWorkgroupName               = 2
    NetSetupDomainName                  = 3
}

$script:DSREG_JOIN_TYPE = New-Enum $Module WinApiModule.DSREG_JOIN_TYPE UInt32 @{
    DSREG_UNKNOWN_JOIN                  = 0
    DSREG_DEVICE_JOIN                   = 1
    DSREG_WORKPLACE_JOIN                = 2
}

$script:FW_STORE_TYPE = New-Enum $Module WinApiModule.FW_STORE_TYPE UInt32 @{
    INVALID                             = 0
    GP_RSOP                             = 1
    LOCAL                               = 2
    NOT_USED_VALUE_3                    = 3
    NOT_USED_VALUE_4                    = 4
    DYNAMIC                             = 5
    GPO                                 = 6
    DEFAULTS                            = 7
    NOT_USED_VALUE_8                    = 8
    NOT_USED_VALUE_9                    = 9
    NOT_USED_VALUE_10                   = 10
    NOT_USED_VALUE_11                   = 11
    MAX                                 = 12
}

$script:FW_POLICY_ACCESS_RIGHT = New-Enum $Module WinApiModule.FW_POLICY_ACCESS_RIGHT UInt32 @{
    INVALID                             = 0
    READ                                = 1
    READ_WRITE                          = 2
    MAX                                 = 3
}

$script:FW_PROFILE_CONFIG = New-Enum $Module WinApiModule.FW_PROFILE_CONFIG UInt32 @{
    INVALID                             = 0
    ENABLE_FW                           = 1
    DISABLE_STEALTH_MODE                = 2
    SHIELDED                            = 3
    DISABLE_UNICAST_RESPONSES_TO_MULTICAST_BROADCAST = 4
    LOG_DROPPED_PACKETS                 = 5
    LOG_SUCCESS_CONNECTIONS             = 6
    LOG_IGNORED_RULES                   = 7
    LOG_MAX_FILE_SIZE                   = 8
    LOG_FILE_PATH                       = 9
    DISABLE_INBOUND_NOTIFICATIONS       = 10
    AUTH_APPS_ALLOW_USER_PREF_MERGE     = 11
    GLOBAL_PORTS_ALLOW_USER_PREF_MERGE  = 12
    ALLOW_LOCAL_POLICY_MERGE            = 13
    ALLOW_LOCAL_IPSEC_POLICY_MERGE      = 14
    DISABLED_INTERFACES                 = 15
    DEFAULT_OUTBOUND_ACTION             = 16
    DEFAULT_INBOUND_ACTION              = 17
    DISABLE_STEALTH_MODE_IPSEC_SECURED_PACKET_EXEMPTION = 18
    MAX                                 = 19
}

$script:FW_PROFILE_TYPE = New-Enum $Module WinApiModule.FW_PROFILE_TYPE Int32 @{
    Invalid                             = 0x00000000
    Domain                              = 0x00000001
    Private                             = 0x00000002
    Public                              = 0x00000004
    All                                 = 0x7fffffff
    Current                             = 0x80000000
    None                                = 0x80000001
}

$script:FW_CONFIG_FLAGS = New-Enum $Module WinApiModule.FW_CONFIG_FLAGS UInt32 @{
    RETURN_DEFAULT_IF_NOT_FOUND         = 0x00000001
} -BitField

$script:FW_RULE_ORIGIN_TYPE = New-Enum $Module WinApiModule.FW_RULE_ORIGIN_TYPE UInt32 @{
    INVALID                             = 0
    LOCAL                               = 1
    GP                                  = 2
    DYNAMIC                             = 3
    AUTOGEN                             = 4
    HARDCODED                           = 5
    MDM                                 = 6
    MAX                                 = 7
    HOST_LOCAL                          = 8
    HOST_GP                             = 9
    HOST_DYNAMIC                        = 10
    HOST_MDM                            = 11
    HOST_MAX                            = 12
}

$script:USER_PRIV = New-Enum $Module WinApiModule.USER_PRIV UInt32 @{
    USER_PRIV_GUEST                     = 0
    USER_PRIV_USER                      = 1
    USER_PRIV_ADMIN                     = 2
}

$script:USER_FLAGS = New-Enum $Module WinApiModule.USER_FLAGS UInt32 @{
    UF_SCRIPT                           = 0x00000001
    UF_ACCOUNTDISABLE                   = 0x00000002
    UF_HOMEDIR_REQUIRED                 = 0x00000008
    UF_LOCKOUT                          = 0x00000010
    UF_PASSWD_NOTREQD                   = 0x00000020
    UF_PASSWD_CANT_CHANGE               = 0x00000040
    UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED  = 0x00000080
    UF_TEMP_DUPLICATE_ACCOUNT           = 0x00000100
    UF_NORMAL_ACCOUNT                   = 0x00000200
    UF_INTERDOMAIN_TRUST_ACCOUNT        = 0x00000800
    UF_WORKSTATION_TRUST_ACCOUNT        = 0x00001000
    UF_SERVER_TRUST_ACCOUNT             = 0x00002000
    UF_DONT_EXPIRE_PASSWD               = 0x00010000
    UF_MNS_LOGON_ACCOUNT                = 0x00020000
    UF_SMARTCARD_REQUIRED               = 0x00040000
    UF_TRUSTED_FOR_DELEGATION           = 0x00080000
    UF_NOT_DELEGATED                    = 0x00100000
    UF_USE_DES_KEY_ONLY                 = 0x00200000
    UF_DONT_REQUIRE_PREAUTH             = 0x00400000
    UF_PASSWORD_EXPIRED                 = 0x00800000
    UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x01000000
    UF_NO_AUTH_DATA_REQUIRED            = 0x02000000
    UF_PARTIAL_SECRETS_ACCOUNT          = 0x04000000
    UF_USE_AES_KEYS                     = 0x08000000
} -BitField

$script:USER_AUTH_FLAGS = New-Enum $Module WinApiModule.USER_AUTH_FLAGS UInt32 @{
    AF_OP_PRINT                         = 0x00000001
    AF_OP_COMM                          = 0x00000002
    AF_OP_SERVER                        = 0x00000004
    AF_OP_ACCOUNTS                      = 0x00000008
} -BitField

$script:SE_OBJECT_TYPE = New-Enum $Module WinApiModule.SE_OBJECT_TYPE UInt32 @{
    SE_UNKNOWN_OBJECT_TYPE              = 0
    SE_FILE_OBJECT                      = 1
    SE_SERVICE                          = 2
    SE_PRINTER                          = 3
    SE_REGISTRY_KEY                     = 4
    SE_LMSHARE                          = 5
    SE_KERNEL_OBJECT                    = 6
    SE_WINDOW_OBJECT                    = 7
    SE_DS_OBJECT                        = 8
    SE_DS_OBJECT_ALL                    = 9
    SE_PROVIDER_DEFINED_OBJECT          = 10
    SE_WMIGUID_OBJECT                   = 11
    SE_REGISTRY_WOW64_32KEY             = 12
    SE_REGISTRY_WOW64_64KEY             = 13
}