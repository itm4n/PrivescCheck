$script:SeverityLevelEnum = New-Enum $Module WinApiModule.SeverityLevel UInt32 @{
    None                                = '0x00000000'
    Low                                 = '0x00000001'
    Medium                              = '0x00000002'
    High                                = '0x00000003'
}

$script:SystemErrorCodeEnum = New-Enum $Module WinApiModule.SystemErrorCode UInt32 @{
    ERROR_INSUFFICIENT_BUFFER           = 122
}

$script:FileAccessRightEnum = New-Enum $Module WinApiModule.FileAccessRight UInt32 @{
    # GenericRead                       = '0x80000000'
    # GenericWrite                      = '0x40000000'
    # GenericExecute                    = '0x20000000'
    # GenericAll                        = '0x10000000'
    MaximumAllowed                      = '0x02000000'
    AccessSystemSecurity                = '0x01000000'
    Synchronize                         = '0x00100000'
    WriteOwner                          = '0x00080000'
    WriteDac                            = '0x00040000'
    ReadControl                         = '0x00020000'
    Delete                              = '0x00010000'
    WriteAttributes                     = '0x00000100'
    ReadAttributes                      = '0x00000080'
    DeleteChild                         = '0x00000040'
    Execute                             = '0x00000020'
    WriteExtendedAttributes             = '0x00000010'
    ReadExtendedAttributes              = '0x00000008'
    AppendData                          = '0x00000004'
    WriteData                           = '0x00000002'
    ReadData                            = '0x00000001'
} -BitField

$script:ServiceAccessRightEnum = New-Enum $Module WinApiModule.ServiceAccessRight UInt32 @{
    QueryConfig                         = '0x00000001'
    ChangeConfig                        = '0x00000002'
    QueryStatus                         = '0x00000004'
    EnumerateDependents                 = '0x00000008'
    Start                               = '0x00000010'
    Stop                                = '0x00000020'
    PauseContinue                       = '0x00000040'
    Interrogate                         = '0x00000080'
    UserDefinedControl                  = '0x00000100'
    Delete                              = '0x00010000'
    ReadControl                         = '0x00020000'
    WriteDac                            = '0x00040000'
    WriteOwner                          = '0x00080000'
    Synchronize                         = '0x00100000'
    AccessSystemSecurity                = '0x01000000'
    GenericAll                          = '0x10000000'
    GenericExecute                      = '0x20000000'
    GenericWrite                        = '0x40000000'
    GenericRead                         = '0x80000000'
    AllAccess                           = '0x000F01FF'
} -BitField

$script:ServiceControlManagerAccessRightEnum = New-Enum $Module WinApiModule.ServiceControlManagerAccessRight UInt32 @{
    Connect                             = '0x00000001'
    CreateService                       = '0x00000002'
    EnumerateService                    = '0x00000004'
    Lock                                = '0x00000008'
    QueryLockStatus                     = '0x00000010'
    ModifyBootConfig                    = '0x00000020'
    AllAccess                           = '0x000f003f'
    GenericRead                         = '0x00020014' # STANDARD_RIGHTS_READ | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS
    GenericWrite                        = '0x00020022' # STANDARD_RIGHTS_WRITE | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_MODIFY_BOOT_CONFIG
    GenericExecute                      = '0x00020009' # STANDARD_RIGHTS_EXECUTE | SC_MANAGER_CONNECT | SC_MANAGER_LOCK
} -BitField

$script:ProcessAccessRightEnum = New-Enum $Module WinApiModule.ProcessAccessRight UInt32 @{
    TERMINATE                           = '0x00000001'
    CREATE_THREAD                       = '0x00000002'
    SET_SESSIONID                       = '0x00000004'
    VM_OPERATION                        = '0x00000008'
    VM_READ                             = '0x00000010'
    VM_WRITE                            = '0x00000020'
    DUP_HANDLE                          = '0x00000040'
    CREATE_PROCESS                      = '0x00000080'
    SET_QUOTA                           = '0x00000100'
    SET_INFORMATION                     = '0x00000200'
    QUERY_INFORMATION                   = '0x00000400'
    SUSPEND_RESUME                      = '0x00000800'
    QUERY_LIMITED_INFORMATION           = '0x00001000'
    SET_LIMITED_INFORMATION             = '0x00002000'
    ALL_ACCESS                          = '0x001FFFFF' # STANDARD_RIGHTS_REQUIRED (0x000F0000L) | SYNCHRONIZE (0x00100000L) | 0xFFFF
    SYNCHRONIZE                         = '0x00100000'
} -BitField

$script:ThreadAccessRightEnum = New-Enum $Module WinApiModule.ThreadAccessRight UInt32 @{
    Terminate                           = '0x00000001'
    SuspendResume                       = '0x00000002'
    GetContext                          = '0x00000008'
    SetContext                          = '0x00000010'
    SetInformation                      = '0x00000020'
    QueryInformation                    = '0x00000040'
    SetThreadToken                      = '0x00000080'
    Impersonate                         = '0x00000100'
    DirectImpersonation                 = '0x00000200'
    SetLimitedInformation               = '0x00000400'
    QueryLimitedInformation             = '0x00000800'
    Delete                              = '0x00010000'
    ReadControl                         = '0x00020000'
    WriteDac                            = '0x00040000'
    WriteOwner                          = '0x00080000'
    Synchronize                         = '0x00100000'
    AllAccess                           = '0x001FFFFF' # STANDARD_RIGHTS_REQUIRED (0x000F0000L) | SYNCHRONIZE (0x00100000L) | 0xFFFF
} -BitField

$script:TokenAccessRightEnum = New-Enum $Module WinApiModule.TokenAccessRight UInt32 @{
    AssignPrimary                       = '0x00000001'
    Duplicate                           = '0x00000002'
    Impersonate                         = '0x00000004'
    Query                               = '0x00000008'
    QuerySource                         = '0x00000010'
    AdjustPrivileges                    = '0x00000020'
    AdjustGroups                        = '0x00000040'
    AdjustDefault                       = '0x00000080'
    AdjustSessionId                     = '0x00000100'
    Read                                = '0x00020008'
    Write                               = '0x000200e0'
    Execute                             = '0x00020000'
    TrustConstraintMask                 = '0x00020018'
    AccessPseudoHandle                  = '0x00000018'
    AllAccessP                          = '0x000f00ff'
    AllAccess                           = '0x000f01ff'
} -BitField

$script:ServiceTypeEnum = New-Enum $Module WinApiModule.ServiceType UInt32 @{
    KernelDriver                        = '0x00000001'
    FileSystemDriver                    = '0x00000002'
    Adapter                             = '0x00000004'
    RecognizerDriver                    = '0x00000008'
    Driver                              = '0x0000000b'
    Win32OwnProcess                     = '0x00000010'
    Win32ShareProcess                   = '0x00000020'
    Win32                               = '0x00000030'
    UserService                         = '0x00000040'
    UserOwnProcess                      = '0x00000050'
    UserShareProcess                    = '0x00000060'
    UserServiceInstance                 = '0x00000080'
    InteractiveProcess                  = '0x00000100'
    PkgService                          = '0x00000200'
    All                                 = '0x000003ff'
} -BitField

$script:ServiceStartTypeEnum = New-Enum $Module WinApiModule.ServiceStartType UInt32 @{
    Boot                                = '0x00000000'
    System                              = '0x00000001'
    Automatic                           = '0x00000002'
    Manual                              = '0x00000003'
    Disabled                            = '0x00000004'
}

$script:SID_NAME_USE = New-Enum $Module WinApiModule.SID_NAME_USE UInt32 @{
    User                                = '0x00000001'
    Group                               = '0x00000002'
    Domain                              = '0x00000003'
    Alias                               = '0x00000004'
    WellKnownGroup                      = '0x00000005'
    DeletedAccount                      = '0x00000006'
    Invalid                             = '0x00000007'
    Unknown                             = '0x00000008'
    Computer                            = '0x00000009'
    Label                               = '0x0000000A'
    LogonSession                        = '0x0000000B'
}

$script:TOKEN_INFORMATION_CLASS = New-Enum $Module WinApiModule.TOKEN_INFORMATION_CLASS UInt32 @{
    TokenUser                           = '0x00000001'
    TokenGroups                         = '0x00000002'
    TokenPrivileges                     = '0x00000003'
    TokenOwner                          = '0x00000004'
    TokenPrimaryGroup                   = '0x00000005'
    TokenDefaultDacl                    = '0x00000006'
    TokenSource                         = '0x00000007'
    TokenType                           = '0x00000008'
    TokenImpersonationLevel             = '0x00000009'
    TokenStatistics                     = '0x0000000A'
    TokenRestrictedSids                 = '0x0000000B'
    TokenSessionId                      = '0x0000000C'
    TokenGroupsAndPrivileges            = '0x0000000D'
    TokenSessionReference               = '0x0000000E'
    TokenSandBoxInert                   = '0x0000000F'
    TokenAuditPolicy                    = '0x00000010'
    TokenOrigin                         = '0x00000011'
    TokenElevationType                  = '0x00000012'
    TokenLinkedToken                    = '0x00000013'
    TokenElevation                      = '0x00000014'
    TokenHasRestrictions                = '0x00000015'
    TokenAccessInformation              = '0x00000016'
    TokenVirtualizationAllowed          = '0x00000017'
    TokenVirtualizationEnabled          = '0x00000018'
    TokenIntegrityLevel                 = '0x00000019'
    TokenUIAccess                       = '0x0000001A'
    TokenMandatoryPolicy                = '0x0000001B'
    TokenLogonSid                       = '0x0000001C'
    TokenIsAppContainer                 = '0x0000001D'
    TokenCapabilities                   = '0x0000001F'
    TokenAppContainerSid                = '0x00000020'
    TokenAppContainerNumber             = '0x00000021'
    TokenUserClaimAttributes            = '0x00000022'
    TokenDeviceClaimAttributes          = '0x00000023'
    TokenRestrictedUserClaimAttributes  = '0x00000024'
    TokenRestrictedDeviceClaimAttributes = '0x00000025'
    TokenDeviceGroups                   = '0x00000026'
    TokenRestrictedDeviceGroups         = '0x00000027'
    TokenSecurityAttributes             = '0x00000028'
    TokenIsRestricted                   = '0x00000029'
    TokenProcessTrustLevel              = '0x0000002A'
    TokenPrivateNameSpace               = '0x0000002B'
    TokenSingletonAttributes            = '0x0000002C'
    TokenBnoIsolation                   = '0x0000002D'
    TokenChildProcessFlags              = '0x0000002E'
    TokenIsLessPrivilegedAppContainer   = '0x0000002F'
    TokenIsSandboxed                    = '0x00000030'
    TokenOriginatingProcessTrustLevel   = '0x00000031'
    MaxTokenInfoClass                   = '0x00000032'
}

$script:TOKEN_TYPE = New-Enum $Module WinApiModule.TOKEN_TYPE UInt32 @{
    TokenPrimary                        = '0x00000001'
    TokenImpersonation                  = '0x00000002'
}

$script:SECURITY_IMPERSONATION_LEVEL = New-Enum $Module WinApiModule.SECURITY_IMPERSONATION_LEVEL UInt32 @{
    SecurityAnonymous                   = '0x00000001'
    SecurityIdentification              = '0x00000002'
    SecurityImpersonation               = '0x00000003'
    SecurityDelegation                  = '0x00000004'
}

$script:TCP_TABLE_CLASS = New-Enum $Module WinApiModule.TCP_TABLE_CLASS UInt32 @{
    TCP_TABLE_BASIC_LISTENER            = '0x00000000'
    TCP_TABLE_BASIC_CONNECTIONS         = '0x00000001'
    TCP_TABLE_BASIC_ALL                 = '0x00000002'
    TCP_TABLE_OWNER_PID_LISTENER        = '0x00000003'
    TCP_TABLE_OWNER_PID_CONNECTIONS     = '0x00000004'
    TCP_TABLE_OWNER_PID_ALL             = '0x00000005'
    TCP_TABLE_OWNER_MODULE_LISTENER     = '0x00000006'
    TCP_TABLE_OWNER_MODULE_CONNECTIONS  = '0x00000007'
    TCP_TABLE_OWNER_MODULE_ALL          = '0x00000008'
}

$script:UDP_TABLE_CLASS = New-Enum $Module WinApiModule.UDP_TABLE_CLASS UInt32 @{
    UDP_TABLE_BASIC                     = '0x00000000'
    UDP_TABLE_OWNER_PID                 = '0x00000001'
    UDP_TABLE_OWNER_MODULE              = '0x00000002'
}

$script:WLAN_INTERFACE_STATE = New-Enum $Module WinApiModule.WLAN_INTERFACE_STATE UInt32 @{
    NotReady                            = '0x00000000'
    Connected                           = '0x00000001'
    AdHocNetworkFormed                  = '0x00000002'
    Disconnecting                       = '0x00000003'
    Disconnected                        = '0x00000004'
    Associating                         = '0x00000005'
    Discovering                         = '0x00000006'
    Authenticating                      = '0x00000007'
}

$script:ADS_USER_FLAGS = New-Enum $Module WinApiModule.ADS_USER_FLAGS UInt32 @{
    Script                              = '0x00000001'
    AccountDisable                      = '0x00000002'
    HomedirRequired                     = '0x00000008'
    Lockout                             = '0x00000010'
    PasswdNotreqd                       = '0x00000020'
    PasswdCantChange                    = '0x00000040'
    EncryptedTextPasswordAllowed        = '0x00000080'
    TempDuplicateAccount                = '0x00000100'
    NormalAccount                       = '0x00000200'
    InterDomainTrustAccount             = '0x00000800'
    WorkstationTrustAccount             = '0x00001000'
    ServerTrustAccount                  = '0x00002000'
    DontExpirePasswd                    = '0x00010000'
    MnsLogonAccount                     = '0x00020000'
    SmartCardRequired                   = '0x00040000'
    TrustedForDelegation                = '0x00080000'
    NotDelegated                        = '0x00100000'
    UseDesKeyOnly                       = '0x00200000'
    DontRequirePreAuth                  = '0x00400000'
    PasswordExpired                     = '0x00800000'
    TrustedToAuthenticateForDelegation  = '0x01000000'
} -BitField

$script:GROUP_TYPE_FLAGS = New-Enum $Module WinApiModule.GROUP_TYPE_FLAGS UInt32 @{
    BuiltinLocalGroup                   = '0x00000001'
    AccountGroup                        = '0x00000002'
    ResourceGroup                       = '0x00000004'
    UniversalGroup                      = '0x00000008'
    AppBasicGroup                       = '0x00000010'
    AppQueryGroup                       = '0x00000020'
    SecurityEnabled                     = '0x80000000'
} -BitField

$script:CRED_TYPE = New-Enum $Module WinApiModule.CRED_TYPE UInt32 @{
    Generic                             = '0x00000001'
    DomainPassword                      = '0x00000002'
    DomainCertificate                   = '0x00000003'
    DomainVisiblePassword               = '0x00000004'
    GenericCertificate                  = '0x00000005'
    DomainExtended                      = '0x00000006'
    Maximum                             = '0x00000007'
    MaximumEx                           = '0x000003ef'
}

$script:CRED_PERSIST = New-Enum $Module WinApiModule.CRED_PERSIST UInt32 @{
    Session                             = '0x00000001'
    LocalMachine                        = '0x00000002'
    Enterprise                          = '0x00000003'
}

# Custom enum, does not actually exist
$script:IP_ADAPTER_FLAGS = New-Enum $Module WinApiModule.IP_ADAPTER_FLAGS UInt32 @{
    DdnsEnabled                         = '0x00000001'
    RegisterAdapterSuffix               = '0x00000002'
    Dhcpv4Enabled                       = '0x00000004'
    ReceiveOnly                         = '0x00000008'
    NoMulticast                         = '0x00000010'
    Ipv6OtherStatefulConfig             = '0x00000020'
    NetBiosOverTcpIpEnabled             = '0x00000040'
    Ipv4Enabled                         = '0x00000080'
    Ipv6Enabled                         = '0x00000100'
    Ipv6ManagedAddressConfigurationSupported = '0x00000200'
} -BitField

$script:WTS_CONNECTSTATE_CLASS = New-Enum $Module WinApiModule.WTS_CONNECTSTATE_CLASS UInt32 @{
    Active                              = '0x00000000'
    Connected                           = '0x00000001'
    ConnectQuery                        = '0x00000002'
    Shadow                              = '0x00000003'
    Disconnected                        = '0x00000004'
    Idle                                = '0x00000005'
    Listen                              = '0x00000006'
    Reset                               = '0x00000007'
    Down                                = '0x00000008'
    Init                                = '0x00000009'
}

$script:APD_FILE_COPY_FLAGS = New-Enum $Module WinApiModule.APD_FILE_COPY_FLAGS UInt32 @{
    APD_STRICT_UPGRADE                  = '0x00000001'
    APD_STRICT_DOWNGRADE                = '0x00000002'
    APD_COPY_ALL_FILES                  = '0x00000004'
    APD_COPY_NEW_FILES                  = '0x00000008'
    APD_COPY_FROM_DIRECTORY             = '0x00000010'
    APD_DONT_COPY_FILES_TO_CLUSTER      = '0x00001000'
    APD_COPY_TO_ALL_SPOOLERS            = '0x00002000'
    APD_INSTALL_WARNED_DRIVER           = '0x00008000'
    APD_RETURN_BLOCKING_STATUS_CODE     = '0x00010000'
} -BitField

$script:ASSOCF = New-Enum $Module WinApiModule.ASSOCF UInt32 @{
    ASSOCF_NONE                         = '0x00000000'
    ASSOCF_INIT_NOREMAPCLSID            = '0x00000001'
    ASSOCF_INIT_BYEXENAME               = '0x00000002'
    ASSOCF_OPEN_BYEXENAME               = '0x00000002'
    ASSOCF_INIT_DEFAULTTOSTAR           = '0x00000004'
    ASSOCF_INIT_DEFAULTTOFOLDER         = '0x00000008'
    ASSOCF_NOUSERSETTINGS               = '0x00000010'
    ASSOCF_NOTRUNCATE                   = '0x00000020'
    ASSOCF_VERIFY                       = '0x00000040'
    ASSOCF_REMAPRUNDLL                  = '0x00000080'
    ASSOCF_NOFIXUPS                     = '0x00000100'
    ASSOCF_IGNOREBASECLASS              = '0x00000200'
    ASSOCF_INIT_IGNOREUNKNOWN           = '0x00000400'
    ASSOCF_INIT_FIXED_PROGID            = '0x00000800'
    ASSOCF_IS_PROTOCOL                  = '0x00001000'
    ASSOCF_INIT_FOR_FILE                = '0x00002000'
} -BitField

$script:ASSOCSTR = New-Enum $Module WinApiModule.ASSOCSTR UInt32 @{
    ASSOCSTR_COMMAND                    = '0x00000001'
    ASSOCSTR_EXECUTABLE                 = '0x00000002'
    ASSOCSTR_FRIENDLYDOCNAME            = '0x00000003'
    ASSOCSTR_FRIENDLYAPPNAME            = '0x00000004'
    ASSOCSTR_NOOPEN                     = '0x00000005'
    ASSOCSTR_SHELLNEWVALUE              = '0x00000006'
    ASSOCSTR_DDECOMMAND                 = '0x00000007'
    ASSOCSTR_DDEIFEXEC                  = '0x00000008'
    ASSOCSTR_DDEAPPLICATION             = '0x00000009'
    ASSOCSTR_DDETOPIC                   = '0x0000000A'
    ASSOCSTR_INFOTIP                    = '0x0000000B'
    ASSOCSTR_QUICKTIP                   = '0x0000000C'
    ASSOCSTR_TILEINFO                   = '0x0000000D'
    ASSOCSTR_CONTENTTYPE                = '0x0000000E'
    ASSOCSTR_DEFAULTICON                = '0x0000000F'
    ASSOCSTR_SHELLEXTENSION             = '0x00000010'
    ASSOCSTR_DROPTARGET                 = '0x00000011'
    ASSOCSTR_DELEGATEEXECUTE            = '0x00000012'
    ASSOCSTR_SUPPORTED_URI_PROTOCOLS    = '0x00000013'
    ASSOCSTR_PROGID                     = '0x00000014'
    ASSOCSTR_APPID                      = '0x00000015'
    ASSOCSTR_APPPUBLISHER               = '0x00000016'
    ASSOCSTR_APPICONREFERENCE           = '0x00000017'
    ASSOCSTR_MAX                        = '0x00000018'
}