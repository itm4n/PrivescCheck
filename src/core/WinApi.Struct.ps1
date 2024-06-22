$script:LARGE_INTEGER = New-Structure $Module WinApiModule.LARGE_INTEGER @{
    LowPart                     = New-StructureField 0 UInt32
    HighPart                    = New-StructureField 1 Int32
}

$script:LUID = New-Structure $Module WinApiModule.LUID @{
    LowPart                     = New-StructureField 0 UInt32
    HighPart                    = New-StructureField 1 Int32
}

$script:SID_AND_ATTRIBUTES = New-Structure $Module WinApiModule.SID_AND_ATTRIBUTES @{
    Sid                         = New-StructureField 0 IntPtr
    Attributes                  = New-StructureField 1 UInt32
}

$script:LUID_AND_ATTRIBUTES = New-Structure $Module WinApiModule.LUID_AND_ATTRIBUTES @{
    Luid                        = New-StructureField 0 $script:LUID
    Attributes                  = New-StructureField 1 UInt32
}

$script:TOKEN_USER = New-Structure $Module WinApiModule.TOKEN_USER @{
    User                        = New-StructureField 0 $script:SID_AND_ATTRIBUTES
}

$script:TOKEN_GROUPS = New-Structure $Module WinApiModule.TOKEN_GROUPS @{
    GroupCount                  = New-StructureField 0 UInt32
    Groups                      = New-StructureField 1 $script:SID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 1)
}

$script:TOKEN_PRIVILEGES = New-Structure $Module WinApiModule.TOKEN_PRIVILEGES @{
    PrivilegeCount              = New-StructureField 0 UInt32
    Privileges                  = New-StructureField 1 $script:LUID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 1)
}

$script:TOKEN_MANDATORY_LABEL = New-Structure $Module WinApiModule.TOKEN_MANDATORY_LABEL @{
    Label                       = New-StructureField 0 $script:SID_AND_ATTRIBUTES
}

$script:TOKEN_STATISTICS = New-Structure $Module WinApiModule.TOKEN_STATISTICS @{
    TokenId                     = New-StructureField 0 $script:LUID
    AuthenticationId            = New-StructureField 1 $script:LUID
    ExpirationTime              = New-StructureField 2 $script:LARGE_INTEGER
    TokenType                   = New-StructureField 3 $script:TOKEN_TYPE
    ImpersonationLevel          = New-StructureField 4 $script:SECURITY_IMPERSONATION_LEVEL
    DynamicCharged              = New-StructureField 5 UInt32
    DynamicAvailable            = New-StructureField 6 UInt32
    GroupCount                  = New-StructureField 7 UInt32
    PrivilegeCount              = New-StructureField 8 UInt32
    ModifiedId                  = New-StructureField 9 $script:LUID
}

$script:TOKEN_ORIGIN = New-Structure $Module WinApiModule.TOKEN_ORIGIN @{
    OriginatingLogonSession     = New-StructureField 0 $script:LUID
}

$script:TOKEN_SOURCE = New-Structure $Module WinApiModule.TOKEN_SOURCE @{
    SourceName                  = New-StructureField 0 Byte[] -MarshalAs @('ByValArray', 8)
    SourceIdentifier            = New-StructureField 1 $script:LUID
}

$script:SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX = New-Structure $Module WinApiModule.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX @{
    Object                      = New-StructureField 0 IntPtr
    UniqueProcessId             = New-StructureField 1 IntPtr
    HandleValue                 = New-StructureField 2 IntPtr
    GrantedAccess               = New-StructureField 3 UInt32
    CreatorBackTraceIndex       = New-StructureField 4 UInt16
    ObjectTypeIndex             = New-StructureField 5 UInt16
    HandleAttributes            = New-StructureField 6 UInt32
    Reserved                    = New-StructureField 7 UInt32
}

$script:SYSTEM_HANDLE_INFORMATION_EX = New-Structure $Module WinApiModule.SYSTEM_HANDLE_INFORMATION_EX @{
    NumberOfHandles             = New-StructureField 0 IntPtr
    Reserved                    = New-StructureField 1 IntPtr
    Handles                     = New-StructureField 2 $script:SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX.MakeArrayType() -MarshalAs @('ByValArray', 1)
}

$script:PPROCESS_BASIC_INFORMATION = New-Structure $Module WinApiModule.PPROCESS_BASIC_INFORMATION @{
    ExitStatus                  = New-StructureField 0 Int32
    PebBaseAddress              = New-StructureField 1 IntPtr
    AffinityMask                = New-StructureField 2 IntPtr
    BasePriority                = New-StructureField 3 Int32
    UniqueProcessId             = New-StructureField 4 IntPtr
    InheritedFromUniqueProcessId = New-StructureField 5 IntPtr
}

# $PROCESSENTRY32 = New-Structure $Module WinApiModule.PROCESSENTRY32 @{
#     Size                        = New-StructureField 0 UInt32
#     Usage                       = New-StructureField 1 UInt32
#     ProcessId                   = New-StructureField 2 UInt32
#     DefaultHeapId               = New-StructureField 3 IntPtr
#     ModuleId                    = New-StructureField 4 UInt32
#     Threads                     = New-StructureField 5 UInt32
#     ParentProcessId             = New-StructureField 6 UInt32
#     PriClassBase                = New-StructureField 7 Int32
#     Flags                       = New-StructureField 8 UInt32
#     ExeFile                     = New-StructureField 9 Char[] -MarshalAs @('ByValArray', 260)
# } -Charset Unicode

# $THREADENTRY32 = New-Structure $Module WinApiModule.THREADENTRY32 @{
#     Size                        = New-StructureField 0 UInt32
#     Usage                       = New-StructureField 1 UInt32
#     ThreadId                    = New-StructureField 2 UInt32
#     OwnerProcessId              = New-StructureField 3 UInt32
#     BasePri                     = New-StructureField 4 Int32
#     DeltaPri                    = New-StructureField 5 Int32
#     Flags                       = New-StructureField 6 UInt32
# }

$script:IN6_ADDR = New-Structure $Module WinApiModule.IN6_ADDR @{
    Addr                        = New-StructureField 0 Byte[] -MarshalAs @('ByValArray', 16)
}

$script:SOCKADDR = New-Structure $Module WinApiModule.SOCKADDR @{
    Family                      = New-StructureField 0 UInt16
    Data                        = New-StructureField 1 Byte[] -MarshalAs @('ByValArray', 14)
}

$script:SOCKADDR_IN6 = New-Structure $Module WinApiModule.SOCKADDR_IN6 @{
    Family                      = New-StructureField 0 Int16
    Port                        = New-StructureField 1 UInt16
    lowInfo                     = New-StructureField 2 UInt32
    Addr                        = New-StructureField 3 $script:IN6_ADDR
    ScopeId                     = New-StructureField 4 UInt32
}

$script:SOCKET_ADDRESS = New-Structure $Module WinApiModule.SOCKET_ADDRESS @{
    Sockaddr                    = New-StructureField 0 IntPtr # LPSOCKADDR -> SOCKADDR or SOCKADDR_IN6
    SockaddrLength              = New-StructureField 1 Int32
}

$script:IP_ADAPTER_UNICAST_ADDRESS_LH = New-Structure $Module WinApiModule.IP_ADAPTER_UNICAST_ADDRESS_LH @{
    Length                      = New-StructureField 0 UInt32
    Flags                       = New-StructureField 1 UInt32
    Next                        = New-StructureField 2 IntPtr # struct _IP_ADAPTER_UNICAST_ADDRESS_LH *Next
    Address                     = New-StructureField 3 $script:SOCKET_ADDRESS
    PrefixOrigin                = New-StructureField 4 UInt32
    SuffixOrigin                = New-StructureField 5 UInt32
    DadState                    = New-StructureField 6 UInt32
    ValidLifetime               = New-StructureField 7 UInt32
    PreferredLifetime           = New-StructureField 8 UInt32
    LeaseLifetime               = New-StructureField 9 UInt32
    OnLinkPrefixLength          = New-StructureField 10 Byte
}

$script:IP_ADAPTER_ANYCAST_ADDRESS_XP = New-Structure $Module WinApiModule.IP_ADAPTER_ANYCAST_ADDRESS_XP @{
    Length                      = New-StructureField 0 UInt32
    Flags                       = New-StructureField 1 UInt32
    Next                        = New-StructureField 2 IntPtr # struct _IP_ADAPTER_ANYCAST_ADDRESS_XP *Next
    Address                     = New-StructureField 3 $script:SOCKET_ADDRESS
}

$script:IP_ADAPTER_MULTICAST_ADDRESS_XP = New-Structure $Module WinApiModule.IP_ADAPTER_MULTICAST_ADDRESS_XP @{
    Length                      = New-StructureField 0 UInt32
    Flags                       = New-StructureField 1 UInt32
    Next                        = New-StructureField 2 IntPtr # struct _IP_ADAPTER_MULTICAST_ADDRESS_XP *Next
    Address                     = New-StructureField 3 $script:SOCKET_ADDRESS
}

$script:IP_ADAPTER_DNS_SERVER_ADDRESS_XP = New-Structure $Module WinApiModule.IP_ADAPTER_DNS_SERVER_ADDRESS_XP @{
    Length                      = New-StructureField 0 UInt32
    Flags                       = New-StructureField 1 UInt32
    Next                        = New-StructureField 2 IntPtr # struct _IP_ADAPTER_DNS_SERVER_ADDRESS_XP *Next
    Address                     = New-StructureField 3 $script:SOCKET_ADDRESS
}

$script:IP_ADAPTER_PREFIX_XP = New-Structure $Module WinApiModule.IP_ADAPTER_PREFIX_XP @{
    Length                      = New-StructureField 0 UInt32
    Flags                       = New-StructureField 1 UInt32
    Next                        = New-StructureField 2 IntPtr # struct _IP_ADAPTER_PREFIX_XP *Next
    Address                     = New-StructureField 3 $script:SOCKET_ADDRESS
    PrefixLength                = New-StructureField 4 UInt32
}

$script:IP_ADAPTER_WINS_SERVER_ADDRESS_LH = New-Structure $Module WinApiModule.IP_ADAPTER_WINS_SERVER_ADDRESS_LH @{
    Length                      = New-StructureField 0 UInt32
    Reserved                    = New-StructureField 1 UInt32
    Next                        = New-StructureField 2 IntPtr # struct _IP_ADAPTER_WINS_SERVER_ADDRESS_LH *Next
    Address                     = New-StructureField 3 $script:SOCKET_ADDRESS
}

$script:IP_ADAPTER_GATEWAY_ADDRESS_LH = New-Structure $Module WinApiModule.IP_ADAPTER_GATEWAY_ADDRESS_LH @{
    Length                      = New-StructureField 0 UInt32
    Reserved                    = New-StructureField 1 UInt32
    Next                        = New-StructureField 2 IntPtr # struct _IP_ADAPTER_GATEWAY_ADDRESS_LH *Next
    Address                     = New-StructureField 3 $script:SOCKET_ADDRESS
}

$script:IP_ADAPTER_DNS_SUFFIX = New-Structure $Module WinApiModule.IP_ADAPTER_DNS_SUFFIX @{
    Next                        = New-StructureField 0 IntPtr # struct _IP_ADAPTER_DNS_SUFFIX *Next
    String                      = New-StructureField 1 String -MarshalAs @('ByValTStr', 256)
} -Charset Unicode

$script:IP_ADAPTER_ADDRESSES = New-Structure $Module WinApiModule.IP_ADAPTER_ADDRESSES @{
    Length                      = New-StructureField 0 UInt32
    IfIndex                     = New-StructureField 1 UInt32
    Next                        = New-StructureField 2 IntPtr # struct _IP_ADAPTER_ADDRESSES_LH    *Next;
    AdapterName                 = New-StructureField 3 String -MarshalAs @('LPStr')
    FirstUnicastAddress         = New-StructureField 4 IntPtr # PIP_ADAPTER_UNICAST_ADDRESS_LH
    FirstAnycastAddress         = New-StructureField 5 IntPtr # PIP_ADAPTER_ANYCAST_ADDRESS_XP
    FirstMulticastAddress       = New-StructureField 6 IntPtr # PIP_ADAPTER_MULTICAST_ADDRESS_XP
    FirstDnsServerAddress       = New-StructureField 7 IntPtr # PIP_ADAPTER_DNS_SERVER_ADDRESS_XP
    DnsSuffix                   = New-StructureField 8 String -MarshalAs @('LPWStr')
    Description                 = New-StructureField 9 String -MarshalAs @('LPWStr')
    FriendlyName                = New-StructureField 10 String -MarshalAs @('LPWStr')
    PhysicalAddress             = New-StructureField 11 Byte[] -MarshalAs @('ByValArray', 8)
    PhysicalAddressLength       = New-StructureField 12 UInt32
    Flags                       = New-StructureField 13 UInt32
    Mtu                         = New-StructureField 14 UInt32
    IfType                      = New-StructureField 15 UInt32
    OperStatus                  = New-StructureField 16 UInt32
    Ipv6IfIndex                 = New-StructureField 17 UInt32
    ZoneIndices                 = New-StructureField 18 UInt32[] -MarshalAs @('ByValArray', 16)
    FirstPrefix                 = New-StructureField 19 IntPtr # PIP_ADAPTER_PREFIX_XP
    TransmitLinkSpeed           = New-StructureField 20 UInt64
    ReceiveLinkSpeed            = New-StructureField 21 UInt64
    FirstWinsServerAddress      = New-StructureField 22 IntPtr # PIP_ADAPTER_WINS_SERVER_ADDRESS_LH
    FirstGatewayAddress         = New-StructureField 23 IntPtr # PIP_ADAPTER_GATEWAY_ADDRESS_LH
    Ipv4Metric                  = New-StructureField 24 UInt32
    Ipv6Metric                  = New-StructureField 25 UInt32
    Luid                        = New-StructureField 26 UInt64
    Dhcpv4Server                = New-StructureField 27 $script:SOCKET_ADDRESS
    CompartmentId               = New-StructureField 28 UInt32
    NetworkGuid                 = New-StructureField 29 Guid
    ConnectionType              = New-StructureField 30 UInt32
    TunnelType                  = New-StructureField 31 UInt32
    Dhcpv6Server                = New-StructureField 32 $script:SOCKET_ADDRESS
    Dhcpv6ClientDuid            = New-StructureField 33 Byte[] -MarshalAs @('ByValArray', 130)
    Dhcpv6ClientDuidLength      = New-StructureField 34 UInt32
    Dhcpv6Iaid                  = New-StructureField 35 UInt32
    FirstDnsSuffix              = New-StructureField 36 IntPtr # PIP_ADAPTER_DNS_SUFFIX
}

$script:MIB_TCPROW_OWNER_PID = New-Structure $Module WinApiModule.MIB_TCPROW_OWNER_PID @{
    State                       = New-StructureField 0 UInt32
    LocalAddr                   = New-StructureField 1 UInt32
    LocalPort                   = New-StructureField 2 Byte[] -MarshalAs @('ByValArray', 4)
    RemoteAddr                  = New-StructureField 3 UInt32
    RemotePort                  = New-StructureField 4 Byte[] -MarshalAs @('ByValArray', 4)
    OwningPid                   = New-StructureField 5 UInt32
}

$script:MIB_UDPROW_OWNER_PID = New-Structure $Module WinApiModule.MIB_UDPROW_OWNER_PID @{
    LocalAddr                   = New-StructureField 0 UInt32
    LocalPort                   = New-StructureField 1 Byte[] -MarshalAs @('ByValArray', 4)
    OwningPid                   = New-StructureField 2 UInt32
}

$script:MIB_TCP6ROW_OWNER_PID = New-Structure $Module WinApiModule.MIB_TCP6ROW_OWNER_PID @{
    LocalAddr                   = New-StructureField 0 Byte[] -MarshalAs @('ByValArray', 16)
    LocalScopeId                = New-StructureField 1 UInt32
    LocalPort                   = New-StructureField 2 Byte[] -MarshalAs @('ByValArray', 4)
    RemoteAddr                  = New-StructureField 3 Byte[] -MarshalAs @('ByValArray', 16)
    RemoteScopeId               = New-StructureField 4 UInt32
    RemotePort                  = New-StructureField 5 Byte[] -MarshalAs @('ByValArray', 4)
    State                       = New-StructureField 6 UInt32
    OwningPid                   = New-StructureField 7 UInt32
}

$script:MIB_UDP6ROW_OWNER_PID = New-Structure $Module WinApiModule.MIB_UDP6ROW_OWNER_PID @{
    LocalAddr                   = New-StructureField 0 Byte[] -MarshalAs @('ByValArray', 16)
    LocalScopeId                = New-StructureField 1 UInt32
    LocalPort                   = New-StructureField 2 Byte[] -MarshalAs @('ByValArray', 4)
    OwningPid                   = New-StructureField 3 UInt32
}

$script:MIB_TCPTABLE_OWNER_PID = New-Structure $Module WinApiModule.MIB_TCPTABLE_OWNER_PID @{
    NumEntries                  = New-StructureField 0 UInt32
    Table                       = New-StructureField 1 $script:MIB_TCPROW_OWNER_PID.MakeArrayType() -MarshalAs @('ByValArray', 1)
}

$script:MIB_UDPTABLE_OWNER_PID = New-Structure $Module WinApiModule.MIB_UDPTABLE_OWNER_PID @{
    NumEntries                  = New-StructureField 0 UInt32
    Table                       = New-StructureField 1 $script:MIB_UDPROW_OWNER_PID.MakeArrayType() -MarshalAs @('ByValArray', 1)
}

$script:MIB_TCP6TABLE_OWNER_PID = New-Structure $Module WinApiModule.MIB_TCP6TABLE_OWNER_PID @{
    NumEntries                  = New-StructureField 0 UInt32
    Table                       = New-StructureField 1 $script:MIB_TCP6ROW_OWNER_PID.MakeArrayType() -MarshalAs @('ByValArray', 1)
}

$script:MIB_UDP6TABLE_OWNER_PID = New-Structure $Module WinApiModule.MIB_UDP6TABLE_OWNER_PID @{
    NumEntries                  = New-StructureField 0 UInt32
    Table                       = New-StructureField 1 $script:MIB_UDP6ROW_OWNER_PID.MakeArrayType() -MarshalAs @('ByValArray', 1)
}

$script:FILETIME = New-Structure $Module WinApiModule.FILETIME @{
    LowDateTime                 = New-StructureField 0 UInt32
    HighDateTime                = New-StructureField 1 UInt32
}

$script:CREDENTIAL = New-Structure $Module WinApiModule.CREDENTIAL @{
    Flags                       = New-StructureField 0 UInt32
    Type                        = New-StructureField 1 UInt32
    TargetName                  = New-StructureField 2 String
    Comment                     = New-StructureField 3 String
    LastWritten                 = New-StructureField 4 $script:FILETIME
    CredentialBlobSize          = New-StructureField 5 UInt32
    CredentialBlob              = New-StructureField 6 IntPtr
    Persist                     = New-StructureField 7 UInt32
    AttributeCount              = New-StructureField 8 UInt32
    Attributes                  = New-StructureField 9 IntPtr
    TargetAlias                 = New-StructureField 10 String
    UserName                    = New-StructureField 11 String
} -Charset Unicode

$script:UNICODE_STRING = New-Structure $Module WinApiModule.UNICODE_STRING @{
    Length                      = New-StructureField 0 UInt16
    MaximumLength               = New-StructureField 1 UInt16
    Buffer                      = New-StructureField 2 IntPtr
}

$script:GENERIC_MAPPING = New-Structure $Module WinApiModule.GENERIC_MAPPING @{
    GenericRead                 = New-StructureField 0 UInt32
    GenericWrite                = New-StructureField 1 UInt32
    GenericExecute              = New-StructureField 2 UInt32
    GenericAll                  = New-StructureField 3 UInt32
}

$script:OBJECT_NAME_INFORMATION = New-Structure $Module WinApiModule.OBJECT_NAME_INFORMATION @{
    Name                        = New-StructureField 0 $script:UNICODE_STRING
}

$script:OBJECT_TYPE_INFORMATION = New-Structure $Module WinApiModule.OBJECT_TYPE_INFORMATION @{
    TypeName                    = New-StructureField 0 $script:UNICODE_STRING
    TotalNumberOfObjects        = New-StructureField 1 UInt32
    TotalNumberOfHandles        = New-StructureField 2 UInt32
    TotalPagedPoolUsage         = New-StructureField 3 UInt32
    TotalNonPagedPoolUsage      = New-StructureField 4 UInt32
    TotalNamePoolUsage          = New-StructureField 5 UInt32
    TotalHandleTableUsage       = New-StructureField 6 UInt32
    HighWaterNumberOfObjects    = New-StructureField 7 UInt32
    HighWaterNumberOfHandles    = New-StructureField 8 UInt32
    HighWaterPagedPoolUsage     = New-StructureField 9 UInt32
    HighWaterNonPagedPoolUsage  = New-StructureField 10 UInt32
    HighWaterNamePoolUsage      = New-StructureField 11 UInt32
    HighWaterHandleTableUsage   = New-StructureField 12 UInt32
    InvalidAttributes           = New-StructureField 13 UInt32
    GenericMapping              = New-StructureField 14 $script:GENERIC_MAPPING
    ValidAccessMask             = New-StructureField 15 UInt32
    SecurityRequired            = New-StructureField 16 Byte
    MaintainHandleCount         = New-StructureField 17 Byte
    TypeIndex                   = New-StructureField 18 Byte
    ReservedByte                = New-StructureField 19 Byte
    PoolType                    = New-StructureField 20 UInt32
    DefaultPagedPoolCharge      = New-StructureField 21 UInt32
    DefaultNonPagedPoolCharge   = New-StructureField 22 UInt32
}

$script:VAULT_ITEM_7 = New-Structure $Module WinApiModule.VAULT_ITEM_7 @{
    SchemaId                    = New-StructureField 0 Guid
    FriendlyName                = New-StructureField 1 String
    Resource                    = New-StructureField 2 IntPtr
    Identity                    = New-StructureField 3 IntPtr
    Authenticator               = New-StructureField 4 IntPtr
    LastWritten                 = New-StructureField 5 $script:FILETIME
    Flags                       = New-StructureField 6 Uint32
    PropertiesCount             = New-StructureField 7 UInt32
    Properties                  = New-StructureField 8 IntPtr
}

$script:VAULT_ITEM_8 = New-Structure $Module WinApiModule.VAULT_ITEM_8 @{
    SchemaId                    = New-StructureField 0 Guid
    FriendlyName                = New-StructureField 1 String
    Resource                    = New-StructureField 2 IntPtr
    Identity                    = New-StructureField 3 IntPtr
    Authenticator               = New-StructureField 4 IntPtr
    PackageSid                  = New-StructureField 5 IntPtr
    LastWritten                 = New-StructureField 6 $script:FILETIME
    Flags                       = New-StructureField 7 Uint32
    PropertiesCount             = New-StructureField 8 UInt32
    Properties                  = New-StructureField 9 IntPtr
}

$script:VAULT_ITEM_DATA_HEADER = New-Structure $Module WinApiModule.VAULT_ITEM_DATA_HEADER @{
    SchemaElementId             = New-StructureField 0 UInt32
    Unknown1                    = New-StructureField 1 UInt32
    Type                        = New-StructureField 2 UInt32
    Unknown2                    = New-StructureField 3 UInt32
}

$script:WLAN_INTERFACE_INFO = New-Structure $Module WinApiModule.WLAN_INTERFACE_INFO @{
    InterfaceGuid               = New-StructureField 0 Guid
    InterfaceDescription        = New-StructureField 1 String -MarshalAs @('ByValTStr', 256)
    State                       = New-StructureField 2 UInt32
} -Charset Unicode

$script:WLAN_PROFILE_INFO = New-Structure $Module WinApiModule.WLAN_PROFILE_INFO @{
    ProfileName                 = New-StructureField 0 String -MarshalAs @('ByValTStr', 256)
    Flags                       = New-StructureField 1 UInt32
} -Charset Unicode

$script:SECURITY_ATTRIBUTES = New-Structure $Module WinApiModule.SECURITY_ATTRIBUTES @{
    Length                      = New-StructureField 0 UInt32
    SecurityDescriptor          = New-StructureField 1 IntPtr
    InheritHandle               = New-StructureField 2 Bool
}

$script:OBJECT_ATTRIBUTES = New-Structure $Module WinApiModule.OBJECT_ATTRIBUTES @{
    Length                      = New-StructureField 0 UInt32
    RootDirectory               = New-StructureField 1 IntPtr
    ObjectName                  = New-StructureField 2 IntPtr
    Attributes                  = New-StructureField 3 UInt32
    SecurityDescriptor          = New-StructureField 4 IntPtr
    SecurityQualityOfService    = New-StructureField 5 IntPtr
}

$script:OBJECT_DIRECTORY_INFORMATION = New-Structure $Module WinApiModule.OBJECT_DIRECTORY_INFORMATION @{
    Name                        = New-StructureField 0 $script:UNICODE_STRING
    TypeName                    = New-StructureField 1 $script:UNICODE_STRING
}

$script:WIN32_FILE_ATTRIBUTE_DATA = New-Structure $Module WinApiModule.WIN32_FILE_ATTRIBUTE_DATA @{
    dwFileAttributes            = New-StructureField 0 UInt32
    ftCreationTime              = New-StructureField 1 $script:FILETIME
    ftLastAccessTime            = New-StructureField 2 $script:FILETIME
    ftLastWriteTime             = New-StructureField 3 $script:FILETIME
    nFileSizeHigh               = New-StructureField 4 UInt32
    nFileSizeLow                = New-StructureField 5 UInt32
}

$script:WTS_SESSION_INFO_1W = New-Structure $Module WinApiModule.WTS_SESSION_INFO_1W @{
    ExecEnvId                   = New-StructureField 0 UInt32
    State                       = New-StructureField 1 $script:WTS_CONNECTSTATE_CLASS
    SessionId                   = New-StructureField 2 UInt32
    SessionName                 = New-StructureField 3 String -MarshalAs @('LPWStr')
    HostName                    = New-StructureField 4 String -MarshalAs @('LPWStr')
    UserName                    = New-StructureField 5 String -MarshalAs @('LPWStr')
    DomainName                  = New-StructureField 6 String -MarshalAs @('LPWStr')
    FarmName                    = New-StructureField 7 String -MarshalAs @('LPWStr')
}

$script:DRIVER_INFO_1 = New-Structure $Module WinApiModule.DRIVER_INFO_1 @{
    Name                        = New-StructureField 0 String -MarshalAs @('LPTStr')
} -Charset Auto

$script:DRIVER_INFO_2 = New-Structure $Module WinApiModule.DRIVER_INFO_2 @{
    Version                     = New-StructureField 0 UInt32
    Name                        = New-StructureField 1 String -MarshalAs @('LPTStr')
    Environment                 = New-StructureField 2 String -MarshalAs @('LPTStr')
    DriverPath                  = New-StructureField 3 String -MarshalAs @('LPTStr')
    DataFile                    = New-StructureField 4 String -MarshalAs @('LPTStr')
    ConfigFile                  = New-StructureField 5 String -MarshalAs @('LPTStr')
} -Charset Auto

$script:DRIVER_INFO_3 = New-Structure $Module WinApiModule.DRIVER_INFO_3 @{
    Version                     = New-StructureField 0 UInt32
    Name                        = New-StructureField 1 String -MarshalAs @('LPTStr')
    Environment                 = New-StructureField 2 String -MarshalAs @('LPTStr')
    DriverPath                  = New-StructureField 3 String -MarshalAs @('LPTStr')
    DataFile                    = New-StructureField 4 String -MarshalAs @('LPTStr')
    ConfigFile                  = New-StructureField 5 String -MarshalAs @('LPTStr')
    HelpFile                    = New-StructureField 6 String -MarshalAs @('LPTStr')
    DependentFiles              = New-StructureField 7 String -MarshalAs @('LPTStr')
    MonitorName                 = New-StructureField 8 String -MarshalAs @('LPTStr')
    DefaultDataType             = New-StructureField 9 String -MarshalAs @('LPTStr')
} -Charset Auto

$script:DRIVER_INFO_4 = New-Structure $Module WinApiModule.DRIVER_INFO_4 @{
    Version                     = New-StructureField 0 UInt32
    Name                        = New-StructureField 1 String -MarshalAs @('LPTStr')
    Environment                 = New-StructureField 2 String -MarshalAs @('LPTStr')
    DriverPath                  = New-StructureField 3 String -MarshalAs @('LPTStr')
    DataFile                    = New-StructureField 4 String -MarshalAs @('LPTStr')
    ConfigFile                  = New-StructureField 5 String -MarshalAs @('LPTStr')
    HelpFile                    = New-StructureField 6 String -MarshalAs @('LPTStr')
    DependentFiles              = New-StructureField 7 String -MarshalAs @('LPTStr')
    MonitorName                 = New-StructureField 8 String -MarshalAs @('LPTStr')
    DefaultDataType             = New-StructureField 9 String -MarshalAs @('LPTStr')
    PreviousNames               = New-StructureField 10 String -MarshalAs @('LPTStr')
} -Charset Auto

$script:DRIVER_INFO_5 = New-Structure $Module WinApiModule.DRIVER_INFO_5 @{
    Version                     = New-StructureField 0 UInt32
    Name                        = New-StructureField 1 String -MarshalAs @('LPTStr')
    Environment                 = New-StructureField 2 String -MarshalAs @('LPTStr')
    DriverPath                  = New-StructureField 3 String -MarshalAs @('LPTStr')
    DataFile                    = New-StructureField 4 String -MarshalAs @('LPTStr')
    ConfigFile                  = New-StructureField 5 String -MarshalAs @('LPTStr')
    DriverAttributes            = New-StructureField 6 UInt32
    ConfigVersion               = New-StructureField 7 UInt32
    DriverVersion               = New-StructureField 8 UInt32
} -Charset Auto

$script:PRINTER_INFO_2 = New-Structure $Module WinApiModule.PRINTER_INFO_2 @{
    ServerName                  = New-StructureField 0 String -MarshalAs @('LPTStr')
    PrinterName                 = New-StructureField 1 String -MarshalAs @('LPTStr')
    ShareName                   = New-StructureField 2 String -MarshalAs @('LPTStr')
    PortName                    = New-StructureField 3 String -MarshalAs @('LPTStr')
    DriverName                  = New-StructureField 4 String -MarshalAs @('LPTStr')
    Comment                     = New-StructureField 5 String -MarshalAs @('LPTStr')
    Location                    = New-StructureField 6 String -MarshalAs @('LPTStr')
    DevMode                     = New-StructureField 7 IntPtr # Should be a pointer to a DEVMODE structure
    SepFile                     = New-StructureField 8 String -MarshalAs @('LPTStr')
    PrintProcessor              = New-StructureField 9 String -MarshalAs @('LPTStr')
    DataType                    = New-StructureField 10 String -MarshalAs @('LPTStr')
    Parameters                  = New-StructureField 11 String -MarshalAs @('LPTStr')
    SecurityDescriptor          = New-StructureField 12 IntPtr # Should be a pointer to a SECURITY_DESCRIPTOR structure
    Attributes                  = New-StructureField 13 UInt32
    Priority                    = New-StructureField 14 UInt32
    DefaultPriority             = New-StructureField 15 UInt32
    StartTime                   = New-StructureField 16 UInt32
    UntilTime                   = New-StructureField 17 UInt32
    Status                      = New-StructureField 18 UInt32
    Jobs                        = New-StructureField 19 UInt32
    AveragePPM                  = New-StructureField 20 UInt32
} -Charset Auto

$script:WKSTA_INFO_100 = New-Structure $Module WinApiModule.WKSTA_INFO_100 @{
    PlatformId                  = New-StructureField 0 UInt32
    ComputerName                = New-StructureField 1 String -MarshalAs @('LPWStr')
    LanGroup                    = New-StructureField 2 String -MarshalAs @('LPWStr')
    VerMajor                    = New-StructureField 3 UInt32
    VerMinor                    = New-StructureField 4 UInt32
}

$script:WKSTA_INFO_101 = New-Structure $Module WinApiModule.WKSTA_INFO_101 @{
    PlatformId                  = New-StructureField 0 UInt32
    ComputerName                = New-StructureField 1 String -MarshalAs @('LPWStr')
    LanGroup                    = New-StructureField 2 String -MarshalAs @('LPWStr')
    VerMajor                    = New-StructureField 3 UInt32
    VerMinor                    = New-StructureField 4 UInt32
    LanRoot                     = New-StructureField 5 String -MarshalAs @('LPWStr')
}

$script:WKSTA_INFO_102 = New-Structure $Module WinApiModule.WKSTA_INFO_102 @{
    PlatformId                  = New-StructureField 0 UInt32
    ComputerName                = New-StructureField 1 String -MarshalAs @('LPWStr')
    LanGroup                    = New-StructureField 2 String -MarshalAs @('LPWStr')
    VerMajor                    = New-StructureField 3 UInt32
    VerMinor                    = New-StructureField 4 UInt32
    LanRoot                     = New-StructureField 5 String -MarshalAs @('LPWStr')
    LoggedOnUsers               = New-StructureField 6 UInt32
}