function Invoke-NetworkAdaptersCheck {
    <#
    .SYNOPSIS
    Collect detailed information about all Ethernet and Wi-Fi network adapters.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Collect detailed information about all active Ethernet adapters.
    
    .EXAMPLE
    PS C:\> Invoke-NetworkAdaptersCheck

    Name            : {B52615AE-995C-415B-9925-0C0815A81598}
    FriendlyName    : Ethernet0
    Type            : Ethernet
    Status          : Up
    DnsSuffix       : localdomain
    Description     : Intel(R) 82574L Gigabit Network Connection
    PhysicalAddress : 00:0c:29:1e:2b:00
    Flags           : DdnsEnabled, Dhcpv4Enabled, Ipv4Enabled, Ipv6Enabled
    IPv6            : fe80::1e9:ec0a:a7a2:993f (/64)
    IPv4            : 192.168.140.130 (/24)
    Gateway         : 192.168.140.2
    DHCPv4Server    : 192.168.140.254
    DHCPv6Server    :
    DnsServers      : 192.168.140.2
    DNSSuffixList   :
    #>

    [CmdletBinding()]Param()

    Get-NetworkAdaptersList | Where-Object { $_.Type -eq "Ethernet" -or $_.Type -eq "IEEE80211" } | Select-Object -Property Name,FriendlyName,Type,Status,DnsSuffix,Description,PhysicalAddress,Flags,IPv6,IPv4,Gateway,DHCPv4Server,DHCPv6Server,DnsServers,DNSSuffixList
}

function Invoke-TcpEndpointsCheck {
    <#
    .SYNOPSIS
    Enumerates all TCP endpoints on the local machine (IPv4 and IPv6)

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    It uses the custom "Get-NetworkEndpoints" function to enumerate all the TCP endpoints on the local machine, IPv4 and IPv6. The list can then be filtered based on a list of known ports.
    
    .PARAMETER Filtered
    Use this switch to filter out the list of endpoints returned by this function. The filter excludes all the standard ports such as 445 or 139 and all the random RPC ports. The RPC port range is dynamically guessed using the helper function "Get-RpcRange".
    
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
        [Switch]$Filtered
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
    It uses the custom "Get-NetworkEndpoints" function to enumerate all the UDP endpoints on the local machine, IPv4 and IPv6. The list can be filtered based on a list of known ports.
    
    .PARAMETER Filtered
    Use this switch to filter out the list of endpoints returned by this function. The filter excludes all the standard ports such as 139 or 500.
    
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
        [Switch]$Filtered
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
    The built-in "netsh" command allows one to list the saved Wifi profiles and extract the cleartext key or passphrase when applicable (e.g.: "netsh wlan show profile MyWifiProfile key=clear"). This function achieves the same goal. It iterates the list of Wlan interfaces in order to enumerate all the Wifi profiles which can be accessed in the context of the current user. If a network is configured with WEP or PSK authentication, it will attempt to extract the cleartext value of the key or passphrase. 
    
    .EXAMPLE
    PS C:\> Invoke-WlanProfilesCheck

    Profile        : MySecretAccessPoint
    SSID           : MySecretAccessPoint
    Authentication : WPA2PSK
    PassPhrase     : AvErYsEcReTpAsSpHrAsE
    Interface      : Compact Wireless-G USB Network Adapter
    State          : Connected
    #>

    [CmdletBinding()] Param()

    function Convert-ProfileXmlToObject {

        [CmdletBinding()] Param(
            [String]$ProfileXml
        )

        $Xml = [xml] $ProfileXml

        $Name = $Xml.WLANProfile.name
        $Ssid = $Xml.WLANProfile.SSIDConfig.SSID.name 
        $Authentication = $Xml.WLANProfile.MSM.security.authEncryption.authentication
        $PassPhrase = $Xml.WLANProfile.MSM.security.sharedKey.keyMaterial

        $ProfileResult = New-Object -TypeName PSObject
        $ProfileResult | Add-Member -MemberType "NoteProperty" -Name "Profile" -Value $Name
        $ProfileResult | Add-Member -MemberType "NoteProperty" -Name "SSID" -Value $Ssid
        $ProfileResult | Add-Member -MemberType "NoteProperty" -Name "Authentication" -Value $Authentication
        $ProfileResult | Add-Member -MemberType "NoteProperty" -Name "PassPhrase" -Value $PassPhrase
        $ProfileResult
    }

    $ERROR_SUCCESS = 0

    try {
        [IntPtr]$ClientHandle = [IntPtr]::Zero
        [UInt32]$NegotiatedVersion = 0
        $Result = $Wlanapi::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$NegotiatedVersion, [ref]$ClientHandle)
        if ($Result -eq $ERROR_SUCCESS) {
    
            Write-Verbose "WlanOpenHandle() OK - Handle: $($ClientHandle)"
    
            [IntPtr]$InterfaceListPtr = [IntPtr]::Zero
            $Result = $Wlanapi::WlanEnumInterfaces($ClientHandle, [IntPtr]::Zero, [ref]$InterfaceListPtr)
            if ($Result -eq $ERROR_SUCCESS) {
    
                Write-Verbose "WlanEnumInterfaces() OK - Interface list pointer: 0x$($InterfaceListPtr.ToString('X8'))"
    
                $NumberOfInterfaces = [Runtime.InteropServices.Marshal]::ReadInt32($InterfaceListPtr)
                Write-Verbose "Number of Wlan interfaces: $($NumberOfInterfaces)"
    
                # Calculate the pointer to the first WLAN_INTERFACE_INFO structure 
                $WlanInterfaceInfoPtr = [IntPtr] ($InterfaceListPtr.ToInt64() + 8) # dwNumberOfItems + dwIndex
    
                for ($i = 0; $i -lt $NumberOfInterfaces; $i++) {
    
                    $WlanInterfaceInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WlanInterfaceInfoPtr, [type] $WLAN_INTERFACE_INFO)
    
                    Write-Verbose "InterfaceInfo struct size: $([Runtime.InteropServices.Marshal]::SizeOf($WlanInterfaceInfo))" 
                    Write-Verbose "Wlan interface Guid: $($WlanInterfaceInfo.InterfaceGuid)"
                    Write-Verbose "Wlan interface: $($WlanInterfaceInfo.InterfaceDescription)"
                    Write-Verbose "Wlan interface State: $($WlanInterfaceInfo.State -as $WLAN_INTERFACE_STATE)"
    
                    [IntPtr]$ProfileListPtr = [IntPtr]::Zero
                    $Result = $Wlanapi::WlanGetProfileList($ClientHandle, $WlanInterfaceInfo.InterfaceGuid, [IntPtr]::Zero, [ref] $ProfileListPtr)
                    if ($Result -eq $ERROR_SUCCESS) {
    
                        Write-Verbose "WlanGetProfileList() OK - Profile list pointer: 0x$($ProfileListPtr.ToString('X8'))"
    
                        $NumberOfProfiles = [Runtime.InteropServices.Marshal]::ReadInt32($ProfileListPtr)
                        Write-Verbose "Number of profiles: $($NumberOfProfiles)"
    
                        # Calculate the pointer to the first WLAN_PROFILE_INFO structure 
                        $WlanProfileInfoPtr = [IntPtr] ($ProfileListPtr.ToInt64() + 8) # dwNumberOfItems + dwIndex
    
                        for ($j = 0; $j -lt $NumberOfProfiles; $j++) {
    
                            $WlanProfileInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WlanProfileInfoPtr, [type] $WLAN_PROFILE_INFO)
                            Write-Verbose "Wlan profile: $($WlanProfileInfo.ProfileName)"
    
                            [String]$ProfileXml = ""
                            [UInt32]$WlanProfileFlags = 4 # WLAN_PROFILE_GET_PLAINTEXT_KEY
                            [UInt32]$WlanProfileAccessFlags = 0
                            $Result = $Wlanapi::WlanGetProfile($ClientHandle, $WlanInterfaceInfo.InterfaceGuid, $WlanProfileInfo.ProfileName, [IntPtr]::Zero, [ref]$ProfileXml, [ref]$WlanProfileFlags, [ref]$WlanProfileAccessFlags)
                            if ($Result -eq $ERROR_SUCCESS) {
    
                                Write-Verbose "WlanGetProfile() OK"
    
                                $Item = Convert-ProfileXmlToObject -ProfileXml $ProfileXml
                                $Item | Add-Member -MemberType "NoteProperty" -Name "Interface" -Value $WlanInterfaceInfo.InterfaceDescription
                                $Item | Add-Member -MemberType "NoteProperty" -Name "State" -Value $($WlanInterfaceInfo.State -as $WLAN_INTERFACE_STATE)
                                $Item
    
                            }
                            else {
                                Write-Verbose "WlanGetProfile() failed (Err: $($Result))"
                            }
    
                            # Calculate the pointer to the next WLAN_PROFILE_INFO structure 
                            $WlanProfileInfoPtr = [IntPtr] ($WlanProfileInfoPtr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($WlanProfileInfo))
                        }
    
                        # cleanup
                        $Wlanapi::WlanFreeMemory($ProfileListPtr)
    
                    }
                    else {
                        Write-Verbose "WlanGetProfileList() failed (Err: $($Result))"
                    }
    
                    # Calculate the pointer to the next WLAN_INTERFACE_INFO structure 
                    $WlanInterfaceInfoPtr = [IntPtr] ($WlanInterfaceInfoPtr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($WlanInterfaceInfo))
                }
    
                # cleanup
                $Wlanapi::WlanFreeMemory($InterfaceListPtr)
    
            }
            else {
                Write-Verbose "WlanEnumInterfaces() failed (Err: $($Result))"
            }
    
            # cleanup
            $Result = $Wlanapi::WlanCloseHandle($ClientHandle, [IntPtr]::Zero)
            if ($Result -eq $ERROR_SUCCESS) {
                Write-Verbose "WlanCloseHandle() OK"
            }
            else {
                Write-Verbose "WlanCloseHandle() failed (Err: $($Result))"
            }
    
        }
        else {
            Write-Verbose "WlanOpenHandle() failed (Err: $($Result))"
        }
    }
    catch {
        # Do nothing
        # Wlan API doesn't exist on this machine probably 
        Write-Verbose $Error[0]
    }
}

function Convert-SocketAddressToObject {
 
    [CmdletBinding()] Param(
        [object] # SOCKET_ADDRESS struct
        $SocketAddress
    )

    if ($SocketAddress.SockAddr -eq [IntPtr]::Zero) {
        Write-Verbose "SOCKET_ADDRESS.lpSockaddr is null"
        return
    }

    # The type of structure pointed to by SOCKET_ADDRESS.lpSockaddr depends on the address family
    # (AF_INET or AF_INT6). The address family is the first member of the target structure, so it is
    # necessary to first read this value in order to determine whether a SOCKADDR or a SOCKADDR_IN6 
    # structure should be used.
    $AddressFamily = [System.Runtime.InteropServices.Marshal]::ReadInt16($SocketAddress.SockAddr)

    if ($AddressFamily -eq 2) {
        $AddressFamilyName = "AF_INET"
        $Addr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SocketAddress.SockAddr, [type]$SOCKADDR)
        $StringAddr = (@($Addr.Data[2], $Addr.Data[3], $Addr.Data[4], $Addr.Data[5]) -join ".")
    }
    elseif ($AddressFamily -eq 23) {
        $AddressFamilyName = "AF_INET6"
        $Addr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SocketAddress.SockAddr, [type]$SOCKADDR_IN6)

        $LeadingZero = $true
        $MidZero = $true
        $Result = ""
        $(for ($i = 0; $i -lt $Addr.Addr.Addr.Length; $i += 2) {
            $c = $Addr.Addr.Addr[$i]
            $d = $Addr.Addr.Addr[$i + 1]
            $t = $c * 256 + $d

            if (($t -eq 0) -and $LeadingZero) { if ($i -eq 0) { $Result += "::" }; continue } else { $LeadingZero = $false }
            if (($t -eq 0) -and (-not $LeadingZero)) { if ($MidZero) { $Result += ":"; $MidZero = $false }; continue }
            $Result += "$('{0:x}' -f $t):"
        })
        $StringAddr = $Result.TrimEnd(":")
    }
    else {
        # Silently fail rather than throwing an exception
        Write-Verbose "Unknown family: $AddressFamily"
        return
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "IPAddress" -Value $StringAddr
    $Result | Add-Member -MemberType "NoteProperty" -Name "Family" -Value $AddressFamily
    $Result | Add-Member -MemberType "NoteProperty" -Name "FamilyName" -Value $AddressFamilyName
    $Result
}

function Get-NetworkAdaptersList {
    <#
    .SYNOPSIS
    List network adpaters.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    This function leverages the Windows API (GetAdaptersAddresses) to list the network adapters.

    .PARAMETER All
    Specify this option to list all NDIS interfaces.
    
    .EXAMPLE
    PS C:\> Get-NetworkInterfaceList

    Name             : {B52615AE-995C-415B-9925-0C0815A81598}
    FriendlyName     : Ethernet0
    Type             : Ethernet
    Status           : Up
    ConnectionType   : Dedicated
    TunnelType       : None
    TxSpeed          : 1000000000
    RxSpeed          : 1000000000
    DnsSuffix        : localdomain
    Description      : Intel(R) 82574L Gigabit Network Connection
    PhysicalAddress  : 00:0c:29:1e:2b:00
    Flags            : DdnsEnabled, Dhcpv4Enabled, Ipv4Enabled, Ipv6Enabled
    IPv6             : fe:80::1:e9:ec:a:a7:a2:99:3f (/64)
    IPv4             : 192.168.140.130 (/24)
    Gateway          : 192.168.140.2
    DHCPv4Server     : 192.168.140.254
    DHCPv6Server     :
    DHCPv6IAID       : 100666409
    DHCPv6ClientDUID : 00:01:00:01:28:2e:96:5d:00:0c:29:1e:2b:00
    DnsServers       : 192.168.140.2
    WINSServers      : 192.168.140.2
    DnsSuffixList    :
    #>

    [CmdletBinding()] Param(
        [switch]
        $All = $false
    )

    $InterfaceTypes = @{
        'Other' = 1
        'Ethernet' = 6
        'TokenRing' = 9
        'PPP' = 23
        'Loopback' = 24
        'ATM' = 37
        'IEEE80211' = 71
        'Tunnel' = 131
        'IEEE1394' = 144
    }

    $InterfacesStatuses = @{
        'Up' = 1
        'Down' = 2
        'Testing' = 3
        'Unknown' = 4
        'Dormant' = 5
        'NotPresent' = 6
        'LowerLayerDown' = 7
    }

    $ConnectionTypes = @{
        'Dedicated' = 1
        'Passive' = 2
        'Demand' = 3
        'Maximum' = 4
    }

    $TunnelTypes = @{
        'None' = 0
        'Other' = 1
        'Direct' = 2
        '6to4' = 11
        'ISATAP' = 13
        'TEREDO' = 14
        'IPHTTPS' = 15
    }

    $GAA_FLAG_INCLUDE_PREFIX = 0x0010
    $GAA_FLAG_INCLUDE_WINS_INFO = 0x0040
    $GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
    $GAA_FLAG_INCLUDE_ALL_INTERFACES = 0x0100

    $Family = 0 # AF_UNSPEC
    $Flags = $GAA_FLAG_INCLUDE_PREFIX -bor $GAA_FLAG_INCLUDE_WINS_INFO -bor $GAA_FLAG_INCLUDE_GATEWAYS
    if ($All) { $Flags = $Flgas -bor $GAA_FLAG_INCLUDE_ALL_INTERFACES }
    $AdaptersSize = 0
    $Result = $Iphlpapi::GetAdaptersAddresses($Family, $Flags, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$AdaptersSize)

    if ($AddressesSize -eq 0) {
        Write-Verbose "GetAdaptersAddresses KO - Error: $Result"
        return
    }

    Write-Verbose "GetAdaptersAddresses OK - Size: $AdaptersSize"

    $AdaptersPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($AdaptersSize)
    $Result = $Iphlpapi::GetAdaptersAddresses($Family, $Flags, [IntPtr]::Zero, $AdaptersPtr, [ref]$AdaptersSize)

    if ($Result -ne 0) {
        Write-Verbose "GetAdaptersAddresses KO - Error: $Result"
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($AdaptersSize)
        return
    }

    Write-Verbose "GetAdaptersAddresses OK"

    do {
        $Adapter = [System.Runtime.InteropServices.Marshal]::PtrToStructure($AdaptersPtr, [type]$IP_ADAPTER_ADDRESSES)

        # Interface type
        $InterfaceType = $InterfaceTypes.GetEnumerator() | Where-Object { $_.value -eq $Adapter.IfType } | ForEach-Object { $_.Name }

        # Status
        $InterfaceStatus = $InterfacesStatuses.GetEnumerator() | Where-Object { $_.value -eq $Adapter.OperStatus } | ForEach-Object { $_.Name }

        # Connection type
        $ConnectionType = $ConnectionTypes.GetEnumerator() | Where-Object { $_.value -eq $Adapter.ConnectionType } | ForEach-Object { $_.Name }

        # Tunnel type
        $TunnelType = $TunnelTypes.GetEnumerator() | Where-Object { $_.value -eq $Adapter.TunnelType } | ForEach-Object { $_.Name }
        
        # Friendly representation of the physical address
        $AdapterPhysicalAddress = ""
        if ($Adapter.PhysicalAddressLength -ne 0) {
            $AdapterPhysicalAddress = $(for ($i = 0; $i -lt $Adapter.PhysicalAddressLength; $i++) { "{0:x2}" -f $Adapter.PhysicalAddress[$i] }) -join ":"
        }

        # Unicast addresses
        $UnicastAddresses = @()
        $UnicastAddressPtr = $Adapter.FirstUnicastAddress
        while ($UnicastAddressPtr -ne [IntPtr]::Zero) {
            $UnicastAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($UnicastAddressPtr, [type]$IP_ADAPTER_UNICAST_ADDRESS_LH)
            $AddrObject = Convert-SocketAddressToObject -SocketAddress $UnicastAddress.Address
            $AddrObject.IPAddress = "$($AddrObject.IPAddress) (/$($UnicastAddress.OnLinkPrefixLength))"
            $UnicastAddresses += $AddrObject
            $UnicastAddressPtr = $UnicastAddress.Next
        }

        # DNS servers
        $DnsServerAddresses = @()
        $DnsServerAddressPtr = $Adapter.FirstDnsServerAddress
        while ($DnsServerAddressPtr -ne [IntPtr]::Zero) {
            $DnsServerAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($DnsServerAddressPtr, [type]$IP_ADAPTER_DNS_SERVER_ADDRESS_XP)
            $AddrObject = Convert-SocketAddressToObject -SocketAddress $DnsServerAddress.Address
            $DnsServerAddresses += $AddrObject
            $DnsServerAddressPtr = $DnsServerAddress.Next
        }

        # WINS server
        $WinsServerAddresses = @()
        $WinsServerAddressPtr = $Adapter.FirstWinsServerAddress
        while ($WinsServerAddressPtr -ne [IntPtr]::Zero) {
            $WinServerAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WinsServerAddressPtr, [type]$IP_ADAPTER_WINS_SERVER_ADDRESS_LH)
            $AddrObject = Convert-SocketAddressToObject -SocketAddress $WinServerAddress.Address
            $WinsServerAddresses += $AddrObject
            $WinsServerAddressPtr = $WinServerAddress.Next
        }

        # Gateway
        $GatewayAddresses = @()
        $GatewayAddressPtr = $Adapter.FirstGatewayAddress
        while ($GatewayAddressPtr -ne [IntPtr]::Zero) {
            $GatewayAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($GatewayAddressPtr, [type]$IP_ADAPTER_GATEWAY_ADDRESS_LH)
            $AddrObject = Convert-SocketAddressToObject -SocketAddress $GatewayAddress.Address
            $GatewayAddresses += $AddrObject
            $GatewayAddressPtr = $GatewayAddress.Next
        }

        # DNS suffix search list
        $DnsSuffixList = @()
        $DnsSuffixPtr = $Adapter.FirstDnsSuffix
        while ($DnsSuffixPtr -ne [IntPtr]::Zero) {
            $DnsSuffix = [System.Runtime.InteropServices.Marshal]::PtrToStructure($DnsSuffixPtr, [type]$IP_ADAPTER_DNS_SUFFIX)
            [string[]]$DnsSuffixList += $DnsSuffix.String
            $DnsSuffixPtr = $DnsSuffix.Next
        }

        # DHCPv4 server
        $Dhcpv4Server = Convert-SocketAddressToObject -SocketAddress $Adapter.Dhcpv4Server

        # DHCPv6 server
        $Dhcpv6Server = Convert-SocketAddressToObject -SocketAddress $Adapter.Dhcpv6Server
        $Dhcpv6ClientDuid = $(for ($i = 0; $i -lt $Adapter.Dhcpv6ClientDuidLength; $i++) { '{0:x2}' -f $Adapter.Dhcpv6ClientDuid[$i] }) -join ":"
        
        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $Adapter.AdapterName
        $Result | Add-Member -MemberType "NoteProperty" -Name "FriendlyName" -Value $Adapter.FriendlyName
        $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $InterfaceType
        $Result | Add-Member -MemberType "NoteProperty" -Name "Status" -Value $InterfaceStatus
        $Result | Add-Member -MemberType "NoteProperty" -Name "ConnectionType" -Value $ConnectionType
        $Result | Add-Member -MemberType "NoteProperty" -Name "TunnelType" -Value $TunnelType
        $Result | Add-Member -MemberType "NoteProperty" -Name "TxSpeed" -Value $Adapter.TransmitLinkSpeed
        $Result | Add-Member -MemberType "NoteProperty" -Name "RxSpeed" -Value $Adapter.ReceiveLinkSpeed
        $Result | Add-Member -MemberType "NoteProperty" -Name "DnsSuffix" -Value $Adapter.DnsSuffix
        $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Adapter.Description
        $Result | Add-Member -MemberType "NoteProperty" -Name "PhysicalAddress" -Value $AdapterPhysicalAddress
        $Result | Add-Member -MemberType "NoteProperty" -Name "Flags" -Value ($Adapter.Flags -as $IP_ADAPTER_FLAGS)
        $Result | Add-Member -MemberType "NoteProperty" -Name "IPv6" -Value (($UnicastAddresses | Where-Object { $_.Family -eq 23 } | ForEach-Object { $_.IPAddress }) -join ", ")
        $Result | Add-Member -MemberType "NoteProperty" -Name "IPv4" -Value (($UnicastAddresses | Where-Object { $_.Family -eq 2 } | ForEach-Object { $_.IPAddress }) -join ", ")
        $Result | Add-Member -MemberType "NoteProperty" -Name "Gateway" -Value (($GatewayAddresses | ForEach-Object { $_.IPAddress }) -join ", ")
        $Result | Add-Member -MemberType "NoteProperty" -Name "DHCPv4Server" -Value $Dhcpv4Server.IPAddress
        $Result | Add-Member -MemberType "NoteProperty" -Name "DHCPv6Server" -Value $Dhcpv6Server.IPAddress
        $Result | Add-Member -MemberType "NoteProperty" -Name "DHCPv6IAID" -Value $(if ($Adapter.Dhcpv6Iaid -ne 0) { $Adapter.Dhcpv6Iaid } else { $null })
        $Result | Add-Member -MemberType "NoteProperty" -Name "DHCPv6ClientDUID" -Value $Dhcpv6ClientDuid
        $Result | Add-Member -MemberType "NoteProperty" -Name "DnsServers" -Value (($DnsServerAddresses | ForEach-Object { $_.IPAddress }) -join ", ")
        $Result | Add-Member -MemberType "NoteProperty" -Name "WINSServers" -Value (($WinsServerAddresses | ForEach-Object { $_.IPAddress }) -join ", ")
        $Result | Add-Member -MemberType "NoteProperty" -Name "DNSSuffixList" -Value ($DnsSuffixList -join ", ")
        $Result

        [IntPtr]$AdaptersPtr = $Adapter.Next

    } while ($AdaptersPtr -ne [IntPtr]::Zero)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($AdaptersPtr)
}

function Get-NetworkEndpoints {
    <#
    .SYNOPSIS
    Get a list of listening ports (TCP/UDP)

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    It uses the 'GetExtendedTcpTable' and 'GetExtendedUdpTable' functions of the Windows API to list the TCP/UDP endpoints on the local machine. It handles both IPv4 and IPv6. For each entry in the table, a custom PS object is returned, indicating the IP version (IPv4/IPv6), the protocol (TCP/UDP), the local address (e.g.: "0.0.0.0:445"), the state, the PID of the associated process and the name of the process. The name of the process is retrieved through a call to "Get-Process -PID <PID>".
    
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

    [CmdletBinding()] Param(
        [Switch]
        $IPv6 = $false, # IPv4 by default 
        [Switch]
        $UDP = $false # TCP by default 
    )

    $AF_INET6 = 23
    $AF_INET = 2
    
    if ($IPv6) { 
        $IpVersion = $AF_INET6
    }
    else {
        $IpVersion = $AF_INET
    }

    if ($UDP) {
        $UDP_TABLE_OWNER_PID = 1
        [Int]$BufSize = 0
        $Result = $Iphlpapi::GetExtendedUdpTable([IntPtr]::Zero, [ref]$BufSize, $true, $IpVersion, $UDP_TABLE_OWNER_PID, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }
    else {
        $TCP_TABLE_OWNER_PID_LISTENER = 3
        [Int]$BufSize = 0
        $Result = $Iphlpapi::GetExtendedTcpTable([IntPtr]::Zero, [ref]$BufSize, $true, $IpVersion, $TCP_TABLE_OWNER_PID_LISTENER, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }

    if ($Result -eq 122) {

        Write-Verbose "GetExtendedProtoTable() OK - Size: $BufSize"

        [IntPtr]$TablePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufSize)

        if ($UDP) {
            $Result = $Iphlpapi::GetExtendedUdpTable($TablePtr, [ref]$BufSize, $true, $IpVersion, $UDP_TABLE_OWNER_PID, 0)
        }
        else {
            $Result = $Iphlpapi::GetExtendedTcpTable($TablePtr, [ref]$BufSize, $true, $IpVersion, $TCP_TABLE_OWNER_PID_LISTENER, 0)
        }

        if ($Result -eq 0) {

            if ($UDP) {
                if ($IpVersion -eq $AF_INET) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $MIB_UDPTABLE_OWNER_PID)
                }
                elseif ($IpVersion -eq $AF_INET6) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $MIB_UDP6TABLE_OWNER_PID)
                }
            }
            else {
                if ($IpVersion -eq $AF_INET) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $MIB_TCPTABLE_OWNER_PID)
                }
                elseif ($IpVersion -eq $AF_INET6) { 
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $MIB_TCP6TABLE_OWNER_PID)
                }
            }
            
            $NumEntries = $Table.NumEntries

            Write-Verbose "GetExtendedProtoTable() OK - NumEntries: $NumEntries"

            $Offset = [IntPtr] ($TablePtr.ToInt64() + 4)

            For ($i = 0; $i -lt $NumEntries; $i++) {

                if ($UDP) {
                    if ($IpVersion -eq $AF_INET) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $MIB_UDPROW_OWNER_PID)
                        $LocalAddr = (New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr)).IPAddressToString
                    }
                    elseif ($IpVersion -eq $AF_INET6) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $MIB_UDP6ROW_OWNER_PID)
                        $LocalAddr = New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr, $TableEntry.LocalScopeId)
                    }
                }
                else {
                    if ($IpVersion -eq $AF_INET) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $MIB_TCPROW_OWNER_PID)
                        $LocalAddr = (New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr)).IPAddressToString
                    }
                    elseif ($IpVersion -eq $AF_INET6) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $MIB_TCP6ROW_OWNER_PID)
                        $LocalAddr = New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr, [Int64] $TableEntry.LocalScopeId)
                    }
                }

                $LocalPort = $TableEntry.LocalPort[0] * 0x100 + $TableEntry.LocalPort[1]
                $ProcessId = $TableEntry.OwningPid

                if ($IpVersion -eq $AF_INET) {
                    $LocalAddress = "$($LocalAddr):$($LocalPort)"
                }
                elseif ($IpVersion -eq $AF_INET6) {
                    # IPv6.ToString doesn't work in PSv2 for some reason
                    try { $LocalAddress = "[$($LocalAddr)]:$($LocalPort)" } catch { $LocalAddress = "????:$($LocalPort)" }
                }

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "IP" -Value $(if ($IpVersion -eq $AF_INET) { "IPv4" } else { "IPv6" } )
                $Result | Add-Member -MemberType "NoteProperty" -Name "Proto" -Value $(if ($UDP) { "UDP" } else { "TCP" } )
                $Result | Add-Member -MemberType "NoteProperty" -Name "LocalAddress" -Value $LocalAddr
                $Result | Add-Member -MemberType "NoteProperty" -Name "LocalPort" -Value $LocalPort
                $Result | Add-Member -MemberType "NoteProperty" -Name "Endpoint" -Value $LocalAddress
                $Result | Add-Member -MemberType "NoteProperty" -Name "State" -Value $(if ($UDP) { "N/A" } else { "LISTENING" } )
                $Result | Add-Member -MemberType "NoteProperty" -Name "PID" -Value $ProcessId
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value (Get-Process -PID $ProcessId).ProcessName
                $Result

                $Offset = [IntPtr] ($Offset.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($TableEntry))
            }

        }
        else {
            Write-Verbose ([ComponentModel.Win32Exception] $LastError)
        }

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TablePtr)

    }
    else {
        Write-Verbose ([ComponentModel.Win32Exception] $LastError)
    }
}