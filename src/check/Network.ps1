function Get-RpcRange {
    <#
    .SYNOPSIS
    Helper - Dynamically identifies the range of randomized RPC ports from a list of ports.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function is a helper for the Invoke-TcpEndpointCheck function. Windows uses a set of RPC ports that are randomly allocated in the range 49152-65535 by default. If we want to filter out these listening ports we must first figure out this set of ports. The aim of this function is to guess this range using basic statistics on a given array of port numbers. We can quite reliably identify the RPC port set because they are concentrated in a very small range. It's not 100% reliable but it will do the job most of the time.

    .PARAMETER Ports
    An array of port numbers

    .EXAMPLE
    PS C:\> Get-RpcRange -Ports $Ports

    MinPort MaxPort
    ------- -------
    49664   49672
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [Int[]] $Ports
    )

    function Get-Statistic {
        [CmdletBinding()]
        param(
            [Int[]] $Ports,
            [Int] $MinPort,
            [Int] $MaxPort,
            [Int] $Span
        )

        $Stats = @()
        For ($i = $MinPort; $i -lt $MaxPort; $i += $Span) {
            $Counter = 0
            foreach ($Port in $Ports) {
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
    $Stats = Get-Statistic -Ports $Ports -MinPort 49152 -MaxPort 65536 -Span 32

    $MaxStat = $null
    foreach ($Stat in $Stats) {
        if ($Stat.PortsInRange -gt $MaxStat.PortsInRange) {
            $MaxStat = $Stat
        }
    }

    For ($i = 0; $i -lt 8; $i++) {
        $Span = ($MaxStat.MaxPort - $MaxStat.MinPort) / 2
        $NewStats = Get-Statistic -Ports $Ports -MinPort $MaxStat.MinPort -MaxPort $MaxStat.MaxPort -Span $Span
        if ($NewStats) {
            if ($NewStats[0].PortsInRange -eq 0) {
                $MaxStat = $NewStats[1]
            }
            elseif ($NewStats[1].PortsInRange -eq 0) {
                $MaxStat = $NewStats[0]
            }
            else {
                break
            }
        }
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "MinPort" -Value $MaxStat.MinPort
    $Result | Add-Member -MemberType "NoteProperty" -Name "MaxPort" -Value $MaxStat.MaxPort
    $Result
}

function Invoke-NetworkAdapterCheck {
    <#
    .SYNOPSIS
    Collect detailed information about all Ethernet and Wi-Fi network adapters.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Collect detailed information about all active Ethernet adapters.

    .EXAMPLE
    PS C:\> Invoke-NetworkAdapterCheck

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

    [CmdletBinding()]
    param()

    Get-NetworkAdaptersList | Where-Object { $_.Type -eq "Ethernet" -or $_.Type -eq "IEEE80211" } | Select-Object -Property Name,FriendlyName,Type,Status,DnsSuffix,Description,PhysicalAddress,Flags,IPv6,IPv4,Gateway,DHCPv4Server,DHCPv6Server,DnsServers,DNSSuffixList
}

function Invoke-TcpEndpointCheck {
    <#
    .SYNOPSIS
    Enumerates all TCP endpoints on the local machine (IPv4 and IPv6)

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    It uses the custom "Get-NetworkEndpoint" function to enumerate all the TCP endpoints on the local machine, IPv4 and IPv6. The list can then be filtered based on a list of known ports.

    .PARAMETER Filtered
    Use this switch to filter out the list of endpoints returned by this function. The filter excludes all the standard ports such as 445 or 139 and all the random RPC ports. The RPC port range is dynamically guessed using the helper function "Get-RpcRange".

    .EXAMPLE
    PS C:\> Invoke-TcpEndpointCheck | ft

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

    [CmdletBinding()]
    param(
        [switch] $Filtered
    )

    $IgnoredPorts = @(135, 139, 445)

    $Endpoints = Get-NetworkEndpoint
    $Endpoints += Get-NetworkEndpoint -IPv6

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

function Invoke-UdpEndpointCheck {
    <#
    .SYNOPSIS
    Enumerates all UDP endpoints on the local machine (IPv4 and IPv6)

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    It uses the custom "Get-NetworkEndpoint" function to enumerate all the UDP endpoints on the local machine, IPv4 and IPv6. The list can be filtered based on a list of known ports.

    .PARAMETER Filtered
    Use this switch to filter out the list of endpoints returned by this function. The filter excludes all the standard ports such as 139 or 500.

    .EXAMPLE
    PS C:\> Invoke-UdpEndpointCheck | ft

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

    [CmdletBinding()]
    param(
        [switch] $Filtered
    )

    # https://support.microsoft.com/en-us/help/832017/service-overview-and-network-port-requirements-for-windows
    $IgnoredPorts = @(53, 67, 123, 137, 138, 139, 500, 1701, 2535, 4500, 445, 1900, 5050, 5353, 5355)

    $Endpoints = Get-NetworkEndpoint -UDP
    $Endpoints += Get-NetworkEndpoint -UDP -IPv6

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

function Invoke-WlanProfileCheck {
    <#
    .SYNOPSIS
    List saved WLAN profiles and try to determine if they are vulnerable.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet invokes the 'Get-WlanProfileList' helper and then performs a series of tests on each returned item. For now, only 802.1x profiles are checked. Therefore, we assume that any other profile is 'compliant' by default. Example of a typical vulnerability: the authentication method is PEAP+MSCHAPv2, but the identity of the authentication server is not verified; an evil twin attack could therefore be used to capture or relay the credentials of the user/machine.
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
    }

    process {
        Get-WlanProfileList | ForEach-Object {

            # Assume not vulnerable by default because there are authentication schemes that we do not support
            # (yet?). We will perform a series of checks on some parameters. As soon as a parameter does not
            # pass a test, we set the 'Vulnerable' status to 'True'. If a test does not pass, the description
            # variable is populated with a text that provides a description of the issue.
            $Description = ""
            $Vulnerable = $false

            if ($_.Dot1X) {

                $PerformServerValidation = $_.Eap.PerformServerValidation
                $PerformServerValidationDescription = $_.Eap.PerformServerValidationDescription
                if ($null -ne $PerformServerValidation) {
                    if ($PerformServerValidation -eq $false) {
                        $Vulnerable = $true
                        $Description = "$($Description)$($PerformServerValidationDescription) "
                    }
                }

                $ServerValidationDisablePrompt = $_.Eap.ServerValidationDisablePrompt
                $ServerValidationDisablePromptDescription = $_.Eap.ServerValidationDisablePromptDescription
                if ($null -ne $ServerValidationDisablePrompt) {
                    if ($ServerValidationDisablePrompt -eq $false) {
                        $Vulnerable = $true
                        $Description = "$($Description)$($ServerValidationDisablePromptDescription) "
                    }
                }

                $TrustedRootCAs = $_.Eap.TrustedRootCAs
                if ($null -eq $TrustedRootCAs) {
                    $Vulnerable = $true
                    $Description = "$($Description)No explicit trusted root CA is specified. "
                }
                else {
                    # TODO: ensure that only a domain CA is specified. Not sure how I should do that yet...
                }

                if ($null -ne $_.InnerEap) {
                    if ($_.InnerEapTypeId -eq 26) {
                        # If MS-CHAPv2 is used for authentication, user (or machine) credentials are used. It is
                        # recommended to use certificate-based authentication instead as user credentials could be cracked
                        # or relayed.
                        $Vulnerable = $true
                        $Description = "$($Description)MS-CHAPv2 is used for authentication. "
                    }
                }
            }

            if ($Vulnerable) {
                $_ | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description
                $AllResults += $_ | Select-Object -Property * -ExcludeProperty Eap,InnerEap
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }
}

function Invoke-AirstrikeAttackCheck {
    <#
    .SYNOPSIS
    Check whether the 'Do not display network selection UI' policy is enforced.

    .DESCRIPTION
    This cmdlet first checks whether the tested machined is a workstation with a version of Windows that supports the policy 'Do not display network selection UI'. If so, it checks whether it was enforced by reading the corresponding registry key/value. If the value is not set to 1, the result is not compliant.

    .EXAMPLE
    PS C:\> Invoke-AirstrikeAttackCheck

    Key         : HKLM\SOFTWARE\Policies\Microsoft\Windows\System
    Value       : DontDisplayNetworkSelectionUI
    Data        : (null)
    Description : The network selection UI is displayed on the logon screen (default).

    .LINK
    https://shenaniganslabs.io/2021/04/13/Airstrike.html
    https://admx.help/?Category=Windows_10_2016&Policy=Microsoft.Policies.WindowsLogon::DontDisplayNetworkSelectionUI
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    $Vulnerable = $false
    $Config = New-Object -TypeName PSObject

    # Check whether the machine is a workstation, otherwise irrelevant.
    $MachineRole = Get-MachineRole
    if ($MachineRole.Name -ne "WinNT") {
        $Description = "Not a workstation, this check is irrelevant."
    }
    else {
        # Check Windows version, if < 7, irrelevant.
        $WindowsVersion = Get-WindowsVersion
        if ((($WindowsVersion.Major -eq 6) -and ($WindowsVersion.Minor -lt 2)) -or ($WindowsVersion.Major -lt 6)) {
            $Description = "This version of Windows is not supported."

        }
        else {
            # Read the value of the 'DontDisplayNetworkSelectionUI' policy.
            $RegKey = "HKLM\SOFTWARE\Policies\Microsoft\Windows\System"
            $RegValue = "DontDisplayNetworkSelectionUI"
            $RegData = (Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue).$RegValue

            $Config | Add-Member -MemberType "NoteProperty" -Name "Key" -Value $RegKey
            $Config | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $RegValue
            $Config | Add-Member -MemberType "NoteProperty" -Name "Data" -Value $(if ($null -eq $RegData) { "(null)" } else { $RegData })

            # If the policy is enabled, the machine is not vulnerable.
            if ($RegData -ge 1) {
                $Description = "The policy 'DontDisplayNetworkSelectionUI' is enabled, not vulnerable."
            }
            else {
                $Description = "The network selection UI is displayed on the logon screen (default)."
                $Vulnerable = $true
            }
        }
    }

    $Config | Add-Member -MemberType "NoteProperty" -Name "Description" -Value $Description

    $CheckResult = New-Object -TypeName PSObject
    $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Config
    $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
    $CheckResult
}

function Convert-SocketAddressToObject {

    [CmdletBinding()]
    param(
        # SOCKET_ADDRESS structure
        [object] $SocketAddress
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
        $Addr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SocketAddress.SockAddr, [type] $script:SOCKADDR)
        $StringAddr = (@($Addr.Data[2], $Addr.Data[3], $Addr.Data[4], $Addr.Data[5]) -join ".")
    }
    elseif ($AddressFamily -eq 23) {
        $AddressFamilyName = "AF_INET6"
        $Addr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SocketAddress.SockAddr, [type] $script:SOCKADDR_IN6)

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
    List network adapters.

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

    [CmdletBinding()]
    param(
        [switch] $All = $false
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
    if ($All) { $Flags = $Flags -bor $GAA_FLAG_INCLUDE_ALL_INTERFACES }
    $AdaptersSize = 0
    $Result = $script:Iphlpapi::GetAdaptersAddresses($Family, $Flags, [IntPtr]::Zero, [IntPtr]::Zero, [ref] $AdaptersSize)

    if ($AddressesSize -eq 0) {
        Write-Verbose "GetAdaptersAddresses KO - Error: $Result"
        return
    }

    Write-Verbose "GetAdaptersAddresses OK - Size: $AdaptersSize"

    $AdaptersPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($AdaptersSize)
    $Result = $script:Iphlpapi::GetAdaptersAddresses($Family, $Flags, [IntPtr]::Zero, $AdaptersPtr, [ref] $AdaptersSize)

    if ($Result -ne 0) {
        Write-Verbose "GetAdaptersAddresses KO - Error: $Result"
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($AdaptersSize)
        return
    }

    Write-Verbose "GetAdaptersAddresses OK"

    do {
        $Adapter = [System.Runtime.InteropServices.Marshal]::PtrToStructure($AdaptersPtr, [type] $script:IP_ADAPTER_ADDRESSES)

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
            $UnicastAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($UnicastAddressPtr, [type] $script:IP_ADAPTER_UNICAST_ADDRESS_LH)
            $AddrObject = Convert-SocketAddressToObject -SocketAddress $UnicastAddress.Address
            $AddrObject.IPAddress = "$($AddrObject.IPAddress) (/$($UnicastAddress.OnLinkPrefixLength))"
            $UnicastAddresses += $AddrObject
            $UnicastAddressPtr = $UnicastAddress.Next
        }

        # DNS servers
        $DnsServerAddresses = @()
        $DnsServerAddressPtr = $Adapter.FirstDnsServerAddress
        while ($DnsServerAddressPtr -ne [IntPtr]::Zero) {
            $DnsServerAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($DnsServerAddressPtr, [type] $script:IP_ADAPTER_DNS_SERVER_ADDRESS_XP)
            $AddrObject = Convert-SocketAddressToObject -SocketAddress $DnsServerAddress.Address
            $DnsServerAddresses += $AddrObject
            $DnsServerAddressPtr = $DnsServerAddress.Next
        }

        # WINS server
        $WinsServerAddresses = @()
        $WinsServerAddressPtr = $Adapter.FirstWinsServerAddress
        while ($WinsServerAddressPtr -ne [IntPtr]::Zero) {
            $WinServerAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WinsServerAddressPtr, [type] $script:IP_ADAPTER_WINS_SERVER_ADDRESS_LH)
            $AddrObject = Convert-SocketAddressToObject -SocketAddress $WinServerAddress.Address
            $WinsServerAddresses += $AddrObject
            $WinsServerAddressPtr = $WinServerAddress.Next
        }

        # Gateway
        $GatewayAddresses = @()
        $GatewayAddressPtr = $Adapter.FirstGatewayAddress
        while ($GatewayAddressPtr -ne [IntPtr]::Zero) {
            $GatewayAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($GatewayAddressPtr, [type] $script:IP_ADAPTER_GATEWAY_ADDRESS_LH)
            $AddrObject = Convert-SocketAddressToObject -SocketAddress $GatewayAddress.Address
            $GatewayAddresses += $AddrObject
            $GatewayAddressPtr = $GatewayAddress.Next
        }

        # DNS suffix search list
        $DnsSuffixList = @()
        $DnsSuffixPtr = $Adapter.FirstDnsSuffix
        while ($DnsSuffixPtr -ne [IntPtr]::Zero) {
            $DnsSuffix = [System.Runtime.InteropServices.Marshal]::PtrToStructure($DnsSuffixPtr, [type] $script:IP_ADAPTER_DNS_SUFFIX)
            [string[]] $DnsSuffixList += $DnsSuffix.String
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
        $Result | Add-Member -MemberType "NoteProperty" -Name "Flags" -Value ($Adapter.Flags -as $script:IP_ADAPTER_FLAGS)
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

        [IntPtr] $AdaptersPtr = $Adapter.Next

    } while ($AdaptersPtr -ne [IntPtr]::Zero)

    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($AdaptersPtr)
}

function Get-NetworkEndpoint {
    <#
    .SYNOPSIS
    Get a list of listening ports (TCP/UDP)

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    It uses the 'GetExtendedTcpTable' and 'GetExtendedUdpTable' functions of the Windows API to list the TCP/UDP endpoints on the local machine. It handles both IPv4 and IPv6. For each entry in the table, a custom PS object is returned, indicating the IP version (IPv4/IPv6), the protocol (TCP/UDP), the local address (e.g.: "0.0.0.0:445"), the state, the PID of the associated process and the name of the process. The name of the process is retrieved through a call to "Get-Process -PID <PID>".

    .EXAMPLE
    PS C:\> Get-NetworkEndpoint | ft

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
    PS C:\> Get-NetworkEndpoint -UDP -IPv6 | ft

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

    [CmdletBinding()]
    param(
        # IPv4 by default
        [Switch] $IPv6 = $false,
        # TCP by default
        [Switch] $UDP = $false
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
        [Int] $BufSize = 0
        $Result = $script:Iphlpapi::GetExtendedUdpTable([IntPtr]::Zero, [ref] $BufSize, $true, $IpVersion, $UDP_TABLE_OWNER_PID, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }
    else {
        $TCP_TABLE_OWNER_PID_LISTENER = 3
        [Int] $BufSize = 0
        $Result = $script:Iphlpapi::GetExtendedTcpTable([IntPtr]::Zero, [ref] $BufSize, $true, $IpVersion, $TCP_TABLE_OWNER_PID_LISTENER, 0)
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    }

    if ($Result -eq 122) {

        Write-Verbose "GetExtendedProtoTable() OK - Size: $BufSize"

        [IntPtr] $TablePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($BufSize)

        if ($UDP) {
            $Result = $script:Iphlpapi::GetExtendedUdpTable($TablePtr, [ref] $BufSize, $true, $IpVersion, $UDP_TABLE_OWNER_PID, 0)
        }
        else {
            $Result = $script:Iphlpapi::GetExtendedTcpTable($TablePtr, [ref] $BufSize, $true, $IpVersion, $TCP_TABLE_OWNER_PID_LISTENER, 0)
        }

        if ($Result -eq 0) {

            if ($UDP) {
                if ($IpVersion -eq $AF_INET) {
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $script:MIB_UDPTABLE_OWNER_PID)
                }
                elseif ($IpVersion -eq $AF_INET6) {
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $script:MIB_UDP6TABLE_OWNER_PID)
                }
            }
            else {
                if ($IpVersion -eq $AF_INET) {
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $script:MIB_TCPTABLE_OWNER_PID)
                }
                elseif ($IpVersion -eq $AF_INET6) {
                    $Table = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TablePtr, [type] $script:MIB_TCP6TABLE_OWNER_PID)
                }
            }

            $NumEntries = $Table.NumEntries

            Write-Verbose "GetExtendedProtoTable() OK - NumEntries: $NumEntries"

            $Offset = [IntPtr] ($TablePtr.ToInt64() + 4)

            For ($i = 0; $i -lt $NumEntries; $i++) {

                if ($UDP) {
                    if ($IpVersion -eq $AF_INET) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $script:MIB_UDPROW_OWNER_PID)
                        $LocalAddr = (New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr)).IPAddressToString
                    }
                    elseif ($IpVersion -eq $AF_INET6) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $script:MIB_UDP6ROW_OWNER_PID)
                        $LocalAddr = New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr, $TableEntry.LocalScopeId)
                    }
                }
                else {
                    if ($IpVersion -eq $AF_INET) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $script:MIB_TCPROW_OWNER_PID)
                        $LocalAddr = (New-Object -TypeName System.Net.IPAddress($TableEntry.LocalAddr)).IPAddressToString
                    }
                    elseif ($IpVersion -eq $AF_INET6) {
                        $TableEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Offset, [type] $script:MIB_TCP6ROW_OWNER_PID)
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
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value (Get-Process -PID $ProcessId -ErrorAction SilentlyContinue).ProcessName
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

function Convert-WlanXmlProfile {
    <#
    .SYNOPSIS
    Convert a WLAN XML profile to a custom PS object.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet takes a WLAN XML profile as an input, parses it, and return a custom object that contains the profile's key information, based on the type of authentication in use. For 802.1x profiles, it returns object(s) containing the detailed configuration. Only the main 802.1x authentication schemes are supported (see the 'Notes' section).

    .PARAMETER WlanProfile
    A string representing a WLAN profile as an XML document.

    .EXAMPLE
    PS C:\> Convert-WlanXmlProfile -WlanProfile $WlanProfile

    SSID           : wp2-access-point
    ConnectionType : ESS (Infrastructure)
    ConnectionMode : auto
    Authentication : WPA2PSK
    Encryption     : AES
    Dot1X          : False

    .EXAMPLE
    PS C:\> Convert-WlanXmlProfile -WlanProfile $WlanProfile

    SSID                  : eap-tls-access-point
    ConnectionType        : ESS (Infrastructure)
    ConnectionMode        : auto
    Authentication        : WPA2
    Encryption            : AES
    Dot1X                 : True
    AuthenticationModeRaw : user
    AuthenticationMode    : Use user credentials only.
    EapTypeId             : 13
    EapType               : EAP-TLS
    Eap                   : @{CredentialsSource=Certificate; ServerValidationDisablePrompt=True; ServerValidationDisablePromptComment=Authentication fails is the certificate is not trusted.; ServerValidationNames=; AcceptServerName=False; AcceptServerNameComment=The server name is not verified.; TrustedRootCAs=0563b8630d62d75abbc8ab1e4bdfb5a899b24d43; TrustedRootCAsComment=DigiCert Assured ID Root CA; PerformServerValidation=False; PerformServerValidationComment=Server validation is not performed.}

    .NOTES
    Supported EAP methods:
        Microsoft implements the following EAP methods: MS-EAP / MSCHAPv2 (26), TLS (13), PEAP (25), SIM (18), AKA (23), AKA' (50), TTLS (21), TEAP (55). In this function, we handle only TLS (13), PEAP (25), TTLS (21), and MSCHAPv2 (26).

    .LINK
    https://docs.microsoft.com/en-us/windows/win32/nativewifi/portal
    #>

    [CmdletBinding()]
    param(
        [ValidateNotNullOrEmpty()]
        [string] $WlanProfile
    )

    begin {
        function ConvertTo-Boolean {
            param([object] $Text)
            if ($null -eq $Text) { Write-Warning "$($MyInvocation.MyCommand.Name) | Null input, assuming False"; return $False }
            if ($Text.GetType() -like "*XmlElement") { $Text = $(if ([string]::IsNullOrEmpty($Text.innerText)) { $Text } else { $Text.innerText }) }
            try { [System.Convert]::ToBoolean($Text) } catch { Write-Warning "Failed to convert to boolean: $($Text)" }
        }

        function Get-ConnectionTypeName {
            param([string] $ConnectionType)
            if ([string]::IsNullOrEmpty($ConnectionType)) { return }
            $Enumeration = @{ "ESS" = "Infrastructure" ; "IBSS" = "Ad-hoc" }
            try { $Enumeration[$ConnectionType] } catch { Write-Warning "Unknown connection type: $($ConnectionType)" }
        }

        function Get-EapTypeName {
            param([string] $MethodType)
            if ([string]::IsNullOrEmpty($MethodType)) { return }
            $Enumeration = @{ "13" = "EAP-TLS" ; "18" = "EAP-SIM" ; "21" = "EAP-TTLS" ; "23" = "EAP-AKA" ; "25" = "PEAP" ; "26" = "MS-EAP" ; "29" = "EAP-MSCHAP-V2" ; "50" = "EAP-AKA'" ; "55" = "TEAP" }
            try { $Enumeration[$MethodType] } catch { "Unknown" }
        }

        function Get-CertificateName {
            param([string] $Thumbprint)
            if ([string]::IsNullOrEmpty($Thumbprint)) { ""; return }
            $Certificate = Get-ChildItem "Cert:\LocalMachine\Root\$($Thumbprint.Replace(' ', ''))" -ErrorAction SilentlyContinue
            if ($null -eq $Certificate) { "Unknown Certificate"; return }
            ($Certificate.Subject.Split(',')[0]).Split('=')[1]
        }

        function Get-AuthModeDescription {
            param([string] $AuthMode)
            if ([string]::IsNullOrEmpty($AuthMode)) { return }
            $Enumeration = @{ "machineOrUser" = "Use user credentials when a user is logged on, use machine credentials otherwise." ; "machine" = "Use machine credentials only." ; "user" = "Use user credentials only." ; "guest" = "Use guest (empty) credentials only." }
            try { $Enumeration[$AuthMode] } catch { "Unknown" }
        }

        function Get-ServerValidationPromptDescription {
            param([boolean] $PromptDisabled)
            if ($PromptDisabled) { "Authentication fails is the certificate is not trusted." } else { "The user can be prompted for server validation." }
        }

        function Get-ServerValidationDescription {
            param([boolean] $PerformValidation)
            if ($PerformValidation) { "Server validation is performed." } else { "Server validation is not performed." }
        }

        function Get-AcceptServerNameDescription {
            param([boolean] $AcceptServerName)
            if ($AcceptServerName) { "The server name is verified." } else { "The server name is not verified." }
        }

        function Get-UseWinLogonCredentialsDescription {
            param([boolean] $UseWinLogonCredentials)
            if ($UseWinLogonCredentials) { "EAP MS-CHAPv2 obtains credentials from winlogon." } else { "EAP MS-CHAPv2 obtains credentials from the user." }
        }

        function Get-TrustedRootCA {
            param([System.Xml.XmlElement] $Node, [string] $Name)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $TrustedRootCAs = $Node.GetElementsByTagName($Name) | ForEach-Object { $_.InnerText.Replace(" ", "") }
            $TrustedRootCANames = $TrustedRootCAs | ForEach-Object { Get-CertificateName -Thumbprint $_ }
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Thumbprints" -Value ($TrustedRootCAs -join ", ")
            $Result | Add-Member -MemberType "NoteProperty" -Name "DisplayNames" -Value ($TrustedRootCANames -join ", ")
            $Result
        }

        function Get-EapType {
            param([System.Xml.XmlElement] $Node)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $EapTypeId = $(if ([string]::IsNullOrEmpty($Node.Type.InnerText)) { $Node.Type } else { $Node.Type.InnerText })
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $EapTypeId
            $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value (Get-EapTypeName -MethodType $EapTypeId)
            $Result
        }

        function Get-EapTlsConfig {
            param([System.Xml.XmlElement] $Node)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $CredentialsSource = $(
                if ($null -ne $Node.EapType.CredentialsSource.SmartCard) { "SmartCard" }
                elseif ($null -ne $Node.EapType.CredentialsSource.CertificateStore) { "Certificate" }
            )
            $ServerValidationNode = $Node.EapType.ServerValidation
            $ServerValidationDisablePrompt = ConvertTo-Boolean -Text $ServerValidationNode.DisableUserPromptForServerValidation
            $AcceptServerName = ConvertTo-Boolean -Text $Node.EapType.AcceptServerName
            $PerformServerValidation = ConvertTo-Boolean -Text $Node.EapType.PerformServerValidation
            $TrustedRootCAs = Get-TrustedRootCA -Node $ServerValidationNode -Name "TrustedRootCA"
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "CredentialsSource" -Value $CredentialsSource
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePrompt" -Value $ServerValidationDisablePrompt
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePromptDescription" -Value (Get-ServerValidationPromptDescription -PromptDisabled $ServerValidationDisablePrompt)
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationNames" -Value $ServerValidationNode.ServerNames
            $Result | Add-Member -MemberType "NoteProperty" -Name "AcceptServerName" -Value $AcceptServerName
            $Result | Add-Member -MemberType "NoteProperty" -Name "AcceptServerNameDescription" -Value (Get-AcceptServerNameDescription -AcceptServerName $AcceptServerName)
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAs" -Value $TrustedRootCAs.Thumbprints
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAsDescription" -Value $TrustedRootCAs.DisplayNames
            $Result | Add-Member -MemberType "NoteProperty" -Name "PerformServerValidation" -Value $PerformServerValidation
            $Result | Add-Member -MemberType "NoteProperty" -Name "PerformServerValidationDescription" -Value (Get-ServerValidationDescription -PerformValidation $PerformServerValidation)
            $Result
        }

        function Get-EapTtlsConfig {
            param([System.Xml.XmlElement] $Node)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $ServerValidationNode = $Node.ServerValidation
            $ServerValidationDisablePrompt = ConvertTo-Boolean -Text $ServerValidationNode.DisablePrompt
            $TrustedRootCAs = Get-TrustedRootCA -Node $ServerValidationNode -Name "TrustedRootCAHash"
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePrompt" -Value $ServerValidationDisablePrompt
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePromptDescription" -Value (Get-ServerValidationPromptDescription -PromptDisabled $ServerValidationDisablePrompt)
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationNames" -Value $ServerValidationNode.ServerNames
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAs" -Value $TrustedRootCAs.Thumbprints
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAsDescription" -Value $TrustedRootCAs.DisplayNames
            $Result
        }

        function Get-EapPeapConfig {
            param([System.Xml.XmlElement] $Node)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $ServerValidationNode = $Node.EapType.ServerValidation
            $ServerValidationDisablePrompt = ConvertTo-Boolean -Text $ServerValidationNode.DisableUserPromptForServerValidation
            $TrustedRootCAs = Get-TrustedRootCA -Node $ServerValidationNode -Name "TrustedRootCA"
            $AcceptServerName = ConvertTo-Boolean -Text $Node.EapType.PeapExtensions.AcceptServerName
            $PerformServerValidation = ConvertTo-Boolean -Text $Node.EapType.PeapExtensions.PerformServerValidation
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePrompt" -Value $ServerValidationDisablePrompt
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationDisablePromptDescription" -Value (Get-ServerValidationPromptDescription -PromptDisabled $ServerValidationDisablePrompt)
            $Result | Add-Member -MemberType "NoteProperty" -Name "ServerValidationNames" -Value $ServerValidationNode.ServerNames
            $Result | Add-Member -MemberType "NoteProperty" -Name "AcceptServerName" -Value $AcceptServerName
            $Result | Add-Member -MemberType "NoteProperty" -Name "AcceptServerNameDescription" -Value (Get-AcceptServerNameDescription -AcceptServerName $AcceptServerName)
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAs" -Value $TrustedRootCAs.Thumbprints
            $Result | Add-Member -MemberType "NoteProperty" -Name "TrustedRootCAsDescription" -Value $TrustedRootCAs.DisplayNames
            $Result | Add-Member -MemberType "NoteProperty" -Name "PerformServerValidation" -Value $PerformServerValidation
            $Result | Add-Member -MemberType "NoteProperty" -Name "PerformServerValidationDescription" -Value (Get-ServerValidationDescription -PerformValidation $PerformServerValidation)
            $Result
        }

        function Get-EapMsChapv2Config {
            param([System.Xml.XmlElement] $Node)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            $UseWinLogonCredentials = ConvertTo-Boolean -Text $Node.EapType.UseWinLogonCredentials
            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "UseWinLogonCredentials" -Value $UseWinLogonCredentials
            $Result | Add-Member -MemberType "NoteProperty" -Name "UseWinLogonCredentialsDescription" -Value (Get-UseWinLogonCredentialsDescription -UseWinLogonCredentials $UseWinLogonCredentials)
            $Result
        }

        function Get-EapConfig {
            param([System.Xml.XmlElement] $Node, [string] $Type)
            if ($null -eq $Node) { Write-Warning "$($MyInvocation.MyCommand.Name) | Input node is null."; return }
            switch ($Type) {
                "13" {
                    Get-EapTlsConfig -Node $Node.Eap
                }
                "21" {
                    Get-EapTtlsConfig -Node $Node.EapTtls
                }
                "25" {
                    Get-EapPeapConfig -Node $Node.Eap
                }
                "26" {
                    Get-EapMsChapv2Config -Node $Node.Eap
                }
                default {
                    Write-Warning "$($MyInvocation.MyCommand.Name) | Unsupported EAP type: $($Type)"
                }
            }
        }
    }

    process {
        if ([string]::IsNullOrEmpty($WlanProfile)) { Write-Warning "$($MyInvocation.MyCommand.Name) | Failed to get content: $($ProfileFileItem.FullName)"; return }
        try { $XmlFile = [xml] $WlanProfile } catch { Write-Warning "$($MyInvocation.MyCommand.Name) | Failed to parse XML: $($ProfileFileItem.FullName)"; return }

        $WifiProfiles = $XmlFile.GetElementsByTagName("WLANProfile")

        foreach ($WifiProfile in $WifiProfiles) {

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "SSID" -Value $WifiProfile.SSIDConfig.SSID.name
            $Result | Add-Member -MemberType "NoteProperty" -Name "ConnectionType" -Value "$($WifiProfile.connectionType) ($(Get-ConnectionTypeName -ConnectionType $WifiProfile.connectionType))"
            $Result | Add-Member -MemberType "NoteProperty" -Name "ConnectionMode" -Value $(if (($WifiProfile.connectionType -eq "ESS") -and ([string]::IsNullOrEmpty($WifiProfile.connectionMode))) { "auto" } else { $WifiProfile.connectionMode })

            $SecurityConfig = $WifiProfile.MSM.security
            if ($null -eq $SecurityConfig) { Write-Warning "SSID: '$($Result.SSID)' | 'Security' node not found."; return }
            $UseDot1X = ConvertTo-Boolean -Text $SecurityConfig.authEncryption.useOneX

            $Result | Add-Member -MemberType "NoteProperty" -Name "Authentication" -Value $SecurityConfig.authEncryption.authentication
            $Result | Add-Member -MemberType "NoteProperty" -Name "Encryption" -Value $SecurityConfig.authEncryption.encryption
            $Result | Add-Member -MemberType "NoteProperty" -Name "PassPhrase" -Value $SecurityConfig.sharedKey.keyMaterial
            $Result | Add-Member -MemberType "NoteProperty" -Name "Dot1X" -Value $UseDot1X

            # If 802.1x is not used, we can return the profile straight away.
            if (-not $UseDot1X) { $Result; return }

            # The OneX node holds the 802.1x configuration. When 'useOneX' is set to true, this node must
            # be present in the 'WLANProfile' XML document. All the information regarding the 802.1x
            # configuration can be found within this node.
            $OneXNode = $SecurityConfig.OneX
            if ($null -eq $OneXNode) { Write-Warning "SSID: '$($Result.SSID)' | 'OneX' node not found."; return }
            $AuthenticationMode = $(if ([string]::IsNullOrEmpty($OneXNode.authMode)) { "machineOrUser" } else { $OneXNode.authMode })

            $Result | Add-Member -MemberType "NoteProperty" -Name "AuthenticationMode" -Value $AuthenticationMode
            $Result | Add-Member -MemberType "NoteProperty" -Name "AuthenticationModeDescription" -Value (Get-AuthModeDescription -AuthMode $AuthenticationMode)

            # Get EAP type from the EapMethod element.
            $EapType = Get-EapType -Node $OneXNode.EAPConfig.EapHostConfig.EapMethod
            if ($null -eq $EapType) { Write-Warning "SSID: '$($Result.SSID)' | EAP type not found."; return }

            $Result | Add-Member -MemberType "NoteProperty" -Name "EapTypeId" -Value $EapType.Id
            $Result | Add-Member -MemberType "NoteProperty" -Name "EapType" -Value $EapType.Name

            # The 802.1x configuration can be stored either in "clear" text or as a binary blob. We only
            # handle the case the configuration is stored in "clear" text. Otherwise, the ignore the Wi-Fi
            # profile and print a warning message.
            $ConfigNode = $OneXNode.EAPConfig.EapHostConfig.Config
            if ($null -eq $ConfigNode) { Write-Warning "SSID: '$($Result.SSID)' | 'Config' node not found."; return }

            $EapConfig = Get-EapConfig -Node $ConfigNode -Type $EapType.Id
            if ($null -eq $EapConfig) { Write-Warning "SSID: '$($Result.SSID)' | Failed to parse EAP configuration."; return }

            $Result | Add-Member -MemberType "NoteProperty" -Name "Eap" -Value $EapConfig
            $Result | Add-Member -MemberType "NoteProperty" -Name "EapStr" -Value ($EapConfig | Format-List | Out-String).Trim()

            # In some cases, there is an additional EAP layer. This may happen when, for example, the initial
            # EAP layer is PEAP, and then MS-CHAPv2 is used to authenticate the user. In this case, we parse
            # the next 'Eap' node, and add the configuration to the object. Otherwise, we simply return the
            # the result object and stop there.
            if ($null -eq $ConfigNode.Eap.EapType.Eap) {
                Write-Verbose "SSID: '$($Result.SSID)' | There is no inner EAP configuration."
                $Result
                return
            }

            $InnerEapType = Get-EapType -Node $ConfigNode.Eap.EapType.Eap
            if ($null -eq $InnerEapType) { Write-Warning "SSID: '$($Result.SSID)' | Inner EAP type not found."; return }

            $Result | Add-Member -MemberType "NoteProperty" -Name "InnerEapTypeId" -Value $InnerEapType.Id
            $Result | Add-Member -MemberType "NoteProperty" -Name "InnerEapType" -Value $InnerEapType.Name

            $InnerEapConfig = Get-EapConfig -Node $ConfigNode.Eap.EapType -Type $InnerEapType.Id
            if ($null -eq $InnerEapConfig) { Write-Warning "SSID: '$($Result.SSID)' | Failed to parse inner EAP configuration."; return }

            $Result | Add-Member -MemberType "NoteProperty" -Name "InnerEap" -Value $InnerEapConfig
            $Result | Add-Member -MemberType "NoteProperty" -Name "InnerEapStr" -Value ($InnerEapConfig | Format-List | Out-String).Trim()

            $Result
        }
    }
}

function Get-WlanProfileList {
    <#
    .SYNOPSIS
    Enumerates the saved Wifi profiles.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet leverages the WLAN API to enumerate saved Wi-Fi profiles. WLAN profiles are stored as XML document. For each profile, the helper cmdlet 'Convert-WlanXmlProfile' is invoked in order to transform this XML document into a custom PS object that is easier to check. In case of a WPA2-PSK profile, the clear-text passphrase will be returned (if possible). In case of a 802.1x profile, detailed information will be returned, depending of the type of authentication.

    .EXAMPLE
    PS C:\> Get-WlanProfileList

    SSID           : wpa2-psk-ap
    ConnectionType : ESS (Infrastructure)
    ConnectionMode : manual
    Authentication : WPA2PSK
    Encryption     : AES
    PassPhrase     : ClearTextPassphraseHere
    Dot1X          : False

    SSID                          : ttls-ap
    ConnectionType                : ESS (Infrastructure)
    ConnectionMode                : auto
    Authentication                : WPA2
    Encryption                    : AES
    PassPhrase                    :
    Dot1X                         : True
    AuthenticationMode            : machineOrUser
    AuthenticationModeDescription : Use user credentials when a user is logged on, use machine credentials otherwise.
    EapTypeId                     : 21
    EapType                       : EAP-TTLS
    Eap                           : @{ServerValidationDisablePrompt=False; ServerValidationDisablePromptDescription=The user can be prompted for server validation.; ServerValidationNames=;
                                    TrustedRootCAs=8f43288ad272f3103b6fb1428485ea3014c0bcfe; TrustedRootCAsDescription=Microsoft Root Certificate Authority 2011}
    EapStr                        : ServerValidationDisablePrompt            : False
                                    ServerValidationDisablePromptDescription : The user can be prompted for server validation.
                                    ServerValidationNames                    :
                                    TrustedRootCAs                           : 8f43288ad272f3103b6fb1428485ea3014c0bcfe
                                    TrustedRootCAsDescription                : Microsoft Root Certificate Authority 2011
    #>

    [CmdletBinding()]
    param()

    try {

        [IntPtr] $ClientHandle = [IntPtr]::Zero
        [UInt32] $NegotiatedVersion = 0
        [UInt32] $ClientVersion = 2 # Client version for Windows Vista and Windows Server 2008
        $Result = $script:Wlanapi::WlanOpenHandle($ClientVersion, [IntPtr]::Zero, [ref] $NegotiatedVersion, [ref] $ClientHandle)
        if ($Result -ne 0) {
            Write-Warning "$($MyInvocation.MyCommand.Name) | WlanOpenHandle() failed (Err: $($Result))"
            return
        }

        [IntPtr] $InterfaceListPtr = [IntPtr]::Zero
        $Result = $script:Wlanapi::WlanEnumInterfaces($ClientHandle, [IntPtr]::Zero, [ref] $InterfaceListPtr)
        if ($Result -ne 0) {
            Write-Warning "$($MyInvocation.MyCommand.Name) | WlanEnumInterfaces() failed (Err: $($Result))"
            $script:Wlanapi::WlanCloseHandle($ClientHandle, [IntPtr]::Zero)
            return
        }

        $NumberOfInterfaces = [Runtime.InteropServices.Marshal]::ReadInt32($InterfaceListPtr)
        Write-Verbose "$($MyInvocation.MyCommand.Name) | Number of WLAN interfaces: $($NumberOfInterfaces)"

        $WlanInterfaceInfoPtr = [IntPtr] ($InterfaceListPtr.ToInt64() + 8) # dwNumberOfItems + dwIndex

        for ($i = 0; $i -lt $NumberOfInterfaces; $i++) {

            $WlanInterfaceInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WlanInterfaceInfoPtr, [type] $script:WLAN_INTERFACE_INFO)

            [IntPtr] $ProfileListPtr = [IntPtr]::Zero
            $Result = $script:Wlanapi::WlanGetProfileList($ClientHandle, $WlanInterfaceInfo.InterfaceGuid, [IntPtr]::Zero, [ref] $ProfileListPtr)
            if ($Result -eq 0) {

                $NumberOfProfiles = [Runtime.InteropServices.Marshal]::ReadInt32($ProfileListPtr)
                Write-Verbose "$($MyInvocation.MyCommand.Name) | Number of WLAN profiles: $($NumberOfProfiles)"

                $WlanProfileInfoPtr = [IntPtr] ($ProfileListPtr.ToInt64() + 8) # dwNumberOfItems + dwIndex

                for ($j = 0; $j -lt $NumberOfProfiles; $j++) {

                    $WlanProfileInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WlanProfileInfoPtr, [type] $script:WLAN_PROFILE_INFO)

                    [String] $ProfileXml = ""
                    [UInt32] $WlanProfileFlags = 4 # WLAN_PROFILE_GET_PLAINTEXT_KEY
                    [UInt32] $WlanProfileAccessFlags = 0
                    $Result = $script:Wlanapi::WlanGetProfile($ClientHandle, $WlanInterfaceInfo.InterfaceGuid, $WlanProfileInfo.ProfileName, [IntPtr]::Zero, [ref] $ProfileXml, [ref] $WlanProfileFlags, [ref] $WlanProfileAccessFlags)
                    if ($Result -eq 0) {
                        Convert-WlanXmlProfile -WlanProfile $ProfileXml
                    }
                    else {
                        Write-Warning "$($MyInvocation.MyCommand.Name) | WlanGetProfile() failed (Err: $($Result))"
                    }

                    $WlanProfileInfoPtr = [IntPtr] ($WlanProfileInfoPtr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($WlanProfileInfo))
                }

                $script:Wlanapi::WlanFreeMemory($ProfileListPtr)
            }
            else {
                Write-Warning "$($MyInvocation.MyCommand.Name) | WlanGetProfileList() failed (Err: $($Result))"
            }

            $WlanInterfaceInfoPtr = [IntPtr] ($WlanInterfaceInfoPtr.ToInt64() + [System.Runtime.InteropServices.Marshal]::SizeOf($WlanInterfaceInfo))
        }

        $null = $script:Wlanapi::WlanFreeMemory($InterfaceListPtr)
        $null = $script:Wlanapi::WlanCloseHandle($ClientHandle, [IntPtr]::Zero)
    }
    catch {
        # The Wlan API probably does not exist on this machine.
        if ($Error[0]) { Write-Warning $Error[0] }
    }
}