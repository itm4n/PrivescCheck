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

    Get-NetworkAdapter | Where-Object { $_.Type -eq "Ethernet" -or $_.Type -eq "IEEE80211" } | Select-Object -Property Name,FriendlyName,Type,Status,DnsSuffix,Description,PhysicalAddress,Flags,IPv6,IPv4,Gateway,DHCPv4Server,DHCPv6Server,DnsServers,DNSSuffixList
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
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevel::None })
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
        $WindowsVersion = Get-WindowsVersionFromRegistry
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
    $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevel::None })
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

function Invoke-NetworkFirewallProfileCheck {
    <#
    .SYNOPSIS
    Check whether the Windows firewall is enabled on each network profile (domain, private, public).

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet relies on the helper function Get-NetworkFirewallActiveProfile to get the state of Windows firewall for each network profile. Then, it simply check whether it is enabled on each of them.
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    process {
        $Severity = $BaseSeverity

        $DomainProfile = Get-NetworkFirewallActiveProfile -Profile "Domain"
        $PrivateProfile = Get-NetworkFirewallActiveProfile -Profile "Private"
        $PublicProfile = Get-NetworkFirewallActiveProfile -Profile "Public"

        $AllResults = @($DomainProfile, $PrivateProfile, $PublicProfile)

        $ProfilesWithFirewallDisabled = $AllResults | Where-Object { $_.Enabled -eq $false }
        if ($null -eq $ProfilesWithFirewallDisabled) {
            $Severity = $script:SeverityLevel::None
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $Severity
        $CheckResult
    }
}