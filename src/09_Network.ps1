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