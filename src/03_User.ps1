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
    
    [CmdletBinding()] Param()
    
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $CurrentUser.Name
    $Result | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $CurrentUser.User
    $Result
}

function Invoke-UserGroupsCheck {
    <#
    .SYNOPSIS
    Enumerates groups the current user belongs to except default and low-privileged ones

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    For each group the current user belongs to, a custom object is returned, indicating the name and the SID of the group.
    
    .EXAMPLE
    PS C:\> Invoke-UserGroupsCheck

    Name                            SID                                         
    ----                            ---                                         
    BUILTIN\Remote Management Users S-1-5-32-580 

    .LINK
    https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
    #>
    
    [CmdletBinding()] Param()

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

    foreach ($Group in $Groups) {

        $GroupSid = $Group.Value 

        if (-not ($IgnoredGroupSids -contains $GroupSid)) {

            $KnownSid = $false 
            foreach ($Pattern in $IgnoredGroupSidPatterns) {
                if ($GroupSid -like $Pattern) {
                    Write-Verbose "Known SID pattern: $GroupSid"
                    $KnownSid = $true
                    break   
                }
            }

            if (-not $KnownSid) {

                try {
                    $GroupName = ($Group.Translate([System.Security.Principal.NTAccount])).Value
                }
                catch {
                    $GroupName = "N/A"
                }

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $GroupName
                $Result | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $GroupSid
                $Result
            }
        }
        else {
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
    Enumerates all the privileges of the current user thanks to the custom Get-UserPrivileges function. Then, it checks whether each privilege is contained in a pre-defined list of high value privileges. 
    
    .EXAMPLE
    Name                   State   Description
    ----                   -----   -----------
    SeImpersonatePrivilege Enabled Impersonate a client after authentication
    #>

    [CmdletBinding()] Param()    

    $HighPotentialPrivileges = "SeAssignPrimaryTokenPrivilege", "SeImpersonatePrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeLoadDriverPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeBackupPrivilege", "SeManageVolumePrivilege"

    $CurrentPrivileges = Get-UserPrivileges

    foreach ($Privilege in $CurrentPrivileges) {

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
    Environment variables may contain sensitive information such as database credentials or API keys.
    #>

    [CmdletBinding()] Param() 

    [String[]] $Keywords = "key", "passw", "secret", "pwd", "creds", "credential", "api"

    Get-ChildItem -Path env: | ForEach-Object {

        $EntryName = $_.Name
        $EntryValue = $_.Value 
        $CheckVal = "$($_.Name) $($_.Value)"
        
        foreach ($Keyword in $Keywords) {

            if ($CheckVal -Like "*$($Keyword)*") {

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $EntryName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Value" -Value $EntryValue
                $Result | Add-Member -MemberType "NoteProperty" -Name "Keyword" -Value $Keyword
                $Result
            }
        }
    }
}