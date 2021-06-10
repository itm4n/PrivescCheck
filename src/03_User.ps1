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
    Enumerates groups the current user belongs to

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Enumerates groups the current user belongs to.
    
    .EXAMPLE
    PS C:\> Invoke-UserGroupsCheck

    Name                                   Type           SID
    ----                                   ----           ---
    DESKTOP-E1BRKMO\None                   Group          S-1-5-21-3539966466-3447975095-3309057754-513
    Everyone                               WellKnownGroup S-1-1-0
    BUILTIN\Users                          Alias          S-1-5-32-545
    BUILTIN\Performance Log Users          Alias          S-1-5-32-559
    NT AUTHORITY\INTERACTIVE               WellKnownGroup S-1-5-4
    CONSOLE LOGON                          WellKnownGroup S-1-2-1
    NT AUTHORITY\Authenticated Users       WellKnownGroup S-1-5-11
    NT AUTHORITY\This Organization         WellKnownGroup S-1-5-15
    NT AUTHORITY\Local account             WellKnownGroup S-1-5-113
    NT AUTHORITY\LogonSessionId_0_205547   LogonSession   S-1-5-5-0-205547
    LOCAL                                  WellKnownGroup S-1-2-0
    NT AUTHORITY\NTLM Authentication       WellKnownGroup S-1-5-64-10
    Mandatory Label\Medium Mandatory Level Label          S-1-16-8192
    #>
    
    [CmdletBinding()] Param()

    Get-UserGroups | Select-Object Name,Type,SID
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