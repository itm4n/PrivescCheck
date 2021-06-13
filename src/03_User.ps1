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

    Get-TokenInformationGroups -InformationClass Groups | Select-Object Name,Type,SID
}

function Invoke-UserRestrictedSidsCheck {
    <#
    .SYNOPSIS
    Enumerates restricted SIDs associated to the current user's token if any.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    This check leverages the Get-TokenInformationGroups helper function to list the restricted SIDs that are associated to the current user's Token. This may provide some useful information in case the current token is WRITE RESTRICTED.
    
    .EXAMPLE
    PS C:\> Invoke-UserRestrictedSidsCheck

    Name                                Type           SID
    ----                                ----           ---
    NT SERVICE\CoreMessagingRegistrar   WellKnownGroup S-1-5-80-1021139062-1866602279-1255292388-1008060685-2498416891
    NT SERVICE\DPS                      WellKnownGroup S-1-5-80-2970612574-78537857-698502321-558674196-1451644582
    NT SERVICE\NcdAutoSetup             WellKnownGroup S-1-5-80-639065985-1709096039-2702309040-2770678766-2981280942
    NT SERVICE\pla                      WellKnownGroup S-1-5-80-2661322625-712705077-2999183737-3043590567-590698655
    Everyone                            WellKnownGroup S-1-1-0
    NT AUTHORITY\LogonSessionId_0_78600 LogonSession   S-1-5-5-0-78600
    NT AUTHORITY\WRITE RESTRICTED       WellKnownGroup S-1-5-33
    #>

    [CmdletBinding()] Param()

    Get-TokenInformationGroups -InformationClass RestrictedSids | Select-Object Name,Type,SID
}

function Invoke-UserPrivilegesCheck {
    <#
    .SYNOPSIS
    Enumerates privileges and identifies the ones that can be used for privilege escalation.

    Author: @itm4n
    License: BSD 3-Clause
    
    .DESCRIPTION
    Enumerates all the privileges of the current user thanks to the Get-UserPrivileges helper function, and compares them against a list of privileges that can be leveraged for local privilege escalation.
    
    .EXAMPLE
    Name                    State   Description                               Exploitable
    ----                    -----   -----------                               -----------
    SeChangeNotifyPrivilege Enabled Bypass traverse checking                        False
    SeImpersonatePrivilege  Enabled Impersonate a client after authentication        True
    #>

    [CmdletBinding()] Param()    

    $HighPotentialPrivileges = "SeAssignPrimaryTokenPrivilege", "SeImpersonatePrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeLoadDriverPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeBackupPrivilege", "SeManageVolumePrivilege"

    Get-TokenInformationPrivileges | ForEach-Object {
        $_ | Add-Member -MemberType "NoteProperty" -Name "Exploitable" -Value ($HighPotentialPrivileges -contains $_.Name) -PassThru
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