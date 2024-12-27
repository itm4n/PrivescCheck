function Invoke-UserCheck {
    <#
    .SYNOPSIS
    Get various information about the current user.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Get various information about the current user.

    .EXAMPLE
    PS C:\> Invoke-UserCheck

    Name             : DESKTOP-AAAAAAAA\Lab-User
    SID              : S-1-5-21-3539966466-3447975095-3309057754-1002
    Integrity        : Medium Mandatory Level (S-1-16-8192)
    SessionId        : 1
    TokenId          : 00000000-0ff0ebc5
    AuthenticationId : 00000000-0003268d
    OriginId         : 00000000-000003e7
    ModifiedId       : 00000000-00032748
    Source           : User32  (00000000-000323db)
    #>

    [CmdletBinding()]
    param()

    $TokenUser = Get-TokenInformationUser
    $TokenIntegrityLevel = Get-TokenInformationIntegrityLevel
    $TokenSessionId = Get-TokenInformationSessionId
    $TokenStatistics = Get-TokenInformationStatistic
    $TokenOrigin = Get-TokenInformationOrigin
    $TokenSource = Get-TokenInformationSource

    $TokenSourceName = [System.Text.Encoding]::ASCII.GetString($TokenSource.SourceName).Trim([char]0) -replace " ", ""

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $TokenUser.DisplayName
    $Result | Add-Member -MemberType "NoteProperty" -Name "SID" -Value $TokenUser.SID
    $Result | Add-Member -MemberType "NoteProperty" -Name "IntegrityLevel" -Value "$($TokenIntegrityLevel.Name) ($($TokenIntegrityLevel.SID))"
    $Result | Add-Member -MemberType "NoteProperty" -Name "SessionId" -Value $TokenSessionId
    $Result | Add-Member -MemberType "NoteProperty" -Name "TokenId" -Value "$('{0:x8}' -f $TokenStatistics.TokenId.HighPart)-$('{0:x8}' -f $TokenStatistics.TokenId.LowPart)"
    $Result | Add-Member -MemberType "NoteProperty" -Name "AuthenticationId" -Value "$('{0:x8}' -f $TokenStatistics.AuthenticationId.HighPart)-$('{0:x8}' -f $TokenStatistics.AuthenticationId.LowPart)"
    $Result | Add-Member -MemberType "NoteProperty" -Name "OriginId" -Value "$('{0:x8}' -f $TokenOrigin.OriginatingLogonSession.HighPart)-$('{0:x8}' -f $TokenOrigin.OriginatingLogonSession.LowPart)"
    $Result | Add-Member -MemberType "NoteProperty" -Name "ModifiedId" -Value "$('{0:x8}' -f $TokenStatistics.ModifiedId.HighPart)-$('{0:x8}' -f $TokenStatistics.ModifiedId.LowPart)"
    $Result | Add-Member -MemberType "NoteProperty" -Name "Source" -Value $(if ([String]::IsNullOrEmpty($TokenSourceName)) { "" } else { "$($TokenSourceName) ($('{0:x8}' -f $TokenSource.SourceIdentifier.HighPart)-$('{0:x8}' -f $TokenSource.SourceIdentifier.LowPart))" })
    $Result
}

function Invoke-UserGroupCheck {
    <#
    .SYNOPSIS
    Enumerates groups the current user belongs to

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Enumerates groups the current user belongs to.

    .EXAMPLE
    PS C:\> Invoke-UserGroupCheck

    Name                                   Type           SID
    ----                                   ----           ---
    DESKTOP-AAAAAAA\None                   Group          S-1-5-21-3539966466-3447975095-3309057754-513
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

    [CmdletBinding()]
    param()

    Get-TokenInformationGroup -InformationClass Groups | Select-Object Name,Type,SID
}

function Invoke-UserRestrictedSidCheck {
    <#
    .SYNOPSIS
    Enumerates restricted SIDs associated to the current user's token if any.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This check leverages the Get-TokenInformationGroup helper function to list the restricted SIDs that are associated to the current user's Token. This may provide some useful information in case the current token is WRITE RESTRICTED.

    .EXAMPLE
    PS C:\> Invoke-UserRestrictedSidCheck

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

    [CmdletBinding()]
    param()

    Get-TokenInformationGroup -InformationClass RestrictedSids | Select-Object Name,Type,SID
}

function Invoke-UserPrivilegeCheck {
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

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    $Vulnerable = $false
    $Privileges = Get-TokenInformationPrivilege

    foreach ($Privilege in $Privileges) {
        $Exploitable = $($script:GlobalConstant.ExploitablePrivileges -contains $Privilege.Name)
        if ($Exploitable) { $Vulnerable = $true }
        $Privilege | Add-Member -MemberType "NoteProperty" -Name "Exploitable" -Value $Exploitable
    }

    $CheckResult = New-Object -TypeName PSObject
    $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Privileges
    $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Vulnerable) { $BaseSeverity } else { $script:SeverityLevel::None })
    $CheckResult
}

function Invoke-UserPrivilegeGpoCheck {
    <#
    .SYNOPSIS
    Check whether the current user is granted privileges, through a group policy, that can be leveraged for local privilege escalation.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet enumerates cached group policy files that define rules for granting users specific privileges. When UAC is enabled, those privileges might not be present in the current user's token. In that case, opening a privileged process is required. The aim of this check is to detect such privileges.

    .EXAMPLE
    PS C:\> Invoke-UserPrivilegeGpoCheck

    Privilege   : SeRelabelPrivilege
    IdentitySid : S-1-5-21-1765376299-219387937-761915811-513
    Identity    : FOUNDATION\Domain Users
    PolicyFile  : C:\Windows\System32\GroupPolicy\DataStore\0\sysvol\foundation.local\Policies\{0629F62E-98C3-4497-BBF2-03F62B04D761}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf

    .LINK
    https://decoder.cloud/2024/05/30/abusing-the-serelabelprivilege/
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
        $PolicyCacheFolderPath = Join-Path -Path $env:windir -ChildPath "System32\GroupPolicy\DataStore"
        $CurrentUserSids = Get-CurrentUserSid
    }

    process {
        $PolicyFiles = [object[]](Get-ChildItem -Path $PolicyCacheFolderPath -Recurse -Filter "GptTmpl.inf" -ErrorAction SilentlyContinue)

        foreach ($PolicyFile in $PolicyFiles) {

            if ([String]::IsNullOrEmpty($PolicyFile.FullName)) { continue }
            $Candidates = Select-String -Path $PolicyFile.FullName -Pattern "Privilege = " -AllMatches

            foreach ($Candidate in $Candidates) {

                # In a cached GPO file, a privilege policy entry is defined like this:
                # SeSomePrivilege = *S-1-2-3-123,*S-1-2-3-456,*S-1-2-3-789
                if ($Candidate.Line -match "^([a-zA-Z]+Privilege) = ([0-9-,*S]+)`$") {

                    # Extract privilege name and SID list from matched line.
                    $PrivilegeName = $Matches[1]
                    $IdentityList = $Matches[2]

                    # Check if the privilege is exploitable, ignore if not.
                    if ($script:GlobalConstant.ExploitablePrivileges -notcontains $PrivilegeName) { continue }

                    # The identity list is represented like this:
                    # *S-1-2-3-123,*S-1-2-3-456,*S-1-2-3-789
                    $Identities = $IdentityList.Split(',') | ForEach-Object { $_ -replace '\*','' }

                    foreach ($Identity in $Identities) {

                        if ($CurrentUserSids -contains $Identity) {

                            $Result = New-Object -TypeName PSObject
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Privilege" -Value $PrivilegeName
                            $Result | Add-Member -MemberType "NoteProperty" -Name "IdentitySid" -Value $Identity
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Identity" -Value $(Convert-SidToName -Sid $Identity)
                            $Result | Add-Member -MemberType "NoteProperty" -Name "PolicyFile" -Value $PolicyFile.FullName
                            $AllResults += $Result
                        }
                    }
                }
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults.Count -gt 0) { $BaseSeverity } else { $script:SeverityLevel::None })
        $CheckResult
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Invoke-UserEnvironmentCheck {
    <#
    .SYNOPSIS
    Checks for sensitive data in environment variables

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Environment variables may contain sensitive information such as database credentials or API keys.
    #>

    [CmdletBinding()]
    param()

    Get-ChildItem -Path env: | ForEach-Object {

        $EntryName = $_.Name
        $EntryValue = $_.Value
        $CheckVal = "$($_.Name) $($_.Value)"

        foreach ($Keyword in $script:GlobalConstant.KeywordsOfInterest) {

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