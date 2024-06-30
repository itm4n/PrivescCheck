function Invoke-WinLogonCredentialCheck {
    <#
    .SYNOPSIS
    Checks credentials stored in the Winlogon registry key

    Author: @itm4n, @nurfed1
    License: BSD 3-Clause

    .DESCRIPTION
    Windows has a registry setting to enable automatic logon. You can set a username and a password in order to automatically initiate a user session on system startup. The password is stored in clear text so it's easy to extract it. This function returns a set of credentials only if the password field is not empty.

    .PARAMETER Remote
    Set this flag if you want to search for GPP files in the SYSVOL share of your primary Domain Controller (request from Issue #19).

    .EXAMPLE
    PS C:\> Invoke-WinLogonCredentialCheck

    Domain Username  Password
    ------ --------  --------
           lab-admin

    .EXAMPLE
    PS C:\> Invoke-WinLogonCredentialCheck -Remote

    FilePath        : \\domain.tld\SYSVOL\domain.tld\Policies\{20b62124-4b0a-4cbe-a5a2-94eaf4267834}\Machine\Preferences\Registry\Registry.xml
    Domains         : Domain-Test1
    Usernames       : Username-Test1, Username-Test1-del, Username-Test1-Create, Username-Test1-replace, Username-Test1
    Passwords       : Password-Test1
    AutoAdminLogons : 1

    .LINK
    https://support.microsoft.com/en-us/help/324737/how-to-turn-on-automatic-logon-in-windows
    https://github.com/itm4n/PrivescCheck/issues/19
    #>

    [CmdletBinding()]
    param(
        [switch] $Remote = $false,
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
    }

    process {
        if ($Remote) {

            $GppPath = "\\$($Env:USERDNSDOMAIN)\SYSVOL"
            Write-Verbose "Target search path is: $($GppPath)"

            $CachedGPPFiles = Get-ChildItem -Path $GppPath -Recurse -Include 'Registry.xml' -Force -ErrorAction SilentlyContinue
            if (-not $CachedGPPFiles) { return }

            foreach ($File in $CachedGPPFiles) {

                try {
                    [xml] $XmlFile = Get-Content -Path $File.FullName -ErrorAction SilentlyContinue
                }
                catch [Exception] {
                    Write-Verbose $_.Exception.Message
                    continue
                }

                $Results = New-Object -TypeName PSObject -Property @{
                    DefaultDomainName    = New-Object System.Collections.ArrayList
                    DefaultUserName      = New-Object System.Collections.ArrayList
                    DefaultPassword      = New-Object System.Collections.ArrayList
                    AutoAdminLogon       = New-Object System.Collections.ArrayList
                    AltDefaultDomainName = New-Object System.Collections.ArrayList
                    AltDefaultUserName   = New-Object System.Collections.ArrayList
                    AltDefaultPassword   = New-Object System.Collections.ArrayList
                    AltAutoAdminLogon    = New-Object System.Collections.ArrayList
                }

                foreach ($Property in $XmlFile.GetElementsByTagName("Properties")) {

                    if ([string]::IsNullOrEmpty($Property.value)) { continue }

                    switch ($Property.name) {

                        DefaultDomainName {
                            $null = $Results.DefaultDomainName.Add($Property.value)
                        }

                        DefaultUserName {
                            $null = $Results.DefaultUserName.Add($Property.value)
                        }

                        DefaultPassword {
                            $null = $Results.DefaultPassword.Add($Property.value)
                        }

                        AutoAdminLogon {
                            $null = $Results.AutoAdminLogon.Add($Property.value)
                        }

                        AltDefaultDomainName {
                            $null = $Results.AltDefaultDomainName.Add($Property.value)
                        }

                        AltDefaultUserName {
                            $null = $Results.AltDefaultUserName.Add($Property.value)
                        }

                        AltDefaultPassword {
                            $null = $Results.AltDefaultPassword.Add($Property.value)
                        }

                        AltAutoAdminLogon {
                            $null = $Results.AltAutoAdminLogon.Add($Property.value)
                        }
                    }
                }

                if ($Results.DefaultPassword.Count -ne 0) {

                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "FilePath" -Value $File.FullName
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Domains" -Value ($Results.DefaultDomainName -join ", ")
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Usernames" -Value ($Results.DefaultUserName -join ", ")
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Passwords" -Value ($Results.DefaultPassword -join ", ")
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AutoAdminLogons" -Value ($Results.AutoAdminLogon -join ", ")
                    $AllResults += $Result
                }

                if ($Results.AltDefaultPassword.Count -ne 0) {

                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "FilePath" -Value $File.FullName
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Domains" -Value ($Results.AltDefaultDomainName -join ", ")
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Usernames" -Value ($Results.AltDefaultUserName -join  ", ")
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Passwords" -Value ($Results.AltDefaultPassword -join ", ")
                    $Result | Add-Member -MemberType "NoteProperty" -Name "AutoAdminLogon" -Value ($Results.AltAutoAdminLogon -join ", ")
                    $AllResults += $Result
                }
            }
        }
        else {
            $RegKey = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            $RegItem = Get-ItemProperty -Path "Registry::$($RegKey)" -ErrorAction SilentlyContinue

            if (-not [String]::IsNullOrEmpty($RegItem.DefaultPassword)) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $RegItem.DefaultDomainName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $RegItem.DefaultUserName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $RegItem.DefaultPassword
                $AllResults += $Result
            }

            if (-not [String]::IsNullOrEmpty($RegItem.AltDefaultPassword)) {
                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Domain" -Value $RegItem.AltDefaultDomainName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Username" -Value $RegItem.AltDefaultUserName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $RegItem.AltDefaultPassword
                $AllResults += $Result
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }
}

function Invoke-CredentialFileCheck {
    <#
    .SYNOPSIS
    List the Credential files that are stored in the current user AppData folders.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Credentials stored in the Credential Manager are actually saved as files in the current user's home folder. The sensitive information is saved in an encrypted format which differs depending on the credential type.

    .EXAMPLE
    PS C:\> Invoke-CredentialFileCheck

    FullPath
    ------
    C:\Users\lab-user\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D
    C:\Users\lab-user\AppData\Roaming\Microsoft\Credentials\9751D70B4AC36953347138F9A5C2D23B
    C:\Users\lab-user\AppData\Roaming\Microsoft\Credentials\9970C9D5A29B2D83514BEFD30A4D48B4
    #>

    [CmdletBinding()]
    param()

    $CredentialsFound = $false

    $Paths = New-Object -TypeName System.Collections.ArrayList
    [void] $Paths.Add($(Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\Credentials"))
    [void] $Paths.Add($(Join-Path -Path $env:APPDATA -ChildPath "Microsoft\Credentials"))

    foreach ($Path in [String[]] $Paths) {

        Get-ChildItem -Force -Path $Path -ErrorAction SilentlyContinue | ForEach-Object {

            $Result = New-Object -TypeName PSObject
            $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Credentials"
            $Result | Add-Member -MemberType "NoteProperty" -Name "FullPath" -Value $_.FullName
            $Result

            if (-not $CredentialsFound) { $CredentialsFound = $true }
        }
    }

    if ($CredentialsFound) {

        $CurrentUser = Invoke-UserCheck

        if ($CurrentUser -and $CurrentUser.SID) {

            $Paths = New-Object -TypeName System.Collections.ArrayList
            [void] $Paths.Add($(Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\Protect\$($CurrentUser.SID)"))
            [void] $Paths.Add($(Join-Path -Path $env:APPDATA -ChildPath "Microsoft\Protect\$($CurrentUser.SID)"))

            foreach ($Path in [String[]] $Paths) {

                Get-ChildItem -Force -Path $Path -ErrorAction SilentlyContinue | Where-Object {$_.Name.Length -eq 36 } | ForEach-Object {

                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value "Protect"
                    $Result | Add-Member -MemberType "NoteProperty" -Name "FullPath" -Value $_.FullName
                    $Result
                }
            }
        }
    }
}

function Invoke-VaultCredentialCheck {
    <#
    .SYNOPSIS
    Enumerates the credentials saved in the Credential Manager.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Credentials saved in the Credential Manager can be extracted by invoking the Win32 CredEnumerate function. This function returns a pointer to an array of PCREDENTIAL pointers. Therefore we can iterate this array to access each CREDENTIAL structure individually. Depending on the type of credential, the CredentialBlob member either contains the cleartext password or a blob which we cannot decode (because it's application specific). For each structure, a custom PS object is returned. The output should be quite similar to the output generated by the command vault::cred in M*m*k*tz (don't want to trigger AMSI with this keyword :P).

    .EXAMPLE
    PS C:\> Invoke-VaultCredentialCheck

    TargetName : LegacyGeneric:target=https://github.com/
    UserName   : user@example.com
    Comment    :
    Type       : Generic
    Persist    : LocalMachine
    Flags      : 0
    Credential : ***

    #>

    [CmdletBinding()]
    param()

    Get-VaultCredential -Filtered
}

function Invoke-VaultListCredentialCheck {
    <#
    .SYNOPSIS
    Enumerates web credentials saved in the Credential Manager.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Had to remove description because of...

    .EXAMPLE
    PS C:\> Invoke-VaultListCredentialCheck

    Type        : Web Credentials
    TargetName  : https://github.com/
    UserName    : foo123@example.com
    Credential  : foo123
    LastWritten : 01/01/1970 13:37:00

    #>

    [CmdletBinding()]
    param()

    Get-VaultList -Filtered
}

function Invoke-GPPCredentialCheck {
    <#
    .SYNOPSIS
    Lists Group Policy Preferences (GPP) containing a non-empty "cpassword" field

    Author: @itm4n
    Credit: @obscuresec, @harmj0y
    License: BSD 3-Clause

    .DESCRIPTION
    Before KB2928120 (see MS14-025), some Group Policy Preferences could be configured with a custom account. This feature was mainly used to deploy a custom local administrator account on a group of machines. There were two problems with this approach though. First, since the Group Policy Objects are stored as XML files in SYSVOL, any domain user can read them. The second problem is that the password set in these GPPs is AES256-encrypted with a default key, which is publicly documented. This means that any authenticated user could potentially access very sensitive data and elevate their privileges on their machine or even the domain.

    This function will check whether any locally cached GPP file contains a non-empty "cpassword" field. If so, it will decrypt it and return a custom PS object containing some information about the GPP along with the location of the file.

    .PARAMETER Remote
    Set this flag if you want to search for GPP files in the SYSVOL share of your primary Domain Controller. Initially, I wanted to do only local checks but this was a special request from @mpgn_x64 so I couldn't say no :P.

    .EXAMPLE
    PS C:\> Invoke-GPPCredentialCheck
    ...
    Type     : User/Group
    UserName : LocalAdmin
    Password : ***
    Content  : Description: Super secure local admin account
    Changed  : 2020-02-09 12:09:59
    FilePath : C:\ProgramData\Microsoft\Group Policy\History\{8B95814A-23A2-4FB7-8BBA-53745EA1F11C}\Machine\Preferences\Groups\Groups.xml

    .LINK
    https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
    https://adsecurity.org/?p=2288
    https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025
    https://support.microsoft.com/en-us/help/2962486/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevati
    #>

    [CmdletBinding()]
    param(
        [switch] $Remote,
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()

        try { Add-Type -Assembly System.Security } catch { Write-Warning "Failed to load assembly: System.Security" }
        try { Add-Type -Assembly System.Core } catch { Write-Warning "Failed to load assembly: System.Core" }

        function Get-DecryptedPassword {
            [CmdletBinding()]
            param(
                [string] $Cpass
            )

            if (-not [string]::IsNullOrEmpty($Cpass)) {

                $Mod = $Cpass.Length % 4
                if ($Mod -gt 0) {
                    $Cpass += "=" * (4 - $Mod)
                }

                $Base64Decoded = [Convert]::FromBase64String($Cpass)

                try {

                    $AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
                    [byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

                    $AesIV = New-Object Byte[]($AesObject.IV.Length)
                    $AesObject.IV = $AesIV
                    $AesObject.Key = $AesKey
                    $DecryptorObject = $AesObject.CreateDecryptor()
                    [byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)

                    [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)

                }
                catch [Exception] {
                    Write-Verbose $_.Exception.Message
                }
            }
        }
    }

    process {
        if ($Remote) {
            $GppPath = "\\$($Env:USERDNSDOMAIN)\SYSVOL"
        }
        else {
            $GppPath = $Env:ALLUSERSPROFILE
            if ($GppPath -notmatch "ProgramData") {
                $GppPath = Join-Path -Path $GppPath -ChildPath "Application Data"
            }
            else {
                $GppPath = Join-Path -Path $GppPath -ChildPath "Microsoft\Group Policy"
            }
        }

        if (Test-Path -Path $GppPath -ErrorAction SilentlyContinue) {

            $CachedGPPFiles = Get-ChildItem -Path $GppPath -Recurse -Include 'Groups.xml','Services.xml','ScheduledTasks.xml','DataSources.xml','Drives.xml','Printers.xml' -Force -ErrorAction SilentlyContinue

            foreach ($File in $CachedGPPFiles) {

                $FileFullPath = $File.FullName
                Write-Verbose $FileFullPath

                try {
                    [xml] $XmlFile = Get-Content -Path $FileFullPath -ErrorAction SilentlyContinue
                }
                catch [Exception] {
                    Write-Verbose $_.Exception.Message
                }

                if ($null -eq $XmlFile) {
                    continue
                }

                $XmlFile.GetElementsByTagName("Properties") | ForEach-Object {

                    $Properties = $_
                    $Cpassword = ""

                    switch ($File.BaseName) {

                        "Groups" {
                            $Type = "User/Group"
                            $UserName = $Properties.userName
                            $Cpassword = $Properties.cpassword
                            $Content = "Description: $($Properties.description)"
                        }

                        "ScheduledTasks" {
                            $Type = "Scheduled Task"
                            $UserName = $Properties.runAs
                            $Cpassword = $Properties.cpassword
                            $Content = "App: $($Properties.appName) $($Properties.args)"
                        }

                        "DataSources" {
                            $Type = "Data Source"
                            $UserName = $Properties.username
                            $Cpassword = $Properties.cpassword
                            $Content = "DSN: $($Properties.dsn)"
                        }

                        "Drives" {
                            $Type = "Mapped Drive"
                            $UserName = $Properties.userName
                            $Cpassword = $Properties.cpassword
                            $Content = "Path: $($Properties.path)"
                        }

                        "Services" {
                            $Type = "Service"
                            $UserName = $Properties.accountName
                            $Cpassword = $Properties.cpassword
                            $Content = "Name: $($Properties.serviceName)"
                        }

                        "Printers" {
                            $Type = "Printer"
                            $UserName = $Properties.username
                            $Cpassword = $Properties.cpassword
                            $Content = "Path: $($Properties.path)"
                        }
                    }

                    if (-not [String]::IsNullOrEmpty($Cpassword)) {
                        $Result = New-Object -TypeName PSObject
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $Type
                        $Result | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $UserName
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Password" -Value $(Get-DecryptedPassword -Cpass $Cpassword)
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Content" -Value $Content
                        $Result | Add-Member -MemberType "NoteProperty" -Name "Changed" -Value $Properties.ParentNode.changed
                        $Result | Add-Member -MemberType "NoteProperty" -Name "FilePath" -Value $FileFullPath
                        $AllResults += $Result
                    }
                }
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }
}

function Invoke-PowerShellHistoryCredentialCheck {
    <#
    .SYNOPSIS
    Searches for interesting keywords in the PowerShell history of the current user.

    .DESCRIPTION
    PowerShell commands are saved in a file (ConsoleHost_history.txt), in a subdirectory of the current user's AppData folder. This script extracts the content of this file and also checks whether it contains some keywords such as "password".

    .EXAMPLE
    PS C:\> Invoke-PowerShellHistoryCredentialCheck

    Path          : C:\Users\lab-user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    CreationTime  : 11/11/2019 11:01:55
    LastWriteTime : 04/10/2020 22:40:30
    Lines         : 634
    Matches       : 12
    #>

    [CmdletBinding()]
    param()

    $HistoryFilePath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    $HistoryFileContent = Get-Content -Path $HistoryFilePath -ErrorAction SilentlyContinue -ErrorVariable ErrorGetContent

    if (-not $ErrorGetContent) {

        $HistoryCount = $HistoryFileContent.Count
        $AllMatches = $HistoryFileContent | Select-String -Pattern $script:KeywordsOfInterest -AllMatches
        $AllMatchesCount = $AllMatches.Count
        $FileItem = Get-Item -Path $HistoryFilePath

        $Item = New-Object -TypeName PSObject
        $Item | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $HistoryFilePath
        $Item | Add-Member -MemberType "NoteProperty" -Name "CreationTime" -Value $FileItem.CreationTime
        $Item | Add-Member -MemberType "NoteProperty" -Name "LastWriteTime" -Value $FileItem.LastWriteTime
        $Item | Add-Member -MemberType "NoteProperty" -Name "Lines" -Value $HistoryCount
        $Item | Add-Member -MemberType "NoteProperty" -Name "Matches" -Value $AllMatchesCount
        $Item
    }
}

function Invoke-HiveFilePermissionCheck {
    <#
    .SYNOPSIS
    Checks for READ access on the SAM, SYSTEM and SECURITY hive files (including potential backups).

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Checks for READ access on the SAM, SYSTEM and SECURITY hive files (including potential backups).

    .EXAMPLE
    PS C:\> Invoke-HiveFilePermissionCheck

    Path              : C:\Windows\System32\config\SAM
    IdentityReference : BUILTIN\Users
    Permissions       : ReadData, ReadExtendedAttributes, Execute, ReadAttributes, ReadControl, Synchronize

    Path              : C:\Windows\System32\config\SYSTEM
    IdentityReference : BUILTIN\Users
    Permissions       : ReadData, ReadExtendedAttributes, Execute, ReadAttributes, ReadControl, Synchronize

    Path              : C:\Windows\System32\config\SECURITY
    IdentityReference : BUILTIN\Users
    Permissions       : ReadData, ReadExtendedAttributes, Execute, ReadAttributes, ReadControl, Synchronize
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        $CurrentUserSids = Get-CurrentUserSid

        $TranslatedIdentityReferences = @{}

        $ArrayOfPaths = New-Object System.Collections.ArrayList
        [void] $ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "repair\SAM"))
        [void] $ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\RegBack\SAM"))
        [void] $ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\SAM"))
        [void] $ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "repair\SYSTEM"))
        [void] $ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\SYSTEM"))
        [void] $ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\RegBack\SYSTEM"))
        [void] $ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "repair\SECURITY"))
        [void] $ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\SECURITY"))
        [void] $ArrayOfPaths.Add($(Join-Path -Path $env:SystemRoot -ChildPath "System32\config\RegBack\SECURITY"))

        foreach ($Path in [string[]] $ArrayOfPaths) {

            try {
                $Acl = Get-Acl -Path $Path -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Access
                if ($null -eq $Acl) { Write-Verbose "ACL is null"; continue }

                foreach ($Ace in $Acl) {

                    $PermissionReference = @(
                        $script:FileAccessRightEnum::ReadData
                    )

                    $Permissions = [enum]::GetValues($script:FileAccessRightEnum) | Where-Object {
                        ($Ace.FileSystemRights.value__ -band ($script:FileAccessRightEnum::$_)) -eq ($script:FileAccessRightEnum::$_)
                    }

                    if (Compare-Object -ReferenceObject $Permissions -DifferenceObject $PermissionReference -IncludeEqual -ExcludeDifferent) {

                        if ($Ace.IdentityReference -notmatch '^S-1-5.*' -and $Ace.IdentityReference -notmatch '^S-1-15-.*') {
                            if (-not ($TranslatedIdentityReferences[$Ace.IdentityReference])) {

                                try {
                                    # translate the IdentityReference if it's a username and not a SID
                                    $IdentityUser = New-Object System.Security.Principal.NTAccount($Ace.IdentityReference)
                                    $TranslatedIdentityReferences[$Ace.IdentityReference] = $IdentityUser.Translate([System.Security.Principal.SecurityIdentifier]) | Select-Object -ExpandProperty Value
                                }
                                catch {
                                    # If we cannot resolve the SID, go to the next ACE.
                                    continue
                                }
                            }
                            $IdentitySID = $TranslatedIdentityReferences[$Ace.IdentityReference]
                        }
                        else {
                            $IdentitySID = $Ace.IdentityReference
                        }

                        if ($CurrentUserSids -contains $IdentitySID) {
                            $Result = New-Object -TypeName PSObject
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Path
                            $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value $Ace.IdentityReference
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Permissions" -Value ($Permissions -join ", ")
                            $AllResults += $Result
                        }
                    }
                }
            }
            catch {
                $null = $_
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Invoke-HiveFileShadowCopyPermissionCheck {
    <#
    .SYNOPSIS
    Checks for READ access on the SAM, SYSTEM and SECURITY hive files in shadow copies.

    Author: @SAERXCIT, @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Checks for READ access on the SAM, SYSTEM and SECURITY hive files in shadow copies.

    .EXAMPLE
    PS C:\> Invoke-HiveFileShadowCopyPermissionCheck

    Volume            : HarddiskVolumeShadowCopy1
    Path              : \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM
    IdentityReference : BUILTIN\Users
    AccessRights      : ReadData, ReadExtendedAttributes, Execute, ReadAttributes, ReadControl, Synchronize

    Volume            : HarddiskVolumeShadowCopy1
    Path              : \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SECURITY
    IdentityReference : BUILTIN\Users
    AccessRights      : ReadData, ReadExtendedAttributes, Execute, ReadAttributes, ReadControl, Synchronize

    Volume            : HarddiskVolumeShadowCopy1
    Path              : \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM
    IdentityReference : BUILTIN\Users
    AccessRights      : ReadData, ReadExtendedAttributes, Execute, ReadAttributes, ReadControl, Synchronize
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
        $CurrentUserSids = Get-CurrentUserSid
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        foreach($ShadowCopy in $(Get-ShadowCopy)) {

            $ConfigPath = $(Join-Path -Path $ShadowCopy.Path -ChildPath "Windows\System32\config")

            foreach ($HiveFile in "SAM", "SECURITY", "SYSTEM") {

                $Path = $(Join-Path -Path $ConfigPath -ChildPath $HiveFile)
                $FileDacl = Get-FileDacl -Path $Path

                if ($null -eq $FileDacl) { continue }

                $PermissionReference = @(
                    $script:FileAccessRightEnum::ReadData
                )

                foreach ($Ace in $FileDacl.Access) {

                    if ($Ace.AceType -notmatch "AccessAllowed") { continue }

                    $Permissions = [Enum]::GetValues($script:FileAccessRightEnum) | Where-Object {
                        ($Ace.AccessMask -band ($script:FileAccessRightEnum::$_)) -eq ($script:FileAccessRightEnum::$_)
                    }

                    if (Compare-Object -ReferenceObject $Permissions -DifferenceObject $PermissionReference -IncludeEqual -ExcludeDifferent) {

                        $IdentityReference = $($Ace | Select-Object -ExpandProperty "SecurityIdentifier").ToString()

                        if ($CurrentUserSids -contains $IdentityReference) {

                            $Result = New-Object -TypeName PSObject
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Volume" -Value $ShadowCopy.Volume
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $Path
                            $Result | Add-Member -MemberType "NoteProperty" -Name "IdentityReference" -Value (Convert-SidToName -Sid $IdentityReference)
                            $Result | Add-Member -MemberType "NoteProperty" -Name "AccessRights" -Value ($Permissions -join ", ")
                            $AllResults += $Result
                        }
                    }
                }
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Invoke-UnattendFileCredentialCheck {
    <#
    .SYNOPSIS
    Enumerates Unattend files and extracts credentials

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Searches common locations for "Unattend.xml" files. When a file is found, it calls the custom "Get-UnattendSensitiveData" function to extract credentials from it. Note: credentials are only returned if the password is not empty and not equal to "*SENSITIVE*DATA*DELETED*".

    .EXAMPLE
    PS C:\> Invoke-UnattendFileCredentialCheck | fl

    Type     : LocalAccount
    Domain   : N/A
    Username : John
    Password : Password1
    File     : C:\WINDOWS\Panther\Unattend.xml
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $AllResults = @()
        $FsRedirectionValue = Disable-Wow64FileSystemRedirection
    }

    process {
        $ArrayOfPaths = [string[]] @(
            (Join-Path -Path $env:windir -ChildPath "Panther\Unattended.xml"),
            (Join-Path -Path $env:windir -ChildPath "Panther\Unattend.xml"),
            (Join-Path -Path $env:windir -ChildPath "Panther\Unattend\Unattended.xml"),
            (Join-Path -Path $env:windir -ChildPath "Panther\Unattend\Unattend.xml"),
            (Join-Path -Path $env:windir -ChildPath "System32\Sysprep\Unattend.xml"),
            (Join-Path -Path $env:windir -ChildPath "System32\Sysprep\Panther\Unattend.xml")
        )

        foreach ($Path in $ArrayOfPaths) {

            if (Test-Path -Path $Path -ErrorAction SilentlyContinue) {

                Write-Verbose "Found file: $Path"

                $Result = Get-UnattendSensitiveData -Path $Path
                if ($Result) {
                    $Result | Add-Member -MemberType "NoteProperty" -Name "File" -Value $Path
                    $AllResults += $Result
                }
            }
        }

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }

    end {
        Restore-Wow64FileSystemRedirection -OldValue $FsRedirectionValue
    }
}

function Invoke-SccmNaaCredentialCheck {
    <#
    .SYNOPSIS
    Check whether SCCM Network Access Account credentials are stored in the WMI database, within the CIM repository.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    The cmdlet simply invokes the Find-WmiCcmNaaCredential command to get a list of locally stored SCCM NAA credentials.
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    process {
        $Entries = Find-WmiCcmNaaCredential | Sort-Object -Property NetworkAccessUsername,NetworkAccessPassword -Unique

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Entries
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Entries) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }
}

function Invoke-SccmCacheFolderCredentialCheck {
    <#
    .SYNOPSIS
    Check for potentially hard coded credentials in files within the SCCM cache folders.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet simply invokes the Find-SccmCacheFileCredential command to get a list of files that potentially contain hard coded credentials.
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    process {
        $AllResults = Find-SccmCacheFileCredential

        $CheckResult = New-Object -TypeName PSObject
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $AllResults
        $CheckResult | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($AllResults) { $BaseSeverity } else { $script:SeverityLevelEnum::None })
        $CheckResult
    }
}