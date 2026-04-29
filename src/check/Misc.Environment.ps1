function Invoke-UserSessionCheck {
    <#
    .SYNOPSIS
    List the the sessions of the currently logged-on users (similar to the command 'query session').

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This check is essentially a wrapper for the helper function Get-RemoteDesktopUserSession.

    .EXAMPLE
    PS C:\> Invoke-UserSessionCheck

    SessionName UserName              Id        State
    ----------- --------              --        -----
    Services                           0 Disconnected
    Console     SRV01\Administrator    1       Active
    RDP-Tcp#3   SANDBOX\Administrator  3       Active
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    $Results = @()

    foreach ($Session in (Get-RemoteDesktopUserSession)) {

        if ([String]::IsNullOrEmpty($Session.UserName)) {
            $UserName = ""
        }
        else {
            if ([String]::IsNullOrEmpty($Session.DomainName)) {
                $UserName = $Session.UserName
            }
            else {
                $UserName = "$($Session.DomainName)\$($Session.UserName)"
            }
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "SessionName" -Value $Session.SessionName
        $Result | Add-Member -MemberType "NoteProperty" -Name "UserName" -Value $UserName
        $Result | Add-Member -MemberType "NoteProperty" -Name "Id" -Value $Session.SessionId
        $Result | Add-Member -MemberType "NoteProperty" -Name "State" -Value $Session.State
        $Results += $Result
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
    $Result
}

function Invoke-UserHomeFolderCheck {
    <#
    .SYNOPSIS
    Enumerates the local user home folders.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    Enumerates the folders located in C:\Users\. For each one, this function checks whether the folder is readable and/or writable by the current user.

    .EXAMPLE
    PS C:\> Invoke-UserHomeFolderCheck

    HomeFolderPath         Read Write
    --------------         ---- -----
    C:\Users\Lab-Admin    False False
    C:\Users\Lab-User      True  True
    C:\Users\Public        True  True
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    $Results = @()
    $UsersHomeFolder = Join-Path -Path $((Get-Item $env:windir).Root) -ChildPath Users

    foreach ($HomeFolder in $(Get-ChildItem -Path $UsersHomeFolder)) {

        $FolderPath = $HomeFolder.FullName
        $ReadAccess = $false
        $WriteAccess = $false

        $ChildItems = Get-ChildItem -Path $FolderPath -ErrorAction SilentlyContinue
        if ($ChildItems) {
            $ReadAccess = $true
            if ([String]::IsNullOrEmpty($FolderPath)) { continue }
            $ModifiablePaths = Get-ModifiablePath -Path $FolderPath | Where-Object { $_ -and (-not [String]::IsNullOrEmpty($_.ModifiablePath)) }
            if ($ModifiablePaths) { $WriteAccess = $true }
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "HomeFolderPath" -Value $FolderPath
        $Result | Add-Member -MemberType "NoteProperty" -Name "Read" -Value $ReadAccess
        $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $WriteAccess
        $Results += $Result
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
    $Result
}

function Invoke-LocalAdminGroupCheck {
    <#
    .SYNOPSIS
    Enumerates the members of the default local admin group

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    For every member of the local admin group, it will check whether it's a local/domain user/group. If it's local it will also check if the account is enabled.

    .EXAMPLE
    PS C:\> Invoke-LocalAdminGroupCheck

    Name          Type IsLocal IsEnabled
    ----          ---- ------- ---------
    Administrator User    True     False
    lab-admin     User    True      True

    .NOTES
    S-1-5-32-544 = SID of the local admin group
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    $Results = @()
    $LocalAdminGroupFullname = ([Security.Principal.SecurityIdentifier]"S-1-5-32-544").Translate([Security.Principal.NTAccount]).Value
    $LocalAdminGroupName = $LocalAdminGroupFullname.Split('\')[1]
    Write-Verbose "Admin group name: $LocalAdminGroupName"

    $AdsiComputer = [ADSI]("WinNT://$($env:COMPUTERNAME),computer")

    try {
        $LocalAdminGroup = $AdsiComputer.psbase.children.find($LocalAdminGroupName, "Group")

        if ($LocalAdminGroup) {

            foreach ($LocalAdminGroupMember in $LocalAdminGroup.psbase.invoke("members")) {

                $MemberName = $LocalAdminGroupMember.GetType().InvokeMember("Name", 'GetProperty', $null, $LocalAdminGroupMember, $null)
                Write-Verbose "Found an admin member: $MemberName"

                $Member = $AdsiComputer.Children | Where-Object { (($_.SchemaClassName -eq "User") -or ($_.SchemaClassName -eq "Group")) -and ($_.Name -eq $MemberName) }

                if ($Member) {

                    if ($Member.SchemaClassName -eq "User") {
                        $UserFlags = $Member.UserFlags.value
                        $MemberIsEnabled = -not $($UserFlags -band $script:ADS_USER_FLAGS::AccountDisable)
                        $MemberType = "User"
                        $MemberIsLocal = $true
                    }
                    elseif ($Member.SchemaClassName -eq "Group") {
                        $GroupType = $Member.GroupType.value
                        $MemberIsLocal = $($GroupType -band $script:GROUP_TYPE_FLAGS::ResourceGroup)
                        $MemberType = "Group"
                        $MemberIsEnabled = $true
                    }
                }
                else {

                    $MemberType = ""
                    $MemberIsLocal = $false
                    $MemberIsEnabled = $null
                }

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $MemberName
                $Result | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $MemberType
                $Result | Add-Member -MemberType "NoteProperty" -Name "IsLocal" -Value $MemberIsLocal
                $Result | Add-Member -MemberType "NoteProperty" -Name "IsEnabled" -Value $MemberIsEnabled
                $Results += $Result
            }
        }
    }
    catch {
        Write-Verbose "$($_.Exception)"
    }

    $Result = New-Object -TypeName PSObject
    $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
    $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
    $Result
}

function Invoke-EndpointProtectionCheck {
    <#
    .SYNOPSIS
    Gets a list of security software products

    .DESCRIPTION
    This check was inspired by the script Invoke-EDRChecker.ps1 (PwnDexter). It enumerates the DLLs that are loaded in the current process, the processes that are currently running, the installed applications and the installed services. For each one of these entries, it extracts some metadata and checks whether it contains some known strings related to a given security software product. If there is a match, the corresponding entry is returned along with the data that was matched.

    .EXAMPLE
    PS C:\> Invoke-EndpointProtectionCheck

    ProductName      Source                Pattern
    -----------      ------                -------
    AMSI             Loaded DLL            FileName=C:\Windows\SYSTEM32\amsi.dll
    AMSI             Loaded DLL            InternalName=amsi.dll
    AMSI             Loaded DLL            OriginalFilename=amsi.dll
    ...
    Windows Defender Service               RegistryKey=HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService
    Windows Defender Service               RegistryPath=Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SecurityHealthService
    Windows Defender Service               DisplayName=@C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe,-1001
    Windows Defender Service               ImagePath="C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"
    Windows Defender Service               DisplayName=@C:\Program Files\Windows Defender\MpAsDesc.dll,-390
    Windows Defender Service               DisplayName=@C:\Program Files\Windows Defender\MpAsDesc.dll,-330
    Windows Defender Service               DisplayName=@C:\Program Files\Windows Defender\MpAsDesc.dll,-370
    Windows Defender Service               DisplayName=@C:\Program Files\Windows Defender\MpAsDesc.dll,-320
    Windows Defender Service               ImagePath="C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2008.9-0\NisSrv.exe"
    Windows Defender Service               DisplayName=@C:\Program Files\Windows Defender\MpAsDesc.dll,-310
    Windows Defender Service               ImagePath="C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2008.9-0\MsMpEng.exe"

    .NOTES
    Credit goes to PwnDexter: https://github.com/PwnDexter/Invoke-EDRChecker
    #>

    [CmdletBinding()]
    param(
        [UInt32] $BaseSeverity
    )

    begin {
        $Signatures = @{}

        ConvertFrom-EmbeddedTextBlob -TextBlob $script:GlobalConstant.EndpointProtectionSignature | ConvertFrom-Csv | ForEach-Object {
            $Signatures.Add($_.Name, $_.Signature)
        }

        function Find-ProtectionSoftware {

            param([Object] $Object)

            $Signatures.Keys | ForEach-Object {

                $ProductName = $_
                $ProductSignatures = $Signatures.Item($_).Split(",")

                $Object | Select-String -Pattern $ProductSignatures -AllMatches | ForEach-Object {

                    $($_ -Replace "@{").Trim("}").Split(";") | ForEach-Object {

                        $_.Trim() | Select-String -Pattern $ProductSignatures -AllMatches | ForEach-Object {

                            $Result = New-Object -TypeName PSObject
                            $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value "$ProductName"
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Pattern" -Value "$($_)"
                            $Result
                        }
                    }
                }
            }
        }
    }

    process {
        # Need to store all the results into a list so we can sort them on the product name.
        $Results = @()

        # Check DLLs loaded in the current process
        $Results += Get-Process -Id $PID -Module | ForEach-Object {

            if (Test-Path -Path $_.FileName -ErrorAction SilentlyContinue) {

                $DllDetails = (Get-Item $_.FileName).VersionInfo | Select-Object -Property CompanyName, FileDescription, FileName, InternalName, LegalCopyright, OriginalFileName, ProductName
                Find-ProtectionSoftware -Object $DllDetails | ForEach-Object {

                    $Result = New-Object -TypeName PSObject
                    $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value "$($_.ProductName)"
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Source" -Value "Loaded DLL"
                    $Result | Add-Member -MemberType "NoteProperty" -Name "Pattern" -Value "$($_.Pattern)"
                    $Result
                }
            }
        }

        # Check running processes
        $Results += Get-Process | Select-Object -Property ProcessName, Name, Path, Company, Product, Description | ForEach-Object {

            Find-ProtectionSoftware -Object $_ | ForEach-Object {

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value "$($_.ProductName)"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Source" -Value "Running process"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Pattern" -Value "$($_.Pattern)"
                $Result
            }
        }

        # Check installed applications
        $Results += Get-InstalledApplication | Select-Object -Property Name | ForEach-Object {

            Find-ProtectionSoftware -Object $_ | ForEach-Object {

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value "$($_.ProductName)"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Source" -Value "Installed application"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Pattern" -Value "$($_.Pattern)"
                $Result
            }
        }

        # Check installed services
        $Results += Get-ServiceFromRegistry -FilterLevel 1 | ForEach-Object {

            Find-ProtectionSoftware -Object $_ | ForEach-Object {

                $Result = New-Object -TypeName PSObject
                $Result | Add-Member -MemberType "NoteProperty" -Name "ProductName" -Value "$($_.ProductName)"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Source" -Value "Service"
                $Result | Add-Member -MemberType "NoteProperty" -Name "Pattern" -Value "$($_.Pattern)"
                $Result
            }
        }

        $Results = $Results | Sort-Object -Property ProductName, Source

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
        $Result
    }
}

function Invoke-AmsiProviderCheck {
    <#
    .SYNOPSIS
    Get information about AMSI providers registered by antimalware software.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet iterates the subkeys of HKLM\SOFTWARE\Microsoft\AMSI\Providers to find the class ID of registered AMSI providers. Then it uses the helper function Get-ComClassFromRegistry to collect information about the COM class.

    .EXAMPLE
    PS C:\> Invoke-AmsiProviderCheck

    Id       : {2781761E-28E0-4109-99FE-B9D127C57AFE}
    Path     : HKLM\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}
    Value    : InprocServer32
    Data     : "%ProgramData%\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MpOav.dll"
    DataType : FilePath
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    process {
        $Results = Get-ChildItem -Path "Registry::HKLM\SOFTWARE\Microsoft\AMSI\Providers" -ErrorAction SilentlyContinue | ForEach-Object {
            $ChildKeyName = $_.PSChildName
            Get-ComClassFromRegistry | Where-Object { $ChildKeyName -like "*$($_.Id)*" }
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
        $Result
    }
}