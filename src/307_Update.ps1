function Get-HotFixList {
    <#
    .SYNOPSIS
    Helper - Gets a list of installed updates and hotfixes.

    .DESCRIPTION
    This check reads the registry in order to enumerate all the installed KB hotfixes. The output is sorted by date so that most recent patches appear first in the list. The output is similar to the output of the built-in 'Get-HotFix' powershell command. There is a major difference between this script and the 'Get-HotFix' command though. The latter relies on WMI to delegate the "enumeration" whereas this script directly parses the registry. The other benefit of this method is that it allows one to extract more information related to the KBs (although it's not in the output of this script). If the current user can't read the registry, the script falls back to the built-in 'Get-HotFix' cmdlet.

    .EXAMPLE
    PS C:\> Get-HotFixList

    HotFixID  Description     InstalledBy           InstalledOn
    --------  -----------     -----------           -----------
    KB4557968 Security Update                       2020-05-11 07:37:09
    KB4560366 Security Update DESKTOP-7A0AKQI\admin 2020-06-22 12:40:39
    KB4566785 Security Update NT AUTHORITY\SYSTEM   2020-07-16 13:08:14
    KB4570334 Security Update NT AUTHORITY\SYSTEM   2020-08-13 17:45:34
    KB4577266 Security Update NT AUTHORITY\SYSTEM   2020-09-11 13:37:59
    KB4537759 Security Update                       2020-05-11 07:44:14
    KB4561600 Security Update NT AUTHORITY\SYSTEM   2020-06-22 13:00:50
    KB4578968 Update          NT AUTHORITY\SYSTEM   2020-10-14 18:06:18
    KB4580325 Security Update NT AUTHORITY\SYSTEM   2020-10-14 13:09:37
    #>

    [CmdletBinding()] Param()

    function Get-PackageInfo {

        Param(
            [String]$Path
        )

        $Info = New-Object -TypeName PSObject

        [xml] $PackageContentXml = Get-Content -Path $Path -ErrorAction SilentlyContinue -ErrorVariable GetContentError
        if (-not $GetContentError) {

            $PackageContentXml.GetElementsByTagName("assembly") | ForEach-Object {

                $Info | Add-Member -MemberType "NoteProperty" -Name "DisplayName" -Value "$($_.displayName)"
                $Info | Add-Member -MemberType "NoteProperty" -Name "SupportInformation" -Value "$($_.supportInformation)"
            }

            $PackageContentXml.GetElementsByTagName("package") | Where-Object { $null -ne $_.identifier } | ForEach-Object {

                $Info | Add-Member -MemberType "NoteProperty" -Name "Identifier" -Value "$($_.identifier)"
                $Info | Add-Member -MemberType "NoteProperty" -Name "ReleaseType" -Value "$($_.releaseType)"
            }

            $Info
        }
    }

    if ($CachedHotFixList.Count -eq 0) {

        # In the registry, one KB may have multiple entries because it can be split up into multiple
        # packages. This array will help keep track of KBs that have already been checked by the
        # script.
        $InstalledKBs = New-Object -TypeName System.Collections.ArrayList

        $AllPackages = Get-ChildItem -Path "Registry::HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages" -ErrorAction SilentlyContinue -ErrorVariable ErrorGetChildItem

        if (-not $ErrorGetChildItem) {

            $AllPackages | ForEach-Object {

                # Filter only KB-related packages
                if (($_.Name | Split-Path -Leaf) -Like "Package_*for_KB*") {

                    $PackageProperties = $_ | Get-ItemProperty

                    # Get the KB id, e.g.: KBXXXXXXX
                    $PackageName = $PackageProperties.InstallName.Split('~')[0].Split('_') | Where-Object { $_ -Like "KB*" }
                    if ($PackageName) {

                        # Check whether this KB has already been handled
                        if (-not ($InstalledKBs -contains $PackageName)) {

                            # Add the KB id to the list so we don't check it multiple times
                            [void]$InstalledKBs.Add($PackageName)

                            # Who installed this update?
                            $InstalledBy = Convert-SidToName -Sid $PackageProperties.InstallUser

                            # Get the install date. It's stored in the registry just like a FILETIME structure. So, we have to
                            # combine the low part and the high part and convert the result to a DateTime object.
                            $DateHigh = $PackageProperties.InstallTimeHigh
                            $DateLow = $PackageProperties.InstallTimeLow
                            $FileTime = $DateHigh * [Math]::Pow(2, 32) + $DateLow
                            $InstallDate = [DateTime]::FromFileTime($FileTime)

                            # Parse the package metadata file and extract some useful information...
                            $ServicingPackagesPath = Join-Path -Path $env:windir -ChildPath "servicing\Packages"
                            $PackagePath = Join-Path -Path $ServicingPackagesPath -ChildPath $PackageProperties.InstallName
                            $PackageInfo = Get-PackageInfo -Path $PackagePath

                            $Result = New-Object -TypeName PSObject
                            $Result | Add-Member -MemberType "NoteProperty" -Name "HotFixID" -Value "$PackageName"
                            $Result | Add-Member -MemberType "NoteProperty" -Name "Description" -Value "$($PackageInfo.ReleaseType)"
                            $Result | Add-Member -MemberType "NoteProperty" -Name "InstalledBy" -Value "$InstalledBy"
                            $Result | Add-Member -MemberType "NoteProperty" -Name "InstalledOnDate" -Value $InstallDate
                            $Result | Add-Member -MemberType "NoteProperty" -Name "InstalledOn" -Value (Convert-DateToString -Date $InstallDate)

                            [void]$CachedHotFixList.Add($Result)
                        }
                    }
                }
            }
        }
        else {
            # If we can't read the registry, fall back to the built-in 'Get-HotFix' cmdlet
            Get-HotFix | Select-Object HotFixID,Description,InstalledBy,InstalledOn | ForEach-Object {
                $_ | Add-Member -MemberType "NoteProperty" -Name "InstalledOnDate" -Value $_.InstalledOn
                $_.InstalledOn = Convert-DateToString -Date $_.InstalledOn
                [void]$CachedHotFixList.Add($_)
            }
        }
    }

    $CachedHotFixList | ForEach-Object {
        $_
    }
}

function Invoke-WindowsUpdateCheck {
    <#
    .SYNOPSIS
    Gets the last update time of the machine.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    The Windows Update status can be queried thanks to the Microsoft.Update.AutoUpdate COM object. It gives the last successful search time and the last successfull update installation time.

    .EXAMPLE
    PS C:\> Invoke-WindowsUpdateCheck

    Time
    ----
    2020-01-12 - 09:17:37
    #>

    [CmdletBinding()] Param()

    try {
        $WindowsUpdate = (New-Object -ComObject "Microsoft.Update.AutoUpdate").Results

        if ($WindowsUpdate.LastInstallationSuccessDate) {
            $WindowsUpdateResult = New-Object -TypeName PSObject
            $WindowsUpdateResult | Add-Member -MemberType "NoteProperty" -Name "Time" -Value $(Convert-DateToString -Date $WindowsUpdate.LastInstallationSuccessDate)
            $WindowsUpdateResult | Add-Member -MemberType "NoteProperty" -Name "TimeRaw" -Value $WindowsUpdate.LastInstallationSuccessDate
            $WindowsUpdateResult
        }
    }
    catch {
        # We might get an access denied when querying this COM object
        Write-Verbose "Error while requesting COM object Microsoft.Update.AutoUpdate."
    }
}

function Invoke-HotFixCheck {
    <#
    .SYNOPSIS
    If a patch was not installed in the last 31 days, return the latest patch that was installed, otherwise return nothing.

    .DESCRIPTION
    This check simply invokes the helper function 'Get-HotFixList' and sorts the results from the newest to the oldest.

    .PARAMETER Info
    Use this flag to get the list of all installed patches.

    .EXAMPLE
    PS C:\> Invoke-HotFixCheck -Info

    HotFixID  Description     InstalledBy           InstalledOn
    --------  -----------     -----------           -----------
    KB4578968 Update          NT AUTHORITY\SYSTEM   2020-10-14 18:06:18
    KB4580325 Security Update NT AUTHORITY\SYSTEM   2020-10-14 13:09:37
    KB4577266 Security Update NT AUTHORITY\SYSTEM   2020-09-11 13:37:59
    KB4570334 Security Update NT AUTHORITY\SYSTEM   2020-08-13 17:45:34
    KB4566785 Security Update NT AUTHORITY\SYSTEM   2020-07-16 13:08:14
    KB4561600 Security Update NT AUTHORITY\SYSTEM   2020-06-22 13:00:50
    KB4560366 Security Update DESKTOP-7A0AKQI\admin 2020-06-22 12:40:39
    KB4537759 Security Update                       2020-05-11 07:44:14
    KB4557968 Security Update                       2020-05-11 07:37:09
    #>

    [CmdletBinding()] Param(
        [switch]$Info
    )

    # Get the list of installed patches
    $HotFixList = Get-HotFixList | Sort-Object -Property "InstalledOnDate" -Descending

    # If the list is empty, return
    if ($(([Object[]]$HotFixList).Length) -eq 0) { return }

    # If Info, return the list directly
    if ($Info) { $HotFixList | Select-Object HotFixID,Description,InstalledBy,InstalledOn; return }

    # To get the latest patch, we can simple get the first item in the list because it is sorted in
    # descending order.
    $LatestHotfix = $HotFixList | Select-Object -First 1
    $TimeSpan = New-TimeSpan -Start $LatestHotfix.InstalledOnDate -End $(Get-Date)

    if ($TimeSpan.TotalDays -gt 31) {
        $LatestHotfix | Select-Object HotFixID,Description,InstalledBy,InstalledOn
    }
    else {
        Write-Verbose "At least one hotfix was installed in the last 31 days."
    }
}

# function Invoke-HotFixVulnCheck {
#     <#
#     .SYNOPSIS
#     Checks whether any hotfix has been installed in the last 31 days.

#     .DESCRIPTION
#     This script first lists all the installed hotfixes. If no result is returned, this will be reported as a finding. If at least one result is returned, the script will check the first one (which corresponds to the latest hotfix). If it's more than 31 days old, it will be returned.
#     #>

#     [CmdletBinding()] Param()

#     $Hotfixes = Get-HotFixList | Sort-Object -Property "InstalledOn" -Descending

#     if ($(([Object[]]$Hotfixes).Length) -gt 0) {

#         $LatestHotfix = $Hotfixes | Select-Object -First 1
#         $TimeSpan = New-TimeSpan -Start $LatestHotfix.InstalledOn -End $(Get-Date)

#         if ($TimeSpan.TotalDays -gt 31) {
#             $LatestHotfix
#         }
#         else {
#             Write-Verbose "At least one hotfix was installed in the last 31 days."
#         }
#     }
#     else {
#         Write-Verbose "The hotfix history is empty."
#     }
# }