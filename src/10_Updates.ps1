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
        [switch]
        $Info
    )

    # Get the list of installed patches
    $HotFixList = Get-HotFixList | Sort-Object -Property "InstalledOn" -Descending
    
    # If the list is empty, return
    if ($(([Object[]]$HotFixList).Length) -eq 0) { return }

    # If Info, return the list directly
    if ($Info) { $HotFixList; return }

    # To get the latest patch, we can simple get the first item in the list because it is sorted in 
    # descending order.
    $LatestHotfix = $HotFixList | Select-Object -First 1
    $TimeSpan = New-TimeSpan -Start $LatestHotfix.InstalledOn -End $(Get-Date)

    if ($TimeSpan.TotalDays -gt 31) {
        $LatestHotfix
    }
    else {
        Write-Verbose "At least one hotfix was installed in the last 31 days."
    }
}

function Invoke-HotFixVulnCheck {
    <#
    .SYNOPSIS
    Checks whether any hotfix has been installed in the last 31 days.
    
    .DESCRIPTION
    This script first lists all the installed hotfixes. If no result is returned, this will be reported as a finding. If at least one result is returned, the script will check the first one (which corresponds to the latest hotfix). If it's more than 31 days old, it will be returned.
    #>

    [CmdletBinding()] Param()

    $Hotfixes = Get-HotFixList | Sort-Object -Property "InstalledOn" -Descending

    if ($(([Object[]]$Hotfixes).Length) -gt 0) {

        $LatestHotfix = $Hotfixes | Select-Object -First 1
        $TimeSpan = New-TimeSpan -Start $LatestHotfix.InstalledOn -End $(Get-Date)

        if ($TimeSpan.TotalDays -gt 31) {
            $LatestHotfix
        }
        else {
            Write-Verbose "At least one hotfix was installed in the last 31 days."
        }
    }
    else {
        Write-Verbose "The hotfix history is empty."
    }
}