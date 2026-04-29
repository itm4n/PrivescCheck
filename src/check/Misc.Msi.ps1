function Invoke-MsiCustomActionCheck {
    <#
    .SYNOPSIS
    Search for MSI files that run Custom Actions as SYSTEM.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet retrieves a list of cached MSI files and analyzes them to find potentially unsafe Custom Actions.

    .EXAMPLE
    PS C:\> Invoke-MsiCustomActionCheck
    ...
    Path              : C:\Windows\Installer\38896.msi
    IdentifyingNumber : 180E1C56-3A53-44D2-B300-ADC28A080515
    Name              : Online Plug-in
    Vendor            : Citrix Systems, Inc.
    Version           : 23.11.0.197
    AllUsers          : 1
    CandidateCount    : 15
    Candidates        : CA_FixCachedIcaWebWrapper; BackupAFDWindowSize; BackupAFDWindowSize_RB; BackupTcpIPWindowSize; BackupTcpIPWindowSize_RB; CallCtxCreatePFNRegKeyIfUpg; CtxModRegForceLAA; FixIniFile; HideCancelButton;
                        GiveUsersLicensingAccess; LogInstallTime; RestoreAFDWindowSize; RestorePassThroughKey; RestoreTcpIPWindowSize; SetTimestamps
    AnalyzeCommand    : Get-MsiFileItem -FilePath "C:\Windows\Installer\38896.msi" | Select-Object -ExpandProperty CustomActions | Where-Object { $_.Candidate }
    RepairCommand     : Start-Process -FilePath "msiexec.exe" -ArgumentList "/fa C:\Windows\Installer\38896.msi"
    ...
    #>

    [CmdletBinding()]
    param (
        [UInt32] $BaseSeverity
    )

    begin {
        $MsiItems = [object[]] (Get-MsiFileItem)
        $CandidateCount = 0
    }

    process {
        $Results = @()
        foreach ($MsiItem in $MsiItems) {

            Write-Verbose "Analyzing file: $($MsiItem.Path)"

            # If the MSI doesn't force the installation for all users (i.e., system-wide),
            # ignore it.
            if ($MsiItem.AllUsers -ne 1) { continue }

            # If the MSI doesn't have any Custom Action, ignore it.
            if ($null -eq $MsiItem.CustomActions) { continue }

            $CandidateCustomActions = [object[]] ($MsiItem.CustomActions | Where-Object { $_.Candidate -eq $true })

            # No interesting Custom Action found, ignore it.
            if ($CandidateCustomActions.Count -eq 0) { continue }

            $CandidateCount += 1

            $AnalyzeCommand = "Get-MsiFileItem -FilePath `"$($MsiItem.Path)`" | Select-Object -ExpandProperty CustomActions | Where-Object { `$_.Candidate }"
            $RepairCommand = "Start-Process -FilePath `"msiexec.exe`" -ArgumentList `"/fa $($MsiItem.Path)`""

            $MsiItem | Add-Member -MemberType "NoteProperty" -Name "CandidateCount" -Value $CandidateCustomActions.Count
            $MsiItem | Add-Member -MemberType "NoteProperty" -Name "Candidates" -Value "$(($CandidateCustomActions | Select-Object -ExpandProperty "Action") -join "; ")"
            $MsiItem | Add-Member -MemberType "NoteProperty" -Name "AnalyzeCommand" -Value $AnalyzeCommand
            $MsiItem | Add-Member -MemberType "NoteProperty" -Name "RepairCommand" -Value $RepairCommand
            $Results += $MsiItem | Select-Object -Property * -ExcludeProperty "CustomActions"
        }

        $Result = New-Object -TypeName PSObject
        $Result | Add-Member -MemberType "NoteProperty" -Name "Result" -Value $Results
        $Result | Add-Member -MemberType "NoteProperty" -Name "Severity" -Value $(if ($Results) { $BaseSeverity } else { $script:SeverityLevel::None })
        $Result
    }

    end {
        Write-Verbose "Candidate count: $($CandidateCount) / $($MsiItems.Count)"
    }
}

function Invoke-MsiExtractBinaryData {

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $true)]
        [string] $Path,
        [Parameter(Position = 1, Mandatory = $true)]
        [string] $Name,
        [Parameter(Position = 2, Mandatory = $true)]
        [string] $OutputPath
    )

    begin {
        $Installer = New-Object -ComObject WindowsInstaller.Installer
    }

    process {
        try {
            if ([string]::IsNullOrEmpty($OutputPath)) { $OutputPath = "$($Name)" }
            Write-Verbose "Output path: $($OutputPath)"

            $Database = Invoke-MsiOpenDatabase -Installer $Installer -Path $Path -Mode 0
            $BinaryData = Get-MsiBinaryDataProperty -Database $Database -Name $Name

            Set-Content -Path $OutputPath -Value $BinaryData
        }
        catch {
            Write-Warning "Invoke-MsiExtractBinaryData exception: $($_)"
        }
    }

    end {
        $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Installer)
    }
}