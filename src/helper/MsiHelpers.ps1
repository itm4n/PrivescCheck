function Invoke-MsiOpenDatabase {
    param ( [object] $Installer, [string] $Path, [int] $Mode )
    # https://learn.microsoft.com/en-us/windows/win32/msi/installer-opendatabase
    # Installer.OpenDatabase(name, openMode)
    # openMode = 0 (msiOpenDatabaseModeReadOnly)
    $Installer.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $Installer, @($Path, $Mode))
}

function Invoke-MsiCreateRecord {
    param ( [object] $Installer, [Int32] $Count )
    # https://learn.microsoft.com/en-us/windows/win32/msi/installer-createrecord
    # Installer.CreateRecord(count)
    $Installer.GetType().InvokeMember("CreateRecord", "InvokeMethod", $null, $Installer, @($Count))
}

function Invoke-MsiDatabaseOpenView {
    param ( [object] $Database, [string] $Query )
    # https://learn.microsoft.com/en-us/windows/win32/msi/database-openview
    # Database.OpenView(sql)
    $Database.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $Database, @($Query))
}

function Invoke-MsiViewExecute {
    param ( [object] $View, [object] $Record )
    # https://learn.microsoft.com/en-us/windows/win32/msi/view-execute
    # View.Execute(record)
    $View.GetType().InvokeMember("Execute", "InvokeMethod", $null, $View, $(if ($Record) { @($Record) } else { $null }))
}

function Invoke-MsiViewFetch {
    param ( [object] $View )
    # https://learn.microsoft.com/en-us/windows/win32/msi/view-fetch
    # View.Fetch()
    $View.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $View, $null)
}

function Invoke-MsiViewClose {
    param ( [object] $View )
    # https://learn.microsoft.com/en-us/windows/win32/api/msiquery/nf-msiquery-msiviewclose
    # View.Close()
    $View.GetType().InvokeMember("Close", "InvokeMethod", $null, $View, $null)
}

function Invoke-MsiGetProperty {
    # https://learn.microsoft.com/en-us/windows/win32/msi/record-object#properties
    param ( [object] $Record, [string] $Property, [Int32] $Index )
    $Record.GetType().InvokeMember($Property, "GetProperty", $null, $Record, @($Index))
}

function Invoke-MsiSetProperty {
    # https://learn.microsoft.com/en-us/windows/win32/msi/record-object#properties
    param ( [object] $Record, [string] $Property, [Int32] $Index, [string] $Value)
    $Record.GetType().InvokeMember($Property, "SetProperty", $null, $Record, @($Index, $Value))
}

function Get-CustomActionExecutableType {
    param ( [uint32] $Type )
    switch ($Type -band 0x0f) {
        1 { "Dll"       ; break } # Target = entry point name
        2 { "Exe"       ; break } # Target = command line args
        3 { "TextData"  ; break } # Target = text string to be formatted and set into property
        5 { "JScript"   ; break } # Target = entry point name, null if none to call
        6 { "VBScript"  ; break } # Target = entry point name, null if none to call
        7 { "Install"   ; break } # Target = property list for nested engine initialization
        default { throw "Unknown executable type for a Custom Action: $($_)" }
    }
}

function Get-CustomActionExecutableSource {
    # MsiDefs.h -> msidbCustomActionType
    param ( [uint32] $Type )
    # PSv2 does not have -shr and -shl operators, so we do the following instead of
    # "-shr 4".
    switch (($Type -band 0x30) * [Math]::Pow(2, -4)) {
        0 { "BinaryData" ; break} # Source = Binary.Name, data stored in stream
        1 { "SourceFile" ; break} # Source = File.File, file part of installation
        2 { "Directory"  ; break} # Source = Directory.Directory, folder containing existing file
        3 { "Property"   ; break} # Source = Property.Property, full path to executable
        default { throw "Unknown source type for a Custom Action: $($_)" }
    }
}

function Get-CustomActionReturnProcessing {
    # MsiDefs.h -> msidbCustomActionType
    param ( [uint32] $Type )
    $MaskedType = $Type -band 0xc0
    # 0x40 -> ignore action return status, continue running
    # 0x80 -> run asynchronously
    if ($MaskedType -band 0x40) { "ContinueOnReturn" } else { "ProcessReturnCode" }
    if ($MaskedType -band 0x80) { "Asynchronous"     } else { "Synchronous"       }
}

function Get-CustomActionExecutionSchedulingFlag {
    # MsiDefs.h -> msidbCustomActionType
    param ( [uint32] $Type )
    if ($Type -band 0x700) {
        if ($Type -band 0x400) {
            "InScript"                                  # queue for execution within script
            if ($Type -band 0x100) { "Rollback"       } # in conjunction with InScript: queue in Rollback script
            if ($Type -band 0x200) { "Commit"         } # in conjunction with InScript: run Commit ops from script on success
        }
        else {
            if ($Type -band 0x100) { "FirstSequence"  } # skip if UI sequence already run
            if ($Type -band 0x200) { "OncePerProcess" } # skip if UI sequence already run in same process
            if ($Type -band 0x300) { "ClientRepeat"   } # run on client only if UI already run on client
        }
    }
    else {
        "Always"                                        # default is execute whenever sequenced
    }
}

function Get-CustomActionSecurityContextFlag {
    # MsiDefs.h -> msidbCustomActionType
    param ( [uint32] $Type )
    if ($Type -band 0x800) {
        "NoImpersonate" # no impersonation, run in system context
    }
    else {
        "Impersonate" # default to impersonate as user, valid only if InScript
        if ($Type -band 0x4000) { "TSAware" } # impersonate for per-machine installs on Terminal Server machines
    }
}

function Get-CustomAction {
    <#
    .SYNOPSIS
    Get a list of Custom Actions defined in an MSI file.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function extracts the Custom Actions defined in an MSI file. If no Custom Action is defined, it returns null.

    .PARAMETER Database
    An object representing an MSI database.

    .PARAMETER Arch
    Ths system's architecture (32, 64).

    .PARAMETER AllUsers
    A parameter representing the value of the ALLUSERS MSI property.
    #>

    param (
        [string] $FilePath,
        [object] $Database,
        [uint32] $Arch,
        [uint32] $AllUsers
    )

    begin {
        $SystemFolders = Get-MsiSystemFolderProperty -Arch $Arch -AllUsers $AllUsers
        $QuietExecFunctions = @("CAQuietExec", "CAQuietExec64", "WixQuietExec", "WixQuietExec64")
    }

    process {
        if ($(Get-MsiTableList -Database $Database) -NotContains "CustomAction") { return }

        try {
            $SqlQuery = "SELECT * FROM CustomAction"
            $View = Invoke-MsiDatabaseOpenView -Database $Database -Query $SqlQuery
            Invoke-MsiViewExecute -View $View

            $Record = Invoke-MsiViewFetch -View $View

            while ($null -ne $Record) {

                $Action = Invoke-MsiGetProperty -Record $Record -Property "StringData" -Index 1
                $Type = [uint32] (Invoke-MsiGetProperty -Record $Record -Property "StringData" -Index 2)
                $Source = Invoke-MsiGetProperty -Record $Record -Property "StringData" -Index 3
                $Target = Invoke-MsiGetProperty -Record $Record -Property "StringData" -Index 4

                $ExeType = Get-CustomActionExecutableType -Type $Type
                $SourceType = Get-CustomActionExecutableSource -Type $Type
                $ReturnProcessing = ([string[]] (Get-CustomActionReturnProcessing -Type $Type)) -join ","
                $SchedulingFlags = ([string[]] (Get-CustomActionExecutionSchedulingFlag -Type $Type)) -join ","
                $SecurityContextFlags = ([string[]] (Get-CustomActionSecurityContextFlag -Type $Type)) -join ","

                $TargetExpanded = Get-MsiExpandedString -String $Target -Database $Database -SystemFolders $SystemFolders
                if ($TargetExpanded -eq $Target) { $TargetExpanded = $null }

                # 0x0800 -> no impersonation, run in system context
                $RunAsSystem = $([bool] ($Type -band 0x0800))
                # 0x8000 -> custom action to be run only during a patch uninstall
                $RunOnPatchUninstallOnly = $([bool] ($Type -band 0x8000))

                if ($SourceType -eq "BinaryData") {
                    $OutputFilename = "$($Source)"
                    if (-not (($Source -like "*.dll") -or ($Source -like "*.exe"))) {
                        switch ($ExeType) {
                            "Exe" { $OutputFilename += ".exe"; break }
                            "Dll" { $OutputFilename += ".dll"; break }
                            default { $OutputFilename += ".bin" }
                        }
                    }
                    $BinaryExtractCommand = "Invoke-MsiExtractBinaryData -Path `"$($FilePath)`" -Name `"$($Source)`" -OutputPath `"$($OutputFilename)`""
                }
                else {
                    $BinaryExtractCommand = "(null)"
                }

                $Candidate = $false
                if (
                    # CA must not be configured to run only on patch uninstall
                    (-not $RunOnPatchUninstallOnly) -and
                    # CA must run as SYSTEM
                    ($RunAsSystem) -and
                    # If CA is a DLL, it must not be a "quiet exec" function
                    (
                        ($ExeType -ne "Dll") -or
                        (
                            ($ExeType -eq "Dll") -and
                            (-not ($QuietExecFunctions -contains $Target))
                        )
                    )
                ) {
                    $Candidate = $true
                }

                $CustomAction = New-Object -TypeName PSObject
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "Action" -Value $Action
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "Type" -Value $Type
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "Source" -Value $Source
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "Target" -Value $Target
                if ($TargetExpanded) { $CustomAction | Add-Member -MemberType "NoteProperty" -Name "TargetExpanded" -Value $TargetExpanded }
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "ExeType" -Value $ExeType
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "SourceType" -Value $SourceType
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "ReturnProcessing" -Value $ReturnProcessing
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "SchedulingFlags" -Value $SchedulingFlags
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "SecurityContextFlags" -Value $SecurityContextFlags
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "RunAsSystem" -Value $RunAsSystem
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "RunOnPatchUninstallOnly" -Value $RunOnPatchUninstallOnly
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "BinaryExtractCommand" -Value $BinaryExtractCommand
                $CustomAction | Add-Member -MemberType "NoteProperty" -Name "Candidate" -Value $Candidate
                $CustomAction

                $Record = Invoke-MsiViewFetch -View $View
            }

            Invoke-MsiViewClose -View $View
        }
        catch {
            Write-Warning "Failed to enumerate Custom Actions (File: '$($MsiFile.FullName)': $($_)"
        }
    }
}

function Get-MsiProperty {
    <#
    .SYNOPSIS
    Get the value of an MSI file property.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function extracts the value of an MSI property, such as the product code, the product name, or the manufacturer name.

    .PARAMETER Database
    An object representing an MSI database.

    .PARAMETER Property
    The name of a metadata property.
    #>
    param (
        [object] $Database,
        [ValidateSet("ProductCode", "ProductName", "Manufacturer", "ProductVersion", "ALLUSERS")]
        [string] $Property
    )
    try {
        # No need for a parameterized query since the Property value is based on a
        # validated set.
        $SqlQuery = "SELECT Value FROM Property WHERE Property='$($Property)'"
        $View = Invoke-MsiDatabaseOpenView -Database $Database -Query $SqlQuery
        Invoke-MsiViewExecute -View $View
        $Record = Invoke-MsiViewFetch -View $View
        if ($Record) { Invoke-MsiGetProperty -Record $Record -Property "StringData" -Index 1 }
    }
    catch {
        Write-Warning "Get-MsiProperty exception (Property=$($Property)): $($_)"
    }
}

function Get-MsiDirectoryProperty {
    <#
    .SYNOPSIS
    Get the "Directory_Parent" and "DefaultDir" properties of a "Directory" entry.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function retrieves the "Directory_Parent" and "DefaultDir" properties of a "Directory" entry from the input MSI database given its name.

    .PARAMETER Database
    An object representing an MSI database.

    .PARAMETER Directory
    The name of a "Directory" entry.
    #>

    [OutputType([string])]
    param (
        [object] $Database,
        [string] $Directory
    )

    begin {
        $Result = $null
        $TempInstaller = New-Object -ComObject WindowsInstaller.Installer
    }

    process {
        try {
            # Prepare a "Record" object to store the value to replace in the parameterized query.
            $Record = Invoke-MsiCreateRecord -Installer $TempInstaller -Count 1
            $null = Invoke-MsiSetProperty -Record $Record -Property "StringData" -Index 1 -Value $Directory

            # Execute the parameterized query.
            $SqlQuery = "SELECT Directory_Parent,DefaultDir FROM Directory WHERE Directory=?"
            $View = Invoke-MsiDatabaseOpenView -Database $Database -Query $SqlQuery
            $null = Invoke-MsiViewExecute -View $View -Record $Record
            $Record = Invoke-MsiViewFetch -View $View
            if ($Record) {
                $DirectoryParent = Invoke-MsiGetProperty -Record $Record -Property "StringData" -Index 1
                $DefaultDir = Invoke-MsiGetProperty -Record $Record -Property "StringData" -Index 2
                if ($DefaultDir -like "*|*") { $DefaultDir = $DefaultDir.Split('|')[1] }
                if ($DirectoryParent) {
                    $Result = "[$($DirectoryParent)]$($DefaultDir)\"
                } else {
                    $Result = "$($DefaultDir)\"
                }
            }
        }
        catch {
            Write-Warning "Get-MsiDirectoryProperty exception: $($_)"
        }
    }

    end {
        $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($TempInstaller)
        $Result
    }
}

function Get-MsiFilenameProperty {
    <#
    .SYNOPSIS
    Get the "FileName" property of a "File" entry.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function extracts the "FileName" property of a "File" entry in the input MSI database given its name.

    .PARAMETER Database
    An object representing an MSI database.

    .PARAMETER File
    The name of a "File" entry.
    #>

    [OutputType([string])]
    param (
        [object] $Database,
        [string] $File
    )

    begin {
        $Result = $null
        $TempInstaller = New-Object -ComObject WindowsInstaller.Installer
    }

    process {
        try {
            # Prepare a "Record" object to store the value to replace in the parameterized query.
            $Record = Invoke-MsiCreateRecord -Installer $TempInstaller -Count 1
            $null = Invoke-MsiSetProperty -Record $Record -Property "StringData" -Index 1 -Value $File

            # Execute the parameterized query.
            $SqlQuery = "SELECT FileName FROM File WHERE File=?"
            $View = Invoke-MsiDatabaseOpenView -Database $Database -Query $SqlQuery
            $null = Invoke-MsiViewExecute -View $View -Record $Record
            $Record = Invoke-MsiViewFetch -View $View
            if ($Record) {
                $Result = Invoke-MsiGetProperty -Record $Record -Property "StringData" -Index 1
                if ($Result -like "*|*") { $Result = $Result.Split('|')[1] }
            }
        }
        catch {
            Write-Warning "Get-MsiFilenameProperty exception: $($_)"
        }
    }

    end {
        $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($TempInstaller)
        $Result
    }
}

function Get-MsiComponentProperty {
    <#
    .SYNOPSIS
    Get the "Directory" property of a "Component" entry.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function retrieves the "Directory" property of an entry in the "Component" table given its name.

    .PARAMETER Database
    An object representing an MSI database.

    .PARAMETER Component
    The name of a "Component" entry.
    #>

    [OutputType([string])]
    param (
        [object] $Database,
        [string] $Component
    )

    begin {
        $Result = $null
        $TempInstaller = New-Object -ComObject WindowsInstaller.Installer
    }

    process {
        try {
            # Prepare a "Record" object to store the value to replace in the parameterized query.
            $Record = Invoke-MsiCreateRecord -Installer $TempInstaller -Count 1
            $null = Invoke-MsiSetProperty -Record $Record -Property "StringData" -Index 1 -Value $Component

            # Execute the parameterized query.
            $SqlQuery = "SELECT Directory_ FROM Component WHERE Component=?"
            $View = Invoke-MsiDatabaseOpenView -Database $Database -Query $SqlQuery
            $null = Invoke-MsiViewExecute -View $View -Record $Record
            $Record = Invoke-MsiViewFetch -View $View
            if ($Record) {
                $Result = Invoke-MsiGetProperty -Record $Record -Property "StringData" -Index 1
                if ($Result -like "*|*") { $Result = $Result.Split('|')[1] }
            }
        }
        catch {
            Write-Warning "Get-MsiComponentProperty exception: $($_)"
        }
    }

    end {
        $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($TempInstaller)
        $Result
    }
}

function Get-MsiBinaryDataProperty {
    <#
    .SYNOPSIS
    Extract binary data from the default "Binary" table of an MSI database.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function extracts a resource from the "Binary" table of the input MSI database given its name.

    .PARAMETER Database
    An object representing an MSI database.

    .PARAMETER Name
    The name of the binary resource to extract.
    #>

    param (
        [object] $Database,
        [string] $Name
    )

    begin {
        $Result = $null
        $TempInstaller = New-Object -ComObject WindowsInstaller.Installer
        $MsiReadStreamAnsi = 2
        $FieldIndex = 1
    }

    process {
        try {
            # Prepare a "Record" object to store the value to replace in the parameterized query.
            $Record = Invoke-MsiCreateRecord -Installer $TempInstaller -Count 1
            $null = Invoke-MsiSetProperty -Record $Record -Property "StringData" -Index 1 -Value $Name

            # Execute the parameterized query.
            $SqlQuery = "SELECT Data FROM Binary WHERE Name=?"
            $View = Invoke-MsiDatabaseOpenView -Database $Database -Query $SqlQuery
            $null = Invoke-MsiViewExecute -View $View -Record $Record
            $Record = Invoke-MsiViewFetch -View $View
            if ($Record) {
                $DataSize = [int32] (Invoke-MsiGetProperty -Record $Record -Property "DataSize" -Index $FieldIndex)
                Write-Verbose "Name: $($Name) | DataSize: $($DataSize)"
                if ($DataSize -eq 0) { return }

                $DataStream = $Record.GetType().InvokeMember("ReadStream", "InvokeMethod", $null, $Record, @($FieldIndex, $DataSize, $MsiReadStreamAnsi))
                if ($null -eq $DataStream) { return }

                $Result = $DataStream
            }
        }
        catch {
            Write-Warning "Get-MsiBinaryDataProperty exception: $($_)"
        }
    }

    end {
        $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($TempInstaller)
        $Result
    }
}

function Get-MsiTableList {
    <#
    .SYNOPSIS
    List the tables contained within an MSI database.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function enumerates the entries of the default table "_Tables" to return a list of tables contained within the input MSI database.

    .PARAMETER Database
    An object representing an MSI database.
    #>

    param ( [object] $Database )

    try {
        $SqlQuery = "SELECT Name FROM _Tables"
        $View = Invoke-MsiDatabaseOpenView -Database $Database -Query $SqlQuery
        Invoke-MsiViewExecute -View $View
        $Record = Invoke-MsiViewFetch -View $View
        while ($null -ne $Record) {
            Invoke-MsiGetProperty -Record $Record -Property "StringData" -Index 1
            $Record = Invoke-MsiViewFetch -View $View
        }
    }
    catch {
        Write-Warning "Get-MsiTableList exception: $($_)"
    }
}

function Get-MsiSystemFolderProperty {
    <#
    .SYNOPSIS
    Get a list of MSI system folder properties.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function resolves the known system folder paths in the context of current environment, user, and MSI properties.

    .PARAMETER Arch
    The target architecture (32 or 64).

    .PARAMETER AllUsers
    A parameter representing the value of the ALLUSERS MSI property.
    #>

    param (
        [ValidateSet(32, 64)]
        [uint32] $Arch,
        [ValidateSet(0, 1, 2)]
        [uint32] $AllUsers
    )
    # https://learn.microsoft.com/en-us/windows/win32/msi/property-reference#system-folder-properties

    $AllUserAppData = Join-Path -Path $env:ALLUSERSPROFILE -ChildPath "Microsoft\Windows"

    @{
        "AdminToolsFolder" = "ADMIN_TOOLS_FOLDER"
        "AppDataFolder" = $env:APPDATA
        "CommonAppDataFolder" = $env:ProgramData
        "CommonFiles64Folder" = $(if ($Arch -eq 64) { $env:CommonProgramFiles } else { $null })
        "CommonFilesFolder" = $(if ($Arch -eq 64) { ${env:CommonProgramFiles(x86)} } else { $env:CommonProgramFiles })
        "DesktopFolder" = Join-Path -Path $(if ($AllUsers) { $env:ALLUSERSPROFILE } else { $env:USERPROFILE }) -ChildPath "Desktop"
        "FavoritesFolder" = Join-Path -Path $(if ($AllUsers) { $env:ALLUSERSPROFILE } else { $env:USERPROFILE }) -ChildPath "Favorites"
        "FontsFolder" = Join-Path -Path $env:windir -ChildPath "Fonts"
        "LocalAppDataFolder" = $env:LOCALAPPDATA
        "MyPicturesFolder" = Join-Path -Path $env:USERPROFILE -ChildPath "Pictures"
        "NetHoodFolder" = "NET_HOOD_FOLDER"
        "PersonalFolder" = $env:USERPROFILE
        "PrintHoodFolder" = "PRINT_HOOD_FOLDER"
        "ProgramFiles64Folder" = $(if ($Arch -eq 64) { $env:ProgramFiles } else { $null })
        "ProgramFilesFolder" = $(if ($Arch -eq 64) { ${env:ProgramFiles(x86)} } else { ${env:ProgramFiles} })
        "ProgramMenuFolder" = Join-Path -Path $(if ($AllUsers) { $AllUserAppData } else { $env:APPDATA }) -ChildPath "Start Menu\Programs"
        "RecentFolder" = "RECENT_FOLDER"
        "SendToFolder" = Join-Path -Path $env:USERPROFILE -ChildPath "SendTo"
        "StartMenuFolder" = Join-Path -Path $(if ($AllUsers) { $AllUserAppData } else { $env:APPDATA }) -ChildPath "Start Menu"
        "StartupFolder" = Join-Path -Path $(if ($AllUsers) { $AllUserAppData } else { $env:APPDATA }) -ChildPath "Start Menu\Programs\Startup"
        "System16Folder" = Join-Path -Path $env:windir -ChildPath "System"
        "System64Folder" = Join-Path -Path $env:windir -ChildPath "System32"
        "SystemFolder" = Join-Path -Path $env:windir -ChildPath "System32"
        "TempFolder" = "TEMP_FOLDER"
        "TemplateFolder" = Join-Path -Path $(if ($AllUsers) { $AllUserAppData } else { $env:USERPROFILE }) -ChildPath "Templates"
        "WindowsFolder" = $env:windir
        "WindowsVolume" = Split-Path -Path $env:windir -Parent
    }
}

function Get-MsiExpandedString {
    <#
    .SYNOPSIS
    Expand variables used in the definition of Custom Actions.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This function takes a string as an input and attempts to resolve any variable it contains. In MSI files, variables are represented using a unique and custom identifier between square brackets.

    .PARAMETER String
    The input string to process.

    .PARAMETER Database
    An object representing an MSI database.

    .PARAMETER SystemFolders
    A list of known system folder properties, already resolved in the current user's context.
    #>

    param (
        [string] $String,
        [object] $Database,
        [object] $SystemFolders
    )

    $Variables = [string[]] ($String | Select-String -Pattern "\[[^\[]+\]" -AllMatches | ForEach-Object { $_.Matches })
    if ($null -eq $Variables) { return $String }
    foreach ($Variable in $Variables) {
        $Source = ($Variable.Replace("[", "")).Replace("]", "")
        # https://learn.microsoft.com/en-us/windows/win32/api/msiquery/nf-msiquery-msiformatrecorda
        switch ($Source[0]) {
            '%' {
                # This is an environment variable.
                $String = $String.Replace("[$($Source)]", "$([Environment]::GetEnvironmentVariable($Source.Substring(1)))")
                break
            }
            '#' {
                # The value can be found in the "File" table.
                $Resolved = Get-MsiFilenameProperty -Database $Database -File $Source.Substring(1)
                if ($Resolved) {
                    $String = $String.Replace("[$($Source)]", "$($Resolved)")
                }
                else {
                    $String = $String.Replace("[$($Source)]", "$($Source)_NOT_RESOLVED")
                }
                break
            }
            '$' {
                # The value can be found in the "Component" table.
                $String = $String.Replace("[$($Source)]", "$($Source)_NOT_RESOLVED")
                $Resolved = Get-MsiComponentProperty -Database $Database -Component $Source.Substring(1)
                if ($Resolved) {
                    $String = $String.Replace("[$($Source)]", "[$($Resolved)]")
                }
                else {
                    $String = $String.Replace("[$($Source)]", "$($Source)_NOT_RESOLVED")
                }
                break
            }
            '\\' {
                # Keep only the first character, remove everything else.
                $String = $String.Replace("[$($Source)]", "$($Source.Substring(1, 1))")
                break
            }
            default {
                # This is a regular variable, search in the "Directory" table.
                if ($SystemFolders.Keys -contains $Source) {
                    $String = $String.Replace("[$($Source)]", "$($SystemFolders[$Source])\")
                }
                else {
                    $Resolved = Get-MsiDirectoryProperty -Database $Database -Directory $Source
                    if ($Resolved) {
                        $String = $String.Replace("[$($Source)]", "$($Resolved)")
                    }
                    else {
                        $String = $String.Replace("[$($Source)]", "$($Source)_NOT_RESOLVED")
                    }
                }
            }
        }
    }
    Get-MsiExpandedString -String $String -Database $Database -SystemFolders $SystemFolders
}

function Get-MsiFileItem {
    <#
    .SYNOPSIS
    Extract important data from cached MSI files.

    Author: @itm4n
    License: BSD 3-Clause

    .DESCRIPTION
    This cmdlet enumerates cached MSI files (located in C:\Windows\Installer) and extracts useful information, such as the product's name, vendor's name, and its Custom Actions, if any are defined.
    #>

    [CmdletBinding()]
    param (
        [string] $FilePath
    )

    begin {
        $InstallerPath = Join-Path -Path $env:windir -ChildPath "Installer"
        $Arch = $(if ([Environment]::Is64BitOperatingSystem) { 64 } else { 32 })
    }

    process {
        if ([string]::IsNullOrEmpty($FilePath)) {
            $MsiFiles = Get-ChildItem -Path "$($InstallerPath)\*.msi" -ErrorAction SilentlyContinue
        }
        else {
            $MsiFiles = Get-Item -Path $FilePath
        }

        foreach ($MsiFile in $MsiFiles) {

            Write-Verbose "Parsing file: $($MsiFile.FullName)"
            $Installer = New-Object -ComObject WindowsInstaller.Installer

            $Database = Invoke-MsiOpenDatabase -Installer $Installer -Path $MsiFile.FullName -Mode 0

            $IdentifyingNumber = [string] (Get-MsiProperty -Database $Database -Property "ProductCode")
            $Name = [string] (Get-MsiProperty -Database $Database -Property "ProductName")
            $Vendor = [string] (Get-MsiProperty -Database $Database -Property "Manufacturer")
            $Version = [string] (Get-MsiProperty -Database $Database -Property "ProductVersion")
            $AllUsers = Get-MsiProperty -Database $Database -Property "ALLUSERS"

            # Extract the GUID value, without the curly braces.
            if ($IdentifyingNumber -match "(\d|[A-F]){8}-((\d|[A-F]){4}-){3}((\d|[A-F]){12})") {
                $IdentifyingNumber = $Matches[0]
            }

            # If ALLUSERS is not defined, the default is "per-user", which corresponds to a value of 0.
            # https://learn.microsoft.com/en-us/windows/win32/msi/allusers
            $AllUsers = [uint32] $(if ($AllUsers) { $AllUsers[1] } else { 0 })

            $MsiFileItem = New-Object -TypeName PSObject
            $MsiFileItem | Add-Member -MemberType "NoteProperty" -Name "Path" -Value $MsiFile.FullName
            $MsiFileItem | Add-Member -MemberType "NoteProperty" -Name "IdentifyingNumber" -Value $(if ($IdentifyingNumber) { $IdentifyingNumber.Trim() })
            $MsiFileItem | Add-Member -MemberType "NoteProperty" -Name "Name" -Value $(if ($Name) { $Name.Trim() })
            $MsiFileItem | Add-Member -MemberType "NoteProperty" -Name "Vendor" -Value $(if ($Vendor) { $Vendor.Trim() })
            $MsiFileItem | Add-Member -MemberType "NoteProperty" -Name "Version" -Value $(if ($Version) { $Version.Trim() })
            $MsiFileItem | Add-Member -MemberType "NoteProperty" -Name "AllUsers" -Value $AllUsers
            $MsiFileItem | Add-Member -MemberType "NoteProperty" -Name "CustomActions" -Value $(Get-CustomAction -FilePath $MsiFile.FullName -Database $Database -Arch $Arch -AllUsers $AllUsers)
            $MsiFileItem

            $null = [System.Runtime.InteropServices.Marshal]::ReleaseComObject($Installer)
        }
    }
}