. $(Join-Path -Path (Split-Path -Path $PSCommandPath -Parent) -ChildPath "00_build_helpers.ps1")

function Invoke-Build {

    [CmdletBinding()] param()

    begin {
        $BuildProfileCore = @(
            "src\core\00_core_reflection.ps1",
            "src\core\01_core_winapi_enumerations.ps1",
            "src\core\02_core_winapi_structures.ps1",
            "src\core\03_core_winapi.ps1"
        )

        $BuildProfilePrivescCheck = $BuildProfileCore + @(
            "src\helpers\00_helpers_main.ps1",
            "src\helpers\01_helpers_winapi_wrappers.ps1",
            "src\helpers\02_helpers_services.ps1",
            "src\helpers\03_helpers_credentials.ps1",
            "src\checks\00_checks_globals.ps1",
            "src\checks\01_checks_main.ps1",
            "src\checks\02_checks_user.ps1",
            "src\checks\03_checks_services.ps1",
            "src\checks\04_checks_applications.ps1",
            "src\checks\05_checks_scheduled_tasks.ps1",
            "src\checks\06_checks_hardening.ps1",
            "src\checks\07_checks_configuration.ps1",
            "src\checks\08_checks_network.ps1",
            "src\checks\09_checks_updates.ps1",
            "src\checks\10_checks_credentials.ps1",
            "src\checks\11_checks_misc.ps1"
        )

        $BuildProfiles = @{
            "PrivescCheck" = $BuildProfilePrivescCheck
        }

        $ScriptHeader = "#Requires -Version 2`n`n"
        $RootPath = Split-Path -Path (Split-Path -Path $PSCommandPath -Parent) -Parent
        $Wordlist = Get-Wordlist -WordLength 10
        $LolDrivers = Get-LolDrivers
    }

    process {

        foreach ($BuildProfileName in $BuildProfiles.Keys) {

            $BuildProfile = $BuildProfiles[$BuildProfileName]
            $ScriptFilename = "$($BuildProfileName).ps1"
            $ScriptPath = Join-Path -Path $RootPath -ChildPath "release\$($ScriptFilename)"
            $ScriptContent = "$($ScriptHeader)"
            $ErrorCount = 0
            $Modules = @()

            Write-Message "Building script '$($ScriptFilename)'..."

            foreach ($ModuleRelativePath in $BuildProfile) {

                $ModulePath = Join-Path -Path $RootPath -ChildPath $ModuleRelativePath
                $ModuleItem = Get-Item -Path $ModulePath -ErrorAction SilentlyContinue

                if ($null -eq $ModuleItem) {
                    Write-Message -Type Error "Failed to open file '$($ModulePath)'."
                    $ErrorCount += 1
                    break
                }

                $ModuleFilename = $ModuleItem.Name

                if ($null -ne $Wordlist) {
                    # Pick a random name from the wordlist.
                    $RandomName = Get-Random -InputObject $Wordlist -Count 1
                    $Wordlist = $Wordlist | Where-Object { $_ -ne $RandomName }
                    $ModuleName = $RandomName.ToLower()
                    $ModuleName = ([regex]$ModuleName[0].ToString()).Replace($ModuleName, $ModuleName[0].ToString().ToUpper(), 1)
                }
                else {
                    # Otherwise use the module name from the file name.
                    $ModuleNameSplit = ($ModuleFilename.Split('.')[0]).Split('_')
                    $ModuleName = $ModuleNameSplit[1..($ModuleNameSplit.Count-1)] -join '_'
                }

                [string[]] $Modules += $ModuleName

                try {
                    $ScriptBlock = Get-Content -Path $ModulePath | Out-String

                    # Populate vulnerable driver list.
                    if ($ModuleFilename -like "*globals*") {

                        Write-Message "Populating file '$($ModuleFilename)' with list of vulnerable drivers..."
                        
                        if ($null -ne $LolDrivers) {

                            $LolDriversCsv = $LolDrivers | ConvertTo-Csv -Delimiter ";" | Out-String
                            Write-Message "Driver list exported as CSV."
                            $ScriptBlock = $ScriptBlock -replace "VULNERABLE_DRIVERS",$LolDriversCsv
                            Write-Message "Driver list written to '$($ModuleFilename)'."
                        }
                    }

                    # Is the script block detected by AMSI after stripping the comments?
                    # Note: if the script block is caught by AMSI, an exception is triggered, so we go
                    # directly to the "catch" block. Otherwise, it means that the module was sucessfully 
                    # loaded.
                    $ScriptBlock = Remove-CommentsFromScriptBlock -ScriptBlock $ScriptBlock
                    $ScriptBlock | Invoke-Expression

                    Write-Message "File '$($ModuleFilename)' (name: '$($ModuleName)') was loaded successfully."

                    $ScriptCompressed = ConvertTo-Gzip -InputText $ScriptBlock
                    $ScriptCompressedEncoded = [System.Convert]::ToBase64String($ScriptCompressed)
                    $ScriptContent += "`$$($ModuleName) = `"$($ScriptCompressedEncoded)`"`n"
                }
                catch {
                    $ErrorCount += 1
                    Write-Message -Type Error "$($_.Exception.Message.Trim())"
                }
            }

            if ($ErrorCount -eq 0) {
                Write-Message -Type Success "Build successful, writing result to file '$($ScriptPath)'..."
                $ScriptContent += "`n$(Get-ScriptLoader -Modules $Modules)"
                $ScriptContent | Out-File -FilePath $ScriptPath -Encoding ascii
            }
        }
    }
}