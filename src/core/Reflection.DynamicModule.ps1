function New-DynamicModule {
    <#
    .SYNOPSIS
    Short description

    .DESCRIPTION
    Long description

    .PARAMETER ModuleName
    Parameter description

    .EXAMPLE
    An example

    .NOTES
    https://github.com/jborean93/PowerShell-AnsibleVault/blob/master/AnsibleVault/Private/Invoke-Win32Api.ps1
    #>

    [CmdletBinding()]
    param(
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    # Check loaded assemblies first to see if the module already exists in memory. It so, simply
    # return the found assembly.
    foreach ($Assembly in [System.AppDomain]::CurrentDomain.GetAssemblies()) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    # The module does not already exist, so create a new one and return it.
    $AppDomain = [Reflection.Assembly].Assembly.GetType('System.AppDomain').GetProperty('CurrentDomain').GetValue($null, @())
    $Assembly = New-Object -TypeName System.Reflection.AssemblyName -ArgumentList $ModuleName
    $AssemblyBuilder = $AppDomain.DefineDynamicAssembly($Assembly, 'Run')
    $DynamicModule = $AssemblyBuilder.DefineDynamicModule($ModuleName, $false)

    # $Assembly = New-Object -TypeName System.Reflection.AssemblyName -ArgumentList $ModuleName
    # $AssemblyBuilder = [System.Reflection.Assembly].Assembly.GetTypes() | Where-Object { $_.Name -eq 'AssemblyBuilder' }
    # # $DynamicAssembly = $AssemblyBuilder::DefineDynamicAssembly($Assembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    # $DynamicAssembly = [System.Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly($Assembly, 'Run')
    # $DynamicModule = $DynamicAssembly.DefineDynamicModule($ModuleName, $false)

    return $DynamicModule
}

$Module = New-DynamicModule -ModuleName "WinApiModule"