function New-Enum {
    <#
    .SYNOPSIS
    Creates an in-memory enumeration for use in your PowerShell session.

    Credit: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

    .DESCRIPTION
    The 'New-Enum' function facilitates the creation of enums entirely in memory using as close to a "C style" as PowerShell will allow.

    .PARAMETER Module
    The in-memory module that will host the enum. Use New-InMemoryModule to define an in-memory module.

    .PARAMETER FullName
    The fully-qualified name of the enum.

    .PARAMETER Type
    The type of each enum element.

    .PARAMETER EnumElements
    A hashtable of enum elements.

    .PARAMETER BitField
    Specifies that the enum should be treated as a bit field.

    .EXAMPLE
    $Mod = New-InMemoryModule -ModuleName Win32
    $ImageSubsystem = New-Enum $Mod PE.IMAGE_SUBSYSTEM UInt16 @{
        UNKNOWN =                  0
        NATIVE =                   1 # Image doesn't require a subsystem.
        WINDOWS_GUI =              2 # Image runs in the Windows GUI subsystem.
        WINDOWS_CUI =              3 # Image runs in the Windows character subsystem.
        OS2_CUI =                  5 # Image runs in the OS/2 character subsystem.
        POSIX_CUI =                7 # Image runs in the Posix character subsystem.
        NATIVE_WINDOWS =           8 # Image is a native Win9x driver.
        WINDOWS_CE_GUI =           9 # Image runs in the Windows CE subsystem.
        EFI_APPLICATION =          10
        EFI_BOOT_SERVICE_DRIVER =  11
        EFI_RUNTIME_DRIVER =       12
        EFI_ROM =                  13
        XBOX =                     14
        WINDOWS_BOOT_APPLICATION = 16
    }
    #>

    [OutputType([Type])]
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateScript( { ($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly]) })]
        $Module,

        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 2, Mandatory = $true)]
        [Type]
        $Type,

        [Parameter(Position = 3, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $EnumElements,

        [Switch]
        $BitField
    )

    if ($Module -is [Reflection.Assembly]) {
        return ($Module.GetType($FullName))
    }

    $EnumType = $Type -as [Type]

    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)

    if ($BitField) {
        $FlagsConstructor = [FlagsAttribute].GetConstructor(@())
        $FlagsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($FlagsConstructor, @())
        $EnumBuilder.SetCustomAttribute($FlagsCustomAttribute)
    }

    foreach ($Key in $EnumElements.Keys) {
        # Apply the specified enum type to each element
        $null = $EnumBuilder.DefineLiteral($Key, $EnumElements[$Key] -as $EnumType)
    }

    $EnumBuilder.CreateType()
}