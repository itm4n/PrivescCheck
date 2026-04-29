# A helper function used to reduce typing while defining struct fields.
function New-StructureField {
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt16]
        $Position,

        [Parameter(Position = 1, Mandatory = $true)]
        [Type]
        $Type,

        [Parameter(Position = 2)]
        [UInt16]
        $Offset,

        [Object[]]
        $MarshalAs
    )

    @{
        Position  = $Position
        Type      = $Type -as [Type]
        Offset    = $Offset
        MarshalAs = $MarshalAs
    }
}

function New-Structure {
    <#
    .SYNOPSIS
    Creates an in-memory struct for use in your PowerShell session.

    Credit: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: field

    .DESCRIPTION
    The 'New-Structure' function facilitates the creation of structures entirely in memory using as close to a "C style" as PowerShell will allow. Struct fields are specified using a hashtable where each field of the struct is composed of the order in which it should be defined, its .NET type, and optionally, its offset and special marshaling attributes. One of the features of 'struct' is that after your struct is defined, it will come with a built-in GetSize method as well as an explicit converter so that you can easily cast an IntPtr to the struct without relying upon calling SizeOf and/or PtrToStructure in the Marshal class.

    .PARAMETER Module
    The in-memory module that will host the struct. Use New-InMemoryModule to define an in-memory module.

    .PARAMETER FullName
    The fully-qualified name of the struct.

    .PARAMETER StructFields
    A hashtable of fields. Use the 'field' helper function to ease defining each field.

    .PARAMETER PackingSize
    Specifies the memory alignment of fields.

    .PARAMETER ExplicitLayout
    Indicates that an explicit offset for each field will be specified.

    .EXAMPLE
    $Mod = New-InMemoryModule -ModuleName Win32
    $ImageDosSignature = New-Enum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
        DOS_SIGNATURE =    0x5A4D
        OS2_SIGNATURE =    0x454E
        OS2_SIGNATURE_LE = 0x454C
        VXD_SIGNATURE =    0x454C
    }
    $ImageDosHeader = New-Structure $Mod PE.IMAGE_DOS_HEADER @{
        e_magic =    field 0 $ImageDosSignature
        e_cblp =     field 1 UInt16
        e_cp =       field 2 UInt16
        e_crlc =     field 3 UInt16
        e_cparhdr =  field 4 UInt16
        e_minalloc = field 5 UInt16
        e_maxalloc = field 6 UInt16
        e_ss =       field 7 UInt16
        e_sp =       field 8 UInt16
        e_csum =     field 9 UInt16
        e_ip =       field 10 UInt16
        e_cs =       field 11 UInt16
        e_lfarlc =   field 12 UInt16
        e_ovno =     field 13 UInt16
        e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
        e_oemid =    field 15 UInt16
        e_oeminfo =  field 16 UInt16
        e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
        e_lfanew =   field 18 Int32
    }
    # Example of using an explicit layout in order to create a union.
    $TestUnion = New-Structure $Mod TestUnion @{
        field1 = field 0 UInt32 0
        field2 = field 1 IntPtr 0
    } -ExplicitLayout
    #>

    [OutputType([Type])]
    param(
        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateScript( { ($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly]) })]
        $Module,

        [Parameter(Position = 2, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout,

        [Runtime.InteropServices.CharSet]
        $Charset
    )

    if ($Module -is [Reflection.Assembly]) {
        return ($Module.GetType($FullName))
    }

    # [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass, Class, Public, Sealed, BeforeFieldInit'
    [Reflection.TypeAttributes] $StructAttributes = 'Class, Public, Sealed, BeforeFieldInit'

    if ($ExplicitLayout) {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    if ($Charset -and (($Charset -eq [Runtime.InteropServices.CharSet]::Auto) -or ($Charset -eq [Runtime.InteropServices.Charset]::Unicode))) {
        if ($Charset -eq [Runtime.InteropServices.CharSet]::Auto) {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AutoClass
        }
        elseif ($Charset -eq [Runtime.InteropServices.CharSet]::Unicode) {
            $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::UnicodeClass
        }
    }
    else {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::AnsiClass
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys) {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field] }
    }

    foreach ($Field in $Fields) {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs) {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1]) {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }

            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize', 'Public, Static', [Int], [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call, [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call, [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit', 'PrivateScope, Public, Static, HideBySig, SpecialName', $StructBuilder, [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call, [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call, [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}