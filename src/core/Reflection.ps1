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

# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
function New-Function {
    param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $true)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [String]
        $EntryPoint,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName      = $DllName
        FunctionName = $FunctionName
        ReturnType   = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }
    if ($EntryPoint) { $Properties['EntryPoint'] = $EntryPoint }

    New-Object PSObject -Property $Properties
}

function Add-Win32Type {
    <#
    .SYNOPSIS
    Creates a .NET type for an unmanaged Win32 function.

    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: func

    .DESCRIPTION
    Add-Win32Type enables you to easily interact with unmanaged (i.e. Win32 unmanaged) functions in PowerShell. After providing Add-Win32Type with a function signature, a .NET type is created using reflection (i.e. csc.exe is never called like with Add-Type). The 'func' helper function can be used to reduce typing when defining multiple function definitions.

    .PARAMETER DllName
    The name of the DLL.

    .PARAMETER FunctionName
    The name of the target function.

    .PARAMETER EntryPoint
    The DLL export function name. This argument should be specified if the specified function name is different than the name of the exported function.

    .PARAMETER ReturnType
    The return type of the function.

    .PARAMETER ParameterTypes
    The function parameters.

    .PARAMETER NativeCallingConvention
    Specifies the native calling convention of the function. Defaults to stdcall.

    .PARAMETER Charset
    If you need to explicitly call an 'A' or 'W' Win32 function, you can specify the character set.

    .PARAMETER SetLastError
    Indicates whether the callee calls the SetLastError Win32 API function before returning from the attributed method.

    .PARAMETER Module
    The in-memory module that will host the functions. Use New-InMemoryModule to define an in-memory module.

    .PARAMETER Namespace
    An optional namespace to prepend to the type. Add-Win32Type defaults to a namespace consisting only of the name of the DLL.

    .EXAMPLE
    $Mod = New-InMemoryModule -ModuleName Win32
    $FunctionDefinitions = @(
    (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
    (func kernel32 GetModuleHandle ([IntPtr]) @([String]) -SetLastError),
    (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
    )
    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
    $Kernel32 = $Types['kernel32']
    $Ntdll = $Types['ntdll']
    $Ntdll::RtlGetCurrentPeb()
    $NtdllBase = $Kernel32::GetModuleHandle('ntdll')
    $Kernel32::GetProcAddress($NtdllBase, 'RtlGetCurrentPeb')

    .NOTES
    Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189 When defining multiple function prototypes, it is ideal to provide Add-Win32Type with an array of function signatures. That way, they are all incorporated into the same in-memory module.
    #>

    [OutputType([Hashtable])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String]
        $DllName,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [String]
        $FunctionName,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [String]
        $EntryPoint,

        [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $true)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $true)]
        [ValidateScript( { ($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly]) })]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    begin {
        $TypeHash = @{}
    }

    process {
        if ($Module -is [Reflection.Assembly]) {
            if ($Namespace) {
                $TypeHash[$DllName] = $Module.GetType("$Namespace.$DllName")
            }
            else {
                $TypeHash[$DllName] = $Module.GetType($DllName)
            }
        }
        else {
            # Define one type for each DLL
            if (!$TypeHash.ContainsKey($DllName)) {
                if ($Namespace) {
                    $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
                }
                else {
                    $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
                }
            }

            $Method = $TypeHash[$DllName].DefineMethod(
                $FunctionName,
                'Public,Static,PInvokeImpl',
                $ReturnType,
                $ParameterTypes)

            # Make each ByRef parameter an Out parameter
            $i = 1
            foreach ($Parameter in $ParameterTypes) {
                if ($Parameter.IsByRef) {
                    [void] $Method.DefineParameter($i, 'Out', $null)
                }

                $i++
            }

            $DllImport = [Runtime.InteropServices.DllImportAttribute]
            $SetLastErrorField = $DllImport.GetField('SetLastError')
            $CallingConventionField = $DllImport.GetField('CallingConvention')
            $CharsetField = $DllImport.GetField('CharSet')
            $EntryPointField = $DllImport.GetField('EntryPoint')
            if ($SetLastError) { $SLEValue = $true } else { $SLEValue = $false }

            if ($PSBoundParameters['EntryPoint']) { $ExportedFuncName = $EntryPoint } else { $ExportedFuncName = $FunctionName }

            # Equivalent to C# version of [DllImport(DllName)]
            $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
            $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
                $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
                [Reflection.FieldInfo[]] @($SetLastErrorField,
                    $CallingConventionField,
                    $CharsetField,
                    $EntryPointField),
                [Object[]] @($SLEValue,
                    ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention),
                    ([Runtime.InteropServices.CharSet] $Charset),
                    $ExportedFuncName))

            $Method.SetCustomAttribute($DllImportAttribute)
        }
    }

    END {
        if ($Module -is [Reflection.Assembly]) {
            return $TypeHash
        }

        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys) {
            $Type = $TypeHash[$Key].CreateType()

            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}

$Module = New-DynamicModule -ModuleName "WinApiModule"