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
    Param (
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

    .PARAMETER Bitfield
    Specifies that the enum should be treated as a bitfield.

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
    Param (
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
        $Bitfield
    )
    
    if ($Module -is [Reflection.Assembly]) {
        return ($Module.GetType($FullName))
    }
    
    $EnumType = $Type -as [Type]
    
    $EnumBuilder = $Module.DefineEnum($FullName, 'Public', $EnumType)
    
    if ($Bitfield) {
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
    Param (
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
    The 'New-Structure' function facilitates the creation of structs entirely in memory using as close to a "C style" as PowerShell will allow. Struct fields are specified using a hashtable where each field of the struct is comprosed of the order in which it should be defined, its .NET type, and optionally, its offset and special marshaling attributes. One of the features of 'struct' is that after your struct is defined, it will come with a built-in GetSize method as well as an explicit converter so that you can easily cast an IntPtr to the struct without relying upon calling SizeOf and/or PtrToStructure in the Marshal class.

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
    Param (
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
    Param (
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
    (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
    (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
    )
    $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
    $Kernel32 = $Types['kernel32']
    $Ntdll = $Types['ntdll']
    $Ntdll::RtlGetCurrentPeb()
    $ntdllbase = $Kernel32::GetModuleHandle('ntdll')
    $Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

    .NOTES
    Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189 When defining multiple function prototypes, it is ideal to provide Add-Win32Type with an array of function signatures. That way, they are all incorporated into the same in-memory module.
    #>

    [OutputType([Hashtable])]
    Param(
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

    BEGIN {
        $TypeHash = @{}
    }

    PROCESS {
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
                'Public,Static,PinvokeImpl',
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

$FileAccessRightsEnum = New-Enum $Module WinApiModule.FileAccessRightsEnum UInt32 @{
    # GenericRead                 = '0x80000000'
    # GenericWrite                = '0x40000000'
    # GenericExecute              = '0x20000000'
    # GenericAll                  = '0x10000000'
    MaximumAllowed              = '0x02000000'
    AccessSystemSecurity        = '0x01000000'
    Synchronize                 = '0x00100000'
    WriteOwner                  = '0x00080000'
    WriteDAC                    = '0x00040000'
    ReadControl                 = '0x00020000'
    Delete                      = '0x00010000'
    WriteAttributes             = '0x00000100'
    ReadAttributes              = '0x00000080'
    DeleteChild                 = '0x00000040'
    Execute                     = '0x00000020'
    WriteExtendedAttributes     = '0x00000010'
    ReadExtendedAttributes      = '0x00000008'
    AppendData                  = '0x00000004'
    WriteData                   = '0x00000002'
    ReadData                    = '0x00000001'
} -Bitfield

$ServiceAccessRightsEnum = New-Enum $Module WinApiModule.ServiceAccessRights UInt32 @{
    QueryConfig          = '0x00000001'
    ChangeConfig         = '0x00000002'
    QueryStatus          = '0x00000004'
    EnumerateDependents  = '0x00000008'
    Start                = '0x00000010'
    Stop                 = '0x00000020'
    PauseContinue        = '0x00000040'
    Interrogate          = '0x00000080'
    UserDefinedControl   = '0x00000100'
    Delete               = '0x00010000'
    ReadControl          = '0x00020000'
    WriteDac             = '0x00040000'
    WriteOwner           = '0x00080000'
    Synchronize          = '0x00100000'
    AccessSystemSecurity = '0x01000000'
    GenericAll           = '0x10000000'
    GenericExecute       = '0x20000000'
    GenericWrite         = '0x40000000'
    GenericRead          = '0x80000000'
    AllAccess            = '0x000F01FF'
} -Bitfield

$ServiceControlManagerAccessRightsEnum = New-Enum $Module WinApiModule.ServiceControlManagerAccessRights UInt32 @{
    Connect             = '0x00000001'
    CreateService       = '0x00000002'
    EnumerateService    = '0x00000004'
    Lock                = '0x00000008'
    QueryLockStatus     = '0x00000010'
    ModifyBootConfig    = '0x00000020'
    AllAccess           = '0x000f003f'
    GenericRead         = '0x00020014' # STANDARD_RIGHTS_READ | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_QUERY_LOCK_STATUS
    GenericWrite        = '0x00020022' # STANDARD_RIGHTS_WRITE | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_MODIFY_BOOT_CONFIG
    GenericExecute      = '0x00020009' # STANDARD_RIGHTS_EXECUTE | SC_MANAGER_CONNECT | SC_MANAGER_LOCK
} -Bitfield

$ProcessAccessRightsEnum = New-Enum $Module WinApiModule.ProcessAccessRights UInt32 @{
    Terminate               = '0x00000001'
    CreateThread            = '0x00000002'
    SetSessionId            = '0x00000004'
    VmOperation             = '0x00000008'
    VmRead                  = '0x00000010'
    VmWrite                 = '0x00000020'
    DupHandle               = '0x00000040'
    CreateProcess           = '0x00000080'
    SetQuota                = '0x00000100'
    SetInformation          = '0x00000200'
    QueryInformation        = '0x00000400'
    SuspendResume           = '0x00000800'
    QueryLimitedInformation = '0x00001000'
    SetLimitedInformation   = '0x00002000'
    AllAccess               = '0x001F0FFF'
    Synchronize             = '0x00100000'
} -Bitfield

$TokenAccessRightsEnum = New-Enum $Module WinApiModule.TokenAccessRights UInt32 @{
    AssignPrimary       = '0x00000001'
    Duplicate           = '0x00000002'
    Impersonate         = '0x00000004'
    Query               = '0x00000008'
    QuerySource         = '0x00000010'
    AdjustPrivileges    = '0x00000020'
    AdjustGroups        = '0x00000040'
    AdjustDefault       = '0x00000080'
    AdjustSessionId     = '0x00000100'
    Read                = '0x00020008'
    Write               = '0x000200e0'
    Execute             = '0x00020000'
    TrustConstraintMask = '0x00020018'
    AccessPseudoHandle  = '0x00000018'
    AllAccessP          = '0x000f00ff'
    AllAccess           = '0x000f01ff'
} -Bitfield

$ServiceTypeEnum = New-Enum $Module WinApiModule.ServiceType UInt32 @{
    KernelDriver        = '0x00000001'
    FileSystemDriver    = '0x00000002'
    Adapter             = '0x00000004'
    RecognizerDriver    = '0x00000008'
    Driver              = '0x0000000b'
    Win32OwnProcess     = '0x00000010'
    Win32ShareProcess   = '0x00000020'
    Win32               = '0x00000030'
    UserService         = '0x00000040'
    UserOwnProcess      = '0x00000050'
    UserShareProcess    = '0x00000060'
    UserServiceInstance = '0x00000080'
    InteractiveProcess  = '0x00000100'
    PkgService          = '0x00000200'
    All                 = '0x000003ff'
} -Bitfield

$ServiceStartTypeEnum = New-Enum $Module WinApiModule.ServiceStartType UInt32 @{
    Boot      = '0x00000000'
    System    = '0x00000001'
    Automatic = '0x00000002'
    Manual    = '0x00000003'
    Disabled  = '0x00000004'
}

$SID_NAME_USE = New-Enum $Module WinApiModule.SID_NAME_USE UInt32 @{
    User             = '0x00000001'
    Group            = '0x00000002'
    Domain           = '0x00000003'
    Alias            = '0x00000004'
    WellKnownGroup   = '0x00000005'
    DeletedAccount   = '0x00000006'
    Invalid          = '0x00000007'
    Unknown          = '0x00000008'
    Computer         = '0x00000009'
    Label            = '0x0000000A'
    LogonSession     = '0x0000000B'
}

$TOKEN_INFORMATION_CLASS = New-Enum $Module WinApiModule.TOKEN_INFORMATION_CLASS UInt32 @{
    TokenUser                               = '0x00000001'
    TokenGroups                             = '0x00000002'
    TokenPrivileges                         = '0x00000003'
    TokenOwner                              = '0x00000004'
    TokenPrimaryGroup                       = '0x00000005'
    TokenDefaultDacl                        = '0x00000006'
    TokenSource                             = '0x00000007'
    TokenType                               = '0x00000008'
    TokenImpersonationLevel                 = '0x00000009'
    TokenStatistics                         = '0x0000000A'
    TokenRestrictedSids                     = '0x0000000B'
    TokenSessionId                          = '0x0000000C'
    TokenGroupsAndPrivileges                = '0x0000000D'
    TokenSessionReference                   = '0x0000000E'
    TokenSandBoxInert                       = '0x0000000F'
    TokenAuditPolicy                        = '0x00000010'
    TokenOrigin                             = '0x00000011'
    TokenElevationType                      = '0x00000012'
    TokenLinkedToken                        = '0x00000013'
    TokenElevation                          = '0x00000014'
    TokenHasRestrictions                    = '0x00000015'
    TokenAccessInformation                  = '0x00000016'
    TokenVirtualizationAllowed              = '0x00000017'
    TokenVirtualizationEnabled              = '0x00000018'
    TokenIntegrityLevel                     = '0x00000019'
    TokenUIAccess                           = '0x0000001A'
    TokenMandatoryPolicy                    = '0x0000001B'
    TokenLogonSid                           = '0x0000001C'
    TokenIsAppContainer                     = '0x0000001D'
    TokenCapabilities                       = '0x0000001F'
    TokenAppContainerSid                    = '0x00000020'
    TokenAppContainerNumber                 = '0x00000021'
    TokenUserClaimAttributes                = '0x00000022'
    TokenDeviceClaimAttributes              = '0x00000023'
    TokenRestrictedUserClaimAttributes      = '0x00000024'
    TokenRestrictedDeviceClaimAttributes    = '0x00000025'
    TokenDeviceGroups                       = '0x00000026'
    TokenRestrictedDeviceGroups             = '0x00000027'
    TokenSecurityAttributes                 = '0x00000028'
    TokenIsRestricted                       = '0x00000029'
    TokenProcessTrustLevel                  = '0x0000002A'
    TokenPrivateNameSpace                   = '0x0000002B'
    TokenSingletonAttributes                = '0x0000002C'
    TokenBnoIsolation                       = '0x0000002D'
    TokenChildProcessFlags                  = '0x0000002E'
    TokenIsLessPrivilegedAppContainer       = '0x0000002F'
    TokenIsSandboxed                        = '0x00000030'
    TokenOriginatingProcessTrustLevel       = '0x00000031'
    MaxTokenInfoClass                       = '0x00000032'
}

$TOKEN_TYPE = New-Enum $Module WinApiModule.TOKEN_TYPE UInt32 @{
    TokenPrimary        = '0x00000001'
    TokenImpersonation  = '0x00000002'
}

$SECURITY_IMPERSONATION_LEVEL = New-Enum $Module WinApiModule.SECURITY_IMPERSONATION_LEVEL UInt32 @{
    SecurityAnonymous       = 0x00000001
    SecurityIdentification  = 0x00000002
    SecurityImpersonation   = 0x00000003
    SecurityDelegation      = 0x00000004
}

$TCP_TABLE_CLASS = New-Enum $Module WinApiModule.TCP_TABLE_CLASS UInt32 @{
    TCP_TABLE_BASIC_LISTENER            = '0x00000000'
    TCP_TABLE_BASIC_CONNECTIONS         = '0x00000001'
    TCP_TABLE_BASIC_ALL                 = '0x00000002'
    TCP_TABLE_OWNER_PID_LISTENER        = '0x00000003'
    TCP_TABLE_OWNER_PID_CONNECTIONS     = '0x00000004'
    TCP_TABLE_OWNER_PID_ALL             = '0x00000005'
    TCP_TABLE_OWNER_MODULE_LISTENER     = '0x00000006'
    TCP_TABLE_OWNER_MODULE_CONNECTIONS  = '0x00000007'
    TCP_TABLE_OWNER_MODULE_ALL          = '0x00000008'
}

$UDP_TABLE_CLASS = New-Enum $Module WinApiModule.UDP_TABLE_CLASS UInt32 @{
    UDP_TABLE_BASIC = '0x00000000'
    UDP_TABLE_OWNER_PID = '0x00000001'
    UDP_TABLE_OWNER_MODULE = '0x00000002'
}

$WLAN_INTERFACE_STATE = New-Enum $Module WinApiModule.WLAN_INTERFACE_STATE UInt32 @{
    NotReady           = '0x00000000'
    Connected          = '0x00000001'
    AdHocNetworkFormed = '0x00000002'
    Disconnecting      = '0x00000003'
    Disconnected       = '0x00000004'
    Associating        = '0x00000005'
    Discovering        = '0x00000006'
    Authenticating     = '0x00000007'
}

$ADS_USER_FLAGS = New-Enum $Module WinApiModule.ADS_USER_FLAGS UInt32 @{
    Script                              = '0x00000001'
    AccountDisable                      = '0x00000002'
    HomedirRequired                     = '0x00000008'
    Lockout                             = '0x00000010'
    PasswdNotreqd                       = '0x00000020'
    PasswdCantChange                    = '0x00000040'
    EncryptedTextPasswordAllowed        = '0x00000080'
    TempDuplicateAccount                = '0x00000100'
    NormalAccount                       = '0x00000200'
    InterdomainTrustAccount             = '0x00000800'
    WorkstationTrustAccount             = '0x00001000'
    ServerTrustAccount                  = '0x00002000'
    DontExpirePasswd                    = '0x00010000'
    MnsLogonAccount                     = '0x00020000'
    SmartcardRequired                   = '0x00040000'
    TrustedForDelegation                = '0x00080000'
    NotDelegated                        = '0x00100000'
    UseDesKeyOnly                       = '0x00200000'
    DontRequirePreauth                  = '0x00400000'
    PasswordExpired                     = '0x00800000'
    TrustedToAuthenticateForDelegation  = '0x01000000'
} -Bitfield

$GROUP_TYPE_FLAGS = New-Enum $Module WinApiModule.GROUP_TYPE_FLAGS UInt32 @{
    BuiltinLocalGroup   = '0x00000001'
    AccountGroup        = '0x00000002'
    ResourceGroup       = '0x00000004'
    UniversalGroup      = '0x00000008'
    AppBasicGroup       = '0x00000010'
    AppQueryGroup       = '0x00000020'
    SecurityEnabled     = '0x80000000'
} -Bitfield

$CRED_TYPE = New-Enum $Module WinApiModule.CRED_TYPE UInt32 @{
    Generic                 = '0x00000001'
    DomainPassword          = '0x00000002'
    DomainCertificate       = '0x00000003'
    DomainVisiblePassword   = '0x00000004'
    GenericCertificate      = '0x00000005'
    DomainExtended          = '0x00000006'
    Maximum                 = '0x00000007'
    MaximumEx               = '0x000003ef'
}

$CRED_PERSIST = New-Enum $Module WinApiModule.CRED_PERSIST UInt32 @{
    Session         = '0x00000001'
    LocalMachine    = '0x00000002'
    Enterprise      = '0x00000003'
}

# Custom enum, does not actually exist
$IP_ADAPTER_FLAGS = New-Enum $Module WinApiModule.IP_ADAPTER_FLAGS UInt32 @{
    DdnsEnabled             = 0x00000001
    RegisterAdapterSuffix   = 0x00000002
    Dhcpv4Enabled           = 0x00000004
    ReceiveOnly             = 0x00000008
    NoMulticast             = 0x00000010
    Ipv6OtherStatefulConfig = 0x00000020
    NetbiosOverTcpipEnabled = 0x00000040
    Ipv4Enabled             = 0x00000080
    Ipv6Enabled             = 0x00000100
    Ipv6ManagedAddressConfigurationSupported = 0x00000200
} -Bitfield

$LARGE_INTEGER = New-Structure $Module WinApiModule.LARGE_INTEGER @{
    LowPart  = New-StructureField 0 UInt32
    HighPart = New-StructureField 1 Int32
}

$LUID = New-Structure $Module WinApiModule.LUID @{
    LowPart  = New-StructureField 0 UInt32
    HighPart = New-StructureField 1 Int32
}

$SID_AND_ATTRIBUTES = New-Structure $Module WinApiModule.SID_AND_ATTRIBUTES @{
    Sid        = New-StructureField 0 IntPtr
    Attributes = New-StructureField 1 UInt32
}

$LUID_AND_ATTRIBUTES = New-Structure $Module WinApiModule.LUID_AND_ATTRIBUTES @{
    Luid       = New-StructureField 0 $LUID
    Attributes = New-StructureField 1 UInt32
}

$TOKEN_USER = New-Structure $Module WinApiModule.TOKEN_USER @{
    User = New-StructureField 0 $SID_AND_ATTRIBUTES
}

$TOKEN_GROUPS = New-Structure $Module WinApiModule.TOKEN_GROUPS @{
    GroupCount  = New-StructureField 0 UInt32
    Groups      = New-StructureField 1 $SID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 1024)
}

$TOKEN_PRIVILEGES = New-Structure $Module WinApiModule.TOKEN_PRIVILEGES @{
    PrivilegeCount = New-StructureField 0 UInt32
    Privileges     = New-StructureField 1 $LUID_AND_ATTRIBUTES.MakeArrayType() -MarshalAs @('ByValArray', 100)
}

$TOKEN_MANDATORY_LABEL = New-Structure $Module WinApiModule.TOKEN_MANDATORY_LABEL @{
    Label = New-StructureField 0 $SID_AND_ATTRIBUTES
}

$TOKEN_STATISTICS = New-Structure $Module WinApiModule.TOKEN_STATISTICS @{
    TokenId             = New-StructureField 0 $LUID
    AuthenticationId    = New-StructureField 1 $LUID
    ExpirationTime      = New-StructureField 2 $LARGE_INTEGER
    TokenType           = New-StructureField 3 $TOKEN_TYPE
    ImpersonationLevel  = New-StructureField 4 $SECURITY_IMPERSONATION_LEVEL
    DynamicCharged      = New-StructureField 5 UInt32
    DynamicAvailable    = New-StructureField 6 UInt32
    GroupCount          = New-StructureField 7 UInt32
    PrivilegeCount      = New-StructureField 8 UInt32
    ModifiedId          = New-StructureField 9 $LUID
}

$TOKEN_ORIGIN = New-Structure $Module WinApiModule.TOKEN_ORIGIN @{
    OriginatingLogonSession = New-StructureField 0 $LUID
}

$TOKEN_SOURCE = New-Structure $Module WinApiModule.TOKEN_SOURCE @{
    SourceName          = New-StructureField 0 Byte[] -MarshalAs @('ByValArray', 8)
    SourceIdentifier    = New-StructureField 1 $LUID
}

$IN6_ADDR = New-Structure $Module WinApiModule.IN6_ADDR @{
    Addr = New-StructureField 0 Byte[] -MarshalAs @('ByValArray', 16)
}

$SOCKADDR = New-Structure $Module WinApiModule.SOCKADDR @{
    Family  = New-StructureField 0 UInt16
    Data    = New-StructureField 1 Byte[] -MarshalAs @('ByValArray', 14)
}

$SOCKADDR_IN6 = New-Structure $Module WinApiModule.SOCKADDR_IN6 @{
    Family  = New-StructureField 0 Int16
    Port    = New-StructureField 1 UInt16
    lowInfo = New-StructureField 2 UInt32
    Addr    = New-StructureField 3 $IN6_ADDR
    ScopeId = New-StructureField 4 UInt32
}

$SOCKET_ADDRESS = New-Structure $Module WinApiModule.SOCKET_ADDRESS @{
    Sockaddr        = New-StructureField 0 IntPtr # LPSOCKADDR -> SOCKADDR or SOCKADDR_IN6
    SockaddrLength  = New-StructureField 1 Int32
}

$IP_ADAPTER_UNICAST_ADDRESS_LH = New-Structure $Module WinApiModule.IP_ADAPTER_UNICAST_ADDRESS_LH @{
    Length              = New-StructureField 0 UInt32
    Flags               = New-StructureField 1 UInt32
    Next                = New-StructureField 2 IntPtr # struct _IP_ADAPTER_UNICAST_ADDRESS_LH *Next
    Address             = New-StructureField 3 $SOCKET_ADDRESS
    PrefixOrigin        = New-StructureField 4 UInt32
    SuffixOrigin        = New-StructureField 5 UInt32
    DadState            = New-StructureField 6 UInt32
    ValidLifetime       = New-StructureField 7 UInt32
    PreferredLifetime   = New-StructureField 8 UInt32
    LeaseLifetime       = New-StructureField 9 UInt32
    OnLinkPrefixLength  = New-StructureField 10 Byte
}

$IP_ADAPTER_ANYCAST_ADDRESS_XP = New-Structure $Module WinApiModule.IP_ADAPTER_ANYCAST_ADDRESS_XP @{
    Length      = New-StructureField 0 UInt32
    Flags       = New-StructureField 1 UInt32
    Next        = New-StructureField 2 IntPtr # struct _IP_ADAPTER_ANYCAST_ADDRESS_XP *Next
    Address     = New-StructureField 3 $SOCKET_ADDRESS
}

$IP_ADAPTER_MULTICAST_ADDRESS_XP = New-Structure $Module WinApiModule.IP_ADAPTER_MULTICAST_ADDRESS_XP @{
    Length      = New-StructureField 0 UInt32
    Flags       = New-StructureField 1 UInt32
    Next        = New-StructureField 2 IntPtr # struct _IP_ADAPTER_MULTICAST_ADDRESS_XP *Next
    Address     = New-StructureField 3 $SOCKET_ADDRESS
}

$IP_ADAPTER_DNS_SERVER_ADDRESS_XP = New-Structure $Module WinApiModule.IP_ADAPTER_DNS_SERVER_ADDRESS_XP @{
    Length      = New-StructureField 0 UInt32
    Flags       = New-StructureField 1 UInt32
    Next        = New-StructureField 2 IntPtr # struct _IP_ADAPTER_DNS_SERVER_ADDRESS_XP *Next
    Address     = New-StructureField 3 $SOCKET_ADDRESS
}

$IP_ADAPTER_PREFIX_XP = New-Structure $Module WinApiModule.IP_ADAPTER_PREFIX_XP @{
    Length          = New-StructureField 0 UInt32
    Flags           = New-StructureField 1 UInt32
    Next            = New-StructureField 2 IntPtr # struct _IP_ADAPTER_PREFIX_XP *Next
    Address         = New-StructureField 3 $SOCKET_ADDRESS
    PrefixLength    = New-StructureField 4 UInt32
}

$IP_ADAPTER_WINS_SERVER_ADDRESS_LH = New-Structure $Module WinApiModule.IP_ADAPTER_WINS_SERVER_ADDRESS_LH @{
    Length      = New-StructureField 0 UInt32
    Reserved    = New-StructureField 1 UInt32
    Next        = New-StructureField 2 IntPtr # struct _IP_ADAPTER_WINS_SERVER_ADDRESS_LH *Next
    Address     = New-StructureField 3 $SOCKET_ADDRESS
}

$IP_ADAPTER_GATEWAY_ADDRESS_LH = New-Structure $Module WinApiModule.IP_ADAPTER_GATEWAY_ADDRESS_LH @{
    Length      = New-StructureField 0 UInt32
    Reserved    = New-StructureField 1 UInt32
    Next        = New-StructureField 2 IntPtr # struct _IP_ADAPTER_GATEWAY_ADDRESS_LH *Next
    Address     = New-StructureField 3 $SOCKET_ADDRESS
}

$IP_ADAPTER_DNS_SUFFIX = New-Structure $Module WinApiModule.IP_ADAPTER_DNS_SUFFIX @{
    Next    = New-StructureField 0 IntPtr # struct _IP_ADAPTER_DNS_SUFFIX *Next
    String  = New-StructureField 1 String -MarshalAs @('ByValTStr', 256)
} -Charset Unicode

$IP_ADAPTER_ADDRESSES = New-Structure $Module WinApiModule.IP_ADAPTER_ADDRESSES @{
    Length                  = New-StructureField 0 UInt32
    IfIndex                 = New-StructureField 1 UInt32
    Next                    = New-StructureField 2 IntPtr # struct _IP_ADAPTER_ADDRESSES_LH    *Next;
    AdapterName             = New-StructureField 3 String -MarshalAs @('LPStr')
    FirstUnicastAddress     = New-StructureField 4 IntPtr # PIP_ADAPTER_UNICAST_ADDRESS_LH
    FirstAnycastAddress     = New-StructureField 5 IntPtr # PIP_ADAPTER_ANYCAST_ADDRESS_XP
    FirstMulticastAddress   = New-StructureField 6 IntPtr # PIP_ADAPTER_MULTICAST_ADDRESS_XP
    FirstDnsServerAddress   = New-StructureField 7 IntPtr # PIP_ADAPTER_DNS_SERVER_ADDRESS_XP
    DnsSuffix               = New-StructureField 8 String -MarshalAs @('LPWStr')
    Description             = New-StructureField 9 String -MarshalAs @('LPWStr')
    FriendlyName            = New-StructureField 10 String -MarshalAs @('LPWStr')
    PhysicalAddress         = New-StructureField 11 Byte[] -MarshalAs @('ByValArray', 8)
    PhysicalAddressLength   = New-StructureField 12 UInt32
    Flags                   = New-StructureField 13 UInt32
    Mtu                     = New-StructureField 14 UInt32
    IfType                  = New-StructureField 15 UInt32
    OperStatus              = New-StructureField 16 UInt32
    Ipv6IfIndex             = New-StructureField 17 UInt32
    ZoneIndices             = New-StructureField 18 UInt32[] -MarshalAs @('ByValArray', 16)
    FirstPrefix             = New-StructureField 19 IntPtr # PIP_ADAPTER_PREFIX_XP
    TransmitLinkSpeed       = New-StructureField 20 UInt64
    ReceiveLinkSpeed        = New-StructureField 21 UInt64
    FirstWinsServerAddress  = New-StructureField 22 IntPtr # PIP_ADAPTER_WINS_SERVER_ADDRESS_LH
    FirstGatewayAddress     = New-StructureField 23 IntPtr # PIP_ADAPTER_GATEWAY_ADDRESS_LH
    Ipv4Metric              = New-StructureField 24 UInt32
    Ipv6Metric              = New-StructureField 25 UInt32
    Luid                    = New-StructureField 26 UInt64
    Dhcpv4Server            = New-StructureField 27 $SOCKET_ADDRESS
    CompartmentId           = New-StructureField 28 UInt32
    NetworkGuid             = New-StructureField 29 Guid
    ConnectionType          = New-StructureField 30 UInt32
    TunnelType              = New-StructureField 31 UInt32
    Dhcpv6Server            = New-StructureField 32 $SOCKET_ADDRESS
    Dhcpv6ClientDuid        = New-StructureField 33 Byte[] -MarshalAs @('ByValArray', 130)
    Dhcpv6ClientDuidLength  = New-StructureField 34 UInt32
    Dhcpv6Iaid              = New-StructureField 35 UInt32
    FirstDnsSuffix          = New-StructureField 36 IntPtr # PIP_ADAPTER_DNS_SUFFIX
}

$MIB_TCPROW_OWNER_PID = New-Structure $Module WinApiModule.MIB_TCPROW_OWNER_PID @{
    State      = New-StructureField 0 UInt32
    LocalAddr  = New-StructureField 1 UInt32
    LocalPort  = New-StructureField 2 Byte[] -MarshalAs @('ByValArray', 4)
    RemoteAddr = New-StructureField 3 UInt32
    RemotePort = New-StructureField 4 Byte[] -MarshalAs @('ByValArray', 4)
    OwningPid  = New-StructureField 5 UInt32
}

$MIB_UDPROW_OWNER_PID = New-Structure $Module WinApiModule.MIB_UDPROW_OWNER_PID @{
    LocalAddr = New-StructureField 0 UInt32
    LocalPort = New-StructureField 1 Byte[] -MarshalAs @('ByValArray', 4)
    OwningPid = New-StructureField 2 UInt32
}

$MIB_TCP6ROW_OWNER_PID = New-Structure $Module WinApiModule.MIB_TCP6ROW_OWNER_PID @{
    LocalAddr     = New-StructureField 0 Byte[] -MarshalAs @('ByValArray', 16)
    LocalScopeId  = New-StructureField 1 UInt32
    LocalPort     = New-StructureField 2 Byte[] -MarshalAs @('ByValArray', 4)
    RemoteAddr    = New-StructureField 3 Byte[] -MarshalAs @('ByValArray', 16)
    RemoteScopeId = New-StructureField 4 UInt32
    RemotePort    = New-StructureField 5 Byte[] -MarshalAs @('ByValArray', 4)
    State         = New-StructureField 6 UInt32
    OwningPid     = New-StructureField 7 UInt32
}

$MIB_UDP6ROW_OWNER_PID = New-Structure $Module WinApiModule.MIB_UDP6ROW_OWNER_PID @{
    LocalAddr    = New-StructureField 0 Byte[] -MarshalAs @('ByValArray', 16)
    LocalScopeId = New-StructureField 1 UInt32
    LocalPort    = New-StructureField 2 Byte[] -MarshalAs @('ByValArray', 4)
    OwningPid    = New-StructureField 3 UInt32
}

$MIB_TCPTABLE_OWNER_PID = New-Structure $Module WinApiModule.MIB_TCPTABLE_OWNER_PID @{
    NumEntries = New-StructureField 0 UInt32
    Table      = New-StructureField 1 $MIB_TCPROW_OWNER_PID.MakeArrayType() -MarshalAs @('ByValArray', 1)
}

$MIB_UDPTABLE_OWNER_PID = New-Structure $Module WinApiModule.MIB_UDPTABLE_OWNER_PID @{
    NumEntries = New-StructureField 0 UInt32
    Table      = New-StructureField 1 $MIB_UDPROW_OWNER_PID.MakeArrayType() -MarshalAs @('ByValArray', 1)
}

$MIB_TCP6TABLE_OWNER_PID = New-Structure $Module WinApiModule.MIB_TCP6TABLE_OWNER_PID @{
    NumEntries = New-StructureField 0 UInt32
    Table      = New-StructureField 1 $MIB_TCP6ROW_OWNER_PID.MakeArrayType() -MarshalAs @('ByValArray', 1)
}

$MIB_UDP6TABLE_OWNER_PID = New-Structure $Module WinApiModule.MIB_UDP6TABLE_OWNER_PID @{
    NumEntries = New-StructureField 0 UInt32
    Table      = New-StructureField 1 $MIB_UDP6ROW_OWNER_PID.MakeArrayType() -MarshalAs @('ByValArray', 1)
}

$FILETIME = New-Structure $Module WinApiModule.FILETIME @{
    LowDateTime  = New-StructureField 0 UInt32
    HighDateTime = New-StructureField 1 UInt32
}

$CREDENTIAL = New-Structure $Module WinApiModule.CREDENTIAL @{
    Flags              = New-StructureField 0 UInt32
    Type               = New-StructureField 1 UInt32
    TargetName         = New-StructureField 2 String
    Comment            = New-StructureField 3 String
    LastWritten        = New-StructureField 4 $FILETIME
    CredentialBlobSize = New-StructureField 5 UInt32
    CredentialBlob     = New-StructureField 6 IntPtr
    Persist            = New-StructureField 7 UInt32
    AttributeCount     = New-StructureField 8 UInt32
    Attributes         = New-StructureField 9 IntPtr
    TargetAlias        = New-StructureField 10 String
    UserName           = New-StructureField 11 String
} -Charset Unicode

$UNICODE_STRING = New-Structure $Module WinApiModule.UNICODE_STRING @{
    Length        = New-StructureField 0 UInt16
    MaximumLength = New-StructureField 1 UInt16
    Buffer        = New-StructureField 2 IntPtr
}

$VAULT_ITEM_7 = New-Structure $Module WinApiModule.VAULT_ITEM_7 @{
    SchemaId        = New-StructureField 0 Guid
    FriendlyName    = New-StructureField 1 String
    Resource        = New-StructureField 2 IntPtr
    Identity        = New-StructureField 3 IntPtr
    Authenticator   = New-StructureField 4 IntPtr
    LastWritten     = New-StructureField 5 $FILETIME
    Flags           = New-StructureField 6 Uint32
    PropertiesCount = New-StructureField 7 UInt32
    Properties      = New-StructureField 8 IntPtr
}

$VAULT_ITEM_8 = New-Structure $Module WinApiModule.VAULT_ITEM_8 @{
    SchemaId        = New-StructureField 0 Guid
    FriendlyName    = New-StructureField 1 String
    Resource        = New-StructureField 2 IntPtr
    Identity        = New-StructureField 3 IntPtr
    Authenticator   = New-StructureField 4 IntPtr
    PackageSid      = New-StructureField 5 IntPtr
    LastWritten     = New-StructureField 6 $FILETIME
    Flags           = New-StructureField 7 Uint32
    PropertiesCount = New-StructureField 8 UInt32
    Properties      = New-StructureField 9 IntPtr
}

$VAULT_ITEM_DATA_HEADER = New-Structure $Module WinApiModule.VAULT_ITEM_DATA_HEADER @{
    SchemaElementId = New-StructureField 0 UInt32
    Unknown1        = New-StructureField 1 UInt32
    Type            = New-StructureField 2 UInt32
    Unknown2        = New-StructureField 3 UInt32
}

$WLAN_INTERFACE_INFO = New-Structure $Module WinApiModule.WLAN_INTERFACE_INFO @{
    InterfaceGuid        = New-StructureField 0 Guid
    InterfaceDescription = New-StructureField 1 String -MarshalAs @('ByValTStr', 256)
    State                = New-StructureField 2 UInt32
} -Charset Unicode

$WLAN_PROFILE_INFO = New-Structure $Module WinApiModule.WLAN_PROFILE_INFO @{
    ProfileName = New-StructureField 0 String -MarshalAs @('ByValTStr', 256)
    Flags       = New-StructureField 1 UInt32
} -Charset Unicode

$SECURITY_ATTRIBUTES = New-Structure $Module WinApiModule.SECURITY_ATTRIBUTES @{
    Length = New-StructureField 0 UInt32
    SecurityDescriptor = New-StructureField 1 IntPtr
    InheritHandle = New-StructureField 2 Bool
}

$OBJECT_ATTRIBUTES = New-Structure $Module WinApiModule.OBJECT_ATTRIBUTES @{
    Length                   = New-StructureField 0 UInt32
    RootDirectory            = New-StructureField 1 IntPtr
    ObjectName               = New-StructureField 2 IntPtr
    Attributes               = New-StructureField 3 UInt32
    SecurityDescriptor       = New-StructureField 4 IntPtr
    SecurityQualityOfService = New-StructureField 5 IntPtr
}

$OBJECT_DIRECTORY_INFORMATION = New-Structure $Module WinApiModule.OBJECT_DIRECTORY_INFORMATION @{
    Name        = New-StructureField 0 $UNICODE_STRING
    TypeName    = New-StructureField 1 $UNICODE_STRING
}

$WIN32_FILE_ATTRIBUTE_DATA = New-Structure $Module WinApiModule.WIN32_FILE_ATTRIBUTE_DATA @{
    dwFileAttributes = New-StructureField 0 UInt32
    ftCreationTime   = New-StructureField 1 $FILETIME
    ftLastAccessTime = New-StructureField 2 $FILETIME
    ftLastWriteTime  = New-StructureField 3 $FILETIME
    nFileSizeHigh    = New-StructureField 4 UInt32
    nFileSizeLow     = New-StructureField 5 UInt32
}

$FunctionDefinitions = @(
    (New-Function advapi32 OpenSCManager ([IntPtr]) @([String], [String], [UInt32]) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError),
    (New-Function advapi32 QueryServiceObjectSecurity ([Bool]) @([IntPtr], [Security.AccessControl.SecurityInfos], [Byte[]], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (New-Function advapi32 CloseServiceHandle ([Bool]) @([IntPtr]) -SetLastError),
    (New-Function advapi32 OpenProcessToken ([Bool]) @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) -SetLastError),
    (New-Function advapi32 GetTokenInformation ([Bool]) @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32].MakeByRefType()) -SetLastError),
    (New-Function advapi32 LookupAccountSid ([Bool]) @([String], [IntPtr], [System.Text.StringBuilder], [UInt32].MakeByRefType(), [System.Text.StringBuilder], [UInt32].MakeByRefType(), [Int].MakeByRefType()) -SetLastError)
    (New-Function advapi32 LookupPrivilegeName ([Int]) @([String], $LUID.MakeByRefType(), [System.Text.StringBuilder], [UInt32].MakeByRefType()) -SetLastError),
    (New-Function advapi32 CredEnumerate ([Bool]) @([IntPtr], [UInt32], [UInt32].MakeByRefType(), [IntPtr].MakeByRefType()) -SetLastError),
    (New-Function advapi32 CredFree ([void]) @([IntPtr])),
    (New-Function advapi32 IsTextUnicode ([Bool]) @([IntPtr], [UInt32], [UInt32].MakeByRefType())),
    (New-Function advapi32 ConvertSidToStringSidW ([Bool]) @([IntPtr], [IntPtr].MakeByRefType()) -SetLastError),
    (New-Function advapi32 IsTokenRestricted ([Bool]) @([IntPtr]) -SetLastError),
    (New-Function advapi32 GetSecurityInfo ([UInt32]) @([IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType()) -SetLastError),
    (New-Function advapi32 ConvertSecurityDescriptorToStringSecurityDescriptor ([Bool]) @([IntPtr], [UInt32], [UInt32], [String].MakeByRefType(), [UInt32].MakeByRefType()) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError),
    (New-Function advapi32 ConvertStringSecurityDescriptorToSecurityDescriptor ([Bool]) @([String], [UInt32], [IntPtr].MakeByRefType(), [UInt32].MakeByRefType()) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError)

    (New-Function iphlpapi GetAdaptersAddresses ([UInt32]) @([UInt32], [UInt32], [IntPtr], [IntPtr], [UInt32].MakeByRefType())),
    (New-Function iphlpapi GetExtendedTcpTable ([UInt32]) @([IntPtr], [UInt32].MakeByRefType(), [Bool], [UInt32], $TCP_TABLE_CLASS, [UInt32]) -SetLastError),
    (New-Function iphlpapi GetExtendedUdpTable ([UInt32]) @([IntPtr], [UInt32].MakeByRefType(), [Bool], [UInt32], $UDP_TABLE_CLASS , [UInt32]) -SetLastError),

    (New-Function kernel32 CreateFile ([IntPtr]) @([String], [UInt32], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr]) ([Runtime.InteropServices.CallingConvention]::Winapi) ([Runtime.InteropServices.CharSet]::Unicode) -SetLastError),
    (New-Function kernel32 GetCurrentProcess ([IntPtr]) @()),
    (New-Function kernel32 OpenProcess ([IntPtr]) @([UInt32], [Bool], [UInt32]) -SetLastError),
    (New-Function kernel32 CloseHandle ([Bool]) @([IntPtr]) -SetLastError),
    (New-Function kernel32 GetTickCount64 ([UInt64]) @()),
    (New-Function kernel32 GetFirmwareEnvironmentVariable ([UInt32]) @([String], [String], [IntPtr], [UInt32]) -SetLastError),
    (New-Function kernel32 GetFirmwareType ([Bool]) @([UInt32].MakeByRefType()) -SetLastError),
    (New-Function kernel32 LocalFree ([IntPtr]) @([IntPtr])),

    (New-Function ntdll RtlNtStatusToDosError ([UInt32]) @([UInt32]) -EntryPoint RtlNtStatusToDosError),
    (New-Function ntdll RtlInitUnicodeString ([IntPtr]) @($UNICODE_STRING.MakeByRefType(), [String]) -EntryPoint RtlInitUnicodeString),
    (New-Function ntdll NtOpenDirectoryObject ([UInt32]) @([IntPtr].MakeByRefType(), [UInt32], $OBJECT_ATTRIBUTES.MakeByRefType()) -EntryPoint NtOpenDirectoryObject),
    (New-Function ntdll NtQueryDirectoryObject ([UInt32]) @([IntPtr], [IntPtr], [UInt32], [Bool], [Bool], [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) -EntryPoint NtQueryDirectoryObject),

    (New-Function vaultcli VaultEnumerateVaults ([UInt32]) @([UInt32], [UInt32].MakeByRefType(), [IntPtr].MakeByRefType()) -EntryPoint VaultEnumerateVaults),
    (New-Function vaultcli VaultOpenVault ([UInt32]) @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) -Entrypoint VaultOpenVault),
    (New-Function vaultcli VaultEnumerateItems ([UInt32]) @([IntPtr], [UInt32], [UInt32].MakeByRefType(), [IntPtr].MakeByRefType()) -EntryPoint VaultEnumerateItems),
    (New-Function vaultcli VaultGetItem7 ([UInt32]) @([IntPtr], [Guid].MakeByRefType(), [IntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr].MakeByRefType()) -EntryPoint VaultGetItem),
    (New-Function vaultcli VaultGetItem8 ([UInt32]) @([IntPtr], [Guid].MakeByRefType(), [IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr].MakeByRefType()) -EntryPoint VaultGetItem),
    (New-Function vaultcli VaultFree ([UInt32]) @([IntPtr]) -EntryPoint VaultFree),
    (New-Function vaultcli VaultCloseVault ([UInt32]) @([IntPtr].MakeByRefType()) -EntryPoint VaultCloseVault),

    (New-Function wlanapi WlanOpenHandle ([UInt32]) @([UInt32], [IntPtr], [UInt32].MakeByRefType(), [IntPtr].MakeByRefType()) -EntryPoint WlanOpenHandle),
    (New-Function wlanapi WlanCloseHandle ([UInt32]) @([IntPtr], [IntPtr]) -EntryPoint WlanCloseHandle)
    (New-Function wlanapi WlanEnumInterfaces ([UInt32]) @([IntPtr], [IntPtr], [IntPtr].MakeByRefType()) -EntryPoint WlanEnumInterfaces),
    (New-Function wlanapi WlanFreeMemory ([Void]) @([IntPtr]) -EntryPoint WlanFreeMemory),
    (New-Function wlanapi WlanGetProfileList ([UInt32]) @([IntPtr], [Guid], [IntPtr], [IntPtr].MakeByRefType()) -EntryPoint WlanGetProfileList),
    (New-Function wlanapi WlanGetProfile ([UInt32]) @([IntPtr], [Guid], [String], [IntPtr], [String].MakeByRefType(), [UInt32].MakeByRefType(), [UInt32].MakeByRefType()) -EntryPoint WlanGetProfile)
)

$Types = $FunctionDefinitions | Add-Win32Type -Module $Module -Namespace 'WinApiModule.NativeMethods'
$Advapi32 = $Types['advapi32']
$Iphlpapi = $Types['iphlpapi']
$Kernel32 = $Types['kernel32']
$Ntdll    = $Types['ntdll']
$Vaultcli = $Types['vaultcli']
$Wlanapi  = $Types['wlanapi']