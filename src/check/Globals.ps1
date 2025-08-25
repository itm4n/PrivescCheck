$script:GlobalVariable = @{
    CheckResultList     = $null
    InitialSessionState = $null
}

$script:GlobalCache = @{
    CurrentUserSids          = $null
    CurrentUserDenySids      = $null
    DriverList               = $null
    InstalledApplicationList = $null
    RegisteredComList        = $null
    ServiceList              = $null
    ScheduledTaskList        = $null
}

$script:GlobalConstant = @{
    KeywordsOfInterest                        = @( "key", "passw", "secret", "pwd", "creds", "credential", "api" )
    CommonApplicationExtensions               = @( "bat", "cmd", "exe", "dll", "msi", "ps1", "reg", "vbe", "vbs" )
    ExploitablePrivileges                     = @( "SeAssignPrimaryTokenPrivilege", "SeImpersonatePrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeLoadDriverPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeBackupPrivilege", "SeManageVolumePrivilege", "SeRelabelPrivilege" )
    DangerousDefaultFileExtensionAssociations = @"
{{CSV_RAW_FILE_EXTENSION_ASSOCIATIONS}}
"@
    VulnerableDrivers                         = @"
{{CSV_RAW_VULNERABLE_DRIVERS}}
"@
    CheckCsvBlob                              = "{{CSV_BLOB_CHECKS}}"
    EndpointProtectionSignatureBlob           = "{{CSV_BLOB_ENDPOINT_PROTECTION_SIGNATURES}}"
}