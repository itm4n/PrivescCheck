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
    DangerousDefaultFileExtensionAssociations = "{{FILE_EXTENSION_ASSOCIATIONS}}"
    VulnerableDrivers                         = "{{VULNERABLE_DRIVERS}}"
    Checks                                    = "{{CHECKS}}"
    EndpointProtectionSignature               = "{{ENDPOINT_PROTECTION_SIGNATURES}}"
}