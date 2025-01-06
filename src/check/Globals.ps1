$script:GlobalVariable = @{
    CheckResultList = $null
    InitialSessionState = $null
}

$script:GlobalCache = @{
    ServiceList = $null
    DriverList = $null
    ScheduledTaskList = $null
    RegisteredComList = $null
    CurrentUserSids = $null
    CurrentUserDenySids = $null
}

$script:GlobalConstant = @{
    KeywordsOfInterest = @( "key", "passw", "secret", "pwd", "creds", "credential", "api" )
    CommonApplicationExtensions = @( "bat", "cmd", "exe", "dll", "msi", "ps1", "reg", "vbe", "vbs" )
    ExploitablePrivileges = @( "SeAssignPrimaryTokenPrivilege", "SeImpersonatePrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeLoadDriverPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeBackupPrivilege", "SeManageVolumePrivilege", "SeRelabelPrivilege" )
    DangerousDefaultFileExtensionAssociations = @"
".application","C:\Windows\System32\dfshim.dll"
".appref-ms","C:\Windows\System32\dfshim.dll"
".bat","%1"
".chm","C:\Windows\hh.exe"
".cmd","%1"
".com","%1"
".cpl","C:\Windows\System32\control.exe"
".diagcab","C:\Windows\system32\msdt.exe"
".hta","C:\Windows\SysWOW64\mshta.exe"
".hlp","C:\Windows\winhlp32.exe"
".htm","C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
".html","C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
".js","C:\Windows\System32\WScript.exe"
".JSE","C:\Windows\System32\WScript.exe"
".library-ms","C:\Windows\Explorer.exe"
".mht","C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
".mhtml","C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
".msc","C:\Windows\system32\mmc.exe"
".msrcincident","C:\Windows\system32\msra.exe"
".pif","%1"
".ppkg","C:\Windows\System32\provtool.exe"
".psc1","WindowsPowerShell\v1.0\powershell.exe"
".reg","C:\Windows\regedit.exe"
".scf","C:\Windows\explorer.exe"
".scr","%1"
".searchConnector-ms","C:\Windows\Explorer.exe"
".search-ms","C:\Windows\Explorer.exe"
".theme","C:\Windows\system32\themecpl.dll"
".themepack","C:\Windows\system32\themecpl.dll"
".URL","C:\Windows\System32\ieframe.dll"
".VBE","C:\Windows\System32\WScript.exe"
".vbs","C:\Windows\System32\WScript.exe"
".WSF","C:\Windows\System32\WScript.exe"
".WSH","C:\Windows\System32\WScript.exe"
"@
    VulnerableDrivers = @"
VULNERABLE_DRIVERS
"@
    CheckCsvBlob = "CHECK_CSV_BLOB"
    EndpointProtectionSignatureBlob = "ENDPOINT_PROTECTION_SIGNATURE_CSV_BLOB"
}