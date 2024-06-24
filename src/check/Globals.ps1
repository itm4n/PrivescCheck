$script:CachedServiceList = New-Object -TypeName System.Collections.ArrayList
$script:CachedDriverList = New-Object -TypeName System.Collections.ArrayList
$script:CachedHotFixList = New-Object -TypeName System.Collections.ArrayList
$script:CachedScheduledTaskList = New-Object -TypeName System.Collections.ArrayList
$script:CachedRegisteredComList = New-Object -TypeName System.Collections.ArrayList
$script:CachedCurrentUserSids = $null
$script:CachedCurrentUserDenySids = $null
$script:ResultArrayList = New-Object -TypeName System.Collections.ArrayList
$script:KeywordsOfInterest = @( "key", "passw", "secret", "pwd", "creds", "credential", "api" )
$script:CommonApplicationExtensions = @( "bat", "cmd", "exe", "dll", "msi", "ps1", "reg", "vbe", "vbs" )
$script:ExploitablePrivileges = @( "SeAssignPrimaryTokenPrivilege", "SeImpersonatePrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeLoadDriverPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeBackupPrivilege", "SeManageVolumePrivilege", "SeRelabelPrivilege" )
$script:DangerousDefaultFileExtensionAssociations = @"
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
$script:VulnerableDrivers = @"
VULNERABLE_DRIVERS
"@
$script:CheckCsvBlob = "CHECK_CSV_BLOB"