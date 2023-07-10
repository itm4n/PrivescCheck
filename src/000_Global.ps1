$global:CachedServiceList = New-Object -TypeName System.Collections.ArrayList
$global:CachedDriverList = New-Object -TypeName System.Collections.ArrayList
$global:CachedHotFixList = New-Object -TypeName System.Collections.ArrayList
$global:CachedScheduledTaskList = New-Object -TypeName System.Collections.ArrayList
$global:CachedCurrentUserSids = $null
$global:CachedCurrentUserDenySids = $null
$global:ResultArrayList = New-Object -TypeName System.Collections.ArrayList
$global:KeywordsOfInterest = @( "key", "passw", "secret", "pwd", "creds", "credential", "api" )
$global:VulnerableDrivers = @"
VULNERABLE_DRIVERS
"@