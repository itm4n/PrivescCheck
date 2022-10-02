# PrivescCheck

This script aims to __enumerate common Windows configuration issues__ that can be leveraged for local privilege escalation. It also __gathers various information__ that might be useful for __exploitation__ and/or __post-exploitation__.

You can find more information about PrivescCheck [here](INFORMATION.md).

## Quick start

### From a command prompt

Assuming, the file `PrivescCheck.ps1` is located in the current directory...

```bat
REM Basic usage
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
REM Extended mode
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended"
REM Extended mode + Write a report file (default format is raw text)
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_%COMPUTERNAME%"
REM Extended mode + Write report files in other formats
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_%COMPUTERNAME% -Format TXT,CSV,HTML,XML"
```

### From a PowerShell prompt

First, load the script in the current session (the first "`.`" is a shortcut for `Import-Module`).

```powershell
# Case #1: Execution policy is already set to "Bypass", so simply load the script.
. .\PrivescCheck.ps1
# Case #2: Default execution policy is set, so set it to "Bypass" for the current PowerShell process and load the script.
Set-ExecutionPolicy Bypass -Scope process -Force; . .\PrivescCheck.ps1
# Case #3: Execution policy is locked down, so get the file's content and pipe it to Invoke-Expression.
Get-Content .\PrivescCheck.ps1 | Out-String | IEX
```

Then, use the `Invoke-PrivescCheck` cmdlet.

```powershell
# Show usage
Get-Help Invoke-PrivescCheck
# Basic usage
Invoke-PrivescCheck
# Extended mode
Invoke-PrivescCheck -Extended
# Extended mode + Write a report file (default format is raw text)
Invoke-PrivescCheck -Extended -Report "PrivescCheck_$($env:COMPUTERNAME)"
# Extended mode + Write report files in other formats
Invoke-PrivescCheck -Extended -Report "PrivescCheck_$($env:COMPUTERNAME)" -Format TXT,CSV,HTML,XML
```

## Known issues

### Metasploit timeout

If you run this script within a Meterpreter session, you will likely get a "timeout" error. Metasploit has a "response timeout" value, which is set to 15 seconds by default, but this script takes a lot more time to run in most environments.

```console
meterpreter > load powershell
Loading extension powershell...Success.
meterpreter > powershell_import /local/path/to/PrivescCheck.ps1
[+] File successfully imported. No result was returned.
meterpreter > powershell_execute "Invoke-PrivescCheck"
[-] Error running command powershell_execute: Rex::TimeoutError Operation timed out.
```

It is possible to set a different value thanks to the `-t` option of the `sessions` command ([documentation](https://www.offensive-security.com/metasploit-unleashed/msfconsole-commands/)). In the following example, a timeout of 2 minutes is set for the session with ID `1`.

```console
msf6 exploit(multi/handler) > sessions -t 120 -i 1
[*] Starting interaction with 1...
meterpreter > powershell_execute "Invoke-PrivescCheck"
```

## Bug reporting. Feature Request. Overall enhancement.

- You think you identified a bug or a false positive/negative?
- You think a particular check is missing?
- You think something could be improved?

That's awesome! :slightly_smiling_face: Please let me know by opening an issue and include as much detail as possible.

Especially if it's a bug, I will need:
- The Windows version and the PowerShell version.
- The script output (do not forget to remove sensitive information).
