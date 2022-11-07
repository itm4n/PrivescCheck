# PrivescCheck

This script aims to __enumerate common Windows configuration issues__ that can be leveraged for local privilege escalation. It also __gathers various information__ that might be useful for __exploitation__ and/or __post-exploitation__.

You can find more information about PrivescCheck [here](INFORMATION.md).

## Use from a command prompt

__Usage #1:__ Basic usage

```bat
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```

__Usage #2:__ Extended mode

```bat
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended"
```

__Usage #3:__ Extended mode + Write a report file (default format is raw text)

```bat
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_%COMPUTERNAME%"
```

__Usage #4:__ Extended mode + Write report files in other formats

```bat
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_%COMPUTERNAME% -Format TXT,CSV,HTML,XML"
```

## Use from a PowerShell prompt

### 1. Load the script as a module

__Case #1:__ Execution policy is already set to `Bypass`, so simply load the script.

```powershell
. .\PrivescCheck.ps1
```

__Case #2:__ Default execution policy is set, so set it to `Bypass` for the current PowerShell process and load the script.

```powershell
Set-ExecutionPolicy Bypass -Scope process -Force
. .\PrivescCheck.ps1
```

__Case #3:__ Execution policy is locked down, so get the file's content and pipe it to `Invoke-Expression`.

```powershell
Get-Content .\PrivescCheck.ps1 | Out-String | IEX
```

### 2. Run the script

Then, use the `Invoke-PrivescCheck` cmdlet.

__Usage #1:__ Basic usage

```powershell
Invoke-PrivescCheck
```

__Usage #2:__ Extended mode

```powershell
Invoke-PrivescCheck -Extended
```

__Usage #3:__ Extended mode + Write a report file (default format is raw text)

```powershell
Invoke-PrivescCheck -Extended -Report "PrivescCheck_$($env:COMPUTERNAME)"
```

__Usage #4:__ Extended mode + Write report files in other formats

```powershell
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
