# PrivescCheck

This script aims to identify __Local Privilege Escalation__ (LPE) vulnerabilities that are usually due to Windows configuration issues, or bad practices. It can also gather useful information for some exploitation and post-exploitation tasks.

## Getting started

After downloading the [script](https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1) and copying it onto the target Windows machine, run it using one of the commands below.

> [!NOTE]
> You __don't__ need to clone the entire repository. The file `PrivescCheck.ps1` is a standalone PowerShell script that contains all the code required by `PrivescCheck` to run on a target host.

> [!IMPORTANT]
> In the commands below, the first `.` (dot) is used for "dot sourcing" the script, so that the functions and cmdlets can be used in the __current scope__ (see PowerShell [dot sourcing feature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_scripts#script-scope-and-dot-sourcing)).

### Basic checks only

```powershell
. .\PrivescCheck.ps1; Invoke-PrivescCheck
```

### Extended checks + All reports

```powershell
. .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,CSV,HTML,XML
```

### One-liner command

```bat
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,CSV,HTML,XML"
```

## Tips and tricks

### PowerShell execution policy

By default, the PowerShell [execution policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies) is set to `Restricted`. However, a more restrictive policy, typically `RemoteSigned`, might be enforced through a GPO.

In this case, open a PowerShell prompt, and import the script as follows.

```powershell
Get-Content .\PrivescCheck.ps1 | Out-String | Invoke-Expression
```

If a policy is not enforced, you can simply modify the execution policy in the current `powershell.exe` process.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module .\PrivescCheck.ps1
```

### PowerShell version 2

A common way to bypass [Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) consists in starting PowerShell in __version 2__ as it does not implement this protection. Therefore, a significant part of the development effort goes into maintaining this compatibility.

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
