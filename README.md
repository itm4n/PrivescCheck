# PrivescCheck

This script aims to identify __Local Privilege Escalation__ (LPE) vulnerabilities that are usually due to Windows configuration issues, or bad practices. It can also gather useful information for some exploitation and post-exploitation tasks.

## Getting started

After downloading the [script](https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1) and copying it onto the target Windows machine, run it using one of the commands below.

> [!NOTE]
> You __don't__ need to clone the entire repository. The file `PrivescCheck.ps1` is a standalone PowerShell script that contains all the code required by `PrivescCheck` to run.

> [!IMPORTANT]
> In the commands below, the first `.` (dot) is used for "dot sourcing" the script, so that the functions and cmdlets can be used in the __current scope__ (see PowerShell [dot sourcing feature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_scripts#script-scope-and-dot-sourcing)).

### Basic checks only

Quickly identify important issues, such as local privilege escalation vulnerabilities.

```bat
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```

### Extended checks + human-readable reports

Identify important issues, but also gather additional information, and save the results to report files that are easy to read.

```bat
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML"
```

### All checks + all reports

Perform extended and audit checks, and save the results to human-readable reports, but also machine-readable files, which can later be parsed for automated report generation.

```bat
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Audit -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML,CSV,XML"
```

## Check types

All the checks implemented in PrivescCheck have a __Type__. This value, and the flags specified on the command line, will determine if they are run, or not.

### Base

Checks of type `Base` will always be executed, unless the script is run as an administrator. They are mainly intended for identifying privilege escalation vulnerabilities, or other important issues.

### Extended

Checks of type `Extended` can only be executed if the option `-Extended` is specified on the command line. They are mainly intended for providing additional information that could be useful for exploit development, or post-exploitation.

### Audit

Checks of type `Audit` can only be executed if the option `-Audit` is specified on the command line. They are mainly intended for providing information that is relevant in the context of a configuration audit.

### Experimental

Checks of type `Experimental` can only be executed if the option `-Experimental` is specified on the command line. These are unstable checks that need further work. Use them with caution.

## Tips and tricks

### PowerShell execution policy

By default, the PowerShell [execution policy](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies) is set to `Restricted` on clients, and `RemoteSigned` on servers, when a new `powershell.exe` process is started. These policies block the execution of (unsigned) scripts, but they can be overriden within the current scope as follows.

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
. .\PrivescCheck.ps1
```

However, this trick does not work when the execution policy is enforced through a GPO. In this case, after starting a new PowerShell session, you can load the script as follows.

```powershell
Get-Content .\PrivescCheck.ps1 | Out-String | Invoke-Expression
```

### PowerShell version 2

A common way to bypass [Constrained Language Mode](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) consists in starting PowerShell __version 2__ as it does not implement this protection. Therefore, a significant part of the development effort goes into maintaining this compatibility.

> [!NOTE]
> Although PowerShell version 2 is still enabled by default on recent versions of Windows, it cannot run without the .Net framework version 2.0, which requires a manual install.

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
