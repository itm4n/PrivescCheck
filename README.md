# PrivescCheck

This script aims to __enumerate common Windows configuration issues__ that can be leveraged for local privilege escalation. It also __gathers various information__ that might be useful for __exploitation__ and/or __post-exploitation__.

The purpose of this tool is to help security consultants identify potential weaknesses on Windows machines during penetration tests and Workstation/VDI audits. It is not intended to be used during Red Team engagements although it may still provide you with a lot of useful information.

This tool is heavily inspired from the amazing work that [@harmj0y](https://twitter.com/harmj0y) and [@mattifestation](https://twitter.com/mattifestation) put in [PowerUp](https://github.com/HarmJ0y/PowerUp). The two original authors decided to switch to DotNet and are now working on the great [SeatBelt](https://github.com/GhostPack/Seatbelt) project, which explains why [PowerUp](https://github.com/HarmJ0y/PowerUp) is no longer maintained. Although [SeatBelt](https://github.com/GhostPack/Seatbelt) brings some undeniable benefits, I think that a standalone PowerShell script is still a good way to go for most pentesters, hence the motivation behind the creation of this tool.

You can find more information about PrivescCheck [here](INFORMATION.md).

## Usage

### 1. Basic usage

From a command prompt:
```
C:\Temp\>powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```

From a PowerShell prompt:
```
PS C:\Temp\> Set-ExecutionPolicy Bypass -Scope process -Force
PS C:\Temp\> . .\PrivescCheck.ps1; Invoke-PrivescCheck
```

From a PowerShell prompt without modifying the execution policy:
```
PS C:\Temp\> Get-Content .\PrivescCheck.ps1 | Out-String | IEX
PS C:\Temp\> Invoke-PrivescCheck
```

### 2. Extended mode

By default, the scope is limited to __vulnerability discovery__ but, you can get a lot more information with the `-Extended` option:

```
Invoke-PrivescCheck -Extended
```

### 3. Generate report files

You can use the `-Report` and `-Format` options to save the results of the script to files in various formats. Accepted formats are `TXT`, `CSV`, `HTML` and `XML`. If `-Format` is empty, the default format is `TXT`, which is a simple copy of what is printed on the terminal.

The value of `-Report` will be used as the base name for the final report, the extension will be automatically appended depending on the chosen format(s).

```
Invoke-PrivescCheck -Report PrivescCheck_%COMPUTERNAME%
Invoke-PrivescCheck -Report PrivescCheck_%COMPUTERNAME% -Format TXT,CSV,HTML,XML
```

## Bug reporting. Feature Request. Overall enhancement.

- You think you identified a bug or a false positive/negative?
- You think a particular check is missing?
- You think something could be improved?

That's awesome! :slightly_smiling_face: Please let me know by opening an issue and include as much detail as possible.

Especially if it's a bug, I will need:
- The Windows version and the PowerShell version.
- The script output (do not forget to remove sensitive information).
