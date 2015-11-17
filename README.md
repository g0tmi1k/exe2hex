# exe2hex

Inline file transfer method using debug and/or PowerShell.

- - -

### Overview


Encodes a executable binary file into ASCII text format.

Restores using `DEBUG.exe` (BATch - x86) and/or PowerShell (PoSh - x86/x64).

```Binary EXE -> ASCII text -> Binary EXE```

- - -

### Quick usage

 + Input with `-s` or `-x /path/to/binary.exe`
 + Output with `-b /path/to/debug.bat` and/or `-p powershell.cmd`

#### Examples

```bash
$ python exe2hex.py -x /usr/share/windows-binaries/nc.exe -b /var/www/html/nc.txt
[*] exe2hex v1.1

[+] Successfully wrote: /var/www/html/nc.txt
$
```

```bash
$ cat /usr/share/windows-binaries/whoami.exe | ./exe2hex.py -s -b who_debug.bat -p who_ps.cmd
[*] exe2hex v1.1

[i] Reading from STDIN
[+] Successfully wrote: who_debug.bat
[+] Successfully wrote: who_ps.cmd
$
```

```bash
$ python exe2hex.py -h
[*] exe2hex v1.1

Usage: exe2hex.py [options]

Options:
  -h, --help  show this help message and exit
  -x EXE      The EXE binary file to convert
  -s          Read from STDIN
  -b BAT      BAT output file (DEBUG.exe method)
  -p POSH     PoSh output file (PowerShell method)
  -e          HTML encode the output?
  -r TEXT     pRefix - text to add before the command
  -f TEXT     suFfix - text to add after the command
  -l INT      Maximum hex values per line
  -v          Enable verbose output
$
```

- - -

### Methods/OS Support

+ **`DEBUG.exe` (BATch mode - `-b`)**
  + Useful for legacy versions of Windows.
  + Every version of Windows x86 (No x64 support).
  + Has a limitation of 64k input file size.
+ **PowerShell (PoSh mode - `-p`)**
  + Useful for recent versions of Windows.
  + Supports both Windows x64 & x86.
  + First integrated into core OS with Windows 7/Windows Server 2008 R2.
  + Windows XP SP2, Windows Server 2003 & Windows Vista requires PowerShell to be pre-installed.
