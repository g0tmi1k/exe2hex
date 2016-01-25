# exe2hex

Inline file transfer using in-built Windows tools (`debug.exe` or PowerShell).

- - -

### Overview

exe2hex encodes an executable binary file into ASCII text format.

The result then can be transferred to the target machine (It is much easier to echo a ASCII file than binary data).

Upon executing exe2hex's output file, the original program is restored by using `DEBUG.exe` or PowerShell (which are pre-installed by default).

```Binary EXE -> ASCII Text -> *Transfer* -> Binary EXE```

![](https://i.imgur.com/UJjgq7q.png)

- - -

### Quick Guide

 + Input using a file (`-x /path/to/binary-program.exe`) or STDIN (`-s`)
 + Output to BATch (`-b file.bat`) and/or PoSH (`-p powershell.cmd`)

#### Example Usage

```bash
$ python3 exe2hex.py -x /usr/share/windows-binaries/sbd.exe
[*] exe2hex v1.3
[i] Outputting to /root/sbd.bat (BATch) and /root/sbd.cmd (PoSh)
[+] Successfully wrote (BATch) /root/sbd.bat
[+] Successfully wrote (PoSh) /root/sbd.cmd
$
```

```bash
$ ./exe2hex.py -x /usr/share/windows-binaries/nc.exe -b /var/www/html/nc.txt -cc
[*] exe2hex v1.3
[i] Attempting to clone and compress
[i] Creating temporary file /tmp/tmpkel8b4f0
[+] Compression (strip) was successful! (0.0% saved)
[+] Compression (UPX) was successful! (50.9% saved)
[+] Successfully wrote (BATch) /var/www/html/nc.txt
$
```

```bash
$ cat /usr/share/windows-binaries/whoami.exe | python exe2hex.py -s -b debug.bat -p ps.cmd
[*] exe2hex v1.3
[i] Reading from STDIN
[+] Successfully wrote (BATch) /root/debug.bat
[+] Successfully wrote (PoSh) /root/ps.cmd
$
```

#### Help

```bash
$ python3 exe2hex.py -h
[*] exe2hex v1.3
Usage: exe2hex.py [options]

Options:
  -h, --help  show this help message and exit
  -x EXE      The EXE binary file to convert
  -s          Read from STDIN
  -b BAT      BAT output file (DEBUG.exe method - x86)
  -p POSH     PoSh output file (PowerShell method - x86/x64)
  -e          URL encode the output
  -r TEXT     pRefix - text to add before the command on each line
  -f TEXT     suFfix - text to add after the command on each line
  -l INT      Maximum HEX values per line
  -v          Enable verbose mode
  -c          Clones and compress the file before converting (-cc for higher
              compression)
$
```

- - -

### Methods/OS Support

+ **`DEBUG.exe` (BATch mode - `-b`)**
  + Supports x86 OSs (No x64 support).
  + Useful for legacy versions of Windows (e.g. Windows XP/Windows 2000).
    + Pre-installed by default. Works out of the box.
  + ~~Limitation of 64k file size for binary programs.~~ Creates multiple parts and joins with `copy /b` so this is not an issue any more!
+ **PowerShell (PoSh mode - `-p`)**
  + Supports both x86 & x64 OSs.
  + Aimed at more "recent" versions of Windows.
    + PowerShell was first integrated into core OS with Windows 7/Windows Server 2008 R2.
    + Windows XP SP2, Windows Server 2003 & Windows Vista requires PowerShell to be pre-installed.
  + This is **not** a `.ps1` file (pure PowerShell). It only calls PowerShell at the end to convert.

- - -

### Features

**Primary purpose**: Convert a binary program into a ASCII HEX file which can be restored using in-built OS programs.

+ Able to use a file or standard input
+ Work on old and new versions of Windows without any 3rd party programs.
+ Supports x86 & x64.
+ Includes a function to compress the file.
+ URL encode the output.
+ Option to add prefix and suffix text to each line.
+ Able to set a maximum HEX length.

Note: This is nothing new. [The core idea has been around since 2003](https://www.blackhat.com/presentations/bh-asia-03/bh-asia-03-chong.pdf) _(if not before!)_.
