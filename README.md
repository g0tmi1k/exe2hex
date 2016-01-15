# exe2hex

Inline file transfer method using `debug.exe` and/or PowerShell.

- - -

### Overview


Encodes a executable binary file into ASCII text format.

Restores using `DEBUG.exe` (BATch - x86) and/or PowerShell (PoSh - x86/x64).

```Binary EXE -> ASCII text -> Binary EXE```

![](https://i.imgur.com/kMcqHNq.png)

- - -

### Quick usage

 + Input with a file (`-x /path/to/binary.exe`) or STDIN (`-s`)
 + Output to BAT (`-b /path/to/debug.bat`) and/or PoSH (`-p powershell.cmd`)

#### Example Usage

```bash
$ python3 exe2hex.py -x /usr/share/windows-binaries/sbd.exe
[*] exe2hex v1.2
[i] Outputting to /root/sbd.bat (BATch) and /root/sbd.cmd (PoSh)
[+] Successfully wrote (BAT): /root/sbd.bat
[+] Successfully wrote (PoSh): /root/sbd.cmd
$
```

```bash
$ ./exe2hex.py -x /usr/share/windows-binaries/nc.exe -b /var/www/html/nc.txt
[*] exe2hex v1.2
[+] Successfully wrote (BAT): /var/www/html/nc.txt
$
```

```bash
$ cat /usr/share/windows-binaries/whoami.exe | python3 exe2hex.py -s -b debug.bat -p ps.cmd
[*] exe2hex v1.2
[i] Reading from STDIN
[!] ERROR: Input is larger than 65536 bytes (BATch/DEBUG.exe limitation)
[i] Attempting to clone and compress
[i] Creating temporary file /tmp/tmpfypsf9if
[i] Running strip on /tmp/tmpfypsf9if
[+] Compression was successful!
[+] Successfully wrote (BAT): /root/debug.bat
[+] Successfully wrote (PoSh): /root/ps.cmd
$
```

#### Help

```bash
$ python3 exe2hex.py -h
[*] exe2hex v1.2
Usage: exe2hex.py [options]

Options:
  -h, --help  show this help message and exit
  -x EXE      The EXE binary file to convert
  -s          Read from STDIN
  -b BAT      BAT output file (DEBUG.exe method - x86)
  -p POSH     PoSh output file (PowerShell method - x64/x86)
  -e          URL encode the output
  -r TEXT     pRefix - text to add before the command on each line
  -f TEXT     suFfix - text to add after the command on each line
  -l INT      Maximum hex values per line
  -v          Enable verbose mode
$
```

- - -

### Methods/OS Support

+ **`DEBUG.exe` (BATch mode - `-b`)**
  + Every version of Windows x86 (No x64 support).
  + Useful for legacy versions of Windows (e.g. XP/2000).
  + Has a limitation of 64k file size for binary files.
+ **PowerShell (PoSh mode - `-p`)**
  + Supports both Windows x86 & x64.
  + Aimed at more "recent" versions of Windows.
  + Powershell was first integrated into core OS with Windows 7/Windows Server 2008 R2.
  + Windows XP SP2, Windows Server 2003 & Windows Vista requires PowerShell to be pre-installed.
  + This is **not** a `.ps1` file (pure powershell). It only calls powershell at the end to convert.
