#!/usr/bin/env python3

# Name: exe2hex v1.3 (2016-01-25)
# Author: g0tmilk ~ https://blog.g0tmi1k.com/
# Licence: MIT License ~ http://opensource.org/licenses/MIT
# Credit to: exe2bat.exe & https://github.com/acjsec/exe2bam
# Notes: Could use certutil for base64...

import os
import shutil
import signal
import subprocess
import sys
import tempfile
from optparse import OptionParser

import urllib.parse

version = '1.3'


###################
# Functions start #
###################

# Use standard error message and exit
def error_exit(msg):
    error_msg(msg)
    sys.exit(1)


# Standard error message (Red)
def error_msg(msg):
    sys.stderr.write("\033[01;31m[!]\033[00m ERROR: %s\n" % msg)


# Standard success message (Green)
def success_msg(msg):
    print("\033[01;32m[+]\033[00m %s" % msg)


# Verbose message (Yellow)
def verbose_msg(msg):
    if verbose:
        notification_msg(msg)


# Standard notification message (Yellow)
def notification_msg(msg):
    print("\033[01;33m[i]\033[00m %s" % msg)


# Banner information (Blue)
def banner_msg(msg):
    print("\033[01;34m[*]\033[00m %s" % msg)


# CTRL + C
def signal_handler(signal, frame):
    print('Quitting...')
    sys.exit(0)


#################
# Functions End #
#################


###########################
# Start BinaryInput class #
###########################

class BinaryInput:
    # Initialization object configuration
    def __init__(self, exe_file, bat_file, posh_file):
        self.exe_file = exe_file  # Full path of binary input
        self.bat_file = bat_file  # Full path of bat output
        self.posh_file = posh_file  # Full path of posh output
        self.exe_filename = ''  # Filename of binary input
        self.bat_filename = ''  # Filename of bat output
        self.short_file = ''  # Short filename of bat output (8.3 filename)
        self.posh_filename = ''  # Filename of posh output
        self.exe_bin = b''  # Binary input (data read in)
        self.bin_size = 0  # Binary input (size of data)
        self.byte_count = 0  # How many loops to read in binary
        self.bat_hex = ''  # Bat hex format output
        self.posh_hex = ''  # PoSh hex format output

        # Extract the input filename from the input path (if there was one)
        if self.exe_file:
            self.exe_file = os.path.abspath(self.exe_file)
            self.exe_filename = os.path.basename(self.exe_file)
        else:
            self.exe_filename = 'binary.exe'
        verbose_msg("Output EXE filename: %s" % self.exe_filename)

        # debug.exe has a limitation when renaming files > 8 characters (8.3 filename).
        self.short_file = os.path.splitext(self.exe_filename)[0][:8]
        verbose_msg("Short filename: %s" % self.short_file)

        # Are we to make a bat file?
        if self.bat_file:
            # Get just the filename
            self.bat_filename = os.path.basename(self.bat_file)
            verbose_msg("BATch filename: %s" % self.bat_filename)

        # Are we to make a posh file?
        if self.posh_file:
            # Get just the filename
            self.posh_filename = os.path.basename(self.posh_file)
            verbose_msg("PoSh filename: %s" % self.bat_filename)

    # Make sure the input file exists
    def check_exe(self):
        if not os.path.isfile(self.exe_file):
            error_exit("The input file was not found (%s)" % self.exe_file)

    # Make sure the binary size <= 64k when using bat files (limitation with debug.exe)
    def check_bat_size(self):
        verbose_msg('Binary file size: %s' % self.bin_size)

        if self.bin_size > 65536:
            verbose_msg('Input is larger than 65536 bytes')

    # Try and use strip and/or upx to compress (useful for bat)
    def compress_exe(self):
        notification_msg('Attempting to clone and compress')

        tf = tempfile.NamedTemporaryFile(delete=False)
        notification_msg('Creating temporary file %s' % tf.name)
        try:
            if (self.exe_file):
                shutil.copy2(self.exe_file, tf.name)
            else:
                with open(tf.name, 'wb') as out:
                    out.write(self.exe_bin)
        except:
            error_exit("A problem occurred while trying to clone into a temporary file")

        # Compress the new temp file
        self.compress_exe_strip(tf)

        # Don't do it if its not needed. (AV may detect this)
        if compress == 2:
            self.compress_exe_upx(tf)

        # Set the temp file as the main file
        self.exe_file = os.path.abspath(tf.name)

    # Use strip to compress (useful for bat)
    def compress_exe_strip(self, tf):
        if shutil.which("strip"):
            verbose_msg('Running strip on %s' % tf.name)

            # Get the size before compression
            before_size = os.path.getsize(tf.name)

            # Program to run to compress
            command = "strip -s %s" % tf.name
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
            process.wait()

            # Size after compression
            after_size = os.path.getsize(tf.name)
            diff_size = before_size - after_size

            # Feedback for the user
            success_msg("Compression (strip) was successful! (%s saved)" % ("{:.1%}".format(diff_size / before_size)))
            verbose_msg('Binary file size (after strip) %s' % os.path.getsize(tf.name))
        else:
            error_msg("Cannot find strip. Skipping...")

    # Use upx to compress (useful for bat). Can be flag'd by AV
    def compress_exe_upx(self, tf):
        if shutil.which("upx"):
            verbose_msg('Running UPX on %s' % tf.name)

            # Get the size before compression
            before_size = os.path.getsize(tf.name)

            # Program to run to compress
            command = "upx -9 -q -f %s" % tf.name
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
            process.wait()

            # Size after compression
            after_size = os.path.getsize(tf.name)
            diff_size = before_size - after_size

            # Feedback for the user
            success_msg("Compression (UPX) was successful! (%s saved)" % ("{:.1%}".format(diff_size / before_size)))
            verbose_msg('Binary file size (after UPX) %s' % os.path.getsize(tf.name))
        else:
            error_msg("Cannot find UPX. Skipping...")

    # Get the contents of the input file
    def read_bin_file(self):
        # Feedback for the user, to know where they are
        verbose_msg('Reading binary file')

        # Start fresh. Empty the value
        self.exe_bin = b''

        # Open the input file
        with open(self.exe_file, "rb") as f:
            # Loop forever
            while 1:
                # Read file
                try:
                    byte = f.read(1)
                except:
                    error_exit("A problem occurred while reading the input file (%s)" % self.exe_file)

                # The last byte will have "0" for its length. Break the loop.
                if len(byte) == 0:
                    break

                # Add the read byte into the byte string
                self.exe_bin += byte

        # Set the size of the input file
        self.bin_size = os.path.getsize(self.exe_file)

    # Get the contents of STDIN input
    def read_bin_stdin(self):
        # Feedback for the user, to know where they are
        notification_msg('Reading from STDIN')

        # Read from STDIN
        f = ''
        try:
            f = sys.stdin.buffer.read()
        except:
            error_exit('A problem occurred while reading STDIN')

        # Get the length of data read
        stdin_bytes = len(f)

        # Did something go wrong?
        if stdin_bytes == 0:
            error_exit('Zero bytes read from STDIN')

        # Set the size from STDIN
        self.bin_size = stdin_bytes

        # Add the read byte into the byte string
        self.exe_bin = f

    # Convert binary data to a bat file
    def bin_to_bat(self):
        # Feedback for the user, to know where they are
        verbose_msg('Converting to BATch')

        # Number of 64k+/max_size loops will be the number of parts made/
        x = -1

        # What is tha max size we can use for the loop
        max_size = 65536 - (hex_len * 2)

        # Loop through binary bytes per 65536 (Debug.exe limitation)
        for exeloop in range(0, len(self.exe_bin), max_size):

            # Increase the loop counter (incase the input file is 64k+)
            x += 1

            # Start fresh. Empty the value
            self.byte_count = 0

            # Loop through binary input file for this section
            for i in range(exeloop, exeloop + max_size, hex_len):

                # Is there any more data? Are we at the end?
                if not (self.exe_bin[i:i + hex_len]):
                    break

                # Numbering for the hex position in this loop
                hex_size = (i - (max_size * x)) + (hex_len * 2)

                # Convert to hex and debug.exe format
                self.bat_hex += '%secho e %s>>%s.hex%s\r\necho ' % (
                    prefix, '{:04x}'.format(hex_size), self.short_file, suffix)
                self.bat_hex += ' '.join('%02x' % y for y in self.exe_bin[i:i + hex_len])
                self.bat_hex += '>>%s.hex%s\r\n' % (self.short_file, suffix)

                # Save the amount of data converted - aka byte counter (debug.exe needs it at the end)
                self.byte_count += hex_len

            # Save the bat file
            self.save_bat(x)

            # Start fresh. Empty the value
            self.bat_hex = ""

        # Finish off the BATch file (incase there's multiple parts
        self.finish_bat(x)

    # Convert binary data to a PoSh file
    def bin_to_posh(self):
        # Feedback for the user, to know where they are
        verbose_msg('Converting to PoSH')

        # Loop through binary bytes
        for i in range(0, len(self.exe_bin), hex_len):
            self.posh_hex += '%sset /p "=' % (prefix)
            self.posh_hex += ''.join('%02x' % i for i in self.exe_bin[i:i + hex_len])
            self.posh_hex += '"<NUL>>%s.hex%s\r\n' % (self.short_file, suffix)

    # Write resulting bat file
    def save_bat(self, loop=0):
        # Create bat file!
        output = '%secho n %s.%s>%s.hex%s\r\n' % (prefix, self.short_file, loop, self.short_file, suffix)
        output += self.bat_hex
        output += '%secho r cx>>%s.hex%s\r\n' % (prefix, self.short_file, suffix)
        output += '%secho %s>>%s.hex%s\r\n' % (prefix, '{:04x}'.format(self.byte_count), self.short_file, suffix)
        output += '%secho w>>%s.hex%s\r\n' % (prefix, self.short_file, suffix)
        output += '%secho q>>%s.hex%s\r\n' % (prefix, self.short_file, suffix)
        output += '%sdebug<%s.hex%s\r\n' % (prefix, self.short_file, suffix)

        # Write file out (Do we need need to overwrite?)
        if loop > 0:
            self.write_file(self.bat_file, output, "BATch", False)
        else:
            self.write_file(self.bat_file, output, "BATch", True)

    # Write resulting bat file
    def finish_bat(self, loop=0):
        # Is there more than one part? Going to be using this for the copy fu
        if loop > 0:
            # Loop them all, start with the first
            parts = '%s.0' % self.short_file
            for i in range(1, loop + 1, 1):
                parts += '+%s.%s' % (self.short_file, i)

            # Command fu, to join all the parts together
            output = '%scopy /b %s %s%s\r\n' % (prefix, parts, self.exe_filename, suffix)
        else:
            # Single file, just move it
            output = '%smove %s.%s %s%s\r\n' % (prefix, self.short_file, loop, self.exe_filename, suffix)

        # Select every temp file used, so it can be deleted
        parts = '%s.hex' % self.short_file
        for i in range(0, loop + 1, 1):
            parts += ' %s.%s' % (self.short_file, i)

        # Some times the del command will not remove it (still in use), so null it!
        output += '%secho .>%s.hex%s\r\n' % (prefix, self.short_file, suffix)

        # The final few things
        output += '%sdel /F /Q %s%s\r\n' % (prefix, parts, suffix)
        output += '%sstart /b %s%s\r\n' % (prefix, self.exe_filename, suffix)

        self.write_file(self.bat_file, output, "BATch", False)

    # Write resulting PoSh file
    def save_posh(self):
        # Create PoSh file!
        output = self.posh_hex
        output += "%spowershell -Command \"$hex=Get-Content -readcount 0 -path './%s.hex';" % (prefix, self.short_file)
        output += "$len=$hex[0].length;"
        output += "$bin=New-Object byte[] ($len/2);"
        output += "$x=0;"
        output += "for ($i=0;$i -le $len-1;$i+=2)"
        output += "{$bin[$x]=[byte]::Parse($hex.Substring($i,2),[System.Globalization.NumberStyles]::HexNumber);"
        output += "$x+=1};"
        output += "set-content -encoding byte '%s' -value $bin;\"%s\r\n" % (self.exe_filename, suffix)
        output += "%sdel /F /Q %s.hex%s\r\n" % (prefix, self.short_file, suffix)
        output += "%sstart /b %s%s\r\n" % (prefix, self.exe_filename, suffix)

        # Write file out
        self.write_file(self.posh_file, output, "PoSh", True)

    # Write output
    def write_file(self, filepath, contents, type, overwrite=True):
        # Do we need to HTML encode it?
        if encode:
            contents = urllib.parse.quote_plus(contents).replace("%0D%0A", "\r\n")

        if os.path.isfile(filepath) and overwrite:
            verbose_msg("File already exists. Overwriting %s" % filepath)

        # Try and write the file out to disk
        try:
            if overwrite:
                f = open(filepath, 'w')
            else:
                f = open(filepath, 'a')
            f.write(contents)
            f.close
            if overwrite:
                success_msg("Successfully wrote (%s) %s" % (type, os.path.abspath(filepath)))
        except:
            error_msg("A problem occurred while writing (%s)" % filepath)

    # Main action
    def run(self):
        # Read binary data (file or STDIN?)
        if self.exe_file != None:
            # If there is a EXE input, check its valid
            self.check_exe()
            if compress:
                self.compress_exe()
            self.read_bin_file()
        else:
            self.read_bin_stdin()
            if compress:
                self.compress_exe()
                self.read_bin_file()

        # Make bat file
        if self.bat_file != None:
            self.check_bat_size()
            self.bin_to_bat()

        # Make PoSh file
        if self.posh_file != None:
            self.bin_to_posh()
            self.save_posh()


#########################
# End BinaryInput class #
#########################


signal.signal(signal.SIGINT, signal_handler)

################
# Main Program #
################

# Only run if we are being used as stand-alone script
if __name__ == "__main__":
    # Display banner
    banner_msg('exe2hex v%s' % version)

    # Configure command-line option parsing
    parser = OptionParser()
    parser.add_option("-x", dest="exe",
                      help="The EXE binary file to convert", metavar="EXE")

    parser.add_option("-s", dest="stdin",
                      help="Read from STDIN", action="store_true", metavar="STDIN")

    parser.add_option("-b", dest="bat",
                      help="BAT output file (DEBUG.exe method - x86)", metavar="BAT")

    parser.add_option("-p", dest="posh",
                      help="PoSh output file (PowerShell method - x86/x64)", metavar="POSH")

    parser.add_option("-e", dest="encode", default=False,
                      help="URL encode the output", action="store_true", metavar="ENCODE")

    parser.add_option("-r", dest="prefix", default='',
                      help="pRefix - text to add before the command on each line", metavar="TEXT")

    parser.add_option("-f", dest="suffix", default='',
                      help="suFfix - text to add after the command on each line", metavar="TEXT")

    parser.add_option("-l", dest="hex_len", default=128,
                      help="Maximum HEX values per line", metavar="INT")

    parser.add_option("-v", dest="verbose", default=False,
                      help="Enable verbose mode", action="store_true", metavar="VERBOSE")

    parser.add_option("-c", dest="compress", default=False,
                      help="Clones and compress the file before converting (-cc for higher compression)",
                      action="count", metavar="COMPRESS")

    # Store command-line options and arguments in variables
    (options, args) = parser.parse_args()
    exe = options.exe
    stdin = options.stdin
    bat = options.bat
    posh = options.posh
    encode = options.encode
    prefix = options.prefix
    suffix = options.suffix
    try:
        hex_len = int(options.hex_len)
    except:
        error_exit('Invalid length for -l %s' % options.hex_len)
    verbose = options.verbose
    compress = options.compress

    # Being helpful if they haven't read -h...
    if len(sys.argv) == 2:
        exe = sys.argv[1]
        print('')
        notification_msg("Next time use \"-x\".   e.g.: %s -x %s" % (sys.argv[0], exe))
        print('')
    # Are there any arguments?
    elif len(sys.argv) <= 1:
        print('')
        print("Encodes an executable binary file into ASCII text format")
        print("Restore using DEBUG.exe (BATch - x86) or PowerShell (PoSh - x86/x64)")
        print('')
        print("Quick Guide:")
        print(" + Input binary file with -s or -x")
        print(" + Output with -b and/or -p")
        print("Example:")
        print(" $ %s -x /usr/share/windows-binaries/sbd.exe" % sys.argv[0])
        print(" $ %s -x /usr/share/windows-binaries/nc.exe -b /var/www/html/nc.txt -cc" % sys.argv[0])
        print(" $ cat /usr/share/windows-binaries/whoami.exe | %s -s -b debug.bat -p ps.cmd" % sys.argv[0])
        print('')
        print('--- --- --- --- --- --- --- --- --- --- --- --- --- --- ---')
        print('')
        parser.print_help()
        sys.exit(1)

    # Any input methods?
    if exe == None and stdin == None:
        error_exit("Missing a executable file ('-x <file>') or STDIN input ('-s')")

    # Too many input methods?
    if exe != None and stdin != None:
        error_exit('Cannot use both a file and STDIN for inputs at the same time')

    # Any output methods?
    if bat == None and posh == None:
        exe_filename = os.path.splitext(os.path.basename(exe))[0]
        bat = '%s.bat' % os.path.abspath(exe_filename)
        posh = '%s.cmd' % os.path.abspath(exe_filename)
        notification_msg("Outputting to %s (BATch) and %s (PoSh)" % (bat, posh))

    # Do the output files clash?
    if bat == posh:
        error_exit('Cannot use the same output filename for both BAT and PoSh')

    # Is someone going to overwrite what they put in?
    if not stdin and (exe == bat or exe == posh):
        error_exit('Cannot use the same input as output')

    # Read in file information
    x = BinaryInput(exe, bat, posh)

    # GO!
    x.run()
