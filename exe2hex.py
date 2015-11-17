#!/usr/bin/env python

# Name: exe2hex v1.1 (2015-11-17)
# Author: g0tmilk ~ https://blog.g0tmi1k.com/
# Licence: MIT License ~ http://opensource.org/licenses/MIT
# Credit to: exe2bat.exe & https://github.com/acjsec/exe2bam

import os
import sys
import urllib
from optparse import OptionParser

version = '1.1'


###################
# Functions start #
###################

# Standard error message and exit
def error_exit(msg):
    error_msg(msg)
    sys.exit(1)


# Standard error message (Red)
def error_msg(msg):
    sys.stderr.write("\033[01;31m[!]\033[00m ERROR: %s\n" % msg)


# Standard success message (Green)
def success_msg(msg):
    print("\033[01;32m[+]\033[00m %s" % msg)


# Standard notification message (Yellow)
def verbose_msg(msg):
    if verbose:
        notification_msg(msg)


# Standard notification message (Yellow)
def notification_msg(msg):
    print("\033[01;33m[i]\033[00m %s" % msg)


# Banner Information (Blue)
def banner_msg(msg):
    print("\033[01;34m[*]\033[00m %s" % msg)


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
        self.bat_short_file = ''  # Short filename of bat output (8.3 filename)
        self.posh_filename = ''  # Filename of posh output
        self.exe_bin = ''  # Binary input read in
        self.bin_size = 0  # Binary input size
        self.byte_count = 0  # How many loops to read in binary
        self.bat_hex = ''  # Bat hex format output
        self.posh_hex = ''  # PoSh hex format output

        # Extract the input filename from the input path (if there was one)
        if self.exe_file:
            self.exe_filename = os.path.basename(self.exe_file)
        else:
            self.exe_filename = 'binary.exe'
        verbose_msg("Output EXE filename: %s" % self.exe_filename)

        # Are we to make a bat file?
        if self.bat_file:
            # Get just the filename
            self.bat_filename = os.path.basename(self.bat_file)
            verbose_msg("BAT filename: %s" % self.bat_filename)

            # debug.exe has a limitation when renaming files > 8 characters (8.3 filename).
            self.bat_short_file = os.path.splitext(self.bat_filename)[0][:8]
            verbose_msg("BAT short filename: %s" % self.bat_short_file)

        # Are we to make a posh file?
        if self.posh_file:
            # Get just the filename
            self.posh_filename = os.path.basename(self.posh_file)
            verbose_msg("PoSh filename: %s" % self.bat_filename)

    # Make sure the input file exists
    def check_exe(self):
        if not os.path.isfile(self.exe_file):
            error_exit("The input file was not found (%s)" % (self.exe_file))

    # Make sure the binary size <= 64k when using bat files (limitation with debug.exe)
    def check_bat_size(self):
        if self.bin_size > 65536:
            error_msg(
                "For BAT output, the input file must be under 64k (%d/65536) (DEBUG.exe limitation)" % (self.bin_size))
            error_msg("[TIP] Try and compress/shrink the input file using strip and/or upx\n")
            return False
        verbose_msg('Binary file size: %s' % self.bin_size)
        return True

    # Get the contents of the input file
    def read_bin_file(self):
        # Feedback for the user, to know where they are
        verbose_msg('Reading binary file')

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
            f = sys.stdin.read()
        except:
            error_exit('A problem occurred while reading STDIN')

        # Get the length of data read
        stdin_bytes = len(f)

        # Did something go wrong?
        if stdin_bytes == 0:
            error_exit('Zero bytes read from STDIN') % stdin_bytes

        # Set the size from STDIN
        self.bin_size = stdin_bytes

        # Add the read byte into the byte string
        for byte in f:
            self.exe_bin += byte

    # Convert binary data to a bat file
    def bin_to_bat(self):
        # Feedback for the user, to know where they are
        verbose_msg('Converting to BAT')

        # Check size due to limitation of debug,exe (<= 64k)
        if self.check_bat_size() == False:
            return False

        # Counter for how many bytes have been looped
        byte_count = 0

        # Loop through binary bytes
        for byte in self.exe_bin:
            # Every hex_len bytes. New line.
            if ((byte_count % hex_len) == 0):
                # Is this anything but the first line?
                if byte_count != 0:
                    # End the line
                    self.bat_hex += ' >>%s.hex%s\r\n' % (self.bat_short_file, suffix)
                # Start a new line
                self.bat_hex += '%secho e %s >>%s.hex%s\r\necho' % (
                    prefix, '{:04x}'.format(byte_count + 256), self.bat_short_file, suffix)

            # Add ASCII hex byte
            self.bat_hex += ' {:02x}'.format(ord(byte))

            # Increment byte counter
            byte_count += 1

        # Add the last output line
        self.bat_hex += ' >>%s.hex%s\r\n' % (self.bat_short_file, suffix)

        # Save byte counter (debug.exe needs it)
        self.byte_count = byte_count

        # Finished here successfully
        return True

    # Convert binary data to a PoSh file
    def bin_to_posh(self):
        # Feedback for the user, to know where they are
        verbose_msg('Converting to PoSH')

        # Counter for how many bytes have been looped
        byte_count = 0

        # Loop through binary bytes
        for byte in self.exe_bin:
            # Every hex_len bytes. New line.
            if ((byte_count % hex_len) == 0):
                self.posh_hex += '"<NUL>'
                # Is this anything but the first line?
                if byte_count != 0:
                    self.posh_hex += '>'
                # End & start a new line
                self.posh_hex += '%s%s\r\n%sset /p "=' % (self.posh_filename, suffix, prefix)

            # Append ASCII hex byte
            self.posh_hex += '{:02x}'.format(ord(byte))

            # Increment byte counter
            byte_count += 1

        # Add the last output line
        self.posh_hex += '"<NUL>>%s%s\r\n' % (self.posh_filename, suffix)

    # Write resulting bat file
    def save_bat(self):
        # Create bat file!
        output = '%secho n %s.dll >%s.hex%s\r\n' % (prefix, self.bat_short_file, self.bat_short_file, suffix)
        output += self.bat_hex
        output += '%secho r cx >>%s.hex%s\r\n' % (prefix, self.bat_short_file, suffix)
        output += '%secho %s >>%s.hex%s\r\n' % (prefix, '{:04x}'.format(self.byte_count), self.bat_short_file, suffix)
        output += '%secho w >>%s.hex%s\r\n' % (prefix, self.bat_short_file, suffix)
        output += '%secho q >>%s.hex%s\r\n' % (prefix, self.bat_short_file, suffix)
        output += '%sdebug<%s.hex%s\r\n' % (prefix, self.bat_short_file, suffix)
        output += '%smove %s.dll %s%s\r\n' % (prefix, self.bat_short_file, self.exe_filename, suffix)
        output += '%sdel /F /Q %s.hex%s\r\n' % (prefix, self.bat_short_file, suffix)
        output += '%sstart /b %s%s\r\n' % (prefix, self.exe_filename, suffix)

        # Write file out
        self.write_file(self.bat_file, output)

    # Write resulting PoSh file
    def save_posh(self):
        # Create PoSh file!
        output = '%sset /p "=' % prefix
        output += self.posh_hex
        output += "%spowershell -Command \"$hex=Get-Content -readcount 0 -path './%s';" % (prefix, self.posh_filename)
        output += "$len=$hex[0].length;"
        output += "$bin=New-Object byte[] ($len/2);"
        output += "$x=0;"
        output += "for ($i=0;$i -le $len-1;$i+=2)"
        output += "{$bin[$x]=[byte]::Parse($hex.Substring($i,2),[System.Globalization.NumberStyles]::HexNumber);"
        output += "$x+=1};"
        output += "set-content -encoding byte '%s' -value $bin;\"%s\r\n" % (self.exe_filename, suffix)
        output += "%sdel /F /Q %s%s\r\n" % (prefix, self.posh_filename, suffix)
        output += "%sstart /b %s%s\r\n" % (prefix, self.exe_filename, suffix)

        # Write file out
        self.write_file(self.posh_file, output)

    # Write output
    def write_file(self, filepath, contents):
        # Do we need to HTML encode it?
        if encode:
            contents = urllib.quote_plus(contents).replace("%0D%0A", "\r\n")

        # Try and write the file out to disk
        try:
            f = open(filepath, 'w')
            f.write(contents)
            f.close
            success_msg("Successfully wrote: %s" % filepath)
        except:
            error_msg("A problem occurred while writing (%s)" % filepath)

    # Main action
    def run(self):
        # Read binary data (file or STDIN?)
        if self.exe_file != None:
            # If there is a EXE input, check its valid
            self.check_exe()
            self.read_bin_file()
        else:
            self.read_bin_stdin()

        # Make bat file
        if self.bat_file != None:
            if self.bin_to_bat():
                self.save_bat()

        # Make PoSh file
        if self.posh_file != None:
            self.bin_to_posh()
            self.save_posh()

#########################
# End BinaryInput class #
#########################


################
# Main Program #
################

# Only run if we are being used as stand-alone script
if __name__ == "__main__":
    # Display banner
    banner_msg('exe2hex v%s' % version)
    print ''

    # Configure command-line option parsing
    parser = OptionParser()
    parser.add_option("-x", dest="exe",
                      help="The EXE binary file to convert", metavar="EXE")

    parser.add_option("-s", dest="stdin",
                      help="Read from STDIN", action="store_true", metavar="STDIN")

    parser.add_option("-b", dest="bat",
                      help="BAT output file (DEBUG.exe method)", metavar="BAT")

    parser.add_option("-p", dest="posh",
                      help="PoSh output file (PowerShell method)", metavar="POSH")

    parser.add_option("-e", dest="encode", default=False,
                      help="HTML encode the output?", action="store_true", metavar="ENCODE")

    parser.add_option("-r", dest="prefix", default='',
                      help="pRefix - text to add before the command", metavar="TEXT")

    parser.add_option("-f", dest="suffix", default='',
                      help="suFfix - text to add after the command", metavar="TEXT")

    parser.add_option("-l", dest="hex_len", default=128,
                      help="Maximum hex values per line", metavar="INT")

    parser.add_option("-v", dest="verbose", default=False,
                      help="Enable verbose output", action="store_true", metavar="VERBOSE")

    # Store command-line options and arguments in variables
    (options, args) = parser.parse_args()
    exe = options.exe
    stdin = options.stdin
    bat = options.bat
    posh = options.posh
    encode = options.encode
    prefix = options.prefix
    suffix = options.suffix
    hex_len = int(options.hex_len)
    verbose = options.verbose

    # Is there any arguments?
    if len(sys.argv) <= 1:
        banner_msg("Encodes a executable binary file into ASCII text format (Windows .cmd file)")
        banner_msg("Restores using DEBUG.exe (BATch - x86) and/or PowerShell (PoSh - x86/x64)")
        print ''
        banner_msg("Quick usage:")
        banner_msg(" + Input with -s or -x")
        banner_msg(" + Output with -b and/or -p")
        banner_msg("Example:")
        banner_msg(" $ %s -x /usr/share/windows-binaries/nc.exe -b /var/www/html/nc.txt" % sys.argv[0])
        banner_msg(" $ cat /usr/share/windows-binaries/whoami.exe | %s -s -b who_debug.bat -p who_ps.cmd" % sys.argv[0])
        print ''
        parser.print_help()
        sys.exit(1)

    # Any input methods?
    if exe == None and stdin == None:
        error_exit('Missing a executable file or STDIN input')

    # Too many input methods?
    if exe != None and stdin != None:
        error_exit('Cannot use both a file and STDIN for inputs at the same time')

    # Any output methods?
    if bat == None and posh == None:
        error_exit('A BAT and/or PoSh output file must be specified')

    # Do the output files clash?
    if bat == posh:
        error_exit('Cannot use the same filename for both BAT and PoSh')

    # Read in file information
    x = BinaryInput(exe, bat, posh)

    # GO!
    x.run()