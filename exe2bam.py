#!/usr/bin/env python

#Exe2Bam! / v1.0 / 2014-08-05
#AJ / aj@infosec.ninja / @acjsec / https://github.com/acjsec/exe2bam
#Largely based on exe2bat

import sys
import os
from optparse import OptionParser

#Defines the maximum size for the exe2bat/debug technique
MAX_SIZE = 2**16

class ExeWriter:
  #Object initialization configuration
  def __init__(self, exe, bat_file, posh_file, output_dir):
    self.exe                = exe
    self.bat_file           = bat_file
    self.bat_short_file     = ''
    self.posh_file          = posh_file
    self.exe_bin            = ''
    self.posh_hex           = ''
    self.bat_hex            = ''
    self.byte_count         = 0
    self.bin_size           = 0
    self.output_dir         = output_dir
    if self.output_dir[-1] != '/': self.output_dir += '/'


  #Standard error message and exit for irreparable problems
  def error_exit(self, msg):
    sys.stderr.write("[-] Error: %s\n" % msg)
    sys.exit(1)


  #Stardard error message 
  def error_msg(self, msg):
    sys.stderr.write("[-] Error: %s\n" % msg)


  #Stardard success message 
  def success_msg(self, msg):
    print("[+] %s" % msg)


  #Standard notification message
  def notification_msg(self, msg):
    print("[!] %s" % msg)


  #Ensure binary size for bat file is <= the maximum size
  def check_bat_size(self):
    if self.bin_size > MAX_SIZE:
      self.error_msg("Binary data for bat file must be under 64k (%d/%d)" % (self.bin_size, MAX_SIZE))
      return False
    else:
      return True


  #Set short bat name
  #Windows debug will rename file if > 8 characters
  #This breaks the rename and execute operations
  def set_bat_short_file(self):
    if len(self.bat_file) > 8:
      self.bat_short_file = self.bat_file[:8]
    else:
      self.bat_short_file = self.bat_file   


  #Set binary size from the executable
  def set_size_exe(self):
    self.bin_size = os.path.getsize(self.exe)


  #Set binary size from STDIN
  def set_size_stdin(self, stdin_length):
    self.bin_size = stdin_length


  #Ensure the executable exists
  def check_exe(self):
    if not os.path.isfile(self.exe):
      self.error_exit("Executable file not found")


  #Ensure the output directory exists
  def check_output_dir(self):
    if not os.path.isdir(self.output_dir):
      self.error_exit("Output directory not found (%s)" % self.output_dir)


  #Acquire binary executable contents
  def read_bin_file(self):
    #Saves the executable byte size for bat/debug maximum comparison
    self.set_size_exe()

    #Open executable and loop through each byte
    with open(self.exe, "rb") as f:
      while 1: 
        try:
          byte = f.read(1)
        except:
          self.error_exit("A problem occurred while attempting to read the file")
        #The final byte is of zero length when using this read technique
        #this result is expected
        if len(byte) == 0:
          break

        #Append valid byte to byte string
        self.exe_bin += byte


  #Acquire binary STDIN contents
  def read_bin_stdin(self):
   #Attempt to read from STDIN
    f = ''
    try:
      f=sys.stdin.read()
    except:
      self.error_exit("A problem occurred while attempting to read STDIN")

    #Acquire length of data read
    stdin_bytes = len(f)

    #Saves the STDIN byte size for bat/debug maximum comparison
    self.set_size_stdin(stdin_bytes)

    if stdin_bytes == 0:
      self.error_exit("Zero bytes read from STDIN)") % stdin_bytes

    #Append valid bytes to byte string
    for byte in f:
      self.exe_bin += byte


  #Convert binary data for bat file
  def bin_to_bat_hex(self):
    byte_count = 0
    self.set_bat_short_file()
    #Loop through binary bytes and split every 128 bytes
    for byte in self.exe_bin:
      if ((byte_count % 128) == 0):
        #The first and subsequent lines require different formatting
        if byte_count   == 0:
          self.bat_hex  += 'echo e %s >>%s.hex\necho'            % ('{:04x}'.format(byte_count+256), self.bat_short_file)
        else:
          self.bat_hex  += ' >>%s.hex\necho e %s >>%s.hex\necho' % (self.bat_short_file, '{:04x}'.format(byte_count+256), self.bat_short_file)

      #Append ASCII hex byte and increment count
      self.bat_hex      += ' {:02x}'.format(ord(byte))
      byte_count        += 1

    #Add final output line and save byte count
    #The byte count is a parameter debug needs for compiling the file
    self.bat_hex        += ' >>%s.hex\n' % self.bat_short_file
    self.byte_count      = byte_count


  #Convert binary data for PoSh file
  def bin_to_posh_hex(self):
    byte_count = 0

    #Loop through binary bytes and split every 128 bytes
    for byte in self.exe_bin:
      if ((byte_count % 128) == 0):
        #The first and subsequent lines require different formatting
        if byte_count == 0:
          self.posh_hex += '" > %s.txt\n<NUL set /p ="'  % self.posh_file
        else:
          self.posh_hex += '" >> %s.txt\n<NUL set /p ="' % self.posh_file

      #Append ASCII hex byte and increment count
      self.posh_hex       += '{:02x}'.format(ord(byte))
      byte_count          += 1

    #Add final output line
    self.posh_hex         += '" >> %s.txt' % self.posh_file

  #Generic method for writing files
  def write_file(self, filepath, contents):
    try:
      f = open(filepath, 'w')
      f.write(contents)
      f.close
      self.success_msg("Successfully wrote: %s" % filepath)
    except:
      self.error_msg("A problem occurred while attempting to write %s" % filepath)


  #Write resulting bat file
  def write_bat(self):
    #Check size and return if size exceeds maximum
    size_check = self.check_bat_size()
    if not size_check: return False

    #Concatenate lines and write file
    output  = 'echo n %s.dll >%s.hex\n' % (self.bat_short_file, self.bat_short_file)
    output += self.bat_hex
    output += 'echo r cx >>%s.hex\n'   % self.bat_short_file
    output += 'echo %s >>%s.hex\n'     % ('{:04x}'.format(self.byte_count), self.bat_short_file)
    output += 'echo w >>%s.hex\n'      % self.bat_short_file
    output += 'echo q >>%s.hex\n'      % self.bat_short_file
    output += 'debug<%s.hex\n'         % self.bat_short_file
    output += 'move %s.dll %s.exe\n'   % (self.bat_short_file, self.bat_short_file)
    output += '%s.exe\n'               % self.bat_short_file
    self.write_file(self.output_dir + self.bat_file + ".bat", output)


  #Write resulting PoSh file
  def write_posh(self):
    #Concatenate lines and write file
    output  = '<NUL set /p ="'
    output += self.posh_hex
    output += "\npowershell $hs=Get-Content -readcount 0 -path './%s.txt'; " % self.posh_file
    output += "$hs = $hs[0]; $c = $hs.length; $bc = $c/2; $bs = New-Object byte[] $bc; "
    output += "$b = $null; $x=0; for ( $i = 0; $i -le $c-1; $i+=2 ) "
    output += "{ $bs[$x] = [byte]::Parse($hs.Substring($i,2), "
    output += "[System.Globalization.NumberStyles]::HexNumber); $x+=1 } "
    output += "set-content -encoding byte '%s.exe' -value $bs; " % self.posh_file
    output += "./%s.exe\n" % self.posh_file
    self.write_file(self.output_dir + self.posh_file + '.bat', output)

    
  #Standard operations for use as stand-alone script
  def run(self):
    #Perform basic checks before proceeding
    if self.exe != None: self.check_exe()
    self.check_output_dir()

    #Acquire binary data from the executable
    if self.exe != None:
      self.read_bin_file()
    else:
      self.notification_msg("Reading from STDIN: Ensure data is piped/redirected")
      self.notification_msg("Send EOF with CTRL-D if stuck")
      print
      self.read_bin_stdin()

    #Create and write bat file if it was specified
    if self.bat_file != None:
      self.bin_to_bat_hex()
      self.write_bat()

    #Create and write PoSh file if it was specified
    if self.posh_file != None:
      self.bin_to_posh_hex()
      self.write_posh()

############################################################
##### End class definition and begin stand-alone setup #####
############################################################

#Only run if used as a stand-alone script
if __name__ == "__main__":
  #Display banner
  print '''                                   __ 
             ___ _____ _____ _____|  |
 ___ _ _ ___|_  | __  |  _  |     |  |
| -_|_'_| -_|  _| __ -|     | | | |__|
|___|_,_|___|___|_____|__|__|_|_|_|__|
                                      '''
  print "[*] Starting exe2BAM! v1.0"
  print
  print "[*] Generates executable from incremental text output"
  print "[*] Outputs traditional bat/debug or new bat/posh formats"
  print
  print "[*] Specify binary input with -s or -x"
  print "[*] Specify output with -b and/or -p"
  print "[*] More details are available with -h/--help"
  print


  #Configure command-line option parsing
  parser = OptionParser()
  parser.add_option("-x", "--exe", dest="exe",
                    help="EXE to convert", metavar="EXE")
  parser.add_option("-s", "--stdin", dest="stdin",
                    help="Read from STDIN", metavar="STDIN", action="store_true")
  parser.add_option("-p", "--posh", dest="posh",
                    help="POSH output file name prefix (exclude extension)", metavar="POSH")
  parser.add_option("-b", "--bat", dest="bat",
                    help="BAT output file name prefix (exclude extension)", metavar="BAT")
  parser.add_option("-o", "--output", dest="output",
                    help="OUTPUT directory for generated files", metavar="OUTPUT")


  #Standard error message and exit for irreparable problems
  #(Duplicate from class method, but needed before instantiation)
  def error_exit(msg):
    sys.stderr.write("[-] Error: %s\n" % msg)
    sys.exit(1)


  #Store command-line options and arguments in variables
  (options, args) = parser.parse_args()
  exe             = options.exe
  bat             = options.bat
  posh            = options.posh
  out_dir         = options.output
  stdin           = options.stdin


  #Perform basic checks for command-line options
  if len(args) > 0:
    error_exit("All values must be specified with options")

  if posh == None and bat == None:
    error_exit("PoSh and/or Bat output file must be specified")
    
  if exe != None and stdin != None:
    error_exit("Cannot use both file and stdin")
    
  if exe == None and stdin == None:
    error_exit("Executable file or STDIN must be specified")
    
  if out_dir == None:
    print "[!] Notice: Output directory not specified, saving file(s) to PWD"
    out_dir = "./"

  #Instanticate object and start operations if everything appears correct
  e = ExeWriter(exe, bat, posh, out_dir)
  e.run()
