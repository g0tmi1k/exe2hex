#!/usr/bin/env python

#Exe2Bam! / v0.1 / 2014-08-05
#AJ / aj@infosec.ninja / @acjsec / https://github.com/acjsec/exe2bam
#Largely based on exe2bat

import sys
import os
from optparse import OptionParser

#This maximum is consistent with the exe2bat/debug maximum of four bytes
MAX_SIZE = 2**16

class ExeWriter:
  #Object initialization configuration
  def __init__(self, exe, bat_file, posh_file, output_dir):
    self.exe                = exe
    self.bat_file           = bat_file
    self.posh_file          = posh_file
    self.exe_bin            = ''
    self.posh_hex           = ''
    self.bat_hex            = ''
    self.bat_byte_count     = 0
    self.output_dir         = output_dir
    if self.output_dir[-1] != '/': self.output_dir += '/'


  #Standard formatting and exit for problems
  def error_exit(self, msg):
    sys.stderr.write("[-] Error: %s\n" % msg)
    sys.exit(1)


  #Stardard error message 
  def error_msg(self, msg):
    sys.stderr.write("[-] Error: %s\n" % msg)


  #Stardard success message 
  def success_msg(self, msg):
    sys.stderr.write("[+] %s\n" % msg)


  #Ensure file is <= maximum size
  def check_size(self):
    exe_size = os.path.getsize(self.exe)
    if exe_size > MAX_SIZE:
      self.error_exit("Filesize must be under 64k (%s: %d bytes)" % (self.exe.split('/')[-1], exe_size))


  #Ensure the executable exists
  def check_exe(self):
    if not os.path.isfile(self.exe):
      self.error_exit("Executable file not found")


  #Ensure the output directory exists
  def check_output_dir(self):
    if not os.path.isdir(self.output_dir):
      self.error_exit("Output directory not found (%s)" % self.output_dir)


  #Acquire binary executable contents
  def read_bin(self):
    #Open executable and loop through each byte
    with open(self.exe, "rb") as f:
      while 1: 
        try:
          byte = f.read(1)
        except:
          self.error_exit("A problem occurred while attempting to read the file")
        #The final byte is of zero length when using this technique; this is expected
        if len(byte) == 0:
          break
        #Append valid byte
        self.exe_bin += byte

  #Convert binary data for bat file
  def bin_to_bat_hex(self):
    byte_count = 0

    #Loop through binary bytes and split every 128 bytes
    for byte in self.exe_bin:
      if ((byte_count % 128) == 0):
        #The first and subsequent lines require different formatting
        if byte_count   == 0:
          self.bat_hex  += 'echo e %s >>%s.hex\necho'            % ('{:04x}'.format(byte_count+256), self.bat_file)
        else:
          self.bat_hex  += ' >>%s.hex\necho e %s >>%s.hex\necho' % (self.bat_file, '{:04x}'.format(byte_count+256), self.bat_file)

      #Append ASCII hex byte and increment count
      self.bat_hex      += ' {:02x}'.format(ord(byte))
      byte_count        += 1

    #Add final write and save byte count
    self.bat_hex        += ' >>%s.hex\n' % self.bat_file
    self.bat_byte_count  = byte_count


  #Convert binary data for PoSh file
  def bin_to_posh_hex(self):
    byte_count = 0

    #Loop through binary bytes and split every 128 bytes
    for byte in self.exe_bin:
      if ((byte_count % 128) == 0):
        #The first and subsequent lines require different formatting
        self.posh_hex += '" > %s.txt\n<NUL set /p ="'  % self.posh_file
      else:
        self.posh_hex += '" >> %s.txt\n<NUL set /p ="' % self.posh_file

      #Append ASCII hex byte and increment count
      self.posh_hex       += '{:02x}'.format(ord(byte))
      byte_count          += 1

    #Final write and corresponding PoSh command
    self.posh_hex         += '" >> px.txt'

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
    output  = 'echo n %s.dll >%s.hex\n' % (self.bat_file, self.bat_file)
    output += self.bat_hex
    output += 'echo r cx >>%s.hex\n'   % self.bat_file
    output += 'echo %s >>%s.hex\n'     % ('{:04x}'.format(self.bat_byte_count), self.bat_file)
    output += 'echo w >>%s.hex\n'      % self.bat_file
    output += 'echo q >>%s.hex\n'      % self.bat_file
    output += 'debug<%s.hex\n'         % self.bat_file
    output += 'move %s.dll %s.exe\n'   % (self.bat_file, self.bat_file)
    output += '%s.exe\n'               % self.bat_file
    self.write_file(self.output_dir + self.bat_file + ".bat", output)


  #Write resulting PoSh file
  def write_posh(self):
    output  = '<NUL set /p ="'
    output += self.posh_hex
    self.write_file(self.output_dir + self.posh_file + '_ps.bat', output)
    self.write_ps1()


  #Write PoSh command (to create executable from PoSh file)
  def write_ps1(self):
    posh_ps1          = "$hs=Get-Content -readcount 0 -path './%s.txt'; " % self.posh_file
    posh_ps1         += "$hs = $hs[0]; $c = $hs.length; $bc = $c/2; $bs = New-Object byte[] $bc; "
    posh_ps1         += "$b = $null; $x=0; for ( $i = 0; $i -le $c-1; $i+=2 ) "
    posh_ps1         += "{ $bs[$x] = [byte]::Parse($hs.Substring($i,2), "
    posh_ps1         += "[System.Globalization.NumberStyles]::HexNumber); $x+=1 } "
    posh_ps1         += "set-content -encoding byte '%s.exe' -value $bs; " % self.posh_file
    posh_ps1         += "./%s.exe" % self.posh_file

    self.write_file(self.output_dir + self.posh_file + '.ps1', posh_ps1)

    
  #Standard operations for stand-alone script
  def run(self):
    #Perform basic checks before proceeding
    self.check_exe()
    self.check_size()
    self.check_output_dir()

    #Acquire binary data from the executable
    self.read_bin()

    #Create and write bat file if it was specified
    if self.bat_file != None:
      self.bin_to_bat_hex()
      self.write_bat()

    #Create and write PoSh file if it was specified
    if self.posh_file != None:
      self.bin_to_posh_hex()
      self.write_posh()

#Only run if used as a stand-alone script
if __name__ == "__main__":
  #Configure command-line option parsing
  parser = OptionParser()
  parser.add_option("-x", "--exe", dest="exe",
                    help="EXE to convert", metavar="EXE")
  parser.add_option("-p", "--posh", dest="posh",
                    help="POSH output file name", metavar="POSH")
  parser.add_option("-b", "--bat", dest="bat",
                    help="BAT output file name", metavar="BAT")
  parser.add_option("-o", "--output", dest="output",
                    help="OUTPUT directory for generated files", metavar="OUTPUT")

  #Standard formatting and exit for problems
  def error_exit(msg):
    sys.stderr.write("[-] Error: %s\n" % msg)
    sys.exit(1)

  #Store command-line options and arguments in variables
  (options, args) = parser.parse_args()
  exe             = options.exe
  bat             = options.bat
  posh            = options.posh
  out_dir         = options.output

  #Perform basic checks for command-line options
  if len(args) > 0:
    error_exit("All values must be specified with options")

  if posh == None and bat == None:
    error_exit("PoSh and/or Bat output file must be specified")
    
  if exe == None:
    error_exit("Executable file must be provided")
    
  if out_dir == None:
    print "[!] Notice: Output directory not specified, saving file(s) to PWD"
    out_dir = "./"

  #Instanticate object and start operations
  e = ExeWriter(exe, bat, posh, out_dir)
  e.run()
