import sys
import subprocess
import os
import serial

DEBUG=False

#env vars
PONGO_DECRYPTOR_TTY_PATH = None

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def dbgprint(*args, **kwargs):
  if DEBUG:
    eprint(*args, **kwargs)

def decryptKBAG(component, cpid, kbag):
  if not "sep" in component.lower():
    dbgprint("This module only handles SEP decryption!")
    return None
  PONGO_DECRYPTOR_TTY_PATH = os.getenv("PONGO_DECRYPTOR_TTY_PATH")
  if not PONGO_DECRYPTOR_TTY_PATH:
    #No tty device configured
    return None
  try:
    ser = serial.Serial(PONGO_DECRYPTOR_TTY_PATH, 115200, timeout=1)
  except:
    eprint("Failed to open serial device '%s'"%(PONGO_DECRYPTOR_TTY_PATH))
    return None

  ser.write(b"\n") #clear outbut
  ser.flush()
  ser.read(0x100) #clear inbuf

  eprint("Decrypting: %s"%kbag)
  cmd = "sep decrypt %s\n"%kbag
  cmd = cmd.encode("UTF-8")
  for i in range(0,len(cmd),0x10):
    #shitty uart sometimes drops packets, so be slow
    ccmd = cmd[i:i+0x10]
    ser.write(ccmd)
    ser.flush()
    ser.read(len(ccmd))
  output = ser.read(0x100)
  ser.close()
  output = output.replace(b"\r",b"")
  outputstr = output.decode("UTF-8").split("kbag out: ")[1].split("\n")[0]
  if len(outputstr) != 0x30*2:
    eprint("FATAL error on Pongo decryption! '%s'"%outputstr)
    exit(99)
  iv = outputstr[0:16*2]
  key= outputstr[16*2:]
  eprint("Got: %s"%iv+key)
  return iv,key
