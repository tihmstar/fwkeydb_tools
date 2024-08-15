import sys
import subprocess

DEBUG=False

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def dbgprint(*args, **kwargs):
  if DEBUG:
    eprint(*args, **kwargs)

def decryptKBAG(component, cpid, kbag):
  if "sep" in component.lower():
    dbgprint("This module does not handle SEP decryption!")
    return None
  eprint("Decrypting: %s"%kbag)
  p = subprocess.Popen("gaster decrypt_kbag %s"%(kbag), shell=True, stdout=subprocess.PIPE)
  output = p.stdout.read()
  outputstr = output.decode("UTF-8")
  if not "CPID: "+hex(cpid) in outputstr:
    dbgprint("Attempted to decrypt on wrong cpid!")
    return None
  sps = outputstr.split("IV: ")[1].split("\n")[0].split(",")
  iv = sps[0]
  key= sps[1].split(" key: ")[1]
  eprint("Got: %s"%iv+key)
  return iv,key
