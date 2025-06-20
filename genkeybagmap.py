import json
import sys

import coreFWKEYDBLib

#run as following: find keys/firmware/ -type f | python genkeybagmap.py > kbags.json

class VersionMismatchException(Exception):
    pass

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

keybags = {}

def processKeyfilePaths(path):
  with open(path,"rb") as f:
    keysfile = json.loads(f.read())
  version = keysfile["version"]
  if version > coreFWKEYDBLib.CURRENT_KEYFILES_VERSION:
    raise VersionMismatchException("keysfile version is too new!")

  keys = keysfile["keys"]

  for filename,elem in keys.items():
    kbag = elem["kbag"]
    if not "iv" in elem:
      continue
    if not "key" in elem:
      continue
    iv = elem["iv"]
    key = elem["key"]
    if not len(kbag):
      continue
    keybags[kbag] = {
      "iv" : iv,
      "key" : key
    }

if __name__ == '__main__':
  f = sys.stdin

  numberOfUnsuccessfullKeyfiles = 0
  
  fileIsEOF = False
  while True:
    l = ""
    while True:
      try:
        c = f.read(1)
      except ValueError as e:
        fileIsEOF = True
        break
      if c == "":
        fileIsEOF = True
        break
      if c == '\n':
        break
      l+=c
    if fileIsEOF or len(l) == 0:
      break
    keyFileIsSuccessfull = False
    try:
      processKeyfilePaths(l)
      keyFileIsSuccessfull = True
    except:
      eprint("Failed processing %s"%(l))
    if not keyFileIsSuccessfull:
      numberOfUnsuccessfullKeyfiles +=1

  sys.stdout.write(json.dumps(keybags,indent=1))
  sys.stdout.flush()
  exit(numberOfUnsuccessfullKeyfiles)
    
