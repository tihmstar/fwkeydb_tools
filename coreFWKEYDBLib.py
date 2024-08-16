import plistlib
from datetime import datetime
import subprocess
import makeBuildManifestFromRestoreplist

CURRENT_KEYFILES_VERSION = "1.0"

class BadImageException(Exception):
  pass

class KeybagException(Exception):
  pass

def getDate():
  return datetime.now().strftime("%FT%TZ")

def isBuildIdentityValidForCPIDAndBDID(buildID, cpid, bdid):
  bid_cpid = int(buildID["ApChipID"],16)
  bid_bdid = int(buildID["ApBoardID"],16)
  return bid_cpid == cpid and bid_bdid == bdid

def downloadFileFromFirmware(url, path):
  p = subprocess.Popen("pzb -g %s -o - %s 2>/dev/null"%(path,url), shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
  output = p.stdout.read()
  if not len(output):
    p = subprocess.Popen("pzb -g AssetData/boot/%s -o - %s 2>/dev/null"%(path,url), shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    output = p.stdout.read()
  if not len(output):
    p = subprocess.Popen("pzb -g AssetData/payload/replace/usr/standalone/update/ramdisk/%s -o - %s 2>/dev/null"%(path,url), shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    output = p.stdout.read()
  return output

def listFilesInUrl(url):
  p = subprocess.Popen("pzb -l %s"%(url), shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
  output = p.stdout.read()
  files = []
  for l in output.decode("UTF-8").split("\n"):
    sps = l.split(" ")
    if len(sps) < 3:
      continue
    if sps[-2] != 'f':
      continue
    files.append(sps[-1])
  return files

def getBuildManifest(url):
  data = downloadFileFromFirmware(url, "BuildManifest.plist")
  if not len(data):
    data = downloadFileFromFirmware(url, "BuildManifesto.plist")
  return plistlib.loads(data)

def getRestoreplist(url):
  data = downloadFileFromFirmware(url, "Restore.plist")
  return plistlib.loads(data)

def makeBuildManifestFromRestoreplistInURL(url):
  data = makeBuildManifestFromRestoreplist.makeBuildManifestFromRestoreplistInURL(url)
  return plistlib.loads(data)

def getKBAGFromIMG4Filedata(data):
  p = subprocess.Popen("img4tool -", shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
  p.stdin.write(data)
  p.stdin.close()
  output = p.stdout.read()
  outputstr = output.decode("UTF-8")
  if not "IM4P:" in outputstr:
    # Maybe not a valid im4p?
    return None
  if "IM4P does not contain KBAG values" in outputstr:
    return ""
  kbs = outputstr.split("KBAG")[1]
  assert("num: 1" in kbs)
  sps = kbs.split("\n")
  iv = sps[2]
  key= sps[3]
  return iv+key

def getKBAGFromIMG3Filedata(data):
  p = subprocess.Popen("img3tool -", shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
  p.stdin.write(data)
  p.stdin.close()
  output = p.stdout.read()
  outputstr = output.decode("UTF-8")
  if not "ParitalDigest: " in outputstr:
    # Maybe not a valid im4p?
    return None
  if "IMG3 does not contain KBAG values" in outputstr:
    return ""
  kbs = outputstr.split("KBAG")[1]
  assert("num: 1" in kbs)
  sps = kbs.split("\n")
  iv = sps[2].replace("\t","").replace(" ","")
  key= sps[3].replace("\t","").replace(" ","")
  return iv+key

def getKBAGFromIMG1Filedata(data):
  p = subprocess.Popen("img1tool -", shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
  p.stdin.write(data)
  p.stdin.close()
  output = p.stdout.read()
  outputstr = output.decode("UTF-8")
  # There is no KBAG, we only care if this is a valid img1 file!
  for l in outputstr.split("\n"):
    if l[0:5] == "magic":
      if ": 8900" in l:
        return ""
  # Not valid img1 file
  return None

def testIMG4Decryption(data, iv, key):
  iv_cmd = ""
  key_cmd = ""
  if iv:
    iv_cmd = (" --iv %s"%(iv))
  if key:
    key_cmd = (" --key %s"%(key))
  p = subprocess.Popen("img4tool%s%s -e -o - -"%(iv_cmd,key_cmd), shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
  p.stdin.write(data)
  p.stdin.close()
  output = p.stdout.read()
  status = p.stderr.read().decode("UTF-8")
  if not "IM4P payload to" in status:
    #Maybe not a valid img4?
    raise BadImageException("Failed to read im4p image")
  firstblock = output[0:16]
  restblocks = output[16:]
  if b"Apple" in restblocks or b"iBoot" in restblocks or b"\x00"*16 in restblocks:
    return True
  return False

def testIMG3Decryption(data, iv, key):
  iv_cmd = ""
  key_cmd = ""
  if iv:
    iv_cmd = (" --iv %s"%(iv))
  if key:
    key_cmd = (" --key %s"%(key))
  p = subprocess.Popen("img3tool%s%s -e -o - -"%(iv_cmd,key_cmd), shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
  p.stdin.write(data)
  p.stdin.close()
  output = p.stdout.read()
  status = p.stderr.read().decode("UTF-8")
  if not "Extracted IMG3 payload to" in status:
    #Maybe not a valid img3?
    raise BadImageException("Failed to read img3 image")
  firstblock = output[0:16]
  restblocks = output[16:]
  if b"Apple" in restblocks or b"iBoot" in restblocks or b"\x00"*16 in restblocks:
    return True
  return False

def testIMG1Decryption(data, iv, key):
  p = subprocess.Popen("img1tool -e -o - -", shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
  p.stdin.write(data)
  p.stdin.close()
  output = p.stdout.read()
  status = p.stderr.read().decode("UTF-8")
  if not "Extracted IMG1 payload to" in status:
    #Maybe not a valid img3?
    raise BadImageException("Failed to read img1 image")
  firstblock = output[0:16]
  restblocks = output[16:]
  if b"Apple" in restblocks or b"iBoot" in restblocks or b"\x00"*16 in restblocks:
    return True
  return False

def getKBAGFromFiledata(data):
  img4ret = getKBAGFromIMG4Filedata(data=data)
  if img4ret != None:
    return img4ret
  img3ret = getKBAGFromIMG3Filedata(data=data)
  if img3ret != None:
    return img3ret
  img1ret = getKBAGFromIMG1Filedata(data=data)
  if img1ret != None:
    return img1ret
  raise KeybagException("Failed to get KBAG from file!")

def testDecryption(data, iv, key):
  try:
    return testIMG4Decryption(data=data, iv=iv, key=key)
  except BadImageException as e:
    pass
  try:
    return testIMG3Decryption(data=data, iv=iv, key=key)
  except BadImageException as e:
    pass
  try:
    return testIMG1Decryption(data=data, iv=iv, key=key)
  except BadImageException as e:
    pass
  raise Exception("Failed to test decryption, no loaders for image")

def getVariantFromBuildIdentity(buildident):
  info = buildident["Info"]
  variant = info["Variant"]
  return variant

def getRamdiskTypeForBuildIdentity(buildident):
  variant = getVariantFromBuildIdentity(buildident).lower()
  if "ipsw" in variant:
    if "erase" in variant:
      return "EraseRamdisk"
    elif "upgrade" in variant:
      return "UpgradeRamdisk"
    else:
      print("ERROR: encountered unexpected ipsw variant '%s'"%(variant))
      assert 0
  else:
    if variant == "Customer Software Update".lower():
      return "OTARamdisk"
    elif variant == "Recovery Customer Install".lower():
      return None
    else:
      print("ERROR: encountered unexpected non-ipsw variant '%s'"%(variant))
      assert 0
