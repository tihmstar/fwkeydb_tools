import plistlib
from datetime import datetime
import subprocess


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

def getBuildManifest(url):
  data = downloadFileFromFirmware(url, "BuildManifest.plist")
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

def testIMG4Decryption(data, iv, key):
  p = subprocess.Popen("img4tool --iv %s --key %s -e -o - -"%(iv,key), shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
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
  p = subprocess.Popen("img3tool --iv %s --key %s -e -o - -"%(iv,key), shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
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

def getKBAGFromFiledata(data):
  img4ret = getKBAGFromIMG4Filedata(data=data)
  if img4ret != None:
    return img4ret
  img3ret = getKBAGFromIMG3Filedata(data=data)
  if img3ret != None:
    return img3ret
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
