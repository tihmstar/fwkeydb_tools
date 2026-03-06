import sys
import os
import json
import binascii
import copy
import hashlib

import moduleDecryptor 
import coreFWKEYDBLib
import irecv_device


#RUN: ./listURLsForDevice.sh iPhone7,2 | python decryptFirmwareBatch.py -

SKIP_EXISTING_KEYFILES = False
BAD_KEYS_ARE_FATAL = True
FAILED_VERIFICATION_ON_EMPTY_KBAG_IS_FATAL = False
CPID_DYNAMIC_BLACKLIST_RETRIES_COUNT = 3

KEYS_DIRECTORY = "keys/"

processedFilesHashes = {}
cpid_dynamic_blacklist = {}

#env set vars
FIRMWARE_CACHE_PATH = None
IRGNORE_MISSING_RAMDISK = False

def processBuildID(url, buildID, build, vers):
  global processedFilesHashes
  cpid = int(buildID["ApChipID"],16)
  bdid = int(buildID["ApBoardID"],16)
  try:
    product = irecv_device.productForCPIDAndBDID(cpid,bdid)
  except Exception as e:
    print("[!] Unknown device exception:",e)
    return
  pathkeysdirs = KEYS_DIRECTORY + "firmware/%s/0x%x/"%(product,cpid)
  pathkeysfile = pathkeysdirs + build
  keysfile = {}
  hasAnyKeys = False
  hasAnyRamdisk = False
  isOta = url[-4:] == ".zip"
  needsAnyKeys = False
  f = None
  cpid_decrypt_attempt = cpid_dynamic_blacklist.get(cpid, 0)
  if CPID_DYNAMIC_BLACKLIST_RETRIES_COUNT and cpid_decrypt_attempt > CPID_DYNAMIC_BLACKLIST_RETRIES_COUNT:
    print("[!] Skipping attempt to generate keyfile without available decryptor for cpid '%s'"%(hex(cpid)))
    return

  try:
    f = open(pathkeysfile,"rb")
  except FileNotFoundError:
    pass
  if f != None:
    try:
      keysfile = json.loads(f.read())
      earlyKeysVersion = keysfile.get("version", "")
      if SKIP_EXISTING_KEYFILES and earlyKeysVersion == coreFWKEYDBLib.CURRENT_KEYFILES_VERSION:
        print("[!] Skipping processing of existing keysfile '%s'"%(pathkeysfile))
        return

    except json.decoder.JSONDecodeError:
      pass
    f.close()
  info = buildID["Info"]
  manifest = buildID["Manifest"]
  assert info["BuildNumber"] == build

  keysVersion = keysfile.get("version", coreFWKEYDBLib.CURRENT_KEYFILES_VERSION)
  assert keysVersion <= coreFWKEYDBLib.CURRENT_KEYFILES_VERSION

  keysfile["version"] = keysVersion

  keysfile["ProductType"] = product
  if "BuildTrain" in info:
    keysfile["BuildTrain"] = info["BuildTrain"]
  keysfile["ProductBuildVersion"] = build
  keysfile["ProductVersion"] = vers
  keysfile["cpid"] = hex(cpid)
  keysfile["bdid"] = hex(bdid)

  keys = keysfile.get("keys", {})
  for cKey,cVal in manifest.items():
    if not "Digest" in cVal and not "PartialDigest" in cVal:
      continue
    if cKey == "OS":
      continue
    cKeySecondName = None
    curElemIsRamdisk = False
    if cKey == "RestoreRamDisk":
      cKeySecondName = coreFWKEYDBLib.getRamdiskTypeForBuildIdentity(buildID)
      curElemIsRamdisk = True
    if "Digest" in cVal:
      digest = cVal["Digest"]
    else:
      digest = None
    filename = cVal["Info"]["Path"]
    kbag = None
    iv = None
    key = None
    variant = coreFWKEYDBLib.getVariantFromBuildIdentity(buildID)
    elemKey = filename
    if digest:
      digestPrintable = binascii.hexlify(digest).decode("UTF-8")
    if digest and digest in processedFilesHashes and (hasAnyRamdisk or cKey != "RestoreRamDisk"):
      ikk = processedFilesHashes[digest]
      iv = ikk["iv"]
      key = ikk["key"]
      kbag = ikk["kbag"]
      print("[.] cached component '%s' with iv '%s' key '%s' kbag '%s'"%(cKey,iv,key,kbag))
      if len(kbag):
        needsAnyKeys = True
      if iv and key:
        hasAnyKeys = True
    else:
      print("[.] downloading component '%s' (%s)"%(cKey,filename))
      data = coreFWKEYDBLib.downloadFileFromFirmware(url, filename, cKey)
      if not len(data):
        print("[!] Failed downloading component '%s' (%s), skipping component!"%(cKey,filename))
        continue
      if not digest:
        digest = hashlib.sha1(data).digest()
        digestPrintable = binascii.hexlify(digest).decode("UTF-8")
      try:
        kbag = coreFWKEYDBLib.getKBAGFromFiledata(data)
        if len(kbag):
          needsAnyKeys = True
      except coreFWKEYDBLib.KeybagException:
        print("[!] Failed to get keybag for component '%s' (%s), skipping component!"%(cKey,filename))
        continue
      if curElemIsRamdisk:
        hasAnyRamdisk = True

      decryptionWasSuccessful = False
      decryptModuleIdx = -1;
      while decryptModuleIdx != None:
        decryptModuleIdx += 1
        if len(kbag):
          kiv,decryptModuleIdx = moduleDecryptor.decryptKBAG(component=cKey, cpid=cpid, kbag=kbag, startModuleIndex=decryptModuleIdx)
          if kiv:
            iv,key = kiv
        else:
          decryptModuleIdx = None
          iv = ""
          key = ""
        if coreFWKEYDBLib.testDecryption(data=data, iv=iv, key=key):
          decryptionWasSuccessful = True
          break

      if (iv != None or key != None) and not decryptionWasSuccessful:
        print("[!] Failed to decrypt component '%s'"%(cKey))
        if not hasAnyKeys:
          continue
        assert not BAD_KEYS_ARE_FATAL or (not FAILED_VERIFICATION_ON_EMPTY_KBAG_IS_FATAL and not len(kbag))
        iv = None
        key = None
      else:
        if iv and key:
          print("[.] decrypted component '%s' with iv '%s' key '%s'"%(cKey,iv,key))
          hasAnyKeys = True

      processedFilesHashes[digest] = {
        "iv": iv,
        "key": key,
        "kbag": kbag,
      }
    elemValue = copy.copy(keys.get(elemKey, {}))
    elemValue["kbag"] = kbag
    elemValue["filename"] = filename
    elemDigests = elemValue.get("digests", [])
    if not digestPrintable in elemDigests:
        elemDigests.append(digestPrintable)
    elemValue["digests"] = elemDigests
    elemNames = elemValue.get("names", [])

    if not cKey in elemNames:
        elemNames.append(cKey)
    if cKeySecondName and not cKeySecondName in elemNames:
        elemNames.append(cKeySecondName)
    elemValue["names"] = elemNames

    elemVariants = elemValue.get("variants", [])
    if not variant in elemVariants:
        elemVariants.append(variant)
    elemValue["variants"] = elemVariants

    if iv != None and key != None:
      elemValue["iv"] = iv
      elemValue["key"] = key

    if True:
      old_elemValue = keys.get(elemKey, {})
      old_date = old_elemValue.get("date", None)
      elemValue["date"] = old_date
      if old_elemValue == elemValue:
        #Don't just update the date
        continue

    elemValue["date"] = coreFWKEYDBLib.getDate()
    keys[elemKey] = elemValue
    keysfile["keys"] = keys

  if url[0:4] != "http":
    print("[!] Skipping non-remote url '%s'"%(url))
  else:
    if not isOta or hasAnyRamdisk or IRGNORE_MISSING_RAMDISK:
      urls = keysfile.get("urls", [])
      if not url in urls:
        urls.append(url)
      keysfile["urls"] = urls
    else:
      print("[!] Skipping OTA url without ramdisk '%s'"%(url))
  if hasAnyKeys or not needsAnyKeys and "keys" in keysfile:
    try:
      os.makedirs(pathkeysdirs)
    except FileExistsError:
      pass
    with open(pathkeysfile,"wb") as f:
      f.write(bytes(json.dumps(keysfile, indent=1), "UTF-8"))
      if hasAnyKeys:
        print("[*] saved keysfile with keys to '%s'"%(pathkeysfile))
      else:
        print("[*] saved keysfile without keys to '%s'"%(pathkeysfile))
  else:
    print("[-] Skipping file without any decrypted keys '%s'"%(pathkeysfile))
    cpid_dynamic_blacklist[cpid] = cpid_decrypt_attempt + 1

def processUrl(url):
  print("[+] Processing '%s'"%(url))
  buildmanifest = None
  try:
    buildmanifest = coreFWKEYDBLib.getBuildManifest(url)
  except:
    print("[!] Failed to get BuildManifest, retrying by converting from Restore.plist")
    try:
      buildmanifest = coreFWKEYDBLib.makeBuildManifestFromRestoreplistInURL(url)
    except:
      print("[!] Failed to convert Restore.plist to BuildManifest")

  if not buildmanifest:
    print("[!] Failed to get BuildManifest, skipping url '%s'"%(url))
    return
  build = buildmanifest["ProductBuildVersion"]
  vers = buildmanifest["ProductVersion"]
  for buildID in buildmanifest["BuildIdentities"]:
    processBuildID(url, buildID, build, vers)


def checkenv(var):
  v = os.getenv(var)
  if not v:
    return False
  try:
    if int(v):
      print("%s=True"%(var))
      return True
  except:
    pass
  return False

def readenv(var):
  v = os.getenv(var)
  if not v:
    return None
  print("%s='%s'"%(var,v))
  return v

if __name__ == '__main__':
  f = None
  # if len(sys.argv) < 2:
  #   print("Usage: echo <url> | %s"%(sys.argv[0]))

  moduleDecryptor.init()
  f = sys.stdin

  IRGNORE_MISSING_RAMDISK = checkenv("IRGNORE_MISSING_RAMDISK")
  FIRMWARE_CACHE_PATH = readenv("FIRMWARE_CACHE_PATH")
  if FIRMWARE_CACHE_PATH != None:
    if FIRMWARE_CACHE_PATH[-1] != '/':
      FIRMWARE_CACHE_PATH += '/'
    coreFWKEYDBLib.setFirmwareCachePath(FIRMWARE_CACHE_PATH)

  fileIsEOF = False
  while True:
    l = ""
    while True:
      c = f.read(1)
      if c == "":
        fileIsEOF = True
        break
      if c == '\n':
        break
      l+=c
    if fileIsEOF:
      break
    processUrl(l)