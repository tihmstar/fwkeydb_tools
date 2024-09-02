import sys
import os
import json
import binascii

import moduleDecryptor 
import coreFWKEYDBLib
import irecv_device


#RUN: ./listURLsForDevice.sh iPhone7,2 | python decryptFirmwareBatch.py -

SKIP_EXISTING_KEYFILES = False
BAD_KEYS_ARE_FATAL=True
CPID_DYNAMIC_BLACKLIST_RETRIES_COUNT = 3

KEYS_DIRECTORY = "keys/"

processedFilesHashes = {}
cpid_dynamic_blacklist = {}

def processBuildID(url, buildID, build, vers):
  global processedFilesHashes
  date = coreFWKEYDBLib.getDate()
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
    if not "Digest" in cVal:
      continue
    if cKey == "OS":
      continue
    cKeySecondName = None
    curElemIsRamdisk = False
    if cKey == "RestoreRamDisk":
      cKeySecondName = coreFWKEYDBLib.getRamdiskTypeForBuildIdentity(buildID)
      curElemIsRamdisk = True
    digest = cVal["Digest"]
    filename = cVal["Info"]["Path"]
    kbag = None
    iv = None
    key = None
    variant = coreFWKEYDBLib.getVariantFromBuildIdentity(buildID)
    elemKey = filename
    digestPrintable = binascii.hexlify(digest).decode("UTF-8")
    if digest in processedFilesHashes:
      ikk = processedFilesHashes[digest]
      iv = ikk["iv"]
      key = ikk["key"]
      kbag = ikk["kbag"]
      if iv and key:
          print("[.] cached component '%s' with iv '%s' key '%s'"%(cKey,iv,key))
          hasAnyKeys = True
    else:
      print("[.] downloading component '%s' (%s)"%(cKey,filename))
      data = coreFWKEYDBLib.downloadFileFromFirmware(url, filename)
      if not len(data):
        print("[!] Failed downloading component '%s' (%s), skipping component!"%(cKey,filename))
        continue
      try:
        kbag = coreFWKEYDBLib.getKBAGFromFiledata(data)
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
          needsAnyKeys = True
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
        assert not BAD_KEYS_ARE_FATAL
        if iv or key:
          iv = None
          key = None
      else:
        if iv and key:
          print("[.] decryptd component '%s' with iv '%s' key '%s'"%(cKey,iv,key))
          hasAnyKeys = True

      processedFilesHashes[digest] = {
        "iv": iv,
        "key": key,
        "kbag": kbag,
      }
    elemValue = keys.get(elemKey, {})
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

    if True:
      old_elemValue = keys.get(elemKey, {})
      old_date = old_elemValue.get("date", None)
      elemValue["date"] = old_date
      if old_elemValue == elemValue:
        #Don't just update the date
        continue

    elemValue["date"] = date
    keys[elemKey] = elemValue
    if iv != None and key != None:
      keys[elemKey]["iv"] = iv
      keys[elemKey]["key"] = key
    keysfile["keys"] = keys

  if url[0:4] != "http":
    print("[!] Skipping non-remote url '%s'"%(url))
  else:
    if not isOta or hasAnyRamdisk:
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
      print("[*] saved keysfile to '%s'"%(pathkeysfile))
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

    
if __name__ == '__main__':
  f = None
  # if len(sys.argv) < 2:
  #   print("Usage: echo <url> | %s"%(sys.argv[0]))

  moduleDecryptor.init()
  f = sys.stdin

  fileIsEOF = False
  while True:
    l = ""
    while not f.closed:
      c = f.read(1)
      if c == "":
        fileIsEOF = True
        break
      if c == '\n':
        break
      l+=c
    if fileIsEOF or f.closed:
      break
    processUrl(l)