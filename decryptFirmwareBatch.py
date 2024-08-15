import sys
import os
import json
import binascii

import moduleDecryptor 
import coreFWKEYDBLib
import irecv_device


#RUN: ./listURLsForDevice.sh iPhone7,2 | python decryptFirmwareBatch.py -


KEYS_DIRECTORY = "keys/"
SKIP_EXISTING_KEYFILES = False

processedFilesHashes = {}


def processBuildID(url, buildID, build, vers):
  global processedFilesHashes
  date = coreFWKEYDBLib.getDate()
  cpid = int(buildID["ApChipID"],16)
  bdid = int(buildID["ApBoardID"],16)
  product = irecv_device.productForCPIDAndBDID(cpid,bdid)
  pathkeysdirs = KEYS_DIRECTORY + "firmware/%s/0x%x/"%(product,cpid)
  pathkeysfile = pathkeysdirs + build
  keysfile = {}
  hasAnyKeys = False
  hasAnyRamdisk = False
  isOta = url[-4:] == ".zip"
  needsAnyKeys = False
  f = None
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
      hasAnyKeys = True
    else:
      print("[.] downloading component '%s' (%s)"%(cKey,filename))
      data = coreFWKEYDBLib.downloadFileFromFirmware(url, filename)
      assert (len(data))
      kbag = coreFWKEYDBLib.getKBAGFromFiledata(data)
      if curElemIsRamdisk:
        hasAnyRamdisk = True
      if len(kbag):
        needsAnyKeys = True
        kiv = moduleDecryptor.decryptKBAG(component=cKey, cpid=cpid, kbag=kbag)
        if kiv:
          iv,key = kiv
        else:
          print("[!] Failed to decrypt component '%s'"%(cKey))
        if iv or key:
          if not coreFWKEYDBLib.testDecryption(data=data, iv=iv, key=key):
            print("[!] Failed verifying decrypted IV/KEY for component '%s'"%(cKey))
            assert 0
            iv = None
            key = None
          else:
            hasAnyKeys = True
      else:
        iv = ""
        key = ""
      processedFilesHashes[digest] = {
        "iv": iv,
        "key": key,
        "kbag": kbag,
      }
    elemValue = keys.get(elemKey, {})
    elemValue["kbag"] = kbag
    elemValue["filename"] = filename
    elemValue["date"] = date
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
    keys[elemKey] = elemValue
    if iv != None and key != None:
      keys[elemKey]["iv"] = iv
      keys[elemKey]["key"] = key
    keysfile["keys"] = keys

  if not isOta or hasAnyRamdisk:
    urls = keysfile.get("urls", [])
    if not url in urls:
      urls.append(url)
    keysfile["urls"] = urls
  else:
    print("[!] Skipping OTA url without ramdisk '%s'"%(url))
  if hasAnyKeys or not needsAnyKeys:
    try:
      os.makedirs(pathkeysdirs)
    except FileExistsError:
      pass
    with open(pathkeysfile,"wb") as f:
      f.write(bytes(json.dumps(keysfile, indent=1), "UTF-8"))
      print("[*] saved keysfile to '%s'"%(pathkeysfile))
  else:
    print("[-] Skipping file without any decrypted keys '%s'"%(pathkeysfile))

def processUrl(url):
  print("[+] Processing '%s'"%(url))
  try:
    buildmanifest = coreFWKEYDBLib.getBuildManifest(url)
  except:
    print("Failed to get BuildManifest from url '%s'"%(url))
    return
  build = buildmanifest["ProductBuildVersion"]
  vers = buildmanifest["ProductVersion"]
  for buildID in buildmanifest["BuildIdentities"]:
    processBuildID(url, buildID, build, vers)

    
if __name__ == '__main__':
  f = None
  if len(sys.argv) < 2:
    print("Usage: %s <links_file.txt>"%(sys.argv[0]))

  moduleDecryptor.init()

  infile = sys.argv[1]
  if infile == "-":
    f = sys.stdin
  else:
    f = open(infile, "r")

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