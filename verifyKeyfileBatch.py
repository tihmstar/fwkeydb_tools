import json
import sys
import binascii

import coreFWKEYDBLib
import irecv_device

FAILED_VERIFICATION_ON_EMPTY_KBAG_IS_FATAL = False

class VersionMismatchException(Exception):
    pass

class MissingUrlException(Exception):
    pass

class WrongUrlException(Exception):
    pass

class InfoMismatchException(Exception):
    pass

class BadKeyEntryException(Exception):
  pass

class UnverifiedEntriesException(Exception):
  pass


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def processKeyfilePaths(path):
  with open(path,"rb") as f:
    keysfile = json.loads(f.read())
  version = keysfile["version"]
  if version > coreFWKEYDBLib.CURRENT_KEYFILES_VERSION:
    raise VersionMismatchException("keysfile version is too new!")
  sps = path.split("/")
  pBuild = sps[-1]
  pCPID = sps[-2]
  pProduct = sps[-3]
  eprint("[+] checking %s/%s/%s"%(pProduct,pCPID,pBuild))
  if keysfile["cpid"] != pCPID:
    raise InfoMismatchException("cpid in file doesn't match path")
  if keysfile["ProductBuildVersion"] != pBuild:
    raise InfoMismatchException("ProductBuildVersion in file doesn't match path")
  if keysfile["ProductType"] != pProduct:
    raise InfoMismatchException("ProductType in file doesn't match path")
  if not "urls" in keysfile:
    raise MissingUrlException("Keysfiles does not contain any URLs")

  cpid = int(pCPID, 16)
  bdid = int(keysfile["bdid"], 16)
  product = irecv_device.productForCPIDAndBDID(cpid, bdid)
  if product != pProduct:
    raise InfoMismatchException("ProductType doesn't match cpid/bdid")

  vers = keysfile["ProductVersion"]
  build = keysfile["ProductBuildVersion"]
  train = keysfile.get("BuildTrain", None)

  keys = keysfile["keys"]
  for url in keysfile["urls"]:
    try:
      buildmanifest = coreFWKEYDBLib.getBuildManifest(url)
    except:
      print("[!] Failed to get BuildManifest, retrying by converting from Restore.plist")
      try:
        buildmanifest = coreFWKEYDBLib.makeBuildManifestFromRestoreplistInURL(url)
      except:
        print("[!] Failed to convert Restore.plist to BuildManifest")
        raise
    bvers = buildmanifest["ProductVersion"]
    bbuild = buildmanifest["ProductBuildVersion"]
    if bvers != vers:
      raise WrongUrlException("URL '%s' doesn't match ProductVersion '%s'"%(url,vers))
    if bbuild != build:
      raise WrongUrlException("URL '%s' doesn't match ProductBuildVersion '%s'"%(url,build))
    for bid in buildmanifest["BuildIdentities"]:
      if not coreFWKEYDBLib.isBuildIdentityValidForCPIDAndBDID(buildID=bid, cpid=cpid, bdid=bdid):
        continue
      manifest = bid["Manifest"]
      for elem,mElem in manifest.items():
        if not "Info" in mElem:
          continue
        mInfo = mElem["Info"]
        if not "Path" in mInfo:
          continue
        mFilename = mInfo["Path"]
        if mFilename in keys:
          kElem = keys[mFilename]
          kFilename = kElem["filename"]
          if kFilename != mFilename:
            continue
          kDigests = kElem["digests"]
          mDigest = binascii.hexlify(mElem["Digest"]).decode("UTF-8")
          if not mDigest in kDigests:
            raise BadKeyEntryException("Digest mismatch for file '%s' stored != real ('%s' != '%s')"%(mFilename,kDigests,mDigest))
          eprint("[.] Downloading file '%s'"%(mFilename))
          try:
            data = coreFWKEYDBLib.downloadFileFromFirmware(url, kFilename)
          except:
            eprint("[!] Failed to download '%s' from '%s'"%(kFilename,url))
            continue
          kkbag = kElem["kbag"]
          real_kbag = coreFWKEYDBLib.getKBAGFromFiledata(data)
          if kkbag != real_kbag:
            raise BadKeyEntryException("KBAG mismatch for file '%s' stored != real ('%s' != '%s')"%(mFilename,kkbag,real_kbag))
          dec_iv = kElem.get("iv", None)
          dec_key = kElem.get("key", None)
          if dec_iv != None or dec_iv != None:
            if (not dec_iv and dec_key) or (not dec_key and dec_iv):
              raise BadKeyEntryException("Got only one of (iv,key) but not both!")
            eprint("[.] Testing decryption of file '%s' ... "%(mFilename), end="")
            if not coreFWKEYDBLib.testDecryption(data, dec_iv, dec_key):
              if len(kkbag) or FAILED_VERIFICATION_ON_EMPTY_KBAG_IS_FATAL:
                eprint("FAIL")
                raise BadKeyEntryException("Bad IV/KEY. Decryption failed for file '%s'"%(mFilename))
              else:
                eprint("FAIL but ", end="")
            eprint("OK")
          else:
            eprint("[.] Skipping decryption of file without iv/key '%s'"%(mFilename))
          del keys[mFilename]
  if len(keys):
    raise UnverifiedEntriesException("Failed to validate the following components:",keys.keys())

if __name__ == '__main__':
  f = sys.stdin

  numberOfUnsuccessfullKeyfiles = 0

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
    if fileIsEOF or len(l) == 0:
      break
    keyFileIsSuccessfull = False
    try:
      processKeyfilePaths(l)
      print("[OK] %s"%(l))
      keyFileIsSuccessfull = True
    except VersionMismatchException as e:
      print("[FATAL] %s Version mismatch: %s"%(l,e))
    except MissingUrlException as e:
      print("[ERROR] %s Missing URL: %s"%(l,e))
    except InfoMismatchException as e:
      print("[FATAL] %s Info mismatch: %s"%(l,e))
    except BadKeyEntryException as e:
      print("[FATAL] %s Bad Key Entry: %s"%(l,e))
    except UnverifiedEntriesException as e:
      print("[Error] %s Unverified entries: %s"%(l,e))
    if not keyFileIsSuccessfull:
      numberOfUnsuccessfullKeyfiles +=1

  exit(numberOfUnsuccessfullKeyfiles)
    
