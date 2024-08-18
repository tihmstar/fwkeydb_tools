from Crypto.Hash import SHA1
import copy
import coreFWKEYDBLib
import plistlib
import sys


def makeBuildManifestFromRestoreplistInURL(url):
  restoreplist = coreFWKEYDBLib.getRestoreplist(url)
  deviceMap = restoreplist["DeviceMap"]
  boardConfig = None
  bdid = 0
  cpid = 0x8900
  for dm in deviceMap:
    c_bc = dm["BoardConfig"]
    if c_bc != "s5l8900xall":
      boardConfig = c_bc
      bdid = dm.get("BDID", 0)
      cpid = dm.get("CPID", 0x8900)
      if bdid != 0:
        break
  if not boardConfig:
    raise Exception("Failed to get boarconfig")
  p_all_flash = ("Firmware/all_flash/all_flash.%s.%s" % (boardConfig,"production"))
  manifest = coreFWKEYDBLib.downloadFileFromFirmware(url, p_all_flash + "/manifest")
  p_manifest = {}
  for mf in manifest.decode("UTF-8").split("\n"):
    if not len(mf):
      continue
    mf_shortname = mf.split(".")[0]
    mf_path = p_all_flash + "/" + mf
    data = coreFWKEYDBLib.downloadFileFromFirmware(url, mf_path)
    h = SHA1.new()
    h.update(data)
    hash = h.digest()
    p_info = {
      "Info": {
        "Path" : mf_path
      },
      "Digest" : hash
    }
    p_manifest[mf_shortname] = p_info

  if True: #add iBSS
    mf_shortname = "iBSS"
    mf_path = ("Firmware/dfu/iBSS.%s.%s.dfu"%(boardConfig, "RELEASE"))
    data = coreFWKEYDBLib.downloadFileFromFirmware(url, mf_path)
    h = SHA1.new()
    h.update(data)
    hash = h.digest()
    p_info = {
      "Info": {
        "Path" : mf_path
      },
      "Digest" : hash
    }
    p_manifest[mf_shortname] = p_info

  while True: #add iBEC
    mf_shortname = "iBEC"
    mf_path = ("Firmware/dfu/iBEC.%s.%s.dfu"%(boardConfig, "RELEASE"))
    data = coreFWKEYDBLib.downloadFileFromFirmware(url, mf_path)
    if not len(data):
      # iOS 1 doesn't have iBEC
      break
    h = SHA1.new()
    h.update(data)
    hash = h.digest()
    p_info = {
      "Info": {
        "Path" : mf_path
      },
      "Digest" : hash
    }
    p_manifest[mf_shortname] = p_info
    break

  if True: #add kernel
    krcs = restoreplist["RestoreKernelCaches"]
    mf_path = list(krcs.values())[0]
    mf_shortname = "KernelCache"
    data = coreFWKEYDBLib.downloadFileFromFirmware(url, mf_path)
    h = SHA1.new()
    h.update(data)
    hash = h.digest()
    p_info = {
      "Info": {
        "Path" : mf_path
      },
      "Digest" : hash
    }
    p_manifest[mf_shortname] = p_info

  p_eraseManifest = None
  p_updateManifest = None

  if True: #add erase ramdisk
    krcs = restoreplist["RestoreRamDisks"]
    mf_path = krcs["User"]
    mf_shortname = "RestoreRamDisk"
    data = coreFWKEYDBLib.downloadFileFromFirmware(url, mf_path)
    h = SHA1.new()
    h.update(data)
    hash = h.digest()
    p_info = {
      "Info": {
        "Path" : mf_path
      },
      "Digest" : hash
    }
    p_eraseManifest = copy.copy(p_manifest)
    p_eraseManifest[mf_shortname] = p_info

  while True: #add update ramdisk
    krcs = restoreplist["RestoreRamDisks"]
    if not "Update" in krcs:
      break
    mf_path = krcs["Update"]
    mf_shortname = "RestoreRamDisk"
    data = coreFWKEYDBLib.downloadFileFromFirmware(url, mf_path)
    h = SHA1.new()
    h.update(data)
    hash = h.digest()
    p_info = {
      "Info": {
        "Path" : mf_path
      },
      "Digest" : hash
    }
    p_updateManifest = copy.copy(p_manifest)
    p_updateManifest[mf_shortname] = p_info
    break

  p_buildidInfo = {
    "BuildNumber" : restoreplist["ProductBuildVersion"],
    "DeviceClass" : boardConfig
  }

  p_erasebuildidInfo = None
  p_updatebuildidInfo = None

  p_erasebuildidInfo = copy.copy(p_buildidInfo)
  p_erasebuildidInfo["RestoreBehavior"] = "Erase"
  p_erasebuildidInfo["Variant"] = "Customer Erase Install (IPSW)"

  if p_updateManifest:
    p_updatebuildidInfo = copy.copy(p_buildidInfo)
    p_updatebuildidInfo["RestoreBehavior"] = "Update"
    p_updatebuildidInfo["Variant"] = "Customer Upgrade Install (IPSW)"

  p_bid = {
    "ApBoardID" : hex(bdid),
    "ApChipID" : hex(cpid),
  }
  p_bid_erase = None
  p_bid_update = None

  p_bid_erase = copy.copy(p_bid)
  p_bid_erase["Info"] = p_erasebuildidInfo
  p_bid_erase["Manifest"] = p_eraseManifest

  p_BuildIdentities = [p_bid_erase]

  if p_updatebuildidInfo:
    p_bid_update = copy.copy(p_bid)
    p_bid_update["Info"] = p_updatebuildidInfo
    p_bid_update["Manifest"] = p_updateManifest
    p_BuildIdentities.append(p_bid_update)


  ret = {
    "BuildIdentities" : p_BuildIdentities,
    "ProductBuildVersion" : restoreplist["ProductBuildVersion"],
    "ProductVersion" : restoreplist["ProductVersion"],
  }
  return plistlib.dumps(ret)



if __name__ == '__main__':
  bm = makeBuildManifestFromRestoreplistInURL(sys.argv[1])
  print(bm.decode("UTF-8"))