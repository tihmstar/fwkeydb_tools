from Crypto.Cipher import AES
import binascii
import sys

PSEUDO_GID = binascii.unhexlify("5f650295e1fffc97ce77abd49dd955b3")


"""
https://theapplewiki.com/wiki/Decrypting_Firmwares

S5L8900
With the 3.0 Golden Master (7A341) and 3.0.1, Apple messed up and, 
instead of using the application processor-specific GID Key, 
used a pseudo-GID of 5f650295e1fffc97ce77abd49dd955b3 to encrypt the KBAG. 
This makes obtaining the keys for this version dead simple. 
Once you have decrypted the KBAG, decryption using the keys in it is the same as above. 
"""

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def decryptKBAG(component, cpid, kbag):
  if cpid != 0x8900:
    return None
  
  cipher = AES.new(PSEUDO_GID, AES.MODE_CBC, b"\x00"*16)
  eprint("Decrypting: %s"%kbag)
  bdecKB = cipher.decrypt(binascii.unhexlify(kbag))
  decKB = binascii.hexlify(bdecKB).decode("UTF-8")
  iv = decKB[0:16*2]
  key = decKB[16*2:48*2]
  eprint("Got: %s"%iv+key)
  return iv,key
