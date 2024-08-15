from Crypto.Cipher import AES
import binascii
import sys

A4_GID_KEY = binascii.unhexlify("e77f3e9c5e6c00086aa7b68e58994a639cc360d6027c90b53eb8b3b015f72f56")

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def decryptKBAG(component, cpid, kbag):
  if cpid != 0x8930:
    return None
  
  cipher = AES.new(A4_GID_KEY, AES.MODE_CBC, b"\x00"*16)
  eprint("Decrypting: %s"%kbag)
  bdecKB = cipher.decrypt(binascii.unhexlify(kbag))
  decKB = binascii.hexlify(bdecKB).decode("UTF-8")
  iv = decKB[0:16*2]
  key = decKB[16*2:48*2]
  eprint("Got: %s"%iv+key)
  return iv,key
