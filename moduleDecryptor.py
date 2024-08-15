import os
import importlib.util
import sys
import string
import secrets


MODULES_DIRECTORY = "modulesDecryption"
modules = []

def gensym(length=32, prefix="gensym_"):
    """
    generates a fairly unique symbol, used to make a module name,
    used as a helper function for load_module

    :return: generated symbol
    """
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits
    symbol = "".join([secrets.choice(alphabet) for i in range(length)])

    return prefix + symbol


def load_module(source, module_name=None):
    """
    reads file source and loads it as a module

    :param source: file to load
    :param module_name: name of module to register in sys.modules
    :return: loaded module
    """

    if module_name is None:
        module_name = gensym()

    spec = importlib.util.spec_from_file_location(module_name, source)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)

    return module

def init():
  global modules
  for f in os.listdir(MODULES_DIRECTORY):
    mpath = MODULES_DIRECTORY+"/"+f
    mname = f[0:-3]
    if not os.path.isfile(mpath):
      continue
    if f[-3:] != ".py":
      continue
    m = load_module(mpath)
    modules.append(m)
    print("[*] Imported decryption module '%s'"%(mname))

def decryptKBAG(component, cpid, kbag):
  for m in modules:
    retval = m.decryptKBAG(component, cpid, kbag)
    if retval:
      return retval
  return None