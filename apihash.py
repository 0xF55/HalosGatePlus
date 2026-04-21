import pefile
import sys
import os

try:
    dllpath = sys.argv[1]
except:
    print("Usage: %s <dllpath>" % sys.argv[0])
    exit(0)

def fnva(s: str) -> int:
    hash_val = 0x811C9DC5  
    prime = 0x01000193

    for c in s.encode():
        hash_val ^= c
        hash_val = (hash_val * prime) & 0xFFFFFFFF

    return hash_val

pe = pefile.PE(dllpath)

output = os.path.splitext(os.path.basename(dllpath))[0] + "_hashs.h"

with open(output,"w") as f:

    f.write("// This file is generated using apihash.py. credits: 0xf55\n\n\n")

    if hasattr(pe,"DIRECTORY_ENTRY_EXPORT"):

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            try:
                name = exp.name.decode()
                if name:
                    f.write("#define hash%s 0x%x\n" % (name,fnva(name)))
            except:
                pass
    else:
        print("No exports found.")

