from hashlib import sha256
import sys, getopt, os
from datetime import datetime

Usage = """
python sha256.py <file> ...                 - calculate checksum for one or more files
python sha256.py -c <hex checksum> <file>   - check checksum for a file
python sha256.py -c <file with paths and checksums>   - check checksum for multiple files
"""

def checksum(path):
    f = open(path, "rb")
    h = sha256()
    data = f.read(8*1024)
    while data:
        h.update(data)
        data = f.read(8*1024)
    
    return h.hexdigest()

opts, args = getopt.getopt(sys.argv[1:], "c:")
opts = dict(opts)

if not args and not "-c" in opts:
    print(Usage)
    sys.exit(2)

status = 0

if not args:
    checksums = {}      # file -> checksum      -- Same file may appear multiple times in the list. Use the last checksum
    lines = open(opts["-c"], "r").readlines()

    for line in lines:
        line = line.strip()
        if line and not line[0] == "#":
            path, c0 = line.split(None, 1)
            checksums[path] = c0.lower()

    for path, c0 in checksums.items():
        if not os.path.isfile(path):
            print(f"{path}:\tnot found")
        else:
            c1 = checksum(path).lower()
            if c1 != c0:
                print(f"{path}:\tchecksum mismatch")
                status = 1
            else:
                print(f"{path}:\tverified")
                
                
elif len(args) == 1:
    c1 = checksum(args[0]).lower()
    if "-c" in opts:
        c0 = opts["-c"].lower()
        if c0 != c1:
            print("checksum mismatch for", args[0])
            status = 1
    else:
        print(c1)
else:
    now = datetime.utcnow()
    print("# use 'python sha256.py -c <this file>' to verify ")
    print("#", now, "UTC")
    for path in args:
        c1 = checksum(path).lower()
        print(f"{path}\t{c1}")
    
sys.exit(status)
