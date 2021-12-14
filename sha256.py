from hashlib import sha256
import sys, getopt

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
    lines = open(opts["-c"], "r").readlines()
    for line in lines:
        line = line.strip()
        if line and not line[0] == "#":
            path, c0 = line.split(None, 1)
            c0 = c0.lower()
            c1 = checksum(path).lower()
            if c1 != c0:
                print("checksum mismatch for", path)
                status = 1
                
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
    print("# use 'python sha256.py -c <this file>' to verify ")
    for path in args:
        c1 = checksum(path).lower()
        print(f"{path}\t{c1}")
    
sys.exit(status)
