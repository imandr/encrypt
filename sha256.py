from hashlib import sha256
import sys, getopt, os
from datetime import datetime

Usage = """
python sha256.py [-u <checksums file>] [<file> ...]  - calculate checksum for one or more files
    -u                                               - update checksums of the given files
python sha256.py -v <checksums file>                 - check checksum for multiple files
python sha256.py -c <hex checksum> <file>            - check checksum for a file
"""

def checksum(path):
    f = open(path, "rb")
    h = sha256()
    data = f.read(8*1024)
    while data:
        h.update(data)
        data = f.read(8*1024)
    
    return h.hexdigest()

def read_checksums(checksums_file):
    checksums = {}      # file -> checksum      -- Same file may appear multiple times in the list. Use the last checksum

    if os.path.isfile(checksums_file):
        with open(checksums_file, "r") as f:
            lines = list(f.readlines())

        for line in lines:
            line = line.strip()
            if line and not line[0] == "#":
                path, c0 = line.split(None, 1)
                checksums[path] = c0.lower()
    return checksums

def verify(checksums_file):
    checksums = read_checksums(checksums_file)
    changed = []
    missing = []
    for path, c_old in checksums.items():
        if not os.path.isfile(path):
            missing.append(path)
        else:
            c = checksum(path)
            if c_old != c:
                changed.append((path, c_old, c))
    return changed, missing
    
def update(checksums_file, paths):
    checksums = read_checksums(checksums_file)
    paths = set(paths) | set(checksums.keys())
    for path in paths:
        checksums[path] = checksum(path)
    write_checksums(checksums, open(checksums_file, "w"))
    
def write_checksums(checksums, out_file):
    now = datetime.utcnow()
    print("# use 'python sha256.py -c <this file>' to verify ", file=out_file)
    print("#", now, "UTC", file=out_file)
    for path, checksum in sorted(checksums.items()):
        print(f"{path}\t{checksum}", file=out_file)

opts, args = getopt.getopt(sys.argv[1:], "c:u:v:h?")
opts = dict(opts)

if "-h" in opts or "-?" in opts or (not opts and not args):
    print(Usage)
    sys.exit(2)

status = 0

if "-v" in opts:
    changed, missing = verify(opts["-v"])
    for path, old_c, new_c in changed:
        print("changed:", path)
        status = 1
    for path in missing:
        print("missing:", path)
        status = 1

elif "-u" in opts:
    update(opts["-u"], args)
    
elif "-c" in opts:
    c = opts["-c"]
    if c != checksum(args[0]):
        print("changed:", args[0])
        status = 1
else:
    checksums = {}
    for path in args:
        checksums[path] = checksum(path)
    write_checksums(checksums, sys.stdout)

sys.exit(status)
