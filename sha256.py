from hashlib import sha256
import sys, getopt

Usage = """
python sha256.py [-c <checksum>] <file>
"""

opts, args = getopt.getopt(sys.argv[1:], "c:")
opts = dict(opts)

if not args:
    print(Usage)
    sys.exit(2)

f = open(args[0], "rb")
h = sha256()
data = f.read(8*1024)
while data:
    h.update(data)
    data = f.read(8*1024)
    
digest = h.hexdigest()

if "-c" in opts:
    sys.exit(0 if digest == opts["-c"] else 1)
else:
    print (digest)