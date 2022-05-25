import hmac, getopt, sys, hashlib
from lib import prompt_password, hash_password, get_key

Usage = """
python signature.py [options] <input_file>
    -w <password>                       # password will be hashed into a key
    -w @<file with one line password>
    -k <hex key>
    -k @<file with binary or hex key>
    -v <signature>                      - verify signature
    -v @<file with signature>           - verify signature
"""

def signature(path, key):
    h = hmac.new(key, digestmod="sha256")
    with open(path, "rb") as f:
        eof = False
        while not eof:
            data = f.read(128*1024)
            if not data:
                eof = True
            else:
                h.update(data)
    return h.digest()

def get_signature(param):
    if param[0] == '@':
        s = open(param[1:], "r").read().strip()
    else:
        s = param
    return bytes.fromhex(s)

def verify(path, key, s):
    if isinstance(s, str):
        s = bytes.fromhex(s)
    d = signature(path, key)
    return s == d

opts, args = getopt.getopt(sys.argv[1:], "w:k:v:")
opts = dict(opts)

key = get_key(opts, "-v" not in opts)
if "-v" in opts:
    target_signature = opts["-v"]
    if target_signature[0] == "@":
        target_signature = open(target_signature[1:], "r").read().strip()
    target_signature = bytes.fromhex(target_signature)
    match = signature(args[0], key) == target_signature
    if not match:
        print("mismatch")
        sys.exit(1)
    else:
        sys.exit(0)

else:
    print(signature(args[0], key).hex())
    


