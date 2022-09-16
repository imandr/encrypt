from getpass import getpass
from hashlib import sha256
import os

KEY_SIZE = 32

def to_bytes(x, encoding="utf-8"):
    if isinstance(x, str):
        x = x.encode(encoding)
    assert isinstance(x, bytes)
    return x
    
def to_str(x, encoding="utf-8"):
    if isinstance(x, bytes):
        x = x.decode(encoding)
    assert isinstance(x, str)
    return x

def hash_password(password):
    password = to_bytes(password)
    hash = sha256()
    hash.update(password)
    key = hash.digest()[:KEY_SIZE]
    #print("hashed password:", key.hex())
    return key

def wipe(path, passes=5):
    size = os.path.getsize(path)
    f = open(path, "wb+")
    block_size = 1024
    patterns = [b'0xff'*block_size, b'0x00'*block_size, b'0xf0'*block_size, b'0x0f'*block_size]
    print("wiping    ", path, "...")
    for ipass in range(passes):
        f.seek(0, 0)
        pattern = patterns[ipass % len(patterns)]
        for off in range(0, size, block_size):
            l = min(block_size, size-off)
            if l > 0:
                f.write(pattern[:l])
        f.flush()
    os.remove(path)

def prompt_password(verify=True):
    password =  getpass("Password:")
    if verify:
        password1 = getpass("Verify  :")
        if password != password1:
            print("Password mismatch")
            sys.exit(2)
    return password
    
def get_key(opts, verify_password=True):
    if "-w" in opts:
        pwd = opts["-w"]
        if pwd[0] == '@':
            pwd = open(pwd[1:], "r").read().strip()
        return hash_password(pwd)
    elif "-k" in opts:
        val = opts["-k"]
        if val[0] == "@":
            key_file = val[1:]
            val = open(key_file, "rb").read().strip()
            if len(val) == KEY_SIZE:
                key = val      # binary key
            elif len(val) == KEY_SIZE*2 and all(c in b"0123456789abcdefABCDEF" for c in val):
                #print("Decodong key from hex:", val)
                key = bytes.fromhex(val.strip().decode("utf-8"))
            else:
                print("Unrecognized key file format:", key_file)
                sys.exit(1)
        else:
            key = bytes.fromhex(val)
            assert len(key) == KEY_SIZE
        #print("key:", key.hex())
        return key
    elif "-g" in opts or "-G" in opts:
        key = secrets.token_bytes(KEY_SIZE)
        out_file = opts.get("-g") or opts.get("-G")
        override = "-G" in opts
        if os.path.isfile(out_file) and not override:
            print(f"Key output file {out_file} exists. Use -G <out file> to overwrite")
            sys.exit(2)
        open(out_file, "w").write(key.hex())
        return key
    else:
        key = hash_password(prompt_password(verify_password))
        return key
           
