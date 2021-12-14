import secrets, sys, os, getopt
from Crypto.Cipher import AES
from hashlib import sha256

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
    print("hashed password:", key.hex())
    return key

def encrypt(key, inp_fn, out_fn = None):
    out_fn = out_fn or inp_fn + ".aes"
    print(f"Encrypting {inp_fn} -> {out_fn} ...")
    iv = secrets.token_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    inp = open(inp_fn, "rb")
    out = open(out_fn, "wb")
    out.write(iv)
    print("iv:", iv.hex())
    while True:
        buf = inp.read(8*1024)
        if not buf:
            break
        out.write(cipher.encrypt(buf))
    out.close()
    inp.close()
    
def decrypt(key, inp_fn, out_fn = None, overwrite_out = False, encoding = "utf-8"):
    if out_fn is None:
        if not inp_fn.endswith(".aes"):
            print("Can not reconstruct original file name. Specify the output file explicitly")
            sys.exit(2)
        out_fn = inp_fn[:-4]
    if os.path.exists(out_fn) and not overwrite_out:
        print(f"Output file {out_fn} exists. Use -f to overwrite")
        sys.exit(2)
        
    print(f"Decrypting {inp_fn} -> {out_fn} ...")

    inp = open(inp_fn, "rb")
    if out_fn == "-":
        out = sys.stdout
    else:
        out = open(out_fn, "wb")
    iv = inp.read(AES.block_size)
    print("iv:", iv.hex())
    cipher = AES.new(key, AES.MODE_CFB, iv)
    while True:
        buf = inp.read(8*1024)
        if not buf:
            break
        decrypted = cipher.decrypt(buf)
        if out is sys.stdout:
            out.write(decrypted.decode(encoding))
        else:
            out.write(decrypted)
    out.close()
    inp.close()

def prompt_password():
    password =  getpass("Password:")
    if cmd == "encrypt":
        password1 = getpass("Verify  :")
        if password != password1:
            print("Password mismatch")
            sys.exit(2)
    return password
    
def get_key(opts):
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
                print("Decodong key from hex:", val)
                key = bytes.fromhex(val.strip().decode("utf-8"))
            else:
                print("Unrecognized key file format:", key_file)
                sys.exit(1)
        else:
            key = bytes.fromhex(val)
            assert len(key) == KEY_SIZE
        print("key:", key.hex())
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
        key = hash_password(prompt_password())
        return key
           

Usage = """
python aes.py (encrypt|decrypt) [options] <input_file> [<output_file>|-]
    -w <password>
    -w @<file with one line password>
    -k <hex key>
    -k @<file with binary or hex key>
    -g <output file for key>            # generate random key and write to file
    -G <output file for key>            # generate random key and write to file and override existing key file if present
    -f <override output file>
    -e <ecnoding>                       # for decrypting to stdout (output file is "-")
"""

if not sys.argv[1:]:
    print(Usage)
    sys.exit(2)

cmd, args = sys.argv[1], sys.argv[2:]
if not args:
    print(Usage)
    sys.exit(2)

opts, args = getopt.getopt(args, "w:k:g:G:fe:")
opts = dict(opts)
args = tuple(args + [None])[:2]
key = get_key(opts)

inp_fn, out_fn = args
opts = dict(opts)
overwrite = "-f" in opts
encoding = opts.get("-e", "utf-8")

if cmd == "encrypt":
    encrypt(key, inp_fn, out_fn)
else:
    decrypt(key, inp_fn, out_fn, overwrite, encoding)
    

    

