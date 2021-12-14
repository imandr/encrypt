import secrets, sys, os, getopt
from Crypto.Cipher import AES
from getpass import getpass
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
    #print("hashed password:", key.hex())
    return key

def encrypt(key, inp_fn, out_fn, remove_input):
    out_fn = out_fn or inp_fn + ".aes"
    print(f"Encrypting {inp_fn} -> {out_fn} ...")
    iv = secrets.token_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    inp = open(inp_fn, "rb")
    out = open(out_fn, "wb")
    out.write(iv)
    #print("iv:", iv.hex())
    while True:
        buf = inp.read(8*1024)
        if not buf:
            break
        out.write(cipher.encrypt(buf))
    out.close()
    inp.close()
    
def decrypt(key, inp_fn, out_fn, encoding, remove_input):
    if out_fn is None:
        if not inp_fn.endswith(".aes"):
            print("Can not reconstruct original file name. Specify the output file explicitly")
            sys.exit(2)
        out_fn = inp_fn[:-4]

    print(f"Decrypting {inp_fn} -> {out_fn} ...")

    inp = open(inp_fn, "rb")
    if out_fn == "-":
        out = sys.stdout
    else:
        out = open(out_fn, "wb")
    iv = inp.read(AES.block_size)
    #print("iv:", iv.hex())
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
    
def decrypt_many(key, inputs, out_dir, overwrite_out, remove_input):
    errors = 0
    outputs = []
    for inp in inputs:
        if not inp.endswith(".aes"):
            print("Can not reconstruct original file name for encrypted file", inp)
            errors += 1
        fn = inp
        if "/" in fn:
            fn = inp.rsplit("/", 1)[-1]
        out = out_dir + "/" + fn[:-4]           # remove ".aes"
        if os.path.isfile(out) and not overwrite_out:
            print(f"Plaintext for encrypted file {inp} exists. Use -f to ovverwrite")
            errors += 1
        outputs.append(out)
    if not errors:
        for inp, out in zip(inputs, outputs):
            decrypt(key, inp, out, overwrite_out, remove_input)
        return True
    else:
        print("Aborted due to errors")
        return False
                
def encrypt_many(key, inputs, out_dir, overwrite_out, remove_input):
    errors = 0
    outputs = []
    for inp in inputs:
        fn = inp
        if "/" in fn:
            fn = inp.rsplit("/", 1)[-1]
        out = out_dir + "/" + fn + ".aes"  
        if os.path.isfile(out) and not overwrite_out:
            print(f"Encrypted file {out} exists. Use -f to ovverwrite")
            errors += 1
        outputs.append(out)
    if not errors:
        for inp, out in zip(inputs, outputs):
            encrypt(key, inp, out, remove_input)
        return True
    else:
        print("Aborted due to errors")
        return False

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
        key = hash_password(prompt_password())
        return key
           

Usage = """
python aes.py (encrypt|decrypt) [options] <input_file> [<output_file>|-]
python aes.py (encrypt|decrypt) [options] <input_file> ... <output dir>
    -w <password>
    -w @<file with one line password>
    -k <hex key>
    -k @<file with binary or hex key>
    -g <output file for key>            # generate random key and write to file
    -G <output file for key>            # generate random key and write to file and override existing key file if present
    -e <ecnoding>                       # for decrypting to stdout (output file is "-")
    -f                                  # override output file
    -r                                  # remove input file
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

opts = dict(opts)
overwrite = "-f" in opts
encoding = opts.get("-e", "utf-8")
remove_input = "-r" in opts

if len(args) == 1 or len(args) == 2 and not os.path.isdir(args[-1]):
    inp = args[0]
    if len(args) == 1:
        out = None
    else:
        out = args[1]
    if out and os.path.isfile(out) and not overwrite:
        print(f"Output {out} exists. Use -f")
        sys.exit(1)
    key = get_key(opts)
    if cmd == "encrypt":
        encrypt(key, inp, out, remove_input)
    elif cmd == "decrypt":
        decrypt(key, inp, out, encoding, remove_input)
else:        
    out_dir = args[-1]
    inputs = args[:-1]
    if len(args) > 1 and os.path.isdir(args[-1]):

    key = get_key(opts)
    if cmd == "encrypt":
        encrypt_many(key, inputs, out_dir, overwrite, remove_input)
    elif cmd == "decrypt":
        decrypt_many(key, inputs, out_dir, overwrite, remove_input)
    else:
        print(Usage)
        sys.exit(2)

    

