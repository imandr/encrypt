import secrets, sys, os, getopt, struct
import Crypto
from Crypto.Cipher import AES
from getpass import getpass
from hashlib import sha256

from lib import to_bytes, to_str, hash_password, wipe, prompt_password, get_key

Version = 1

KEY_SIZE = 32

Verbose = False

def encrypt(key, inp_fn, out_fn, remove_input, send_to_stdout):
    output = None
    close_out = False
    if out_fn is None:
        if send_to_stdout:
            output = sys.stdout.buffer
        else:
            out_fn = out_fn or inp_fn + ".aes"
    if output is None:  
        close_out = True
        output = open(out_fn, "wb")
    if Verbose:
        print(f"encrypting {inp_fn} -> {out_fn} ...")
    iv = secrets.token_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    if inp_fn == "-":
        inp = sys.stdin.buffer
    else:
        inp = open(inp_fn, "rb")
    flags = 0    
    header = struct.pack(">HL", Version, flags)
    output.write(header)
    output.write(iv)
    while True:
        buf = inp.read(8*1024)
        if not buf:
            break
        output.write(cipher.encrypt(buf))
    if close_out:
        output.close()
    inp.close()
    if remove_input:
        wipe(inp_fn)
    
def decrypt(key, inp_fn, out_fn, remove_input, send_to_stdout):
    output = None
    close_out = False
    if out_fn is None:
        if send_to_stdout:
            output = sys.stdout.buffer
        else:
            if not inp_fn.endswith(".aes"):
                print("Can not reconstruct original file name. Specify the output file explicitly")
                sys.exit(2)
            out_fn = inp_fn[:-4]

    if output is None:
        output = open(out_fn, "wb")
        close_out = True

    if Verbose:
        print(f"decrypting {inp_fn} -> %s ..." % ())

    inp = open(inp_fn, "rb")

    header_length = 2+4   # version + flags + IV
    header = inp.read(header_length)
    iv = inp.read(AES.block_size)

    if len(header) != header_length or len(iv) != AES.block_size:
        raise ValueError(f"Invalid format for encrypted file {inp_fn}")

    version, flags = struct.unpack(">HL", header)           # ignored
        
    cipher = AES.new(key, AES.MODE_CFB, iv)
    while True:
        buf = inp.read(8*1024)
        if not buf:
            break
        decrypted = cipher.decrypt(buf)
        output.write(decrypted)
    if close_out:
        output.close()
    inp.close()
    if remove_input:
        wipe(inp_fn)

def decrypt_many(key, inputs, output_dir, overwrite_out, remove_input):
    errors = 0
    outputs = []
    for inp in inputs:
        if not os.path.exists(inp):
            print("Not found:", inp, file=sys.stderr)
            continue
        if not os.path.isfile(inp):
            print("Not a file:", inp, file=sys.stderr)
            continue            
        inp_dir, _, inp_fn = inp.rpartition("/")
        if not inp.endswith(".aes"):
            print("Can not reconstruct original file name for encrypted file", inp)
            errors += 1
        out_fn = inp_fn[:-4]        # cut ".aes"
        out_dir = output_dir or inp_dir
        out = out_dir + "/" + out_fn if out_dir else out_fn
        if os.path.isfile(out) and not overwrite_out:
            print(f"Plaintext for encrypted file {inp} exists. Use -f to ovverwrite")
            errors += 1
        outputs.append(out)
    if not errors:
        for inp, out in zip(inputs, outputs):
            decrypt(key, inp, out, remove_input, False)
        return True
    else:
        print("Aborted due to errors")
        return False

def encrypt_many(key, inputs, output_dir, overwrite_out, remove_input):
    errors = 0
    outputs = []
    for inp in inputs:
        if not os.path.exists(inp):
            print("Not found:", inp, file=sys.stderr)
            continue
        if not os.path.isfile(inp):
            print("Not a file:", inp, file=sys.stderr)
            continue            
        inp_dir, _, inp_fn = inp.rpartition("/")
        out_fn = inp_fn + ".aes"
        out_dir = output_dir or inp_dir
        out = out_dir + "/" + out_fn if out_dir else out_fn
        if os.path.isfile(out) and not overwrite_out:
            print(f"Encrypted file {out} exists. Use -f to ovverwrite")
            errors += 1
        outputs.append(out)
    if not errors:
        for inp, out in zip(inputs, outputs):
            encrypt(key, inp, out, remove_input, False)
        return True
    else:
        print("Aborted due to errors")
        return False

Usage = """
python aes.py (encrypt|decrypt) [options] <input_file> [<output_file>]
python aes.py (encrypt|decrypt) [options] <input_file> ... <output dir>
    -w <password>                       # password will be hashed into a key
    -w @<file with one line password>
    -k <hex key>
    -k @<file with binary or hex key>
    -g <output file for key>            # generate random key and write to file
    -G <output file for key>            # generate random key and write to file and override existing key file if present
    -f                                  # override output file
    -r                                  # securely wipe and remove input file(s)
    -c                                  # send output to stdout (single file only)
    -v                                  # verbose output

python aes.py wipe <file> ...           # securely wipe and remove files
"""

if not sys.argv[1:]:
    print(Usage)
    sys.exit(2)

cmd, args = sys.argv[1], sys.argv[2:]
if not args:
    print(Usage)
    sys.exit(2)

opts, args = getopt.getopt(args, "w:k:g:G:fcrv")
opts = dict(opts)

opts = dict(opts)
overwrite = "-f" in opts
remove_input = "-r" in opts
send_to_stdout = "-c" in opts
Verbose = "-v" in opts

if cmd == "wipe":
    for path in args:
        if Verbose:
            print("wiping", path, "...")
        wipe(path)
    sys.exit(0)

if len(args) == 1 or len(args) == 2 and not os.path.isdir(args[-1]):
    inp = args[0]
    if len(args) == 1:
        out = None
    else:
        out = args[1]
    if out and os.path.isfile(out) and not overwrite:
        print(f"Output {out} exists. Use -f")
        sys.exit(1)
    if cmd == "encrypt":
        key = get_key(opts, verify_password=True)
        encrypt(key, inp, out, remove_input, send_to_stdout)
    elif cmd == "decrypt":
        key = get_key(opts, verify_password=False)
        decrypt(key, inp, out, remove_input, send_to_stdout)
else:
    if os.path.isfile(args[-1]):
        out_dir = None
        inputs = args
    elif os.path.isdir(args[-1]):
        out_dir = args[-1]
        inputs = args[:-1]
    else:
        print("Output directory does not exist")
        sys.exit(1)

    key = get_key(opts)
    if cmd == "encrypt":
        encrypt_many(key, inputs, out_dir, overwrite, remove_input)
    elif cmd == "decrypt":
        decrypt_many(key, inputs, out_dir, overwrite, remove_input)
    else:
        print(Usage)
        sys.exit(2)

    

