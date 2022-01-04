import secrets, string, sys, getopt

Usage = """
python generate.py [options]
    -n <length>             -- password length, default: 10
    -s                      -- do not allow special characters
"""

opts, args = getopt.getopt(sys.argv[1:], "sn:?h")
opts = dict(opts)

if "-?" in opts or "-h" in opts:
    print(Usage)
    sys.exit(2)

chars = string.ascii_letters + string.digits
if "-s" not in opts:
    chars = chars + string.punctuation
length = int(opts.get("-n", 10))


chars = [c for c in chars if c not in '"#&*<>[]`{}']         # not safe chars

password = "".join([secrets.choice(chars) for _ in range(length)])
print(password)

