import secrets, string, sys, getopt, math, os

Usage = """
python generate.py [options]
    -n <length>             -- password length, default: 10 characters or 4 words, if -w was used
    -s                      -- do not allow special characters
    -w                      -- generate password as a sequence of words from the common vocabulary
"""

opts, args = getopt.getopt(sys.argv[1:], "vsn:?hw")
opts = dict(opts)

if "-?" in opts or "-h" in opts:
    print(Usage)
    sys.exit(2)


if "-w" in opts:
    length = int(opts.get("-n", 3))
    voc_file = "/usr/share/dict/words"
    if not os.path.isfile(voc_file):
        print(f"Vocabulary file {voc_file} not found")
        sys.exit(1)
    vocabulary = open(voc_file, "r")
    words = set(w.strip().lower() for w in vocabulary)
    words = list(w for w in words if w)
    combinations = len(words)**length
    password = "-".join([secrets.choice(words) for _ in range(length)])
else:
    length = int(opts.get("-n", 10))
    chars = string.ascii_letters + string.digits
    if "-s" not in opts:
        chars = chars + string.punctuation
    chars = [c for c in chars if c not in '"#&*<>[]`{}']         # not safe chars
    combinations = len(chars)**length
    password = "".join([secrets.choice(chars) for _ in range(length)])

if "-v" in opts:
    log10 = int(math.log(combinations)/math.log(10))
    t = int(combinations/3.0e13/2+0.5)          # average time to crack password at the rate of 10**6 passwords per second
    print(f"Password strength: {combinations} (>10**{log10}) combinations, or {t:.1e} years of cracking")

print(password)

