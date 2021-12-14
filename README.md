# encrypt

## File encryption/decryption tool

```sh
$ python aes.py (encrypt|decrypt) [options] <input_file> [<output_file>|-]
    -w <password>
    -w @<file with one line password>
    -k <hex key>
    -k @<file with binary or hex key>
    -g <output file for key>            # generate random key and write to file
    -G <output file for key>            # generate random key and write to file and override existing key file if present
    -f <override output file>
    -e <ecnoding>                       # for decrypting to stdout (output file is "-")
```

## SHA256 checksum calculation

```sh
$ python sha256.py [-c <checksum>] <file>
```