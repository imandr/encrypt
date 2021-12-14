# encrypt

## File encryption/decryption tool

### Command syntax and arguments

```sh
$ python aes.py (encrypt|decrypt) [options] <input_file> [<output_file>]
python aes.py (encrypt|decrypt) [options] <input_file> ... <output dir>
    -w <password>
    -w @<file with one line password>
    -k <hex key>
    -k @<file with binary or hex key>
    -g <output file for key>            # generate random key and write to file
    -G <output file for key>            # generate random key and write to file and override existing key file if present
    -f                                  # override output file
    -r                                  # remove input file
    -c                                  # send output to stdout (single file only)
    -v                                  # verbose output
```

### Encrypted file format

 * format version - 2 bytes
 * flags - 4 bytes, currently unused
 * AES initialization vector (IV) - 16 bytes, Python ``secrets`` module is used to generate random IV
 * Encrypted file content - AES is used in CFB mode witg the IV above
 
So the encrypted file size is the original file size plus 2 + 4 + 16 bytes

## SHA256 checksum calculation

```sh
$ python sha256.py [-c <checksum>] <file>
```