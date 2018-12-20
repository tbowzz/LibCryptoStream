# libcipher

## About

This is a wrapper around libcrypto's AES-256 EVP cipher.  It contains utility functions to encrypt a file of any type. It also can decrypt an AES-256-encrypted file when provided with the IV used to encrypt said file.

## Usage

#### Ubuntu Setup

```
sudo ./install_requirements.sh
cd libcipher
./make.sh
```

#### Execution

```
# To encrypt a plaintext file and write it to a file. This also saves the IV to file.
./cipher encrypt plain.txt output.bin iv.bin

# To decrypt the file created, pass in the filename and the IV filename.
./cipher decrypt output.bin outputplain.txt iv.bin

# To encrypt then decrypt a string
./cipher string "foo bar biz baz"
```