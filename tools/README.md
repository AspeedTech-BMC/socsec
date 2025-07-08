# Tools - How to

## OTP info generation

```bash
$ python3 otp_info_gen.py \
        {workbook} {sheet} \
        {output_file} \
        {conf/strap/strap_ext/caliptra}
```

## OTP sample json file generation

```bash
$ python3 e2j.py \
        --input {otp_memory_map_file} \
        --strap {otp_strap_file}
```
Output file: AST2700a1_Sample.json

## Caliptra keys sample json file generation

```bash
$ python3 cal_info_gen.py gen_sample
```

## Caliptra key hash generation

```bash
$ python3 cal_info_gen.py gen_keyhash \
        --key_folder {key_folder} \
        --output_folder {output_folder} \
        config
```

- Example
  - config: sample_cptra_vdrkey.json
  - config: sample_cptra_ownkey.json

## Extract Caliptra Firmware Image data to be signed
### Vendor TBS
```bash
$ dd if={cptra_fw_file} of=vendor_data_tbs.bin skip=5520 bs=1 count=116
```

### Owner TBS
```bash
$ dd if={cptra_fw_file} of=owner_data_tbs.bin skip=5520 bs=1 count=156
```

## Signing with ECC
```bash
$ openssl dgst -sha384 -sign {prvKey} -out {signature_ecc} {data}
```

## Signing with LMS

This tool is used to sign data with an LMS private key, and use the corresponding public key for verification.
The output is an LMS signature.

- Example
```bash
python3 lms_signing_tool.py --data vendor_data_tbs.bin --key {prvKey} --public_key {pubKey} --output {signature_lms}
python3 lms_signing_tool.py --data owner_data_tbs.bin --key {prvKey} --public_key {pubKey} --output {signature_lms}
```

- Usage
```bash
$ python3 lms_signing_tool.py -h
usage: lms_signing_tool.py [-h] --data DATA --key KEY [--public_key PUBLIC_KEY] --output OUTPUT

LMS Signing Tool

options:
  -h, --help            show this help message and exit
  --data DATA           Path to the data file to be signed
  --key KEY             Path to the private key file
  --public_key PUBLIC_KEY
                        Path to the public key file for verification (optional)
  --output OUTPUT       Path to the output file for the signature
```

## Insert Vendor keys and signatures

This tool is used to insert 32 vendor ECC public keys, 4 vendor LMS public keys, a vendor ECC signature,
and a vendor LMS signature into the Caliptra runtime firmware bundle.

- Example
```bash
$ python3 cptra_vdr_key_ins.py {cptra_fw_file} {key_dir} {signature_ecc} {signature_lms}
```

- Usage
```bash
$ python3 cptra_vdr_key_ins.py -h
usage: cptra_vdr_key_ins.py [-h] file_path key_directory vendor_ecc_sig_file vendor_lms_sig_file

Process ECC and LMS signatures and public keys.

positional arguments:
  file_path            Path to the file to be modified (Caliptra firmware image)
  key_directory        Directory containing the pem/pub files
  vendor_ecc_sig_file  Path to the ECC signature file in DER format
  vendor_lms_sig_file  Path to the LMS signature file in binary format

options:
  -h, --help           show this help message and exit
```

## Insert Owner keys and signatures

This tool is used to insert an owner ECC public key, an owner LMS public key, an owner ECC signature,
and an owner LMS signature into the Caliptra runtime firmware bundle.

- Example
```bash
$ python3 cptra_own_key_ins.py {cptra_fw_file} --ecc_key {pubKey} --lms_key {pubKey} --ecc_sig {signature_ecc} --lms_sig {signature_lms}
```

- Usage
```bash
$ python3 cptra_own_key_ins.py -h
usage: cptra_own_key_ins.py [-h] --ecc_key ECC_KEY --lms_key LMS_KEY --ecc_sig ECC_SIG --lms_sig LMS_SIG file_path

Insert ECC and LMS keys and signatures into a firmware image.

positional arguments:
  file_path          Path to the firmware image file

options:
  -h, --help         show this help message and exit
  --ecc_key ECC_KEY  Path to the ECC public key file in PEM format
  --lms_key LMS_KEY  Path to the LMS public key file in .pub format
  --ecc_sig ECC_SIG  Path to the ECC signature file in DER format
  --lms_sig LMS_SIG  Path to the LMS signature file in binary format
```

## Caliptra Firmware Image Signature Verification

This tool is used for Caliptra runtime firmware signature verification, including:
- Vendor ECDSA384 signature verification
- Owner ECDSA384 signature verification
- Vendor LMS signature verification
- Owner LMS signature verification

- Example
```bash
$ python3 cptra_img_sig_ver.py {cptra_fw_file}
```

- Output
```bash
Caliptra Vendor ECDSA384 signature verification succeeded.
Caliptra Owner ECDSA384 signature verification succeeded.
Caliptra Vendor LMS signature verification succeeded.
Caliptra Owner LMS signature verification succeeded.
```

- Usage
```bash
$ python3 cptra_img_sig_ver.py -h
usage: cptra_img_sig_ver.py [-h] cptra_fw

Verify ECC and LMS signatures in a Caliptra firmware file.

positional arguments:
  cptra_fw    Path to the source file to verify

options:
  -h, --help  show this help message and exit
```

## How to compare key hash?

### Vendor key hash

- Generate vendor key hash from key source
```bash
$ python3 cal_info_gen.py gen_keyhash \
        --key_folder {key_folder} \
        --output_folder {output_folder} \
        sample_cptra_vdrkey.json

Output: vendor_key.bin, vendor_key_hash.bin
```

- Generate vendor key hash from cptra fw
```bash
$ dd if={cptra_fw} of={output_file} bs=1 skip=8 count=$((0x788 - 0x8))
$ sha384sum {output_file} | tee >(awk '{print $1}' | xxd -r -p > vendor_key_digest.bin)
```

- Compare two of them
```bash
$ diff vendor_key_hash.bin vendor_key_digest.bin
```

### Owner key hash

- Generate owner key hash from key source
```bash
$ python3 cal_info_gen.py gen_keyhash \
        --key_folder {key_folder} \
        --output_folder {output_folder} \
        sample_cptra_ownkey.json

Output: owner_key.bin, owner_key_hash.bin
```

- Generate owner key hash from cptra fw
```bash
$ dd if={cptra_fw} of={output_file} bs=1 skip=3652 count=$((0x90))
$ sha384sum {output_file} | tee >(awk '{print $1}' | xxd -r -p > owner_key_digest.bin)
```

- Compare two of them
```bash
$ diff owner_key_hash.bin owner_key_digest.bin
```
