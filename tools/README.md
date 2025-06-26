# Tools

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

## Caliptra Firmware Image Signature Verification

This tool used to do Caliptra runtime firmware signature verification.
- Vendor ECDSA384 signature verification
- Owner ECDSA384 signature verification
- Vendor LMS signature verification
- Owner LMS signature verification

```bash
$ python3 cptra_img_sig_ver.py {cptra_fw_file}
```

Output:
```
Caliptra Vendor ECDSA384 signature verification succeeded.
Caliptra Owner ECDSA384 signature verification succeeded.
Caliptra Vendor LMS signature verification succeeded.
Caliptra Owner LMS signature verification succeeded.
```