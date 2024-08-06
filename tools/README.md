# Tools

## OTP info generation

```bash
python3 otp_info_gen.py \
        {workbook} {sheet} \
        {output_file} \
        {conf/strap/strap_ext/caliptra}
```

## OTP sample json file generation

```bash
python3 e2j.py \
        --input {otp_memory_map_file} \
        --strap {otp_strap_file}
```
Output file: AST2700a1_Sample.json

## Caliptra keys sample json file generation

```bash
python3 cal_info_gen.py gen_sample
```

## Caliptra key hash generation

```bash
python3 cal_info_gen.py gen_keyhash \
        --key_folder {key_folder} \
        --output_folder {output_folder} \
        config
```
