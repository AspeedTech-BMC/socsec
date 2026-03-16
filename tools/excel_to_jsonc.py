import pandas as pd
import json
import os
import re
import argparse
import textwrap

def clean_field_name(name):
    """
    Clean field name:
    1. Remove leading/trailing spaces.
    2. Keep letters, numbers, underscores, hyphens -, brackets [], and dots .
    3. Replace internal spaces or multiple spaces with a single underscore.
    """
    if pd.isna(name):
        return ""
    s = str(name).strip()
    s = re.sub(r'[^a-zA-Z0-9_\[\].\s\-]', '', s)
    s = re.sub(r'\s+', '_', s)
    return s

def format_jsonc_val(val):
    if isinstance(val, bool):
        return "true" if val else "false"
    return json.dumps(val)

def write_jsonc(data, comments, output_path):
    """Manually construct JSONC string with wrapped comments and write to file"""
    WRAP_WIDTH = 89

    with open(output_path, 'w') as f:
        f.write("{\n")
        f.write(f'    "name": {json.dumps(data["name"])},\n')
        f.write(f'    "version": {json.dumps(data["version"])},\n')

        # New order: rom_region -> rbp_region -> config_region -> strap_region -> strap_ext_region -> user_region -> secure_region -> caliptra_region
        regions = [
            "rom_region",
            "rbp_region",
            "config_region",
            "strap_region",
            "strap_ext_region",
            "user_region",
            "secure_region",
            "caliptra_region"
        ]

        for i, region in enumerate(regions):
            f.write(f'    "{region}": ')
            if region == "secure_region":
                f.write(json.dumps(data[region], indent=4).replace('\n', '\n    '))
            elif region == "rom_region" and not data[region]:
                f.write("{}")
            else:
                f.write("{\n")
                items = list(data[region].items())
                for j, (key, val) in enumerate(items):
                    comment = comments.get(region, {}).get(key)
                    if comment:
                        for raw_line in str(comment).split('\n'):
                            raw_line = raw_line.strip()
                            if not raw_line:
                                continue
                            wrapped_lines = textwrap.wrap(raw_line, width=WRAP_WIDTH)
                            for w_line in wrapped_lines:
                                f.write(f'        // {w_line}\n')

                    comma = "" if j == len(items) - 1 else ","
                    if isinstance(val, dict):
                        val_str = json.dumps(val, indent=4).replace('\n', '\n        ').strip()
                    else:
                        val_str = format_jsonc_val(val)

                    f.write(f'        "{key}": {val_str}{comma}\n')
                f.write("    }")

            if i < len(regions) - 1:
                f.write(",")
            f.write("\n")

        f.write("}\n")

def excel_to_jsonc(excel_path, output_path):
    xl = pd.ExcelFile(excel_path)
    data = {
        "name": os.path.splitext(os.path.basename(excel_path))[0],
        "version": "2700A2",
        "rom_region": {},
        "rbp_region": {},
        "config_region": {},
        "strap_region": {},
        "strap_ext_region": {},
        "user_region": {},
        "secure_region": {"keys": []},
        "caliptra_region": {}
    }
    comments = {k: {} for k in data.keys()}
    usr_config = []

    # 1. OTPRBP
    if 'OTPRBP' in xl.sheet_names:
        df = pd.read_excel(xl, 'OTPRBP')
        for _, row in df.iterrows():
            name = str(row['Name'])
            if 'Reserved' in name or name in ['Sum', 'Actual']:
                continue

            clean_n = clean_field_name(name)
            size_bit = row['Size (bit)']
            addr_raw = row['Start address (word)']

            try:
                addr_int = int(str(addr_raw), 16) if isinstance(addr_raw, str) else int(addr_raw)
                idx = addr_int - 0x3E0
                desc = str(row['Description']) if 'Description' in row else ""

                if size_bit > 32:
                    num_parts = (size_bit + 31) // 32
                    for p in range(num_parts):
                        part_name = f"{clean_n}_{p}"
                        data["rbp_region"][part_name] = "0x0"
                        if p == 0:
                            comments["rbp_region"][part_name] = f"OTPRBP{idx} - {size_bit} bits\n{desc}"
                else:
                    data["rbp_region"][clean_n] = "0x0"
                    comments["rbp_region"][clean_n] = f"OTPRBP{idx} - {size_bit} bits\n{desc}"
            except (ValueError, TypeError):
                pass

    # 2. OTPCFG
    if 'OTPCFG' in xl.sheet_names:
        df = pd.read_excel(xl, 'OTPCFG')
        for _, row in df.iterrows():
            name = str(row['Name'])
            if 'Reserved' in name or name == 'Sum':
                continue
            clean_n = clean_field_name(name)
            data["config_region"][clean_n] = False if row['Size (bit)'] == 1 else "0x0"
            reg = str(row['Register']).split('/')[0] if 'Register' in row else "OTPCFG"
            bit = str(row['Bit']) if 'Bit' in row else ""
            desc = str(row['Description']) if 'Description' in row else ""
            comments["config_region"][clean_n] = f"{reg}[{bit}]\n{desc}"

    # 3. OTPSTRAP
    if 'OTPSTRAP' in xl.sheet_names:
        df = pd.read_excel(xl, 'OTPSTRAP')
        for _, row in df.iterrows():
            name = str(row['Name'])
            if 'Reserved' in name or name in ['Sum', 'Actual'] or 'prot' in name:
                continue
            clean_n = clean_field_name(name)
            data["strap_region"][clean_n] = {
                "value": False if row['Size (bit)'] == 1 else "0x0",
                "protect": False
            }
            reg_val = str(row['Register']) if 'Register' in row else "OTPSTRAP"
            desc = str(row['Description']) if 'Description' in row else ""
            comments["strap_region"][clean_n] = f"{reg_val}\n{desc}"
            if "OTPSTRAP[31]" in reg_val:
                break

    # 4. OTPSTRAP_EXT
    if 'OTPSTRAP_EXT' in xl.sheet_names:
        df = pd.read_excel(xl, 'OTPSTRAP_EXT')
        for _, row in df.iterrows():
            name = str(row['Name'])
            if 'Reserved' in name or name in ['Sum', 'Actual'] or 'valid' in name:
                continue
            clean_n = clean_field_name(name)
            data["strap_ext_region"][clean_n] = {
                "value": False if row['Size (bit)'] == 1 else "0x0",
                "valid": False
            }
            reg_val = str(row['Register']) if 'Register' in row else "OTPSTRAP_EXT"
            desc = str(row['Description']) if 'Description' in row else ""
            comments["strap_ext_region"][clean_n] = f"{reg_val}\n{desc}"

    # 4_5. OTPUSR
    if 'OTPUSR' in xl.sheet_names:
        df = pd.read_excel(xl, 'OTPUSR')
        for _, row in df.iterrows():
            name = str(row['Name'])
            if 'Reserved' in name or name in ['Sum', 'Actual']:
                continue

            clean_n = clean_field_name(name)
            size_bit = row['Size (bit)']
            addr_raw = row['Start address (word)']

            try:
                addr_int = int(str(addr_raw), 16) if isinstance(addr_raw, str) else int(addr_raw)
                desc = str(row['Description']) if 'Description' in row else ""

                usr_config.append({
                    "key": clean_n,
                    "type": "string" if size_bit > 1 else "boolean",
                    "w_offset": addr_int - 0x440,
                    "bit_offset": 0,
                    "bit_length": size_bit,
                    "info": [desc] if desc else []
                })
                data["user_region"][clean_n] = "0x0" if size_bit > 1 else False
                comments["user_region"][clean_n] = f"OTPUSR 0x{addr_int:X} - {size_bit} bits\n{desc}"
            except (ValueError, TypeError):
                pass

    # 5. OTPSEC (secure_region)
    if 'OTPSEC' in xl.sheet_names:
        df = pd.read_excel(xl, 'OTPSEC')
        for _, row in df.iterrows():
            if 'Key Body' in str(row['Note']):
                name_val = str(row['Name'])
                match = re.match(r'(.*)\s+(\d+)', name_val)
                if match:
                    ktype = "cal_own_pub_hash" if "Owner" in match.group(1) else "soc_vault"
                    addr_raw = row['Start address (word)']
                    try:
                        addr = int(str(addr_raw), 16) if isinstance(addr_raw, str) else int(addr_raw)
                        data["secure_region"]["keys"].append({
                            "key_file": "owner_key_hash.bin" if ktype == "cal_own_pub_hash" else "vault_key.bin",
                            "type": ktype,
                            "w_offset": hex(addr - 0x1000),
                            "number_id": int(match.group(2))
                        })
                    except (ValueError, TypeError):
                        pass

    # 6. OTPCAL
    if 'OTPCAL' in xl.sheet_names:
        df = pd.read_excel(xl, 'OTPCAL')
        for _, row in df.iterrows():
            name = str(row['Name'])
            if 'Reserved' in name or name in ['Sum', 'Actual', 'PUF']:
                continue
            clean_n = clean_field_name(name)
            data["caliptra_region"][clean_n] = False if row['Size (bit)'] == 1 else ""
            addr_raw = row['Start address (word)']
            try:
                addr = int(str(addr_raw), 16) if isinstance(addr_raw, str) else int(addr_raw)
                desc = str(row['Description']) if 'Description' in row else ""
                comments["caliptra_region"][clean_n] = f"OTPCAL{addr - 0x1C00}\n{desc}"
            except (ValueError, TypeError):
                pass

    write_jsonc(data, comments, output_path)
    print(f"Successfully converted '{excel_path}' to '{output_path}'")

    if usr_config:
        config_path = os.path.join(os.path.dirname(output_path), "2700a2_usr.json")
        with open(config_path, 'w') as f:
            json.dump(usr_config, f, indent=4)
        print(f"Successfully generated OTP user configuration to '{config_path}'")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Convert AST2700 OTP Excel memory map to JSONC.')
    parser.add_argument('input', help='Input Excel file path')
    parser.add_argument('output', help='Output JSONC file path')

    args = parser.parse_args()

    if os.path.exists(args.input):
        excel_to_jsonc(args.input, args.output)
    else:
        print(f"Error: Input file '{args.input}' not found.")
