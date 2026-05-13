#!/usr/bin/env python3
import argparse
import json
import hashlib
import struct
import os
import extract_fit_signed_data
def parse_args():
    parser = argparse.ArgumentParser(description='Calculate Measurements for STASH_MEASUREMENT flow')
    parser.add_argument('--fw', help='Path to FW JSON file (e.g. ast27x0_fw.json)')
    parser.add_argument('--image-dir', default='../image', help='Directory containing FW images (default: ../image)')
    parser.add_argument('--efuse', required=True, help='Path to eFuse JSON file')
    parser.add_argument('--hwstrap', required=True, help='Path to HW Strap JSON file')
    parser.add_argument('--otp', required=True, help='Path to OTP binary file')
    parser.add_argument('--output', required=True, help='Output reference measurements JSON file')
    return parser.parse_args()

def parse_int(val):
    if val is None:
        return 0
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        if val.lower().startswith('0x'):
            return int(val, 16)
        return int(val)
    return 0

def get_fit_default_config(fdt_bytes):
    magic, totalsize, off_dt_struct, off_dt_strings, off_mem_rsvmap, version, last_comp_version, boot_cpuid_phys, size_dt_strings, size_dt_struct = struct.unpack(">10I", fdt_bytes[:40])
    dt_struct = fdt_bytes[off_dt_struct:off_dt_struct + size_dt_struct]
    dt_strings = fdt_bytes[off_dt_strings:off_dt_strings + size_dt_strings]

    offset = 0
    path = []
    while offset < len(dt_struct):
        tag = struct.unpack(">I", dt_struct[offset:offset+4])[0]
        offset += 4

        if tag == 1:
            name_start = offset
            name_end = dt_struct.find(b'\0', offset)
            name = dt_struct[name_start:name_end].decode('ascii')
            offset = (name_end + 1 + 3) & ~3
            path.append(name)
        elif tag == 2:
            if path:
                path.pop()
        elif tag == 3:
            length, nameoff = struct.unpack(">II", dt_struct[offset:offset+8])
            offset += 8
            prop_name = extract_fit_signed_data.get_string(dt_strings, nameoff)
            if len(path) == 2 and path[0] == '' and path[1] == 'configurations' and prop_name == 'default':
                return dt_struct[offset:offset+length].decode('ascii').strip('\0')
            offset = (offset + length + 3) & ~3
        elif tag == 9:
            break
    return "conf-ast2700-evb.dtb"

def calc_fw(fw_json_path, image_dir):
    if not fw_json_path:
        return {}, {}
    with open(fw_json_path, 'r') as f:
        config = json.load(f)

    fw_hashes = {}
    fw_padding = {}
    base_dir = os.path.dirname(os.path.abspath(fw_json_path))
    for key, filename in config.items():
        path = os.path.join(base_dir, filename)
        if not os.path.exists(path):
            path = filename
        if not os.path.exists(path) and image_dir:
            path = os.path.join(image_dir, filename)

        with open(path, 'rb') as bin_f:
            data = bin_f.read()
            if key.upper() == 'KERNEL':
                config_name = get_fit_default_config(data)
                hashed_nodes, hashed_strings_region, algo = extract_fit_signed_data.extract_properties(data, config_name)
                regions = extract_fit_signed_data.parse_fdt(data, hashed_nodes, ["data"])
                if hashed_strings_region:
                    regions.append({
                        'start': hashed_strings_region[0],
                        'size': hashed_strings_region[1],
                        'nodes': {"<String Table>"}
                    })
                signed_data = bytearray()
                for r in regions:
                    signed_data.extend(data[r['start']:r['start']+r['size']])

                with open("signed_data.bin", "wb") as f_out:
                    f_out.write(signed_data)
                fw_hashes[key.upper()] = hashlib.sha384(signed_data).hexdigest()
            else:
                rem = len(data) % 4
                if rem != 0:
                    pad_len = 4 - rem
                    data += b'\x00' * pad_len
                    fw_padding[key.upper()] = pad_len

                fw_hashes[key.upper()] = hashlib.sha384(data).hexdigest()

    return fw_hashes, fw_padding

def calc_efuse(efuse_path):
    with open(efuse_path, 'r') as f:
        config = json.load(f)
    scu0_810 = parse_int(config.get("SCU0_810", 0))
    scu1_804 = parse_int(config.get("SCU1_804", 0))

    data = struct.pack('<II', scu0_810, scu1_804)
    return hashlib.sha384(data).hexdigest()

def calc_hwstrap(hwstrap_path):
    with open(hwstrap_path, 'r') as f:
        config = json.load(f)

    scu0_10 = parse_int(config.get("SCU0_010", 0))
    scu1_10 = parse_int(config.get("SCU1_010", 0))
    scu1_30 = parse_int(config.get("SCU1_030", 0))

    data = struct.pack('<III', scu0_10, scu1_10, scu1_30)
    return hashlib.sha384(data).hexdigest()

def calc_otp_full(otp_path):
    # Mirrors rom_patch_5.c patch_stash_measurement_otp():
    # for (int i = 0; i < SW_PUF_REGION_START_ADDR; i += 2)
    #     otp_readl(i, &otp_data)  -> reads 4 bytes at byte offset i*2, no overlap
    SW_PUF_REGION_START_ADDR = 0x1f80  # 16-bit word address
    read_size = SW_PUF_REGION_START_ADDR * 2  # total bytes to read

    with open(otp_path, 'rb') as f:
        data = f.read(read_size)

    if len(data) < read_size:
        data += b'\x00' * (read_size - len(data))

    m = hashlib.sha384()

    # i is 16-bit word address, step by 2 (= one 32-bit read)
    # byte offset = i * 2, read 4 bytes
    i = 0
    while i < SW_PUF_REGION_START_ADDR:
        byte_off = i * 2
        chunk = data[byte_off:byte_off + 4]
        if len(chunk) < 4:
            chunk += b'\x00' * (4 - len(chunk))
        m.update(chunk)
        i += 2

    return m.hexdigest()

def extend_pcr(pcr_value, measurement_hex):
    # PCR_new = SHA384(PCR_old || measurement)
    measurement_bytes = bytes.fromhex(measurement_hex)
    return hashlib.sha384(pcr_value + measurement_bytes).digest()

def main():
    args = parse_args()

    fw_hashes, fw_padding = calc_fw(args.fw, args.image_dir)
    efus_hash = calc_efuse(args.efuse)
    stra_hash = calc_hwstrap(args.hwstrap)
    otp_full_hash = calc_otp_full(args.otp)

    result = {}

    # Store FW measurements
    for k, v in fw_hashes.items():
        result[k] = v

    if fw_padding:
        result["PADDING_INFO"] = fw_padding

    result["OTP_FULL"] = otp_full_hash
    result["STRA"] = stra_hash
    result["EFUS"] = efus_hash

    # Calculate PCR31
    pcr31 = b'\x00' * 48

    # Original stash flow
    if "FMC" not in fw_hashes:
        # rom_patch: extend full OTP measurement (patch_stash_measurement_otp)
        pcr31 = extend_pcr(pcr31, otp_full_hash)
        pcr31 = extend_pcr(pcr31, stra_hash)
        pcr31 = extend_pcr(pcr31, efus_hash)

    for k, v in fw_hashes.items():
        if k == "KERNEL":
            # Extend 3 times for KERNEL
            for _ in range(3):
                pcr31 = extend_pcr(pcr31, v)
        else:
            pcr31 = extend_pcr(pcr31, v)
            if k == "FMC":
                # Stash order: fmc -> otp -> hwstrap -> efuse
                pcr31 = extend_pcr(pcr31, otp_full_hash)
                pcr31 = extend_pcr(pcr31, stra_hash)
                pcr31 = extend_pcr(pcr31, efus_hash)

    result["PCR31"] = pcr31.hex()

    with open(args.output, 'w') as f:
        json.dump(result, f, indent=4)
        f.write('\n')

if __name__ == '__main__':
    main()
