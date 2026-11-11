#!/usr/bin/env python3
"""
calculate_measurements_v10.py — offline reference-measurement tool for ROM patch v10.

Usage (mirrors the original tool):
  python3 calculate_measurements_v10.py \
      --efuse=ast27x0_efuse.json \
      --hwstrap=ast27x0_hwstrap.json \
      --otp=otp-ast2700.bin \
      --output=reference_measurements_v10.json

What changed from the original calculate_measurements.py:
  - calc_otp_v10() replaces calc_otp_full():
      * Tag "OTP" -> "OTPM"
      * Pre-reads four backup values from the OTP backup zone (0x3F5–0x3F8)
        and ORs them into their respective primary fields before hashing, mirroring
        the aging-recovery logic in patch_stash_measurement_otp().
      * Zeros the entire backup zone (pairs 0x3F6–0x3FE) in the hash stream.
      * Zeros STRAP pairs 0x422–0x42C (strap values are captured separately by
        stash_measurement_hw_straps(); including them here would double-count).
      * STRAP pairs 0x420–0x421 (WR_PROT) and 0x42E–0x42F (GBL_ECC) hash as-is.
  - PCR31 uses OTPM instead of OTP_FULL.

OTP addressing (from otp_mem.h):
  RBP_REGION_START_ADDR  = 0x3E0  (16-bit word address)
  RBP_REGION_END_ADDR    = 0x400
  STRAP_REGION_START_ADDR = 0x420
  SW_PUF_REGION_START_ADDR = 0x1F80  (loop upper bound, exclusive)

  Backup slot word addresses:
    OTPBRP_CPTRA_OWN_PK_KEYHASH_RETIRE_BK = RBP_START + 0x15 = 0x3F5  -> bk_3e3
    OTPBRP_CPTRA_MANU_ECC_KEY_MASK_BK     = RBP_START + 0x16 = 0x3F6  -> bk_3f2
    OTPBRP_CPTRA_MANU_LMS_KEY_MASK_BK     = RBP_START + 0x17 = 0x3F7  -> bk_3f3 (lo), bk_3f4 (hi)
"""
import argparse
import json
import hashlib
import struct
import os
import extract_fit_signed_data


def parse_args():
    parser = argparse.ArgumentParser(
        description='Calculate Measurements for STASH_MEASUREMENT flow (ROM patch v10)')
    parser.add_argument('--fw', help='Path to FW JSON file (e.g. ast27x0_fw.json)')
    parser.add_argument('--image-dir', default='../image',
                        help='Directory containing FW images (default: ../image)')
    parser.add_argument('--efuse', required=True, help='Path to eFuse JSON file')
    parser.add_argument('--hwstrap', required=True, help='Path to HW Strap JSON file')
    parser.add_argument('--otp', required=True, help='Path to OTP binary file')
    parser.add_argument('--output', required=True,
                        help='Output reference measurements JSON file')
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
    magic, totalsize, off_dt_struct, off_dt_strings, off_mem_rsvmap, version, \
        last_comp_version, boot_cpuid_phys, size_dt_strings, size_dt_struct = \
        struct.unpack(">10I", fdt_bytes[:40])
    dt_struct = fdt_bytes[off_dt_struct:off_dt_struct + size_dt_struct]
    dt_strings = fdt_bytes[off_dt_strings:off_dt_strings + size_dt_strings]

    offset = 0
    path = []
    while offset < len(dt_struct):
        tag = struct.unpack(">I", dt_struct[offset:offset + 4])[0]
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
            length, nameoff = struct.unpack(">II", dt_struct[offset:offset + 8])
            offset += 8
            prop_name = extract_fit_signed_data.get_string(dt_strings, nameoff)
            if (len(path) == 2 and path[0] == '' and path[1] == 'configurations'
                    and prop_name == 'default'):
                return dt_struct[offset:offset + length].decode('ascii').strip('\0')
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
                hashed_nodes, hashed_strings_region, algo = \
                    extract_fit_signed_data.extract_properties(data, config_name)
                regions = extract_fit_signed_data.parse_fdt(data, hashed_nodes, ["data"])
                if hashed_strings_region:
                    regions.append({
                        'start': hashed_strings_region[0],
                        'size': hashed_strings_region[1],
                        'nodes': {"<String Table>"}
                    })
                signed_data = bytearray()
                for r in regions:
                    signed_data.extend(data[r['start']:r['start'] + r['size']])

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


def calc_otp_v10(otp_path):
    """
    Mirrors patch_stash_measurement_otp() from rom_patch_3_payload.c (v10).

    Streams OTP word-pairs 0x0000–0x1F7E through SHA-384 with the following
    substitutions (all addresses are 16-bit OTP word addresses):

      Backup OR:
        pair(0x3E2/0x3E3): OR bk_3e3 (from word 0x3F5) into high half
        pair(0x3F2/0x3F3): OR bk_3f2 (from word 0x3F6) into low, bk_3f3 (from 0x3F7) into high
        pair(0x3F4/0x3F5): OR bk_3f4 (from word 0x3F8) into low, zero high slot

      Zero regions:
        pairs 0x3F6–0x3FE  (RBP backup zone)
        pairs 0x422–0x42C  (STRAP: SCU strap stash covers these)

      As-is:
        pairs 0x420–0x421  (OTPSTRAP WR_PROT)
        pairs 0x42E–0x42F  (OTPSTRAP GBL_ECC)
    """
    RBP_START = 0x3E0
    SW_PUF_REGION_START_ADDR = 0x1F80
    read_size = SW_PUF_REGION_START_ADDR * 2  # bytes

    with open(otp_path, 'rb') as f:
        raw = f.read(read_size)
    if len(raw) < read_size:
        raw += b'\x00' * (read_size - len(raw))

    def readw(word_addr):
        """Read one 16-bit OTP word (LE) at the given word address."""
        off = word_addr * 2
        if off + 2 <= len(raw):
            return struct.unpack_from('<H', raw, off)[0]
        return 0

    def readl(word_addr):
        """Read two consecutive 16-bit OTP words as a 32-bit LE value."""
        off = word_addr * 2
        if off + 4 <= len(raw):
            return struct.unpack_from('<I', raw, off)[0]
        return 0

    # Pre-read backup values (treat read errors as 0, fail-open for backup)
    bk_3e3 = readw(RBP_START + 0x15)   # 0x3F5: backup of CPTRA_OWN_PK_KEYHASH_RETIRE
    bk_3f2 = readw(RBP_START + 0x16)   # 0x3F6: backup of CPTRA_MANU_ECC_KEY_MASK
    lms_bk = readl(RBP_START + 0x17)   # 0x3F7/0x3F8: backup of CPTRA_MANU_LMS_KEY_MASK
    bk_3f3 = lms_bk & 0xffff           # backup of LMS primary low word (0x3F3)
    bk_3f4 = lms_bk >> 16              # backup of LMS primary high word (0x3F4)

    m = hashlib.sha384()

    for addr in range(0, SW_PUF_REGION_START_ADDR, 2):
        word = readl(addr)

        if addr == RBP_START + 0x2:          # 0x3E2: OR bk_3e3 into high half (word 0x3E3)
            word = (word | (bk_3e3 << 16)) & 0xFFFFFFFF
        elif addr == RBP_START + 0x12:       # 0x3F2: OR bk_3f2 (lo) and bk_3f3 (hi)
            word = (word | bk_3f2 | (bk_3f3 << 16)) & 0xFFFFFFFF
        elif addr == RBP_START + 0x14:       # 0x3F4: OR bk_3f4 into lo, zero hi (0x3F5)
            word = (word | bk_3f4) & 0xFFFF
        elif RBP_START + 0x16 <= addr < 0x400:  # 0x3F6–0x3FE: backup zone, zero all
            word = 0
        elif 0x420 < addr < 0x42E:          # 0x422–0x42C: STRAP (SCU strap stash covers)
            word = 0

        m.update(struct.pack('<I', word))

    return m.hexdigest()


def extend_pcr(pcr_value, measurement_hex):
    measurement_bytes = bytes.fromhex(measurement_hex)
    return hashlib.sha384(pcr_value + measurement_bytes).digest()


def main():
    args = parse_args()

    fw_hashes, fw_padding = calc_fw(args.fw, os.path.expanduser(args.image_dir))
    efus_hash = calc_efuse(args.efuse)
    stra_hash = calc_hwstrap(args.hwstrap)
    otpm_hash = calc_otp_v10(args.otp)

    result = {}

    for k, v in fw_hashes.items():
        result[k] = v

    if fw_padding:
        result["PADDING_INFO"] = fw_padding

    result["OTPM"] = otpm_hash
    result["STRA"] = stra_hash
    result["EFUS"] = efus_hash

    # PCR31: stash order is OTPM -> STRA -> EFUS (same as v9 but with backup-aware OTP hash)
    pcr31 = b'\x00' * 48

    if "FMC" not in fw_hashes:
        pcr31 = extend_pcr(pcr31, otpm_hash)
        pcr31 = extend_pcr(pcr31, stra_hash)
        pcr31 = extend_pcr(pcr31, efus_hash)

    for k, v in fw_hashes.items():
        if k == "KERNEL":
            for _ in range(3):
                pcr31 = extend_pcr(pcr31, v)
        else:
            pcr31 = extend_pcr(pcr31, v)
            if k == "FMC":
                pcr31 = extend_pcr(pcr31, otpm_hash)
                pcr31 = extend_pcr(pcr31, stra_hash)
                pcr31 = extend_pcr(pcr31, efus_hash)

    result["PCR31"] = pcr31.hex()

    with open(args.output, 'w') as f:
        json.dump(result, f, indent=4)
        f.write('\n')


if __name__ == '__main__':
    main()
