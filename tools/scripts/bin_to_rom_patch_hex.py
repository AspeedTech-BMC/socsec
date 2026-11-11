#!/usr/bin/env python3
"""Convert a ROM patch binary file to the hex string format for user_region ROM_patch in OTP JSONC config."""

import argparse
import sys
from pathlib import Path

MAX_BITS = 32768 + 10240
MAX_BYTES = MAX_BITS // 8  # 5376 bytes


def bin_to_rom_patch_hex(bin_path: Path) -> str:
    data = bin_path.read_bytes()

    if len(data) > MAX_BYTES:
        print(f"Error: binary size {len(data)} bytes exceeds ROM_patch limit of {MAX_BYTES} bytes ({MAX_BITS} bits)",
              file=sys.stderr)
        sys.exit(1)

    # Interpret bytes as little-endian integer — matches make_config_region_v2's bitarray layout
    value = int.from_bytes(data, byteorder='little')
    return f"0x{value:x}"


def main():
    parser = argparse.ArgumentParser(
        description="Convert ROM patch binary to hex string for OTP JSONC user_region ROM_patch field"
    )
    parser.add_argument("bin_file", type=Path, help="Input ROM patch binary file (e.g. rom_patch_user.bin)")
    args = parser.parse_args()

    if not args.bin_file.exists():
        print(f"Error: file not found: {args.bin_file}", file=sys.stderr)
        sys.exit(1)

    hex_str = bin_to_rom_patch_hex(args.bin_file)
    size = args.bin_file.stat().st_size
    print(f"// {args.bin_file.name}: {size} bytes ({size * 8} bits)")
    print(f'"ROM_patch": "{hex_str}"')


if __name__ == "__main__":
    main()
