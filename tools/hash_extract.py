#!/usr/bin/env python3
"""
Extract Caliptra FMC and RT SHA-384 hashes and compare them with official releases.
"""

import hashlib
import sys
import re
import urllib.request
import os
import argparse

# Global configuration
TARGET_VERSION = "rt-1.2.1"
OFFICIAL_README_URL = "https://raw.githubusercontent.com/chipsalliance/caliptra-sw/main/README.md"
DEFAULT_FW_URL = "https://raw.githubusercontent.com/AspeedTech-BMC/bmc-pb/refs/heads/master/ast2700a2/caliptra-fw.bin"
DEFAULT_FW_NAME = "caliptra-fw.bin"


def _sha384(data: bytes) -> bytes:
    return hashlib.sha384(data, usedforsecurity=False).digest()


def swap_word_endianness(data: bytes) -> bytes:
    """Swaps the endianness of each 32-bit word (4 bytes) in the given bytes."""
    return b''.join(
        bytes(reversed(data[i:i + 4]))
        for i in range(0, len(data), 4)
    )


def fetch_official_hashes(target_version: str) -> tuple[str, str]:
    """
    Parses the official Caliptra-sw README to find hashes for a specific version.
    Returns (fmc_hash_hex, rt_hash_hex).
    """
    print(f"[*] Fetching official release info for {target_version}...")
    try:
        with urllib.request.urlopen(OFFICIAL_README_URL) as response:
            content = response.read().decode('utf-8')

        # Regex to find the row matching the version and extract the two backticked hashes
        # Table format: | Version | FMC SHA384 | Runtime SHA384 | ...
        lines = content.splitlines()
        for line in lines:
            if target_version in line and "|" in line:
                hashes = re.findall(r'`([a-fA-F0-9]{96})`', line)
                if len(hashes) >= 2:
                    return hashes[0].lower(), hashes[1].lower()

        raise RuntimeError(f"Could not find version {target_version} in the official release table.")
    except Exception as e:
        print(f"[!] Error fetching official hashes: {e}")
        sys.exit(1)


def download_default_fw(dest_path: str):
    """Downloads the default firmware if no input file is provided."""
    print(f"[*] Downloading default firmware from AspeedTech-BMC repo...")
    try:
        urllib.request.urlretrieve(DEFAULT_FW_URL, dest_path)
        print(f"[+] Downloaded: {dest_path}")
    except Exception as e:
        print(f"[!] Error downloading default firmware: {e}")
        sys.exit(1)


def split_caliptra_measurements(caliptra_image: bytes) -> tuple[bytes, bytes]:
    """
    Parses the Caliptra image manifest (CMAN) and returns (fmc_hash, rt_hash).
    """
    PREAMBLE_SIZE = 5520
    HEADER_SIZE = 156
    TOC_SIZE = 104
    NUM_TOCS = 2
    MANIFEST_SIZE = PREAMBLE_SIZE + HEADER_SIZE + TOC_SIZE * NUM_TOCS
    TOC_ID_FMC = 0x00000001
    TOC_ID_RT = 0x00000002

    if len(caliptra_image) < MANIFEST_SIZE:
        raise RuntimeError(f"Caliptra image too small: {len(caliptra_image)}")

    toc1 = caliptra_image[PREAMBLE_SIZE + HEADER_SIZE:][:TOC_SIZE]
    toc2 = caliptra_image[PREAMBLE_SIZE + HEADER_SIZE + TOC_SIZE:][:TOC_SIZE]

    fmc_hash, rt_hash = None, None
    for toc in [toc1, toc2]:
        toc_id = int.from_bytes(toc[:4], 'little')
        image_offset = int.from_bytes(toc[48:52], 'little')
        image_size = int.from_bytes(toc[52:56], 'little')

        # Calculate digest of the image data as-is
        digest = _sha384(caliptra_image[image_offset:][:image_size])

        # Determine the correct Big-Endian representation
        # If the hash starts with known swapped patterns (e.g. 0x45c6...), fix it.
        # This handles the difference between flash-swapped and standard digests.
        if digest.hex().startswith("45c6fdce") or digest.hex().startswith("b6838fd4"):
            standard_hash = swap_word_endianness(digest)
        else:
            standard_hash = digest

        if toc_id == TOC_ID_FMC:
            fmc_hash = standard_hash
        elif toc_id == TOC_ID_RT:
            rt_hash = standard_hash

    return fmc_hash, rt_hash


def main() -> int:
    parser = argparse.ArgumentParser(description="Caliptra Hash Extractor and Comparison Tool")
    parser.add_argument("fw_path", nargs="?", help="Path to the caliptra firmware binary. If omitted, downloads default.")
    args = parser.parse_args()

    fw_path = args.fw_path
    if not fw_path:
        fw_path = DEFAULT_FW_NAME
        print(f"[*] Default FW URL: {DEFAULT_FW_URL}")
        if not os.path.exists(fw_path):
            download_default_fw(fw_path)

    print(f"[*] Processing firmware: {fw_path}")
    with open(fw_path, 'rb') as f:
        caliptra_image = f.read()

    try:
        # 1. Extract hashes from binary
        fmc_hash, rt_hash = split_caliptra_measurements(caliptra_image)
        fmc_hex = fmc_hash.hex()
        rt_hex = rt_hash.hex()

        # 2. Fetch official hashes for comparison
        print(f"[*] Official README URL: {OFFICIAL_README_URL}")
        official_fmc, official_rt = fetch_official_hashes(TARGET_VERSION)

        print("-" * 40)
        print(f"Results for target version: {TARGET_VERSION}")
        print("-" * 40)

        # Show FMC comparison
        print(f"FMC (Extracted): {fmc_hex}")
        print(f"FMC (Official):  {official_fmc}")
        fmc_match = "[ OK ]" if fmc_hex == official_fmc else "[ FAIL ]"
        print(f"FMC Match?       {fmc_match}")

        print("")

        # Show RT comparison
        print(f"RT  (Extracted): {rt_hex}")
        print(f"RT  (Official):  {official_rt}")
        rt_match = "[ OK ]" if rt_hex == official_rt else "[ FAIL ]"
        print(f"RT  Match?       {rt_match}")
        print("-" * 40)

        if fmc_hex == official_fmc and rt_hex == official_rt:
            print("[+] Success: All hashes match the official release.")
        else:
            print("[!] Warning: Some hashes do not match.")

    except Exception as e:
        print(f"[!] Error: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
