#!/usr/bin/python3

import struct
import argparse
import sys

def insert_manifest_owner_sigs(input_manifest_file, ecc_sig_file, lms_sig_file, output_manifest_file):
    try:
        with open(input_manifest_file, 'rb') as f:
            manifest_data = bytearray(f.read())

        with open(ecc_sig_file, 'rb') as f:
            ecc_sig = f.read()
        with open(lms_sig_file, 'rb') as f:
            lms_sig = f.read()

        # Validate sizes
        if len(lms_sig) != 1620:
            raise ValueError("LMS signature must be 1620 bytes.")

        # Parse ECC signature in DER format
        def parse_der_signature(der_data):
            if der_data[0] != 0x30:
                raise ValueError("Invalid DER format: Expected SEQUENCE tag.")

            length = der_data[1]
            r_offset = 2
            r_length = der_data[r_offset + 1]
            r = der_data[r_offset + 2:r_offset + 2 + r_length]

            s_offset = r_offset + 2 + r_length + 1
            s_length = der_data[s_offset]
            s = der_data[s_offset + 1:s_offset + 1 + s_length]

            return r, s

        r, s = parse_der_signature(ecc_sig)

        print("r:", r.hex())
        print("s:", s.hex())

        # Validate sizes of r and s
        if len(r) > 48 and r[0] == 0x00:
            r = r[1:]
        if len(s) > 48 and s[0] == 0x00:
            s = s[1:]
        if len(r) > 48 or len(s) > 48:
            raise ValueError("Invalid ECC signature: r or s exceeds 48 bytes.")

        # Pad r and s to 48 bytes if necessary
        r = r.rjust(48, b'\x00')
        s = s.rjust(48, b'\x00')

        print("r:", r.hex())
        print("s:", s.hex())

        # Reverse endianness for each 4-byte chunk in r and s
        def reverse_endian_4bytes(data):
            if len(data) % 4 != 0:
                raise ValueError("Data length must be a multiple of 4 for endianness reversal.")
            reversed_chunks = [data[i:i+4][::-1] for i in range(0, len(data), 4)]
            return b''.join(reversed_chunks)

        r = reverse_endian_4bytes(r)
        s = reverse_endian_4bytes(s)

        # Combine r and s into the signature
        ecc_sig = r + s

        # Insert signatures into manifest
        ecc_sig_offset = 0x7e8
        lms_sig_offset = ecc_sig_offset + 96

        manifest_data[ecc_sig_offset:ecc_sig_offset + 96] = ecc_sig
        manifest_data[lms_sig_offset:lms_sig_offset + 1620] = lms_sig

        with open(output_manifest_file, 'wb') as f:
            f.write(manifest_data)

        print(f"Successfully inserted signatures into manifest: {output_manifest_file}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Insert manifest owner ECC & LMS keys and signatures into a SoC manifest file."
    )
    parser.add_argument("input_manifest_file", help="Path to the input SoC manifest file.")
    parser.add_argument("ecc_sig_file", help="Path to the ECC signature file.")
    parser.add_argument("lms_sig_file", help="Path to the LMS signature file.")
    parser.add_argument("output_manifest_file", help="Path to write the updated SoC manifest file.")

    args = parser.parse_args()

    insert_manifest_owner_sigs(
        args.input_manifest_file,
        args.ecc_sig_file,
        args.lms_sig_file,
        args.output_manifest_file
    )

if __name__ == "__main__":
    main()
