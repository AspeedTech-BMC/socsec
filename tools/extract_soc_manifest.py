#!/usr/bin/python3

import struct
import argparse
import sys

def extract_soc_manifest(input_file, output_manifest_file):
    try:
        with open(input_file, 'rb') as f:
            data = f.read()

        # Parse header to locate SoC Manifest (identifier 0x2)
        header_offset = 0x1C  # Offset for identifier
        location_offset = 0x20  # Offset for Image Location Offset
        size_offset = 0x24  # Offset for Size

        identifier = struct.unpack('<I', data[header_offset:header_offset + 4])[0]
        if identifier != 0x2:
            raise ValueError("SoC Manifest identifier not found.")

        image_location = struct.unpack('<I', data[location_offset:location_offset + 4])[0]
        image_size = struct.unpack('<I', data[size_offset:size_offset + 4])[0]

        soc_manifest = data[image_location:image_location + image_size]

        with open(output_manifest_file, 'wb') as f:
            f.write(soc_manifest)

        print(f"Successfully extracted SoC Manifest to {output_manifest_file}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

def extract_manifest_vendor_data(soc_manifest_file, output_vendor_data_file):
    try:
        with open(soc_manifest_file, 'rb') as f:
            soc_manifest = f.read()

        # Extract fields for manifest vendor data tbs
        manifest_version_offset = 8
        manifest_flags_offset = 16
        manifest_vendor_ecc384_key_offset = 20
        manifest_vendor_lms_key_offset = 116

        manifest_version = soc_manifest[manifest_version_offset:manifest_version_offset + 4]
        manifest_flags = soc_manifest[manifest_flags_offset:manifest_flags_offset + 4]
        manifest_vendor_ecc384_key = soc_manifest[manifest_vendor_ecc384_key_offset:manifest_vendor_ecc384_key_offset + 96]
        manifest_vendor_lms_key = soc_manifest[manifest_vendor_lms_key_offset:manifest_vendor_lms_key_offset + 48]

        vendor_data = manifest_version + manifest_flags + manifest_vendor_ecc384_key + manifest_vendor_lms_key

        with open(output_vendor_data_file, 'wb') as f:
            f.write(vendor_data)

        print(f"Successfully extracted manifest vendor data tbs to {output_vendor_data_file}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

def extract_manifest_owner_data(soc_manifest_file, output_owner_data_file):
    try:
        with open(soc_manifest_file, 'rb') as f:
            soc_manifest = f.read()

        # Extract fields for manifest owner data
        manifest_owner_ecc384_key_offset = 0x758
        manifest_owner_lms_key_offset = manifest_owner_ecc384_key_offset + 96

        manifest_owner_ecc384_key = soc_manifest[manifest_owner_ecc384_key_offset:manifest_owner_ecc384_key_offset + 96]
        manifest_owner_lms_key = soc_manifest[manifest_owner_lms_key_offset:manifest_owner_lms_key_offset + 48]

        owner_data = manifest_owner_ecc384_key + manifest_owner_lms_key

        with open(output_owner_data_file, 'wb') as f:
            f.write(owner_data)

        print(f"Successfully extracted manifest owner data to {output_owner_data_file}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

def extract_manifest2_owner_data(soc_manifest_file, output_owner_data_file):
    try:
        with open(soc_manifest_file, 'rb') as f:
            soc_manifest = f.read()

        # Extract fields for manifest2 owner data
        manifest_version_offset = 8
        svn_offset = 12
        manifest_flags_offset = 16
        manifest_owner_ecc384_key_offset = 0x758
        manifest_owner_lms_key_offset = manifest_owner_ecc384_key_offset + 96

        manifest_version = soc_manifest[manifest_version_offset:manifest_version_offset + 4]
        svn = soc_manifest[svn_offset:svn_offset + 4]
        manifest_flags = soc_manifest[manifest_flags_offset:manifest_flags_offset + 4]
        manifest_owner_ecc384_key = soc_manifest[manifest_owner_ecc384_key_offset:manifest_owner_ecc384_key_offset + 96]
        manifest_owner_lms_key = soc_manifest[manifest_owner_lms_key_offset:manifest_owner_lms_key_offset + 48]

        owner_data = manifest_version + svn + manifest_flags + manifest_owner_ecc384_key + manifest_owner_lms_key

        with open(output_owner_data_file, 'wb') as f:
            f.write(owner_data)

        print(f"Successfully extracted manifest2 owner data to {output_owner_data_file}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Extract SoC Manifest and manifest vendor data tbs from input file."
    )
    parser.add_argument("input_file", help="Path to the input file containing the header and images.")
    parser.add_argument("output_manifest_file", help="Path to write the extracted SoC Manifest.")
    parser.add_argument("output_vendor_data_file", help="Path to write the extracted manifest vendor data tbs.")
    parser.add_argument("output_owner_data_file", help="Path to write the extracted manifest owner data tbs.")
    parser.add_argument("output_manifest2_owner_data_file", help="Path to write the extracted manifest2 owner data tbs.")

    args = parser.parse_args()

    extract_soc_manifest(args.input_file, args.output_manifest_file)
    extract_manifest_vendor_data(args.output_manifest_file, args.output_vendor_data_file)
    extract_manifest_owner_data(args.output_manifest_file, args.output_owner_data_file)
    extract_manifest2_owner_data(args.output_manifest_file, args.output_manifest2_owner_data_file)

if __name__ == "__main__":
    main()
