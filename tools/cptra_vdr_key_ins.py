#!/usr/bin/python3

import binascii
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
import argparse  # Added for argument parsing

# DEBUG FLAG to dump debug information
DEBUG = False

# LMS Flags
LMS_SUPPORTED = True

VEN_ECC_PUB_KEYS_NAME = [
    "S2700_ECC_Public_Key_1.pem",
    "S2700_ECC_Public_Key_2.pem",
    "S2700_ECC_Public_Key_3.pem",
    "S2700_ECC_Public_Key_4.pem",
]

VEN_LMS_PUB_KEYS_NAME = [
    "test_oem_dss_lms_key_0.pub",
    "test_oem_dss_lms_key_1.pub",
    "test_oem_dss_lms_key_2.pub",
    "test_oem_dss_lms_key_3.pub",
    "test_oem_dss_lms_key_0.pub",
    "test_oem_dss_lms_key_1.pub",
    "test_oem_dss_lms_key_2.pub",
    "test_oem_dss_lms_key_3.pub",
    "test_oem_dss_lms_key_0.pub",
    "test_oem_dss_lms_key_1.pub",
    "test_oem_dss_lms_key_2.pub",
    "test_oem_dss_lms_key_3.pub",
    "test_oem_dss_lms_key_0.pub",
    "test_oem_dss_lms_key_1.pub",
    "test_oem_dss_lms_key_2.pub",
    "test_oem_dss_lms_key_3.pub",
    "test_oem_dss_lms_key_0.pub",
    "test_oem_dss_lms_key_1.pub",
    "test_oem_dss_lms_key_2.pub",
    "test_oem_dss_lms_key_3.pub",
    "test_oem_dss_lms_key_0.pub",
    "test_oem_dss_lms_key_1.pub",
    "test_oem_dss_lms_key_2.pub",
    "test_oem_dss_lms_key_3.pub",
    "test_oem_dss_lms_key_0.pub",
    "test_oem_dss_lms_key_1.pub",
    "test_oem_dss_lms_key_2.pub",
    "test_oem_dss_lms_key_3.pub",
    "test_oem_dss_lms_key_0.pub",
    "test_oem_dss_lms_key_1.pub",
    "test_oem_dss_lms_key_2.pub",
    "test_oem_dss_lms_key_3.pub",
]

ecc_public_key_size = 96
num_ecc_public_keys = 4
lms_public_key_size = 48
num_lms_public_keys = 32
ecc_key_idx_size = 4
lms_key_idx_size = 4
ecc_signature_size = 96
lms_signature_size = 1620
owner_num_ecc_public_keys = 1
owner_num_lms_public_keys = 1

ecc_public_key_offset = 0x8
lms_public_key_offset = ecc_public_key_offset + ecc_public_key_size * num_ecc_public_keys                                       # 0x188
ecc_signature_offset = lms_public_key_offset + lms_public_key_size * num_lms_public_keys + ecc_key_idx_size + lms_key_idx_size  # 0x790
lms_signature_offset = ecc_signature_offset + ecc_signature_size                                                                # 0x7f0

owner_ecc_public_key_offset = lms_signature_offset + lms_signature_size                                                         # 0x7f0 + 0x654 = 0xe44
owner_lms_public_key_offset = owner_ecc_public_key_offset + ecc_public_key_size * owner_num_ecc_public_keys                     # 0xe44 + 0x60 = 0xea4
owner_ecc_signature_offset = owner_lms_public_key_offset + lms_public_key_size * owner_num_lms_public_keys                      # 0xea4 + 0x30 = 0xed4
owner_lms_signature_offset = owner_ecc_signature_offset + ecc_signature_size                                                    # 0xed4 + 0x60 = 0xf34
preamble_reserved_offset = owner_lms_signature_offset + lms_signature_size                                                      # 0xf34 + 0x654 = 0x1588

def load_public_key(pem_path):
    with open(pem_path, 'rb') as pem_file:
        pem_data = pem_file.read()
    public_key = serialization.load_pem_public_key(
        pem_data, backend=default_backend())
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key
    else:
        raise ValueError("The provided key is not an ECDSA public key")

def extract_xy_from_public_key(public_key):
    numbers = public_key.public_numbers()
    x = '{:064x}'.format(numbers.x)
    y = '{:064x}'.format(numbers.y)
    return x, y

def convert_endianness(value):
    if len(value) % 2 != 0:
        value = '0' + value
#    return value
    value_bytes = binascii.unhexlify(value)
    reversed_bytes = bytearray()
    for i in range(0, len(value_bytes), 4):
        reversed_bytes.extend(value_bytes[i:i+4][::-1])
    return binascii.hexlify(reversed_bytes).decode()

def replace_in_file(file_path, offset, value):
    with open(file_path, 'r+b') as f:
        f.seek(offset)
        f.write(binascii.unhexlify(value))

def load_signature(ecc_signature_file):
    with open(ecc_signature_file, 'rb') as sig_file:
        base64_signature = sig_file.read()
        signature = base64.b64decode(base64_signature)
    return signature

def extract_rs_from_signature(signature):
    r, s = decode_dss_signature(signature)
    r_hex = '{:064x}'.format(r)
    s_hex = '{:064x}'.format(s)
    return r_hex, s_hex

def main():
    # Replace command-line argument handling with ArgumentParser
    parser = argparse.ArgumentParser(description="Process ECC and LMS signatures and public keys.")
    parser.add_argument("file_path", help="Path to the file to be modified (Caliptra firmware image)")
    parser.add_argument("key_directory", help="Directory containing the pem/pub files")
    parser.add_argument("vendor_ecc_sig_file", help="Path to the ECC signature file in DER format")
    parser.add_argument("vendor_lms_sig_file", nargs="?", default=None, help="Path to the LMS signature file in binary format (optional)")

    args = parser.parse_args()

    # Assign parsed arguments to variables
    file_path = args.file_path
    key_directory = args.key_directory
    vendor_ecc_sig_file = args.vendor_ecc_sig_file
    vendor_lms_sig_file = args.vendor_lms_sig_file

    # Collect PEM files from the specified directory
    pem_files = [
        key_directory + VEN_ECC_PUB_KEYS_NAME[0],
        key_directory + VEN_ECC_PUB_KEYS_NAME[1],
        key_directory + VEN_ECC_PUB_KEYS_NAME[2],
        key_directory + VEN_ECC_PUB_KEYS_NAME[3],
    ]

    # Extract and convert endianness
    values = []
    for pem_file in pem_files:
        print("Load", pem_file)
        public_key = load_public_key(pem_file)
        x, y = extract_xy_from_public_key(public_key)
        if DEBUG:
            print("Public Key Coordinates:")
            print("x:", x)
            print("y:", y)

        x_endian = convert_endianness(x)
        y_endian = convert_endianness(y)
        values.append(x_endian + y_endian)

    # Combine all values into a single string
    combined_values = ''.join(values)

    # Replace the combined value in the file at offset 0x8
    if DEBUG:
        print("combined_ecc_values", combined_values)
    replace_in_file(file_path, ecc_public_key_offset, combined_values)

    if LMS_SUPPORTED:
        # Load LMS public keys
        lms_public_keys = []
        for i in range(num_lms_public_keys):
            pem_file = key_directory + VEN_LMS_PUB_KEYS_NAME[i]
            print("Load", pem_file)
            with open(pem_file, 'rb') as f:
                # If the file has a .pub extension, skip the first 4 bytes
                if pem_file.endswith('.pub'):
                    f.read(4)
                lms_public_key = f.read()
                lms_public_keys.append(lms_public_key)

        # Convert LMS public keys to hex format
        lms_values = []
        for lms_key in lms_public_keys:
            lms_value = binascii.hexlify(lms_key).decode()
            lms_values.append(lms_value)

        # Combine all LMS public keys into a single string
        combined_lms_values = ''.join(lms_values)
        if DEBUG:
            print("combined_lms_values", combined_lms_values)

        # Replace the combined LMS public keys in the file at the specified offset
        replace_in_file(file_path, lms_public_key_offset, combined_lms_values)
    else:
        print("LMS is not supported. Skipping LMS public key replacement.")
        # Replace LMS public keys with all zeros
        lms_value = '0' * (lms_public_key_size * 2)  # Each byte is represented by 2 hex digits

        for i in range(num_lms_public_keys):
            current_offset = lms_public_key_offset + (i * lms_public_key_size)
            replace_in_file(file_path, current_offset, lms_value)

    print("Public keys have been replaced in the file.")

    # Extract and convert endianness
    signature = load_signature(vendor_ecc_sig_file)
    r, s = extract_rs_from_signature(signature)
    if DEBUG:
        print("Extracted Signature Coordinates:")
        print("r", r)
        print("s", s)

    r_endian = convert_endianness(r)
    s_endian = convert_endianness(s)

    # Combine r and s
    combined_rs = r_endian + s_endian
    if DEBUG:
        print("combined_ecc_signature", combined_rs)

    # Replace the combined value in the file at offset 0x790
    replace_in_file(file_path, ecc_signature_offset, combined_rs)
    print("ECC Signature's r and s have been replaced in the file.")

    if LMS_SUPPORTED and vendor_lms_sig_file:
        # Load LMS signature from the specified file
        with open(vendor_lms_sig_file, 'rb') as lms_sig_file:
            lms_signature = lms_sig_file.read()

        # Convert LMS signature to hex format
        lms_signature_hex = binascii.hexlify(lms_signature).decode()
        if DEBUG:
            print("lms_signature_hex", lms_signature_hex)

        # Replace the LMS signature in the file at the specified offset
        replace_in_file(file_path, lms_signature_offset, lms_signature_hex)
        print("LMS signature has been replaced in the file.")
    # elif LMS_SUPPORTED:
    #     print("LMS signature file not provided. Replacing with zeros.")
    #     # Replace LMS signature with all zeros
    #     lms_value = '0' * (lms_signature_size * 2)  # Each byte is represented by 2 hex digits
    #     replace_in_file(file_path, lms_signature_offset, lms_value)
    else:
        print("LMS is not supported. Skipping LMS signature replacement.")

if __name__ == "__main__":
    main()
