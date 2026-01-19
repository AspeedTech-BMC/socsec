#!/usr/bin/python3

import binascii
import argparse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ecc_public_key_offset = 0xe44   # Offset for the Owner ECC public key in the firmware image
lms_public_key_offset = 0xea4   # Offset for the Owner LMS public key in the firmware image
ecc_signature_offset = 0xed4    # Offset for the Owner ECC signature in the firmware image
lms_signature_offset = 0xf34    # Offset for the Owner LMS signature in the firmware image

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
    value_bytes = binascii.unhexlify(value)
    reversed_bytes = bytearray()
    for i in range(0, len(value_bytes), 4):
        reversed_bytes.extend(value_bytes[i:i+4][::-1])
    return binascii.hexlify(reversed_bytes).decode()

def replace_in_file(file_path, offset, value):
    with open(file_path, 'r+b') as f:
        f.seek(offset)
        f.write(binascii.unhexlify(value))

def load_signature(signature_file):
    with open(signature_file, 'rb') as sig_file:
        signature = sig_file.read()  # Directly read the binary content
    return signature

def extract_rs_from_signature(signature):
    try:
        r, s = decode_dss_signature(signature)
    except ValueError as e:
        raise ValueError(f"Error parsing ASN.1 value: {e}. Ensure the signature is in DER format.")
    r_hex = '{:064x}'.format(r)
    s_hex = '{:064x}'.format(s)
    return r_hex, s_hex

def main():
    parser = argparse.ArgumentParser(description="Insert ECC and LMS keys and signatures into a firmware image.")
    parser.add_argument("file_path", help="Path to the firmware image file")
    parser.add_argument("--ecc_key", required=True, help="Path to the ECC public key file in PEM format")
    parser.add_argument("--lms_key", required=False, help="Path to the LMS public key file in .pub format")
    parser.add_argument("--ecc_sig", required=True, help="Path to the ECC signature file in DER format")
    parser.add_argument("--lms_sig", required=False, help="Path to the LMS signature file in binary format")

    args = parser.parse_args()

    # Load and process ECC public key
    public_key = load_public_key(args.ecc_key)
    x, y = extract_xy_from_public_key(public_key)
    x_endian = convert_endianness(x)
    y_endian = convert_endianness(y)
    combined_ecc_key = x_endian + y_endian

    # Replace ECC public key in the file
    replace_in_file(args.file_path, ecc_public_key_offset, combined_ecc_key)

    # Load and process LMS public key (optional)
    if args.lms_key:
        with open(args.lms_key, 'rb') as lms_file:
            lms_file.read(4)  # Skip the first 4 bytes
            lms_key_data = lms_file.read()
        lms_key_hex = binascii.hexlify(lms_key_data).decode()
        # Replace LMS public key in the file
        replace_in_file(args.file_path, lms_public_key_offset, lms_key_hex)

    # Load and process ECC signature
    ecc_signature = load_signature(args.ecc_sig)
    r, s = extract_rs_from_signature(ecc_signature)
    r_endian = convert_endianness(r)
    s_endian = convert_endianness(s)
    combined_ecc_signature = r_endian + s_endian

    # Replace ECC signature in the file
    replace_in_file(args.file_path, ecc_signature_offset, combined_ecc_signature)

    # Load and process LMS signature (optional)
    if args.lms_sig:
        with open(args.lms_sig, 'rb') as lms_sig_file:
            lms_signature_data = lms_sig_file.read()
        lms_signature_hex = binascii.hexlify(lms_signature_data).decode()
        # Replace LMS signature in the file
        replace_in_file(args.file_path, lms_signature_offset, lms_signature_hex)

    print("Keys and signatures have been successfully inserted into the firmware image.")

if __name__ == "__main__":
    main()
