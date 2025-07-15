#!/usr/bin/python3

import argparse
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from pyhsslms import LmsPublicKey, LmsSignature
import hashlib

MFST_VENDOR_TBS = "manifest_vendor_data_tbs.bin"
MFST_OWNER_TBS = "manifest_owner_data_tbs.bin"
MFST2_OWNER_TBS = "manifest2_owner_data_tbs.bin"

DEBUG = False  # Set to True to enable debug output

# Function to load a public key from a PEM file
def load_public_key(pem_path):
    with open(pem_path, 'rb') as pem_file:
        pem_data = pem_file.read()
    public_key = serialization.load_pem_public_key(
        pem_data, backend=default_backend())
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key
    else:
        raise ValueError("The provided key is not an ECDSA public key")

# Revert endianness for each 4 bytes in public_key_bytes
def revert_endian_4bytes(data):
    return b''.join(data[i:i+4][::-1] for i in range(0, len(data), 4))

# Function to verify an ECC signature
def verify_ecc_signature(public_key, data, signature):
    try:

        signature = revert_endian_4bytes(signature)
        # r, s = decode_dss_signature(signature)
        # Extract r and s from the signature_bytes
        r = int.from_bytes(signature[:48], byteorder='big')
        s = int.from_bytes(signature[48:], byteorder='big')

        # Convert r and s to DER format
        der_signature = encode_dss_signature(r, s)
        public_key.verify(
            der_signature,
            data,
            ec.ECDSA(hashes.SHA384())
        )
        return True
    except Exception as e:
        print(f"ECC signature verification failed: {e}")
        return False

# Function to verify an LMS signature
def verify_lms_signature(public_key_path, data, signature):
    try:
        with open(public_key_path, 'rb') as f:
            public_key_bytes = f.read()
            if len(public_key_bytes) == 52:
                public_key_bytes = public_key_bytes[4:]  # Adjust for LMS public key format

        # Deserialize the public key using the correct constructors
        public_key = LmsPublicKey.deserialize(public_key_bytes)

        data = hashlib.sha384(data).digest()

        if DEBUG:
            print(public_key.prettyPrint())

        if DEBUG:
            sig = LmsSignature.deserialize(signature)
            print(sig.prettyPrint())

        # Verify the signature using the public key and signed data
        return public_key.verify(data, signature)

    except Exception as e:
        print(f"Verification failed: {e}")
        return False

# Main function
def main():
    parser = argparse.ArgumentParser(description="Verify signatures in soc_manifest.bin.")
    parser.add_argument("manifest", help="Path to the soc_manifest.bin file")
    parser.add_argument("vendor_ecc_key", help="Path to the vendor ECC public key")
    parser.add_argument("owner_ecc_key", help="Path to the owner ECC public key")
    parser.add_argument("--vendor_lms_key", help="Path to the vendor LMS public key (optional)", default=None)
    parser.add_argument("--owner_lms_key", help="Path to the owner LMS public key (optional)", default=None)

    args = parser.parse_args()

    # Load the public keys
    vendor_ecc_key = load_public_key(args.vendor_ecc_key)
    owner_ecc_key = load_public_key(args.owner_ecc_key)

    # Read the manifest file
    with open(args.manifest, 'rb') as f:
        manifest_data = f.read()

    # Extract data and signatures (adjust offsets as needed)
    with open(MFST_VENDOR_TBS, 'rb') as f:
        vendor_data = f.read()

    with open(MFST_OWNER_TBS, 'rb') as f:
        owner_data = f.read()

    with open(MFST2_OWNER_TBS, 'rb') as f:
        owner2_data = f.read()

    ecc_sig_offset = 0xa4
    lms_sig_offset = ecc_sig_offset + 0x60

    vendor_ecc_sig = manifest_data[ecc_sig_offset:ecc_sig_offset + 96]
    vendor_lms_sig = manifest_data[lms_sig_offset:lms_sig_offset + 1620]

    ecc_sig_offset = 0x7e8
    lms_sig_offset = ecc_sig_offset + 0x60
    owner_ecc_sig = manifest_data[ecc_sig_offset:ecc_sig_offset + 96]
    owner_lms_sig = manifest_data[lms_sig_offset:lms_sig_offset + 1620]

    ecc_sig_offset = 0xe9c
    lms_sig_offset = ecc_sig_offset + 0x60
    owner2_ecc_sig = manifest_data[ecc_sig_offset:ecc_sig_offset + 96]
    owner2_lms_sig = manifest_data[lms_sig_offset:lms_sig_offset + 1620]

    # Verify vendor ECC signature
    print("Verifying MFST vendor ECC signature...")
    if verify_ecc_signature(vendor_ecc_key, vendor_data, vendor_ecc_sig):
        print("MFST Vendor ECC signature verification succeeded.")
    else:
        print("MFST Vendor ECC signature verification failed.")
        exit(1)

    # Verify owner ECC signature
    print("Verifying MFST owner ECC signature...")
    if verify_ecc_signature(owner_ecc_key, owner_data, owner_ecc_sig):
        print("MFST Owner ECC signature verification succeeded.")
    else:
        print("MFST Owner ECC signature verification failed.")
        exit(1)

    # Verify owner2 ECC signature
    print("Verifying MFST2 owner ECC signature...")
    if verify_ecc_signature(owner_ecc_key, owner2_data, owner2_ecc_sig):
        print("MFST2 Owner ECC signature verification succeeded.")
    else:
        print("MFST2 Owner ECC signature verification failed.")
        exit(1)

    # LMS signature verification can be added here if needed
    # Verify vendor LMS signature
    if args.vendor_lms_key:
        print("Verifying MFST vendor LMS signature...")
        if verify_lms_signature(args.vendor_lms_key, vendor_data, vendor_lms_sig):
            print("MFST Vendor LMS signature verification succeeded.")
        else:
            print("MFST Vendor LMS signature verification failed.")
            exit(1)

    # Verify owner LMS signature
    if args.owner_lms_key:
        print("Verifying MFST owner LMS signature...")
        if verify_lms_signature(args.owner_lms_key, owner_data, owner_lms_sig):
            print("MFST Owner LMS signature verification succeeded.")
        else:
            print("MFST Owner LMS signature verification failed.")
            exit(1)

    # Verify owner2 LMS signature
    if args.owner_lms_key:
        print("Verifying MFST2 owner LMS signature...")
        if verify_lms_signature(args.owner_lms_key, owner2_data, owner2_lms_sig):
            print("MFST2 Owner LMS signature verification succeeded.")
        else:
            print("MFST2 Owner LMS signature verification failed.")
            exit(1)

if __name__ == "__main__":
    main()
