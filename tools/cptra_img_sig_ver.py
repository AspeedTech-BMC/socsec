import struct
import sys
from pyhsslms import LmsPublicKey
import hashlib
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP384R1
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

# DEBUG FLAG to dump debug information
DEBUG = False

# Constants
VENDOR_ECC_PUBLIC_KEY_START_OFFSET = 0x8
VENDOR_ECC_PUBLIC_KEY_INDEX_OFFSET = 0x788
VENDOR_ECC_SIGNATURE_OFFSET = 0x790
VENDOR_LMS_PUBLIC_KEY_START_OFFSET = 0x188
VENDOR_LMS_PUBLIC_KEY_INDEX_OFFSET = 0x78c
VENDOR_LMS_SIGNATURE_OFFSET = 0x7f0
VENDOR_SIGNED_DATA_SIZE = 0x74

OWNER_ECC_PUBLIC_KEY_START_OFFSET = 0xe44
OWNER_ECC_SIGNATURE_OFFSET = 0xed4
OWNER_LMS_PUBLIC_KEY_START_OFFSET = 0xea4
OWNER_LMS_SIGNATURE_OFFSET = 0xf34
OWNER_SIGNED_DATA_SIZE = 0x9c

LMS_PUBLIC_KEY_SIZE = 48
SIGNED_DATA_OFFSET = 0x1590
LMS_SIGN_LENGTH = 1620          # Assuming LMS signature size is 1620 bytes

ECDSA384_PUBLIC_KEY_SIZE = 96   # Assuming ECDSA384 public key size is 96 bytes
ECDSA384_SIGN_LENGTH = 96       # Assuming ECDSA384 signature size is 96 bytes


def extract_public_key(file_path, start_offset, index, key_size):
    with open(file_path, 'rb') as f:
        # Calculate the offset of the public key
        public_key_offset = start_offset + (index * key_size)
        f.seek(public_key_offset)
        public_key = f.read(key_size)

        # Debug: Print the raw public key bytes
        if DEBUG:
            print("Extracted Public Key:", public_key.hex())
            print("Extracted Public Key Length:", len(public_key))

        return public_key


def extract_lms_signature(file_path, signature_offset, signed_data_offset, signed_data_size):
    with open(file_path, 'rb') as f:
        # Extract the LMS signature
        f.seek(signature_offset)
        signature = f.read(LMS_SIGN_LENGTH)

        # Debug: Print the raw signature bytes
        if DEBUG:
            print("Extracted Signature:", signature.hex())
            print("Extracted Signature Length:", len(signature))

        # Extract the signed data
        f.seek(signed_data_offset)
        signed_data = f.read(signed_data_size)

        # Debug: Print the raw signed data bytes
        if DEBUG:
            print("Extracted Signed Data:", signed_data.hex())
            print("Extracted Signed Data Length:", len(signed_data))

        # Hash the signed data using SHA-384
        signed_data = hashlib.sha384(signed_data).digest()
        if DEBUG:
            print("SHA-384 Hashed Signed Data:", signed_data.hex())
            print("SHA-384 Hash Length:", len(signed_data))

        return signature, signed_data

def verify_lms_signature(public_key_bytes, signature_bytes, signed_data):
    """
    Verifies an LMS signature.

    Args:
        public_key_bytes (bytes): The serialized LMS public key.
        signature_bytes (bytes): The LMS signature.
        signed_data (bytes): The original data that was signed.

    Returns:
        bool: True if the signature is valid, False otherwise.
    """
    try:
        # Deserialize the public key using the correct constructors
        public_key = LmsPublicKey.deserialize(public_key_bytes)

        # Verify the signature using the public key and signed data
        return public_key.verify(signed_data, signature_bytes)

    except Exception as e:
        print(f"Verification failed: {e}")
        return False

def extract_ecdsa384_signature(file_path, signature_offset, signed_data_offset, signed_data_size):
    with open(file_path, 'rb') as f:
        f.seek(signature_offset)
        signature = f.read(ECDSA384_SIGN_LENGTH)

        if DEBUG:
            print("Extracted ECDSA384 Signature:", signature.hex())
            print("Extracted ECDSA384 Signature Length:", len(signature))

        f.seek(signed_data_offset)
        signed_data = f.read(signed_data_size)

        if DEBUG:
            print("Extracted Signed Data:", signed_data.hex())
            print("Extracted Signed Data Length:", len(signed_data))

        # signed_data = hashlib.sha384(signed_data).digest()
        # if DEBUG:
        #     print("SHA-384 Hashed Signed Data:", signed_data.hex())

        return signature, signed_data


def verify_ecdsa384_signature(public_key_bytes, signature_bytes, signed_data):
    try:
        # Revert endianness for each 4 bytes in public_key_bytes
        def revert_endian_4bytes(data):
            return b''.join(data[i:i+4][::-1] for i in range(0, len(data), 4))

        pubkey_bytes_fixed = revert_endian_4bytes(public_key_bytes)

        if DEBUG:
            print(f"Qx: {pubkey_bytes_fixed[:48].hex()}")
            print(f"Qy: {pubkey_bytes_fixed[48:].hex()}")

        # Extract Qx and Qy from the fixed public_key_bytes
        Qx = int.from_bytes(pubkey_bytes_fixed[:48], byteorder='big')
        Qy = int.from_bytes(pubkey_bytes_fixed[48:], byteorder='big')
        
        # Construct the public key from Qx and Qy
        public_numbers = EllipticCurvePublicNumbers(Qx, Qy, SECP384R1())
        public_key = public_numbers.public_key()

        signature_bytes = revert_endian_4bytes(signature_bytes)

        # Extract r and s from the signature_bytes
        r = int.from_bytes(signature_bytes[:48], byteorder='big')
        s = int.from_bytes(signature_bytes[48:], byteorder='big')

        # Convert r and s to DER format
        der_signature = encode_dss_signature(r, s)

        if DEBUG:
            print(f"Signature r: {r:#0{98}x}")
            print(f"Signature s: {s:#0{98}x}")
            print(f"DER-encoded Signature: {der_signature.hex()}")

        # Verify the signature
        public_key.verify(
            der_signature,
            signed_data,
            ec.ECDSA(hashes.SHA384())
        )
        return True

    except Exception as e:
        print(f"ECDSA384 Verification failed: {e}")
        return False


def main():
    if len(sys.argv) != 2:
        print("Usage: python lms_verification.py <source_file>")
        sys.exit(1)

    source_file = sys.argv[1]

    try:
        # Vendor ECDSA384 verification
        vendor_index = None
        with open(source_file, 'rb') as f:
            f.seek(VENDOR_ECC_PUBLIC_KEY_INDEX_OFFSET)
            vendor_index = struct.unpack('<I', f.read(4))[0]

        vendor_public_key = extract_public_key(
            source_file, VENDOR_ECC_PUBLIC_KEY_START_OFFSET, vendor_index, ECDSA384_PUBLIC_KEY_SIZE)

        vendor_signature, vendor_signed_data = extract_ecdsa384_signature(
            source_file, VENDOR_ECC_SIGNATURE_OFFSET, SIGNED_DATA_OFFSET, VENDOR_SIGNED_DATA_SIZE)

        if verify_ecdsa384_signature(vendor_public_key, vendor_signature, vendor_signed_data):
            print("Caliptra Vendor ECDSA384 signature verification succeeded.")
        else:
            print("Caliptra Vendor ECDSA384 signature verification failed.")

        # Owner ECDSA384 verification
        owner_public_key = extract_public_key(
            source_file, OWNER_ECC_PUBLIC_KEY_START_OFFSET, 0, ECDSA384_PUBLIC_KEY_SIZE)

        owner_signature, owner_signed_data = extract_ecdsa384_signature(
            source_file, OWNER_ECC_SIGNATURE_OFFSET, SIGNED_DATA_OFFSET, OWNER_SIGNED_DATA_SIZE)

        if verify_ecdsa384_signature(owner_public_key, owner_signature, owner_signed_data):
            print("Caliptra Owner ECDSA384 signature verification succeeded.")
        else:
            print("Caliptra Owner ECDSA384 signature verification failed.")

        # Vendor LMS verification
        vendor_index = None
        with open(source_file, 'rb') as f:
            f.seek(VENDOR_LMS_PUBLIC_KEY_INDEX_OFFSET)
            vendor_index = struct.unpack('<I', f.read(4))[0]

        vendor_public_key = extract_public_key(
            source_file, VENDOR_LMS_PUBLIC_KEY_START_OFFSET, vendor_index, LMS_PUBLIC_KEY_SIZE)

        vendor_signature, vendor_signed_data = extract_lms_signature(
            source_file, VENDOR_LMS_SIGNATURE_OFFSET, SIGNED_DATA_OFFSET, VENDOR_SIGNED_DATA_SIZE)

        if verify_lms_signature(vendor_public_key, vendor_signature, vendor_signed_data):
            print("Caliptra Vendor LMS signature verification succeeded.")
        else:
            print("Caliptra Vendor LMS signature verification failed.")

        # Owner LMS verification
        owner_public_key = extract_public_key(
            source_file, OWNER_LMS_PUBLIC_KEY_START_OFFSET, 0, LMS_PUBLIC_KEY_SIZE)

        owner_signature, owner_signed_data = extract_lms_signature(
            source_file, OWNER_LMS_SIGNATURE_OFFSET, SIGNED_DATA_OFFSET, OWNER_SIGNED_DATA_SIZE)

        if verify_lms_signature(owner_public_key, owner_signature, owner_signed_data):
            print("Caliptra Owner LMS signature verification succeeded.")
        else:
            print("Caliptra Owner LMS signature verification failed.")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
