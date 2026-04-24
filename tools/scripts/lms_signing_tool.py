import argparse
import hashlib
from pyhsslms import LmsPrivateKey, LmsPublicKey, LmsSignature
import struct
import os

# DEBUG FLAG to dump debug information
DEBUG = False

# CPTRA_SAMPLE_KEY = True
CPTRA_SAMPLE_KEY = False
if CPTRA_SAMPLE_KEY:
    SUPPORTED_LMS_Q_VALUE = 5

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
        # Debug: Print the raw public key bytes
        if DEBUG:
            print("Extracted Public Key:", public_key_bytes.hex())
            print("Extracted Public Key Length:", len(public_key_bytes))

        # Deserialize the public key using the correct constructors
        public_key = LmsPublicKey.deserialize(public_key_bytes)

        if DEBUG:
            print(public_key.prettyPrint())

        if DEBUG:
            sig = LmsSignature.deserialize(signature_bytes)
            print(sig.prettyPrint())

        print("Start verification...")
        # Verify the signature using the public key and signed data
        return public_key.verify(signed_data, signature_bytes)

    except Exception as e:
        print(f"Verification failed: {e}")
        return False

def generate_lms_signature(private_key_bytes, data_to_sign, output_file):
    """
    Generates an LMS signature and writes it to the specified output file.

    Args:
        private_key_bytes (bytes): The serialized LMS private key.
        data_to_sign (bytes): The data to be signed.
        output_file (str): The file to write the signature to.
    """
    try:
        # Hash the data using SHA-384
        hashed_data = hashlib.sha384(data_to_sign).digest()

        # Debug: Print hashed data
        print(f"Hashed Data (SHA-384): {hashed_data.hex()}")

        if CPTRA_SAMPLE_KEY:
            # Adjust SEED & I location
            I = private_key_bytes[8:24]
            SEED = private_key_bytes[24:48]
            private_key_bytes = private_key_bytes[:8] + SEED + \
                I + struct.pack(">L", SUPPORTED_LMS_Q_VALUE)

        # Generate the LMS signature using LMS Private Key
        private_key = LmsPrivateKey.deserialize(private_key_bytes)

        # Debug: Print private key details
        if DEBUG:
            print(private_key.prettyPrint())

        # Generate the signature
        print("Generating LMS signature...")
        signature = private_key.sign(hashed_data)

        # Write the signature to the output file
        with open(output_file, 'wb') as f:
            f.write(signature)

        print(f"LMS signature successfully written to {output_file}")

    except Exception as e:
        print(f"Error during LMS signing: {e}")

def load_lms_private_key_from_binary(binary_file_path):
    """
    Loads an LMS private key from a binary file.

    Args:
        binary_file_path (str): Path to the binary file containing the LMS private key.

    Returns:
        bytes: The raw LMS private key data.
    """
    try:
        with open(binary_file_path, 'rb') as binary_file:
            return binary_file.read()
    except Exception as e:
        print(f"Error loading LMS private key from binary file: {e}")
        raise

def main():
    parser = argparse.ArgumentParser(description="LMS Signing Tool")
    parser.add_argument("--data", required=True,
                        help="Path to the data file to be signed")
    parser.add_argument("--key", required=True,
                        help="Path to the private key file")
    parser.add_argument(
        "--public_key", help="Path to the public key file for verification (optional)")
    parser.add_argument("--output", required=True,
                        help="Path to the output file for the signature")

    args = parser.parse_args()
    try:
        # Read the data to be signed
        with open(args.data, 'rb') as data_file:
            data_to_sign = data_file.read()

        # Read the LMS private key from binary file
        private_key_bytes = load_lms_private_key_from_binary(args.key)

        # Generate the LMS signature
        if CPTRA_SAMPLE_KEY:
            generate_lms_signature(private_key_bytes, data_to_sign, args.output)
        else:
            generate_lms_signature(private_key_bytes[12:], data_to_sign, args.output)

        # Attempt to verify the generated signature using the corresponding public key
        if args.public_key:
            if os.path.exists(args.public_key):
                with open(args.public_key, 'rb') as pub_file:
                    public_key_bytes = pub_file.read()
                with open(args.output, 'rb') as sig_file:
                    signature_bytes = sig_file.read()
                if CPTRA_SAMPLE_KEY:
                    is_valid = verify_lms_signature(
                        public_key_bytes, signature_bytes, hashlib.sha384(data_to_sign).digest())
                else:
                    is_valid = verify_lms_signature(
                        public_key_bytes[4:], signature_bytes, hashlib.sha384(data_to_sign).digest())
                if is_valid:
                    print("Signature verification succeeded.")
                else:
                    print("Signature verification failed.")
            else:
                print(f"Public key file not found: {args.public_key}")

    except FileNotFoundError as e:
        print(f"File not found: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
