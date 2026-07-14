#!/usr/bin/python3
"""
Insert Owner ECC/LMS public keys and signatures into a Caliptra firmware image.

Field layout (CMAN image, owner section):
  0xE44  Owner ECC public key   96 bytes  (x[48] || y[48], dword-swapped)
  0xEA4  Owner LMS public key   48 bytes  (RFC 8554 byte stream, as-is)
  0xED4  Owner ECC signature    96 bytes  (r[48] || s[48], dword-swapped)
  0xF34  Owner LMS signature  1620 bytes  (RFC 8554 byte stream, as-is)

LMS key input formats (auto-detected):
  .pem (caliptra-sw, 48 bytes): lms_type(4)+lmots_type(4)+I(16)+K(24), no prefix
  .pub (52 bytes)             : 4-byte prefix + the same 48 bytes
"""

import binascii
import argparse
import struct
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

ecc_public_key_offset = 0xe44   # Owner ECC public key
lms_public_key_offset = 0xea4   # Owner LMS public key
ecc_signature_offset  = 0xed4   # Owner ECC signature
lms_signature_offset  = 0xf34   # Owner LMS signature

ECC_COORD_BYTES  = 48           # P-384: x, y, r, s are 48 bytes each
LMS_PUBKEY_BYTES = 48           # lms_type + lmots_type + I + K
LMS_SIG_BYTES    = 1620         # q + ots_sig + lms_type + auth path (h15/w4)

# Valid LMS typecodes for sanity checking (SHA256/192 family used by Caliptra)
VALID_LMS_TYPECODES = {0x0A, 0x0B, 0x0C, 0x0D, 0x0E}   # h5/h10/h15/h20/h25


def load_public_key(pem_path):
    with open(pem_path, 'rb') as pem_file:
        pem_data = pem_file.read()
    public_key = serialization.load_pem_public_key(
        pem_data, backend=default_backend())
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return public_key
    raise ValueError("The provided key is not an ECDSA public key")


def to_fixed_len_hex(value: int, length_bytes: int = ECC_COORD_BYTES) -> str:
    """Format an integer as fixed-length big-endian hex (zero-padded).

    P-384 coordinates/signature components are 48 bytes. Using '{:064x}'
    only guarantees a MINIMUM of 64 hex chars, so values with leading zero
    bytes would be mis-padded and shift the whole field. Pad explicitly to
    the exact byte length instead.
    """
    h = '{:x}'.format(value)
    expected = length_bytes * 2
    if len(h) > expected:
        raise ValueError(f"value too large for {length_bytes} bytes: {len(h)} hex chars")
    return h.rjust(expected, '0')


def convert_endianness(value_hex: str) -> str:
    """Reverse bytes within each 4-byte dword (Caliptra word-swapped format)."""
    value_bytes = binascii.unhexlify(value_hex)
    if len(value_bytes) % 4 != 0:
        raise ValueError(f"length {len(value_bytes)} is not dword-aligned")
    reversed_bytes = bytearray()
    for i in range(0, len(value_bytes), 4):
        reversed_bytes.extend(value_bytes[i:i + 4][::-1])
    return binascii.hexlify(reversed_bytes).decode()


def replace_in_file(file_path, offset, hex_value, expected_len=None):
    data = binascii.unhexlify(hex_value)
    if expected_len is not None and len(data) != expected_len:
        raise ValueError(
            f"field at 0x{offset:X}: got {len(data)} bytes, expected {expected_len}")
    with open(file_path, 'r+b') as f:
        f.seek(offset)
        f.write(data)
    print(f"  wrote {len(data):5d} bytes @ 0x{offset:X}")


def load_lms_public_key(path: str) -> bytes:
    """Load an LMS public key, auto-detecting .pem (48B) / .pub (52B) format.

    Never blindly skip bytes: check whether the buffer starts with a valid
    big-endian LMS typecode. caliptra .pem keys start directly with the
    typecode (e.g. 0000000C); .pub files carry a 4-byte prefix before it.
    """
    with open(path, 'rb') as f:
        raw = f.read()

    def typecode_at(off):
        return struct.unpack(">I", raw[off:off + 4])[0] if len(raw) >= off + 4 else None

    if len(raw) == LMS_PUBKEY_BYTES and typecode_at(0) in VALID_LMS_TYPECODES:
        print(f"  LMS key: .pem format detected (typecode 0x{typecode_at(0):08X}), no prefix to strip")
        return raw
    if len(raw) == LMS_PUBKEY_BYTES + 4 and typecode_at(4) in VALID_LMS_TYPECODES:
        print(f"  LMS key: .pub format detected, stripping 4-byte prefix")
        return raw[4:]
    raise ValueError(
        f"unrecognized LMS public key: len={len(raw)}, "
        f"typecode@0=0x{typecode_at(0):08X}" if typecode_at(0) is not None else "file too short")


def load_signature(signature_file):
    with open(signature_file, 'rb') as sig_file:
        return sig_file.read()


def main():
    parser = argparse.ArgumentParser(
        description="Insert ECC and LMS keys and signatures into a firmware image.")
    parser.add_argument("file_path", help="Path to the firmware image file (modified in place)")
    parser.add_argument("--ecc_key", required=True, help="ECC public key, PEM format")
    parser.add_argument("--lms_key", required=False,
                        help="LMS public key, .pem (48B) or .pub (52B); format auto-detected")
    parser.add_argument("--ecc_sig", required=True, help="ECC signature, DER format")
    parser.add_argument("--lms_sig", required=False,
                        help="LMS signature, raw binary (1620 bytes)")
    args = parser.parse_args()

    # ── ECC public key ──────────────────────────────────────────────
    public_key = load_public_key(args.ecc_key)
    numbers = public_key.public_numbers()
    x_endian = convert_endianness(to_fixed_len_hex(numbers.x))
    y_endian = convert_endianness(to_fixed_len_hex(numbers.y))
    print("ECC public key:")
    replace_in_file(args.file_path, ecc_public_key_offset,
                    x_endian + y_endian, expected_len=ECC_COORD_BYTES * 2)

    # ── LMS public key (optional) ───────────────────────────────────
    if args.lms_key:
        print("LMS public key:")
        lms_key = load_lms_public_key(args.lms_key)
        replace_in_file(args.file_path, lms_public_key_offset,
                        binascii.hexlify(lms_key).decode(),
                        expected_len=LMS_PUBKEY_BYTES)

    # ── ECC signature ───────────────────────────────────────────────
    r, s = decode_dss_signature(load_signature(args.ecc_sig))
    r_endian = convert_endianness(to_fixed_len_hex(r))
    s_endian = convert_endianness(to_fixed_len_hex(s))
    print("ECC signature:")
    replace_in_file(args.file_path, ecc_signature_offset,
                    r_endian + s_endian, expected_len=ECC_COORD_BYTES * 2)

    # ── LMS signature (optional) ────────────────────────────────────
    if args.lms_sig:
        lms_sig = load_signature(args.lms_sig)
        if len(lms_sig) != LMS_SIG_BYTES:
            raise ValueError(
                f"LMS signature must be {LMS_SIG_BYTES} bytes, got {len(lms_sig)}")
        # RFC 8554 signatures are written verbatim (big-endian byte stream)
        print("LMS signature:")
        replace_in_file(args.file_path, lms_signature_offset,
                        binascii.hexlify(lms_sig).decode(),
                        expected_len=LMS_SIG_BYTES)

    print("Keys and signatures have been successfully inserted into the firmware image.")


if __name__ == "__main__":
    main()
