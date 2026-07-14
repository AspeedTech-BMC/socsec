import argparse
import hashlib
from pyhsslms import LmsPrivateKey, LmsPublicKey, LmsSignature
from pyhsslms.pyhsslms import (lms_params, lmots_params, LmotsPrivateKey,
                               H, u32, u16, D_LEAF, D_INTR, LenI)
import struct
import os

# DEBUG FLAG to dump debug information
DEBUG = False

# caliptra-sw image/crypto/src/lib.rs:
#   LMS_TREE_GEN_SUPPORTED_FULL_HEIGHT = 10
#   SUPPORTED_LMS_Q_VALUE = 5
# For trees taller than h10, caliptra-sw only computes the real LM-OTS
# public key at leaf q=5; every other leaf K is replaced with all zeros
# before hashing the Merkle tree. Signatures therefore must use q=5 and
# an auth path computed over that same "zero-leaf" tree.
CPTRA_TREE_GEN_SUPPORTED_FULL_HEIGHT = 10
CPTRA_SUPPORTED_LMS_Q_VALUE = 5

def is_cptra_pem_key(raw_bytes):
    """
    Returns True if raw_bytes looks like a caliptra-sw style key:
      lms_type(4) + lmots_type(4) + id/I(16) + SEED(n)   (48 bytes for n24)
    i.e. it starts directly with a valid LMS typecode and has no q field.
    """
    if raw_bytes[0:4] not in lms_params:
        return False
    lmots_type = raw_bytes[4:8]
    if lmots_type not in lmots_params:
        return False
    _, n, _, _, _ = lmots_params[lmots_type]
    return len(raw_bytes) == 8 + LenI + n

def _fast_ots_pubkey(alg, I, SEED, n, p, w, q):
    """RFC 8554 Algorithm 1 LM-OTS public key K for leaf q,
    keys derived per Appendix A (matches pyhsslms / caliptra-sw)."""
    import hashlib as _hl
    sha = _hl.sha256 if alg == 'sha256' else None
    qb = u32(q)
    pre = I + qb
    y = bytearray()
    for i in range(p):
        ib = u16(i)
        t = sha(pre + ib + b'\xff' + SEED).digest()[:n]
        for j in range(2 ** w - 1):
            t = sha(pre + ib + bytes([j]) + t).digest()[:n]
        y += t
    return sha(pre + b'\x80\x80' + bytes(y)).digest()[:n]


def _build_tree(alg, I, SEED, n, p, w, m, h, zero_leaf, q):
    """Build the LMS Merkle tree; returns node array T (T[1] = root).

    zero_leaf=True  : caliptra-sw style — only leaf q has a real OTS
                      public key, all other leaves use K = 0x00*n.
    zero_leaf=False : RFC 8554 standard — every leaf is real (slow for
                      h15: ~30-60s in pure Python; result is cached).
    """
    num_leaves = 1 << h
    cache_file = None
    if not zero_leaf and h > CPTRA_TREE_GEN_SUPPORTED_FULL_HEIGHT:
        tag = hashlib.sha256(b'v1' + I + SEED + u32(num_leaves)).hexdigest()[:16]
        cache_file = f".lms_tree_cache_{tag}.bin"
        if os.path.exists(cache_file):
            blob = open(cache_file, 'rb').read()
            if len(blob) == (2 * num_leaves - 1) * m:
                print(f"Loaded full tree from cache: {cache_file}")
                return [None] + [blob[i * m:(i + 1) * m]
                                 for i in range(2 * num_leaves - 1)]
    T = [None] * (2 * num_leaves)
    zero_k = b'\x00' * n
    for i in range(num_leaves):
        if zero_leaf and i != q:
            K = zero_k
        else:
            K = _fast_ots_pubkey(alg, I, SEED, n, p, w, i)
        r = num_leaves + i
        T[r] = H(alg, I + u32(r) + D_LEAF + K, m)
    for r in range(num_leaves - 1, 0, -1):
        T[r] = H(alg, I + u32(r) + D_INTR + T[2 * r] + T[2 * r + 1], m)
    if cache_file:
        with open(cache_file, 'wb') as f:
            f.write(b''.join(T[1:]))
        print(f"Full tree cached to: {cache_file}")
    return T


def generate_cptra_lms_signature(raw_pem_key, message, output_file,
                                 q=CPTRA_SUPPORTED_LMS_Q_VALUE,
                                 pub_key_bytes=None):
    """
    Sign `message` with a 48-byte .pem style LMS private key:
      lms_type(4) + lmots_type(4) + id/I(16) + SEED(n)     (big endian)

    Two possible tree constructions exist for such keys:
      zero-leaf : caliptra-sw image tooling (image/crypto/src/lib.rs)
                  computes a real LM-OTS public key ONLY at leaf q=5 for
                  trees taller than h10; all other leaves use K=0. The
                  root and auth path come from that degenerate tree.
      full      : RFC 8554 standard keygen — every leaf is real.

    Both are valid to an RFC verifier (it just recomputes the root), but
    the auth path / root differ, so signing MUST use the same mode the
    public key was generated with. If `pub_key_bytes` is provided, the
    mode is auto-detected by comparing the zero-leaf root against the
    public key's K first (cheap), falling back to the full tree (slow,
    cached). Without a public key, zero-leaf (caliptra default) is used.
    """
    lms_type = raw_pem_key[0:4]
    lmots_type = raw_pem_key[4:8]
    I = raw_pem_key[8:8 + LenI]
    alg, n, p, w, ls = lmots_params[lmots_type]
    _, m, h = lms_params[lms_type]
    SEED = raw_pem_key[8 + LenI:8 + LenI + n]

    tall_tree = h > CPTRA_TREE_GEN_SUPPORTED_FULL_HEIGHT
    K_expected = None
    if pub_key_bytes is not None and len(pub_key_bytes) >= 24 + m:
        if pub_key_bytes[8:8 + LenI] != I:
            print("WARNING: public key I does not match private key I "
                  "- this is not a matching key pair!")
        K_expected = pub_key_bytes[8 + LenI:8 + LenI + m]

    # --- Decide tree mode ---
    zero_leaf = tall_tree          # caliptra default for h > 10
    T = None
    if tall_tree:
        print(f"Building zero-leaf tree (caliptra-sw style, real leaf only at q={CPTRA_SUPPORTED_LMS_Q_VALUE})...")
        T = _build_tree(alg, I, SEED, n, p, w, m, h,
                        zero_leaf=True, q=CPTRA_SUPPORTED_LMS_Q_VALUE)
        if K_expected is not None and T[1] != K_expected:
            print("Zero-leaf root does not match public key K -> "
                  "this key pair was generated with a FULL tree.")
            print(f"Building full RFC 8554 tree (h={h}, this may take a minute; result is cached)...")
            zero_leaf = False
            T = _build_tree(alg, I, SEED, n, p, w, m, h,
                            zero_leaf=False, q=q)
    else:
        zero_leaf = False
        T = _build_tree(alg, I, SEED, n, p, w, m, h, zero_leaf=False, q=q)

    if zero_leaf:
        q = CPTRA_SUPPORTED_LMS_Q_VALUE   # zero-leaf trees only have this leaf
        print(f"Tree mode: zero-leaf (caliptra), q fixed to {q}")
    else:
        print(f"Tree mode: full RFC 8554 tree, q = {q}")

    if K_expected is not None:
        if T[1] == K_expected:
            print("Tree root matches public key K - OK")
        else:
            print("WARNING: tree root does NOT match the provided public key. "
                  "The signature will not verify against it.")

    # --- LM-OTS signature at leaf q (RFC 8554 4.5, Appendix A derivation) ---
    ots_priv = LmotsPrivateKey(I=I, q=u32(q), SEED=SEED, lmots_type=lmots_type)
    ots_sig = ots_priv.sign(message)   # lmots_type + C + y[p]

    # --- Auth path for leaf q ---
    num_leaves = 1 << h
    path = b''
    node = num_leaves + q
    for _ in range(h):
        path += T[node ^ 1]
        node >>= 1

    # --- RFC 8554 LMS signature: u32(q) + ots_sig + lms_type + path ---
    signature = u32(q) + ots_sig + lms_type + path
    with open(output_file, 'wb') as f:
        f.write(signature)
    print(f"Computed root K: {T[1].hex()}")
    print(f"LMS signature successfully written to {output_file}")


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

def normalize_lms_private_key(raw_bytes):
    """
    Normalize raw .prv key bytes to the format expected by
    LmsPrivateKey.deserialize():
      lms_type(4) + lmots_type(4) + SEED(n) + I(16) + q(4)

    .prv (64 bytes): 12-byte header + lms_type + lmots_type +
                     SEED(n) + I(16) + q
    (caliptra .pem keys are handled by generate_cptra_lms_signature instead)
    """
    # .prv format: skip 12-byte header; q is already present
    return raw_bytes[12:]

def normalize_lms_public_key(raw_bytes):
    """
    Normalize raw key bytes to the format expected by LmsPublicKey.deserialize():
      lms_type(4) + lmots_type(4) + I(16) + K(n)

    Supported input formats:
      .pem (48 bytes): starts directly with a valid lms_type, no extra prefix
      .pub (52 bytes): 4-byte prefix + lms_type + ... + I + K
    """
    if raw_bytes[0:4] in lms_params:
        # Already a bare public key, no prefix to strip
        return raw_bytes
    else:
        # Has a 4-byte prefix (e.g. algorithm/version tag); skip it
        return raw_bytes[4:]

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
        if is_cptra_pem_key(private_key_bytes):
            # .pem key: I-first layout; tree mode auto-detected via public key
            print("Detected .pem key format")
            hashed_data = hashlib.sha384(data_to_sign).digest()
            print(f"Hashed Data (SHA-384): {hashed_data.hex()}")
            pub_bytes = None
            if args.public_key and os.path.exists(args.public_key):
                with open(args.public_key, 'rb') as pf:
                    pub_bytes = pf.read()
            generate_cptra_lms_signature(
                private_key_bytes, hashed_data, args.output,
                pub_key_bytes=pub_bytes)
        else:
            generate_lms_signature(normalize_lms_private_key(private_key_bytes), data_to_sign, args.output)

        # Attempt to verify the generated signature using the corresponding public key
        if args.public_key:
            if os.path.exists(args.public_key):
                with open(args.public_key, 'rb') as pub_file:
                    public_key_bytes = pub_file.read()
                with open(args.output, 'rb') as sig_file:
                    signature_bytes = sig_file.read()
                is_valid = verify_lms_signature(
                    normalize_lms_public_key(public_key_bytes), signature_bytes, hashlib.sha384(data_to_sign).digest())
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
