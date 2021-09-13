# Copyright (c) 2020 ASPEED Technology Inc.

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import sys
import re
import os
import struct
import subprocess
import tempfile
from Crypto.Hash import SHA
from Crypto.Hash import SHA224
from Crypto.Hash import SHA256
from Crypto.Hash import SHA384
from Crypto.Hash import SHA512
from Crypto.Util import Counter
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from bitarray import bitarray
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from ecdsa import SigningKey, VerifyingKey, NIST384p
from ecdsa.ellipticcurve import Point

from socsec import rsa_importkey
from socsec import parse_path
from socsec import insert_bytearray
from socsec import rsa_bit_length
from socsec import rsa_key_to_bin
from socsec import hexdump
from socsec import OTP_info
from socsec import __version__

RSA_SHA = 1        # mode 2
AES_RSA_SHA = 2    # mode 2 with aes encryption
AES_GCM = 3        # mode gcm
HASH_BINDING = 4
ECDSA_P384 = 5
AES_ECDSA_P384 = 6

RSA_OEM = 1
RSA_SOC_PUB = 2
RSA_SOC_PRI = 3
AES_OEM = 4
AES_VAULT = 5
ECDSA_PUB = 6
ECDSA_PARMETER = 7


class SecError(Exception):
    """Application-specific errors.

    These errors represent issues for which a stack-trace should not be
    presented.

    Attributes:
        message: Error message.
    """

    def __init__(self, message):
        Exception.__init__(self, message)


class Algorithm(object):
    """Contains details about an algorithm.

    See the avb_vbmeta_image.h file for more details about algorithms.

    Attributes:
      algorithm_type: Integer code corresponding to |AvbAlgorithmType|.
      hash_name: Empty or a name from |hashlib.algorithms|.
      hash_num_bytes: Number of bytes used to store the hash.
      rsa_num_bytes: Number of bytes used to store the signature.
      public_key_num_bytes: Number of bytes used to store the public key.
      padding: Padding used for signature, if any.
    """

    def __init__(self, algorithm_type, hash_alg, hash_num_bytes,
                 rsa_num_bytes, public_key_num_bytes, rsa_padding='pkcs1'):
        self.algorithm_type = algorithm_type
        self.hash_alg = hash_alg
        self.hash_num_bytes = hash_num_bytes
        self.rsa_num_bytes = rsa_num_bytes
        self.public_key_num_bytes = public_key_num_bytes
        self.rsa_padding = rsa_padding


class ChainPartitionDescriptor(object):
    def __init__(self, image_path, out_path, sign_key_path, verify_key_path,
                 next_verify_key_path):
        self.image_path = image_path
        self.out_path = out_path
        self.sign_key_path = sign_key_path
        self.verify_key_path = verify_key_path
        self.next_verify_key_path = next_verify_key_path


def BIT(off):
    return 1 << off


def parse_number(string):
    """Parse a string as a number.

    This is just a short-hand for int(string, 0) suitable for use in the
    |type| parameter of |ArgumentParser|'s add_argument() function. An
    improvement to just using type=int is that this function supports
    numbers in other bases, e.g. "0x1234".

    Arguments:
        string: The string to parse.

    Returns:
        The parsed integer.

    Raises:
        ValueError: If the number could not be parsed.
    """
    return int(string, 0)


def print_rsa_key(rsa_key_file):

    with open(rsa_key_file, 'r') as f:
        key_file_str = f.read()
    rsa_key = RSA.importKey(key_file_str)

    n_bit = bitarray(bin(rsa_key.n)[2:])
    e_bit = bitarray(bin(rsa_key.e)[2:])
    d_bit = bitarray(bin(rsa_key.d)[2:])
    n_remain = (8-(len(n_bit) % 8)) % 8
    e_remain = (8-(len(e_bit) % 8)) % 8
    d_remain = (8-(len(d_bit) % 8)) % 8
    for _ in range(0, n_remain):
        n_bit.insert(0, 0)
    for _ in range(0, e_remain):
        e_bit.insert(0, 0)
    for _ in range(0, d_remain):
        d_bit.insert(0, 0)

    n_byte = bytearray(n_bit.tobytes())
    e_byte = bytearray(e_bit.tobytes())
    d_byte = bytearray(d_bit.tobytes())

    print('n')
    hexdump(n_byte)
    print('e')
    hexdump(e_byte)
    print('d')
    hexdump(d_byte)


def mgf1(mgf_seed, mask_len, hash_type):
    '''
    Mask Generation Function based on a hash function as defined in Section B.2.1 of [RFC8017]
    @Input:
        mgs_seed - seed from which mask is generated, an octet string
        mask_len - intended length in octets of the mask, at most 2^32 hLen
        hash_type - the digest hash function to use, default is SHA1
    Outout:
        mask: an octet string of length mask_len
    '''
    # get hash length given hash function
    h_len = 32

    # If maskLen > 2^32 hLen, output "mask too long" and stop.
    if mask_len > 0x10000:
        raise ValueError('mask too long')

    # Let T be the empty octet string.
    T = b''

    # For counter i from 0 to \ceil (mask_len / h_len) - 1
    for i in range(0, int((mask_len+h_len-1)/h_len)):
        sha = hash_type.new()
        sha.update(mgf_seed)

        # Convert counter to an octet string C of length 4 octets
        # C = i2osp(i, 4)
        C = i.to_bytes(4, byteorder='big', signed=False)

        # Concatenate the hash of the seed mgfSeed and C to the octet string T
        # T = T || Hash(mgfSeed || C)
        sha.update(C)
        # T = T + hash_class.digest()
        T = b"".join([T, sha.digest()])

    # Output the leading maskLen octets of T as the octet string mask.
    return T[:mask_len]


def rsa_pkcs15_sign(alg_data, rsa_key_file, src_bin,
                    signing_helper, signing_helper_with_files, order='little'):
    src_bin = bytearray(src_bin)
    if order == 'little':
        src_bin.reverse()

    if signing_helper_with_files is not None:
        signing_file = tempfile.NamedTemporaryFile()
        signing_file.write(src_bin)
        signing_file.flush()
        p = subprocess.Popen([
            signing_helper_with_files, rsa_key_file, signing_file.name])
        retcode = p.wait()
        if retcode != 0:
            raise ValueError('Error signing')
        signing_file.seek(0)
        read_f = signing_file.read()

        signature = bytearray(read_f)
        if order == 'little':
            signature.reverse()
    else:
        if signing_helper is not None:
            p = subprocess.Popen(
                [signing_helper, rsa_key_file],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
        else:
            p = subprocess.Popen(
                ['openssl', 'rsautl', '-sign', '-inkey', rsa_key_file],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
        (pout, perr) = p.communicate(input=src_bin)
        retcode = p.wait()
        if retcode != 0:
            raise ValueError('Error signing: {}'.format(perr))

        signature = bytearray(pout)
        if order == 'little':
            signature.reverse()

    if len(signature) < 512:
        signature = signature + bytearray(512 - len(signature))

    return signature


def rsa_pss_sign(alg_data, rsa_key_file, mHash,
                 signing_helper, signing_helper_with_files, deterministic):
    emLen = alg_data.rsa_num_bytes
    MSBits = (emLen - 1) & 0x7

    if deterministic:
        salt = bytearray(20)
    else:
        salt = os.urandom(20)

    padding1 = bytearray(8)
    m_ = padding1+mHash+salt

    sha = alg_data.hash_alg.new(m_)
    H = sha.digest()

    # emLen – sLen – hLen – 2
    padding2 = bytearray(emLen - 20 - alg_data.hash_num_bytes - 2)
    DB = padding2+b'\x01'+salt

    maskedDB_len = emLen - 1 - alg_data.hash_num_bytes  # emLen - bc_len - hLen
    dbMask = mgf1(H, maskedDB_len, alg_data.hash_alg)

    maskedDB = bytearray(a ^ b for (a, b) in zip(DB, dbMask))
    if MSBits:
        maskedDB[0] = maskedDB[0] & 0xFF >> (8 - MSBits)

    EM = maskedDB+H+b'\xbc'
    p = subprocess.Popen(
        ['openssl', 'rsautl', '-sign', '-raw', '-inkey', rsa_key_file],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    (pout, perr) = p.communicate(input=EM)
    retcode = p.wait()
    if retcode != 0:
        raise ValueError('Error signing: {}'.format(perr))

    sign = bytearray(pout)
    if len(sign) < 512:
        sign = sign + bytearray(512 - len(sign))

    print("rsa key")
    print_rsa_key(rsa_key_file)
    print('mHash')
    hexdump(mHash)
    print('salt')
    hexdump(salt)
    print('M\'')
    hexdump(m_)
    print('H')
    hexdump(H)
    print('DB')
    hexdump(DB)
    print('dbMask')
    hexdump(dbMask)
    print('EM')
    hexdump(EM)
    print('signature')
    hexdump(sign[:emLen])

    return sign[:emLen]


def rsa_sign(alg_data, rsa_key_file, src_bin,
             signing_helper, signing_helper_with_files, deterministic, order='little'):
    if alg_data.rsa_padding == 'pkcs1':
        return rsa_pkcs15_sign(alg_data, rsa_key_file, src_bin,
                               signing_helper, signing_helper_with_files, order)
    else:
        return rsa_pss_sign(alg_data, rsa_key_file, src_bin,
                            signing_helper, signing_helper_with_files, deterministic)


def rsa_raw_ver(alg_data, rsa_key_file, signature, order='little'):
    rev_signature = bytearray(signature)
    if order == 'little':
        rev_signature.reverse()

    if len(rev_signature) < alg_data.rsa_num_bytes:
        rev_signature = rev_signature + \
            bytearray(alg_data.rsa_num_bytes - len(rev_signature))

    rsa_key = rsa_importkey(rsa_key_file)
    try:
        if rsa_key.d:
            cmd = "openssl rsautl -verify -raw -inkey " + rsa_key_file
    except (AttributeError):
        cmd = "openssl rsautl -verify -raw --pubin -inkey " + rsa_key_file

    p = subprocess.Popen(
        cmd,
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    sign_dec, stderr = p.communicate(input=rev_signature)

    if stderr or p.returncode != 0:
        print(stderr)

    sign_dec = bytearray(sign_dec)
    if order == 'little':
        sign_dec.reverse()

    return sign_dec


def rsa_pkcs15_verify(alg_data, rsa_key_file, signature, digest, order='little'):
    sign_dec = rsa_raw_ver(alg_data, rsa_key_file, signature, order)
    if order == 'little':
        sign_dec = sign_dec[:len(digest)]
    else:
        sign_dec = sign_dec[len(sign_dec) - len(digest):]

    if sign_dec == digest:
        return True
    else:
        return False


def rsa_pss_em_ver(alg_data, EM, mHash):
    emLen = alg_data.rsa_num_bytes
    maskedDB_len = emLen - 1 - alg_data.hash_num_bytes  # emLen - bc_len - H_len
    maskedDB = EM[:maskedDB_len]
    H = EM[maskedDB_len:maskedDB_len+alg_data.hash_num_bytes]
    dbMask = mgf1(H, maskedDB_len, alg_data.hash_alg)
    DB = bytes(a ^ b for (a, b) in zip(maskedDB, dbMask))
    salt = DB[-20:]
    m_ = bytearray(8)+mHash+salt
    sha = alg_data.hash_alg.new(m_)
    h_ = sha.digest()

    print('mHash')
    hexdump(mHash)
    print('EM')
    hexdump(EM)
    print('maskedDB')
    hexdump(maskedDB)
    print('H')
    hexdump(H)
    print('dbMask')
    hexdump(dbMask)
    print('DB')
    hexdump(DB)
    print('salt')
    hexdump(salt)
    print('M\'')
    hexdump(m_)
    print('H\'')
    hexdump(h_)
    print('H')
    hexdump(H)

    if h_ == H:
        print("pass")
        return True
    else:
        print("fail")
        return False


def rsa_pss_verify(alg_data, rsa_key_file, signature, mHash):
    EM = rsa_raw_ver(alg_data, rsa_key_file, signature, 'big')
    return rsa_pss_em_ver(alg_data, EM, mHash)


def rsa_verify(alg_data, rsa_key_file, signature, digest, order='little'):
    if alg_data.rsa_padding == 'pkcs1':
        return rsa_pkcs15_verify(alg_data, rsa_key_file, signature, digest, order)
    else:
        return rsa_pss_verify(alg_data, rsa_key_file, signature, digest)


def rsa_encrypt(rsa_key_file, src_bin, order='little', randfunc=None):
    rsa_key = rsa_importkey(rsa_key_file)

    src_bin = bytearray(src_bin)
    if order == 'little':
        src_bin.reverse()

    if rsa_key.has_private():
        t = RSA.construct((rsa_key.n, rsa_key.d, rsa_key.e))
        cipher = Cipher_pkcs1_v1_5.new(t, randfunc)
        src_enc = cipher.encrypt(src_bin)
    else:
        cipher = Cipher_pkcs1_v1_5.new(rsa_key, randfunc)
        src_enc = cipher.encrypt(src_bin)

    src_enc = bytearray(src_enc)
    if order == 'little':
        src_enc.reverse()

    key_bit_length = len(bitarray(bin(rsa_key.n)[2:]))
    key_byte_length = int((key_bit_length + 7) / 8)
    if len(src_enc) < key_byte_length:
        src_enc = src_enc + bytearray(key_byte_length - len(src_enc))
    return src_enc


def ecdsa_sign(ecdsa_sign_key_path, src_bin,
               signing_helper, signing_helper_with_files):
    with open(ecdsa_sign_key_path, 'r') as f:
        key_file_str = f.read()
    ecdsa_key = SigningKey.from_pem(key_file_str)
    return ecdsa_key.sign_digest_deterministic(src_bin)


def ecdsa_verify(ecdsa_key_path, src_bin, digest):
    with open(ecdsa_key_path, 'r') as f:
        key_file_str = f.read()
    sk = SigningKey.from_pem(key_file_str)
    vk = sk.verifying_key
    return vk.verify_digest(src_bin, digest)


class Sec(object):
    """Business logic for socsec command-line tool."""

    MAGIC_WORD_VB = 'SOCSEC'
    ROT_HEADER_FORMAT = '<8I'
    ROT_HEADER_SIZE = struct.calcsize(ROT_HEADER_FORMAT)
    COT_INFO_FORMAT = '<2I'
    COT_INFO_SIZE = struct.calcsize(COT_INFO_FORMAT)
    COT_HEADER_FORMAT = '<16s6I472s'
    COT_HEADER_SIZE = struct.calcsize(COT_HEADER_FORMAT)

    def parse_algorithm(self, algorithm_name, rsa_padding='pkcs1'):
        algorithm_type = -1
        rsa_len = 0
        sha_len = 0
        match_alg = re.match(
            r'AES_RSA(1024|2048|3072|4096)_SHA(224|256|384|512)',
            algorithm_name, re.M)

        if match_alg:
            algorithm_type = AES_RSA_SHA
            rsa_len = match_alg.group(1)
            sha_len = match_alg.group(2)

        match_alg = re.match(
            r'RSA(1024|2048|3072|4096)_SHA(224|256|384|512)',
            algorithm_name, re.M)

        if match_alg:
            algorithm_type = RSA_SHA
            rsa_len = match_alg.group(1)
            sha_len = match_alg.group(2)

        match_alg = re.match(
            r'SHA(224|256|384|512)',
            algorithm_name, re.M)

        if match_alg:
            algorithm_type = HASH_BINDING
            sha_len = match_alg.group(1)

        match_alg = re.match(
            r'AES_ECDSA384_RSA(2048|3072|4096)',
            algorithm_name, re.M)

        if match_alg:
            algorithm_type = AES_ECDSA_P384
            rsa_len = match_alg.group(1)

        if algorithm_name == 'AES_GCM':
            algorithm_type = AES_GCM
        elif algorithm_name == 'ECDSA384':
            algorithm_type = ECDSA_P384
        elif algorithm_name == 'AES_ECDSA384':
            algorithm_type = AES_ECDSA_P384

        if algorithm_type == -1:
            raise SecError('Algorithm is invalid')

        if rsa_len == '1024':
            rsa_num_bytes = 128
            public_key_num_bytes = 2*1024//8
        elif rsa_len == '2048':
            rsa_num_bytes = 256
            public_key_num_bytes = 2*2048//8
        elif rsa_len == '3072':
            rsa_num_bytes = 384
            public_key_num_bytes = 2*3072//8
        elif rsa_len == '4096':
            rsa_num_bytes = 512
            public_key_num_bytes = 2*4096//8
        else:
            rsa_num_bytes = 0
            public_key_num_bytes = 0

        if sha_len == '224':
            hash_alg = SHA224
            hash_num_bytes = 28
        elif sha_len == '256':
            hash_alg = SHA256
            hash_num_bytes = 32
        elif sha_len == '384':
            hash_alg = SHA384
            hash_num_bytes = 48
        elif sha_len == '512':
            hash_alg = SHA512
            hash_num_bytes = 64
        else:
            hash_alg = None
            hash_num_bytes = 0

        if algorithm_type in [AES_RSA_SHA, RSA_SHA]:
            if rsa_padding == 'pss':
                val = 0
                if rsa_num_bytes == 256 and hash_num_bytes == 32:
                    val = 1
                elif rsa_num_bytes == 384 and hash_num_bytes == 48:
                    val = 1
                elif rsa_num_bytes == 512 and hash_num_bytes == 64:
                    val = 1
                if val == 0:
                    raise SecError(
                        "PSS padding is for RSA2048_SHA256,RSA3072_SHA384 or RSA4096_SHA512")

        return Algorithm(algorithm_type, hash_alg, hash_num_bytes,
                         rsa_num_bytes, public_key_num_bytes, rsa_padding=rsa_padding)

    def verify_bl1_mode_2_image(self, sec_image, verify_key_path, alg_data,
                                sign_image_size, signature_offset, rsa_key_order):
        sha = alg_data.hash_alg.new(sec_image[0:sign_image_size])
        digest = sha.digest()
        image_signature = sec_image[signature_offset:
                                    (signature_offset+alg_data.rsa_num_bytes)]
        if not rsa_verify(alg_data, verify_key_path,
                          image_signature, digest, order=rsa_key_order):
            raise SecError("signature verify failed")

    def verify_bl1_mode_ecdsa_image(self, sec_image, verify_key_path,
                                    sign_image_size, signature_offset):
        sha = SHA384.new(sec_image[0:sign_image_size])
        digest = sha.digest()
        image_signature = sec_image[signature_offset:
                                    (signature_offset+96)]
        if not ecdsa_verify(verify_key_path,
                            image_signature, digest):
            raise SecError("signature verify failed")

    def decode_bl1_mode_2_enc_image(self, image, sec_image, header_offset,
                                    enc_offset, aes_data_offset, aes_key,
                                    rsa_aes_key_path, alg_data,
                                    sign_image_size, key_in_otp):
        aes_iv = sec_image[aes_data_offset:aes_data_offset+16]

        ctr = Counter.new(128, initial_value=int.from_bytes(
            aes_iv, byteorder='big'))
        aes = AES.new(aes_key, AES.MODE_CTR, counter=ctr)
        dec_image = bytearray(aes.decrypt(
            bytes(sec_image[enc_offset:sign_image_size])))
        if image[enc_offset:] != dec_image:
            raise SecError("image decrypt failed")

    def verify_bl1_mode_gcm_image(self, image, sec_image, signature_offset,
                                  sign_image_size,
                                  enc_offset, aes_data_offset, aes_key):
        image_signature = sec_image[signature_offset:signature_offset+16]
        rev_signature = bytearray(16)
        for i in range(0, 15, 4):
            rev_signature[i] = image_signature[12-i]
            rev_signature[i+1] = image_signature[13-i]
            rev_signature[i+2] = image_signature[14-i]
            rev_signature[i+3] = image_signature[15-i]

        aes_iv = sec_image[aes_data_offset:aes_data_offset+12]
        try:
            aes = AES.new(aes_key, AES.MODE_GCM, nonce=aes_iv[0:12])
            aes.update(sec_image[:enc_offset])
            plaintext = aes.decrypt_and_verify(
                sec_image[enc_offset:sign_image_size], rev_signature)
        except (ValueError, KeyError):
            raise SecError("gcm verify failed")

        # if image[enc_offset:] != plaintext[:len(image)-enc_offset]:
        if image[enc_offset:] != plaintext:
            raise SecError("image decrypt failed")

    def verify_bl1_image(self, image, sec_image, header_offset, rsa_vk_path,
                         ecdsa_vk_path, gcm_aes_key, aes_key, rsa_aes_key_path,
                         alg_data, key_in_otp, rsa_key_order):
        header = sec_image[header_offset:header_offset+self.ROT_HEADER_SIZE]
        (aes_data_offset, enc_offset, sign_image_size,
         signature_offset, revision_low, revision_high,
         reserved, bl1_header_checksum) = struct.unpack(self.ROT_HEADER_FORMAT, header)

        if((aes_data_offset + enc_offset + sign_image_size +
            signature_offset + revision_low + revision_high +
                reserved + bl1_header_checksum) & 0xffffffff) != 0:
            raise SecError("header checksum verify failed")
        if sign_image_size % 512:
            raise SecError("The sign_image_size should be 512 bytes aligned")

        print("check header PASS")

        if alg_data.algorithm_type in [RSA_SHA, AES_RSA_SHA]:
            self.verify_bl1_mode_2_image(sec_image, rsa_vk_path, alg_data,
                                         sign_image_size, signature_offset, rsa_key_order)
            print("check integrity PASS")
        elif alg_data.algorithm_type in [ECDSA_P384, AES_ECDSA_P384]:
            self.verify_bl1_mode_ecdsa_image(sec_image, ecdsa_vk_path,
                                             sign_image_size, signature_offset)
            print("check integrity PASS")

        if alg_data.algorithm_type == AES_RSA_SHA and key_in_otp:
            self.decode_bl1_mode_2_enc_image(image, sec_image, header_offset,
                                             enc_offset, aes_data_offset, aes_key,
                                             rsa_aes_key_path, alg_data,
                                             sign_image_size, key_in_otp)
            print("check aes decode PASS")

        if alg_data.algorithm_type == AES_GCM:
            self.verify_bl1_mode_gcm_image(image, sec_image, signature_offset,
                                           sign_image_size, enc_offset,
                                           aes_data_offset, gcm_aes_key)
            print("check gcm integrity and decode PASS")

    def verify_sv_chain_image(self, image_list, first_layer_vk_path,
                              alg_data, rsa_key_order):
        for i in range(0, len(image_list)):
            print('BL{:d} verifying'.format(i + 2))
            part_image = image_list[i]
            header = part_image[:self.COT_HEADER_SIZE]

            (magic_word, info, sign_image_size, signature_offset,
             npkey_offset, revision_low, revision_high, reserved) = struct.unpack(self.COT_HEADER_FORMAT, header)

            mw = self.MAGIC_WORD_VB.encode()

            if magic_word[0:len(mw)] == mw:
                print("check header magic word PASS")
            else:
                raise SecError("header magic word verify failed")

            if i == 0:
                va = alg_data
                vk = first_layer_vk_path
            else:
                va = next_alg_data
                vk = next_vk

            if i != len(image_list) - 1:
                next_alg_data = self.parse_cot_info(info)
                next_vk_n = part_image[npkey_offset:npkey_offset +
                                       int(next_alg_data.public_key_num_bytes / 2)]
                next_vk_n = int.from_bytes(
                    next_vk_n, byteorder=rsa_key_order, signed=False)
                next_vk_obj = RSA.construct((next_vk_n, 65537))
                signing_file = tempfile.NamedTemporaryFile()
                next_vk_obj.exportKey
                signing_file.write(next_vk_obj.publickey().exportKey('PEM'))
                signing_file.flush()
                next_vk = signing_file.name

            self.verify_bl1_mode_2_image(part_image, vk, va, sign_image_size,
                                         signature_offset, rsa_key_order)
            print("check integrity PASS")

    def make_bl1_mode_2_image(self, image, alg_data, sign_key_path,
                              header_offset,
                              sign_image_size, signature_offset,
                              rsa_key_order,
                              signing_helper, signing_helper_with_files, deterministic):

        # sign the image
        sha = alg_data.hash_alg.new(image[0:sign_image_size])
        digest = sha.digest()
        signature = rsa_sign(
            alg_data, sign_key_path, digest,
            signing_helper, signing_helper_with_files, deterministic, order=rsa_key_order)

        insert_bytearray(signature, image, signature_offset)

    def make_bl1_mode_2_enc_image(self, image, alg_data, sign_key_path,
                                  header_offset,
                                  sign_image_size, signature_offset,
                                  enc_offset, aes_key, aes_iv, aes_data_offset,
                                  key_in_otp, rsa_aes_key_path, rsa_key_order,
                                  signing_helper, signing_helper_with_files,
                                  deterministic, rsa_aes_randfunc=None):

        # encrypt image
        ctr = Counter.new(128, initial_value=int.from_bytes(
            aes_iv, byteorder='big'))
        aes = AES.new(aes_key, AES.MODE_CTR, counter=ctr)
        enc_image = bytearray(aes.encrypt(
            bytes(image[enc_offset:sign_image_size])))

        insert_bytearray(enc_image, image, enc_offset)

        # insert aes object
        if key_in_otp:
            insert_bytearray(aes_iv, image, aes_data_offset)
        else:
            if rsa_key_order == 'little':
                aes_object = bytearray(48)
            else:
                aes_object = bytearray(64)
            insert_bytearray(aes_key, aes_object, 0)
            insert_bytearray(aes_iv, aes_object, 0x20)
            enc_aes_object = rsa_encrypt(
                rsa_aes_key_path, bytes(aes_object), order=rsa_key_order,
                randfunc=rsa_aes_randfunc)
            insert_bytearray(enc_aes_object, image, aes_data_offset)

        # sign the image
        sha = alg_data.hash_alg.new(image[0:sign_image_size])
        digest = sha.digest()
        signature = rsa_sign(
            alg_data, sign_key_path, digest,
            signing_helper, signing_helper_with_files, deterministic, order=rsa_key_order)
        insert_bytearray(signature, image, signature_offset)

    def make_bl1_mode_gcm_image(self, image, alg_data, gcm_aes_key, gcm_aes_iv,
                                header_offset, enc_offset,
                                sign_image_size, signature_offset,
                                aes_data_offset,
                                signing_helper, signing_helper_with_files):

        aes = AES.new(gcm_aes_key, AES.MODE_GCM, nonce=gcm_aes_iv[0:12])
        aes.update(image[:enc_offset])
        ciphertext, signature = aes.encrypt_and_digest(
            image[enc_offset:sign_image_size])

        # reverse signature for secure boot rom code
        rev_signature = bytearray(16)
        for i in range(0, 15, 4):
            rev_signature[i] = signature[12-i]
            rev_signature[i+1] = signature[13-i]
            rev_signature[i+2] = signature[14-i]
            rev_signature[i+3] = signature[15-i]

        insert_bytearray(ciphertext, image, enc_offset)
        insert_bytearray(gcm_aes_iv, image, aes_data_offset)
        insert_bytearray(rev_signature, image, signature_offset)

    def make_bl1_mode_ecdsa_image(self, image, ecdsa_sign_key, sign_image_size,
                                  signature_offset, signing_helper,
                                  signing_helper_with_files):
        # sign the image
        sha = SHA384.new(image[0:sign_image_size])
        digest = sha.digest()

        signature = ecdsa_sign(ecdsa_sign_key, digest,
                               signing_helper, signing_helper_with_files)
        insert_bytearray(signature, image, signature_offset)

    def make_bl1_mode_ecdsa_enc_image(self, image, alg_data, ecdsa_sign_key,
                                      header_offset,
                                      sign_image_size, signature_offset,
                                      enc_offset, aes_key, aes_iv, aes_data_offset,
                                      key_in_otp, rsa_aes_key_path,
                                      signing_helper, signing_helper_with_files,
                                      deterministic, rsa_aes_randfunc=None):

        # encrypt image
        ctr = Counter.new(128, initial_value=int.from_bytes(
            aes_iv, byteorder='big'))
        aes = AES.new(aes_key, AES.MODE_CTR, counter=ctr)
        enc_image = bytearray(aes.encrypt(
            bytes(image[enc_offset:sign_image_size])))

        insert_bytearray(enc_image, image, enc_offset)

        # insert aes object
        if key_in_otp:
            insert_bytearray(aes_iv, image, aes_data_offset)
        else:
            aes_object = bytearray(64)
            insert_bytearray(aes_key, aes_object, 0)
            insert_bytearray(aes_iv, aes_object, 0x20)
            enc_aes_object = rsa_encrypt(
                rsa_aes_key_path, bytes(aes_object), order='big',
                randfunc=rsa_aes_randfunc)
            insert_bytearray(enc_aes_object, image, aes_data_offset)

        # sign the image
        sha = SHA384.new(image[0:sign_image_size])
        digest = sha.digest()
        signature = ecdsa_sign(ecdsa_sign_key, digest,
                               signing_helper, signing_helper_with_files)
        insert_bytearray(signature, image, signature_offset)

    def _cot_info(self, cot_alg_data, rsa_e_bits_len):
        info = 0
        if cot_alg_data.algorithm_type == RSA_SHA:
            info = 1
            if cot_alg_data.rsa_num_bytes == 128:
                info |= 0
            elif cot_alg_data.rsa_num_bytes == 256:
                info |= 1 << 3
            elif cot_alg_data.rsa_num_bytes == 384:
                info |= 2 << 3
            elif cot_alg_data.rsa_num_bytes == 512:
                info |= 3 << 3
            info |= rsa_e_bits_len << 20
        elif cot_alg_data.algorithm_type == HASH_BINDING:
            info = 0
        else:
            raise SecError(
                "COT only support RSA_SHA and HASH_BINDING algorithm")

        if cot_alg_data.hash_num_bytes == 28:
            info |= 0
        elif cot_alg_data.hash_num_bytes == 32:
            info |= 1 << 1
        elif cot_alg_data.hash_num_bytes == 48:
            info |= 2 << 1
        elif cot_alg_data.hash_num_bytes == 64:
            info |= 3 << 1
        return info

    def parse_cot_info(self, info):
        if info & 1:
            algorithm_type = RSA_SHA
        else:
            algorithm_type = HASH_BINDING

        rsa_info = (info >> 3) & 3

        if rsa_info == 0:
            rsa_num_bytes = 128
            public_key_num_bytes = 2*1024//8
        elif rsa_info == 1:
            rsa_num_bytes = 256
            public_key_num_bytes = 2*2048//8
        elif rsa_info == 2:
            rsa_num_bytes = 384
            public_key_num_bytes = 2*3072//8
        else:
            rsa_num_bytes = 512
            public_key_num_bytes = 2*4096//8

        hash_info = (info >> 1) & 3

        if hash_info == 0:
            hash_alg = SHA224
            hash_num_bytes = 28
        elif hash_info == 1:
            hash_alg = SHA256
            hash_num_bytes = 32
        elif hash_info == 2:
            hash_alg = SHA384
            hash_num_bytes = 48
        else:
            hash_alg = SHA512
            hash_num_bytes = 64

        return Algorithm(algorithm_type, hash_alg, hash_num_bytes,
                         rsa_num_bytes, public_key_num_bytes)

    def insert_bl1_cot_info(self, image, cot_alg_data, cot_header_offset,
                            verify_key_path, cot_digest_fd, cot_data_offset):

        if cot_alg_data.algorithm_type == RSA_SHA:
            cot_data = bytearray(rsa_key_to_bin(verify_key_path, 'public'))
        elif cot_alg_data.algorithm_type == HASH_BINDING:
            cot_data = bytearray(cot_digest_fd.read())
        else:
            raise SecError(
                "COT only support RSA_SHA and HASH_BINDING algorithm")

        info = self._cot_info(cot_alg_data, 17)
        cot_header = struct.pack(
            self.COT_INFO_FORMAT,
            info,
            cot_data_offset
        )

        insert_bytearray(cot_header, image, cot_header_offset)

        insert_bytearray(cot_data, image, cot_data_offset)

    def make_secure_bl1_image(self, soc_version, bl1_image_fd, rsa_sign_key_path,
                              ecdsa_sign_key_path, gcm_aes_key_fd, output_fd,
                              algorithm_name, rsa_padding, header_offset, revision_id,
                              enc_offset, aes_key_fd, rsa_aes_key_path,
                              key_in_otp,
                              rsa_key_order,
                              flash_patch_offset,
                              cot_algorithm_name,
                              cot_verify_key_path,
                              cot_digest_fd,
                              signing_helper,
                              signing_helper_with_files,
                              stack_intersects_verification_region,
                              deterministic):
        """Implements the 'make_secure_bl1_image' command.

        Arguments:
            soc_version: SOC version, e.g. '2600', '2605', '1030'
            bl1_image_fd: Bootloader 1 image fd.
            rsa_sign_key_path: Path to rsa signing key to use or None.
            ecdsa_sign_key_path: Path to ecdsa signing key to use or None.
            gcm_aes_key_fd: aes key for GCM_AES mode.
            output_fd: File to write the image to.
            algorithm_name: Name of algorithm to use.
            rsa_padding:
            header_offset: secure image header offset.
            revision_id: Revision id for rollback prevention.
            enc_offset: image encryption start offset.
            aes_key_fd; aes key for AES_RSA**_SHA* mode.
            rsa_aes_key_path; rsa key for AES_RSA**_SHA* mode when key_in_otp is false
            key_in_otp: AES_RSA**_SHA* mode and the aes key is in the OTP
            rsa_key_order: bit endian or little endian.
            flash_patch_offset: for ast2605, default is 0x50
            cot_algorithm_name: Name of algorithm for CoT.
            cot_verify_key_path: rsa public key for verify CoT image.
            cot_digest_fd:
            signing_helper: Program which signs a hash and return signature.
            signing_helper_with_files: Same as signing_helper but uses files instead.
            stack_intersects_verification_region: allows the signing of images that occupy the entire 64KB verifiable region
            deterministic: IVs are read from deterministic sources
        Raises:
            SecError: If a chained partition is malformed.
        """
        aes_key = None
        gcm_aes_key = None

        bl1_image = bytearray(bl1_image_fd.read())
        bl1_image_len = len(bl1_image)
        if soc_version in ['2600', '2605']:
            if header_offset == None:
                header_offset = 0x20
            if enc_offset == None:
                enc_offset = 0x50
            if ((stack_intersects_verification_region is None) or
                    (stack_intersects_verification_region == 'true')):
                bl1_max_len = 60 * 1024
            else:
                bl1_max_len = 64 * 1024 - 512
            if bl1_image_len > bl1_max_len:
                raise SecError(
                    "The maximum size of BL1 image is {} bytes.".format(bl1_max_len))
            if soc_version == '2605' and flash_patch_offset == None:
                flash_patch_offset = 0x50
            else:
                flash_patch_offset = 0
        elif soc_version == '1030':
            if header_offset == None:
                header_offset = 0x400
            if enc_offset == None:
                enc_offset = 0x430
            if bl1_image_len > (768 * 1024):
                raise SecError("The maximum size of BL1 image is 768 KBytes.")
            flash_patch_offset = 0
        else:
            raise SecError("SOC version is not avaliable")

        if enc_offset % 16:
            raise SecError("The enc_offset should be 16 bytes aligned")

        if enc_offset < header_offset + 0x30:
            raise SecError(
                "The enc_offset should 0x30 more than header_offset")

        if rsa_key_order not in ['big', 'little']:
            raise SecError("RSA key order should be 'big' or 'little'")

        if rsa_padding not in ['pkcs1', 'pss']:
            raise SecError(
                "RSA padding is invalid, only support pkcs1 and pss")
        if rsa_padding == 'pss':
            rsa_key_order = 'big'

        alg_data = self.parse_algorithm(
            algorithm_name, rsa_padding=rsa_padding)

        aes_data_offset = 0
        sign_image_size = 0
        signature_offset = 0
        revision_low = 0
        revision_high = 0
        bl1_header_checksum = 0

        if cot_algorithm_name:
            cot_alg_data = self.parse_algorithm(cot_algorithm_name)
            cot_header_offset = header_offset + self.ROT_HEADER_SIZE
            cot_data_offset = max((bl1_image_len + 0xf) & (~0xf),
                                  (cot_header_offset + self.COT_INFO_SIZE + 0xf) & (~0xf))
            if cot_alg_data.algorithm_type == RSA_SHA:
                sign_image_size = cot_data_offset + cot_alg_data.public_key_num_bytes
            elif cot_alg_data.algorithm_type == HASH_BINDING:
                sign_image_size = cot_data_offset + cot_alg_data.hash_num_bytes
            else:
                raise SecError(
                    "COT only support RSA_SHA and HASH_BINDING algorithm")
            sign_image_size = (sign_image_size + 511) & (~511)
        else:
            sign_image_size = (bl1_image_len + 511) & (~511)

        if alg_data.algorithm_type == AES_RSA_SHA:
            aes_data_offset = sign_image_size
            if key_in_otp:
                signature_offset = sign_image_size + 16
            else:
                signature_offset = sign_image_size + alg_data.rsa_num_bytes
        elif alg_data.algorithm_type == AES_GCM:
            aes_data_offset = sign_image_size
            signature_offset = sign_image_size + 16
        elif alg_data.algorithm_type == AES_ECDSA_P384:
            aes_data_offset = sign_image_size
            if key_in_otp:
                signature_offset = sign_image_size + 16
            else:
                signature_offset = sign_image_size + alg_data.rsa_num_bytes
        else:
            enc_offset = 0
            signature_offset = sign_image_size

        if revision_id < 0 or revision_id > 64:
            raise SecError(
                "revision_id is out of range. (0 <= revision_id <= 64)")

        for i in range(revision_id):
            if i < 32:
                revision_low |= BIT(i)
            else:
                j = i - 32
                revision_high |= BIT(j)

        bl1_header_checksum = -(aes_data_offset + enc_offset +
                                sign_image_size + signature_offset +
                                revision_low + revision_high +
                                flash_patch_offset) & 0xFFFFFFFF
        bl1_header = struct.pack(
            self.ROT_HEADER_FORMAT,
            aes_data_offset,
            enc_offset,
            sign_image_size,
            signature_offset,
            revision_low,
            revision_high,
            flash_patch_offset,
            bl1_header_checksum
        )
        bl1_image.extend(bytearray(sign_image_size - bl1_image_len))
        output_image = bytearray(sign_image_size)
        insert_bytearray(bl1_image, output_image, 0)
        # insert header
        insert_bytearray(bl1_header, output_image, header_offset)

        if cot_algorithm_name:
            self.insert_bl1_cot_info(output_image, cot_alg_data,
                                     cot_header_offset, cot_verify_key_path,
                                     cot_digest_fd, cot_data_offset)
            plain_image = output_image.copy()
        else:
            plain_image = bl1_image

        sign_key_path = ''
        if alg_data.algorithm_type == RSA_SHA:
            if not rsa_sign_key_path:
                raise SecError("Missing sign key")
            self.make_bl1_mode_2_image(output_image, alg_data, rsa_sign_key_path,
                                       header_offset,
                                       sign_image_size, signature_offset,
                                       rsa_key_order,
                                       signing_helper, signing_helper_with_files, deterministic)
        elif alg_data.algorithm_type == AES_RSA_SHA:
            if not rsa_sign_key_path:
                raise SecError("Missing sign key")
            if deterministic:
                aes_iv_path = '/dev/zero'
                # The Cipher_pkcs1_v1_5 infra from pycryptodome==3.9.7 skips
                # over 0 values returned by the supplied randfunc. Make our
                # dummy implementation return non-zero values (0xff) instead.
                def rsa_aes_randfunc(size): return bytes([0xff] * size)
            else:
                aes_iv_path = '/dev/urandom'
                # Use the default randfunc selected by Cipher_pkcs1_v1_5.new()
                rsa_aes_randfunc = None

            aes_iv = open(aes_iv_path, 'rb').read(16)

            if aes_key_fd:
                aes_key = bytearray(aes_key_fd.read())
            else:
                raise SecError("Missing aes_key for AES_RSA_SHA")
            if (not key_in_otp) & (not rsa_aes_key_path):
                raise SecError(
                    "Missing --rsa_aes when key is not in otp")
            self.make_bl1_mode_2_enc_image(output_image, alg_data, rsa_sign_key_path,
                                           header_offset,
                                           sign_image_size, signature_offset,
                                           enc_offset, aes_key,
                                           aes_iv, aes_data_offset,
                                           key_in_otp, rsa_aes_key_path,
                                           rsa_key_order,
                                           signing_helper,
                                           signing_helper_with_files,
                                           deterministic, rsa_aes_randfunc)
        elif alg_data.algorithm_type == AES_GCM:
            aes_iv_path = '/dev/zero' if deterministic else '/dev/urandom'
            gcm_aes_iv = open(aes_iv_path, 'rb').read(12)
            gcm_aes_iv = gcm_aes_iv + b"\x00\x00\x00\x01"

            if gcm_aes_key_fd:
                gcm_aes_key = bytearray(gcm_aes_key_fd.read())
            else:
                raise SecError("Missing gcm_aes_key for AES_GCM")
            self.make_bl1_mode_gcm_image(output_image, alg_data, gcm_aes_key, gcm_aes_iv,
                                         header_offset, enc_offset,
                                         sign_image_size, signature_offset,
                                         aes_data_offset,
                                         signing_helper, signing_helper_with_files)
        elif alg_data.algorithm_type == ECDSA_P384:
            if not ecdsa_sign_key_path:
                raise SecError("Missing sign key")
            self.make_bl1_mode_ecdsa_image(output_image, ecdsa_sign_key_path,
                                           sign_image_size,
                                           signature_offset, signing_helper,
                                           signing_helper_with_files)
        elif alg_data.algorithm_type == AES_ECDSA_P384:
            if not ecdsa_sign_key_path:
                raise SecError("Missing sign key")
            if deterministic:
                aes_iv_path = '/dev/zero'
                # The Cipher_pkcs1_v1_5 infra from pycryptodome==3.9.7 skips
                # over 0 values returned by the supplied randfunc. Make our
                # dummy implementation return non-zero values (0xff) instead.
                def rsa_aes_randfunc(size): return bytes([0xff] * size)
            else:
                aes_iv_path = '/dev/urandom'
                # Use the default randfunc selected by Cipher_pkcs1_v1_5.new()
                rsa_aes_randfunc = None

            aes_iv = open(aes_iv_path, 'rb').read(16)

            if aes_key_fd:
                aes_key = bytearray(aes_key_fd.read())
            else:
                raise SecError("Missing aes_key for AES_RSA_SHA")
            if (not key_in_otp) & (not rsa_aes_key_path):
                raise SecError(
                    "Missing --rsa_aes when key is not in otp")
            self.make_bl1_mode_ecdsa_enc_image(output_image, alg_data, ecdsa_sign_key_path,
                                               header_offset,
                                               sign_image_size, signature_offset,
                                               enc_offset, aes_key,
                                               aes_iv, aes_data_offset,
                                               key_in_otp, rsa_aes_key_path,
                                               signing_helper,
                                               signing_helper_with_files,
                                               deterministic, rsa_aes_randfunc)
        else:
            raise SecError("Algorithm not supported")

        self.verify_bl1_image(plain_image, output_image, header_offset,
                              rsa_sign_key_path, ecdsa_sign_key_path, gcm_aes_key,
                              aes_key, rsa_aes_key_path,
                              alg_data, key_in_otp, rsa_key_order)

        output_fd.write(bytes(output_image))
        output_fd.close()

    def make_sv_partation_image(self, alg_data, descriptor, rsa_key_order,
                                signing_helper, signing_helper_with_files):

        image = bytearray(open(descriptor.image_path, 'rb').read())
        image[:0] = bytearray(self.COT_HEADER_SIZE)
        image_len = len(image)

        sign_image_size = 0
        signature_offset = 0
        npkey_offset = 0
        revision_low = 0
        revision_high = 0

        if descriptor.next_verify_key_path:
            npkey_bin = bytearray(rsa_key_to_bin(
                descriptor.next_verify_key_path, 'public'))
            npkey_offset = (image_len + 0xf) & (~0xf)
            sign_image_size = npkey_offset + alg_data.public_key_num_bytes
            insert_bytearray(npkey_bin, image, npkey_offset)

            info = self._cot_info(alg_data, 17)
        else:
            sign_image_size = (image_len + 0xf) & (~0xf)
            info = 0

        sign_image_size = (sign_image_size + 511) & (~511)
        signature_offset = sign_image_size

        header = struct.pack(
            self.COT_HEADER_FORMAT,
            self.MAGIC_WORD_VB.encode(),
            info,
            sign_image_size,
            signature_offset,
            npkey_offset,
            revision_low,
            revision_high,
            bytearray(472)
        )
        insert_bytearray(header, image, 0)

        image.extend(bytearray(sign_image_size - image_len))
        sha = alg_data.hash_alg.new(image[0:sign_image_size])
        digest = sha.digest()

        signature = rsa_sign(
            alg_data, descriptor.sign_key_path, digest,
            signing_helper, signing_helper_with_files, False, order=rsa_key_order)

        insert_bytearray(signature, image, signature_offset)

        return image

    def make_sv_chain_image(self, algorithm, cot_part,
                            image_relative_path, rsa_key_order,
                            signing_helper, signing_helper_with_files):

        print('WARNING: ASPEED CoT is deprecated.')
        cot_alg_data = self.parse_algorithm(algorithm)

        descriptors = []
        part_count = len(cot_part)
        for i in range(0, part_count):
            part_list = cot_part[i].split(':')
            if len(part_list) != 4:
                raise SecError(
                    'Malformed chained partition "{}".'.format(cot_part[i]))
            if i < part_count - 1:
                npart_list = cot_part[i + 1].split(':')
                if len(npart_list) != 4:
                    raise SecError(
                        'Malformed chained partition "{}".'.format(cot_part[i + 1]))
                next_part_verify_key_path = npart_list[2]
            else:
                next_part_verify_key_path = None

            input_image_path = image_relative_path + part_list[0]
            output_image_path = image_relative_path + part_list[1]
            sign_key_path = part_list[2]
            verify_key_path = part_list[3]

            desc = ChainPartitionDescriptor(input_image_path,
                                            output_image_path,
                                            sign_key_path,
                                            verify_key_path,
                                            next_part_verify_key_path)
            descriptors.append(desc)

        image_list = []
        for desc in descriptors:

            sec_image = self.make_sv_partation_image(
                cot_alg_data, desc, rsa_key_order,
                signing_helper, signing_helper_with_files)

            open(desc.out_path, 'w+b').write(bytes(sec_image))
            image_list.append(sec_image)

        self.verify_sv_chain_image(image_list, descriptors[0].verify_key_path,
                                   cot_alg_data, rsa_key_order)


class SecureBootVerify(object):
    otp = OTP_info
    sec = Sec()

    def parse_otp(self, otp_image):
        info_struct = {}
        header = otp_image[0:self.otp.HEADER_SIZE]

        (magic_b, soc_ver, _, image_info, data_info, config_info, strap_info,
         checksum_offset) = struct.unpack(self.otp.HEADER_FORMAT, header)

        magic = magic_b[0:len(self.otp.MAGIC_WORD_OTP)].decode()
        if magic != self.otp.MAGIC_WORD_OTP:
            raise SecError('OTP image magic word is invalid')
        info_struct['rsa_key_order'] = 'little'
        if soc_ver == OTP_info.SOC_AST2600A0:
            otp_info = self.otp.OTP_INFO['A0']
        elif soc_ver == OTP_info.SOC_AST2600A1:
            otp_info = self.otp.OTP_INFO['A1']
        elif soc_ver == OTP_info.SOC_AST2600A2:
            otp_info = self.otp.OTP_INFO['A2']
        elif soc_ver == OTP_info.SOC_AST2600A3:
            otp_info = self.otp.OTP_INFO['A3']
            if image_info & self.otp.INC_ORDER:
                info_struct['rsa_key_order'] = 'big'
            else:
                info_struct['rsa_key_order'] = 'little'
        elif soc_ver == OTP_info.SOC_AST1030A0:
            otp_info = self.otp.OTP_INFO['1030A0']
        elif soc_ver == OTP_info.SOC_AST1030A1:
            otp_info = self.otp.OTP_INFO['1030A1']
            if image_info & self.otp.INC_ORDER:
                info_struct['rsa_key_order'] = 'big'
            else:
                info_struct['rsa_key_order'] = 'little'
        else:
            raise SecError('OTP image version is invalid')

        info_struct['version'] = soc_ver
        image_size = image_info & 0xffff
        sha = SHA256.new(otp_image[:image_size])
        digest = sha.digest()

        if digest != otp_image[checksum_offset:checksum_offset+32]:
            raise SecError('OTP image checksum is invalid')

        data_offset = data_info & 0xffff
        data_size = (data_info >> 16) & 0xffff
        conf_offset = config_info & 0xffff
        conf_size = (config_info >> 16) & 0xffff

        if image_info & self.otp.INC_DUMP:
            data_region = otp_image[data_offset:data_offset+data_size]
            config_region = otp_image[conf_offset:conf_offset+conf_size]
        else:
            d_size = otp_info['data_region_size']
            c_size = otp_info['config_region_size']
            data_region = bytearray(d_size)
            config_region = bytearray(c_size)
            img_data = otp_image[data_offset:data_offset+d_size]
            img_dmask = otp_image[data_offset+d_size:data_offset+d_size*2]
            img_conf = otp_image[conf_offset:conf_offset+c_size]
            img_cmask = otp_image[conf_offset+c_size:conf_offset+c_size*2]
            for i in range(d_size):
                data_region[i] = img_data[i] & ~img_dmask[i]
            for i in range(c_size):
                config_region[i] = img_conf[i] & ~img_cmask[i]

        return info_struct, data_region, config_region

    def parse_config(self, soc_version, config_region):
        cfg0 = struct.unpack('<I', config_region[0:4])[0]
        cfg3 = struct.unpack('<I', config_region[8:12])[0]
        cfg4 = struct.unpack('<I', config_region[12:16])[0]

        sign_scheme = (cfg0 >> 10) & 0xf
        sb_mode = (cfg0 >> 7) & 0x1
        enc_mode = (cfg0 >> 27) & 0x1
        header_offset = cfg3 & 0xffff
        key_retire = (cfg4 & 0x7f) | ((cfg4 >> 16) & 0x7f)
        retire_list = [0]*7

        if header_offset == 0:
            if soc_version in [OTP_info.SOC_AST2600A0, OTP_info.SOC_AST2600A1,
                               OTP_info.SOC_AST2600A2, OTP_info.SOC_AST2600A3]:
                header_offset = 0x20
            elif soc_version in [OTP_info.SOC_AST1030A0, OTP_info.SOC_AST1030A1]:
                header_offset = 0x400

        for i in range(7):
            bit = (key_retire >> i) & 0x1
            if bit == 1:
                retire_list[i] = 1

        if soc_version in [OTP_info.SOC_AST2600A0, OTP_info.SOC_AST2600A1,
                           OTP_info.SOC_AST2600A2, OTP_info.SOC_AST2600A3]:
            if sb_mode == 0:
                algorithm_type = AES_GCM
                print('Algorithm: AES_GCM')
            else:
                if enc_mode == 1:
                    algorithm_type = AES_RSA_SHA
                    print('Algorithm: AES_RSA_SHA')
                else:
                    algorithm_type = RSA_SHA
                    print('Algorithm: RSA_SHA')
        elif soc_version == OTP_info.SOC_AST1030A0:
            if sb_mode == 1:
                raise SecError("PFR mode")

            if enc_mode == 1:
                algorithm_type = AES_RSA_SHA
                print('Algorithm: AES_RSA_SHA')
            else:
                algorithm_type = RSA_SHA
                print('Algorithm: RSA_SHA')
        elif soc_version == OTP_info.SOC_AST1030A1:
            if sb_mode == 1:
                raise SecError("PFR mode")
            if sign_scheme in [0, 1, 2, 3]:
                if enc_mode == 1:
                    algorithm_type = AES_ECDSA_P384
                    print('Algorithm: AES_ECDSA_P384')
                else:
                    algorithm_type = ECDSA_P384
                    print('Algorithm: ECDSA_P384')
            elif sign_scheme in [4, 8, 12, 5, 10, 15]:
                if enc_mode == 1:
                    algorithm_type = AES_RSA_SHA
                    print('Algorithm: AES_RSA_SHA')
                else:
                    algorithm_type = RSA_SHA
                    print('Algorithm: RSA_SHA')
                if sign_scheme in [4, 8, 12]:
                    print('RSA padding: PSS')
                else:
                    print('RSA padding: PKCS1')

        if soc_version in [OTP_info.SOC_AST2600A0, OTP_info.SOC_AST2600A1,
                           OTP_info.SOC_AST2600A2, OTP_info.SOC_AST2600A3,
                           OTP_info.SOC_AST1030A0]:
            # 2600 and 1030A0 only support pkcs1 padding
            rsa_padding = 'pkcs1'
            rsa_len = (cfg0 >> 10) & 0x3
            sha_len = (cfg0 >> 12) & 0x3
        else:
            # 1030A1 support pss padding
            sign_scheme = (cfg0 >> 10) & 0xf
            if sign_scheme == 4:
                rsa_padding = 'pss'
                rsa_len = 1
                sha_len = 1
            elif sign_scheme == 8:
                rsa_padding = 'pss'
                rsa_len = 2
                sha_len = 2
            elif sign_scheme == 12:
                rsa_padding = 'pss'
                rsa_len = 3
                sha_len = 3
            elif sign_scheme in [5, 10, 15]:
                rsa_padding = 'pkcs1'
                rsa_len = (cfg0 >> 10) & 0x3
                sha_len = (cfg0 >> 12) & 0x3
                if [rsa_len, sha_len] not in [[1, 1], [2, 2], [3, 3]]:
                    raise SecError(
                        "Signature scheme not support : 0x{:X}".format(sign_scheme))
            else:
                if sign_scheme == 1:
                    rsa_num_bytes = 256
                elif sign_scheme in [0, 2]:
                    rsa_num_bytes = 384
                else:
                    rsa_num_bytes = 512

                return Algorithm(algorithm_type, SHA384, 0x30, rsa_num_bytes, rsa_num_bytes*2, None), header_offset, retire_list

        if rsa_len == 0:
            rsa_num_bytes = 128
            public_key_num_bytes = 2*1024//8
            print('RSA length: 1024')
        elif rsa_len == 1:
            rsa_num_bytes = 256
            public_key_num_bytes = 2*2048//8
            print('RSA length: 2048')
        elif rsa_len == 2:
            rsa_num_bytes = 384
            public_key_num_bytes = 2*3072//8
            print('RSA length: 3072')
        else:
            rsa_num_bytes = 512
            public_key_num_bytes = 2*4096//8
            print('RSA length: 4096')

        if sha_len == 0:
            hash_alg = SHA224
            hash_num_bytes = 28
            print('HASH length: 224')
        elif sha_len == 1:
            hash_alg = SHA256
            hash_num_bytes = 32
            print('HASH length: 256')
        elif sha_len == 2:
            hash_alg = SHA384
            hash_num_bytes = 48
            print('HASH length: 384')
        else:
            hash_alg = SHA512
            hash_num_bytes = 64
            print('HASH length: 512')

        return Algorithm(algorithm_type, hash_alg, hash_num_bytes,
                         rsa_num_bytes, public_key_num_bytes, rsa_padding), \
            header_offset, retire_list

    def parse_data(self, info_struct, alg_data, data_region, retire_list):
        if info_struct['version'] == OTP_info.SOC_AST2600A0:
            type_lookup = {0x0: AES_OEM,
                           0x1: AES_VAULT,
                           0x8: RSA_OEM,
                           0xa: RSA_SOC_PUB,
                           0xe: RSA_SOC_PRI}
        elif info_struct['version'] in [OTP_info.SOC_AST2600A1,
                                        OTP_info.SOC_AST2600A2,
                                        OTP_info.SOC_AST1030A0]:
            type_lookup = {0x1: AES_VAULT,
                           0x2: AES_OEM,
                           0x8: RSA_OEM,
                           0xa: RSA_SOC_PUB,
                           0xe: RSA_SOC_PRI}
        elif info_struct['version'] == OTP_info.SOC_AST2600A3:
            if info_struct['rsa_key_order'] == 'big':
                type_lookup = {0x1: AES_VAULT,
                               0x2: AES_OEM,
                               0x9: RSA_OEM,
                               0xb: RSA_SOC_PUB,
                               0xd: RSA_SOC_PRI}
            else:
                type_lookup = {0x1: AES_VAULT,
                               0x2: AES_OEM,
                               0x8: RSA_OEM,
                               0xa: RSA_SOC_PUB,
                               0xc: RSA_SOC_PRI}
        elif info_struct['version'] == OTP_info.SOC_AST1030A1:
            type_lookup = {0x1: AES_VAULT,
                           0x2: AES_OEM,
                           0x9: RSA_OEM,
                           0xb: RSA_SOC_PUB,
                           0xd: RSA_SOC_PRI,
                           0x5: ECDSA_PARMETER,
                           0x7: ECDSA_PUB}

        key_list = []
        find_last = 0
        for i in range(16):
            h = struct.unpack('<I', data_region[(i*4):(i*4+4)])[0]
            kl = {}
            kl['ID'] = h & 0x7
            kl['RETIRE'] = retire_list[kl['ID']]
            kl['OFFSET'] = ((h >> 3) & 0x3ff) << 3
            kl['TYPE'] = type_lookup[(h >> 14) & 0xf]
            kl['PAR'] = (h >> 18) & 0x3
            key_list.append(kl)
            if h & (1 << 13):
                find_last = 1
                break

        if find_last == 0:
            raise SecError("Can not find Last List in OTP data region")

        for kl in key_list:
            if kl['TYPE'] in [RSA_OEM, RSA_SOC_PUB, RSA_SOC_PRI]:
                if kl['PAR'] == 0:
                    rsa_len = 1024//8
                elif kl['PAR'] == 1:
                    rsa_len = 2048//8
                elif kl['PAR'] == 2:
                    rsa_len = 3072//8
                else:
                    rsa_len = 4096//8
                if rsa_len != alg_data.rsa_num_bytes:
                    raise SecError(
                        "OTP key type is not compatible with config")

                key_offset = kl['OFFSET']

                kl['M'] = data_region[key_offset: key_offset+rsa_len]
                if kl['TYPE'] == RSA_SOC_PRI:
                    kl['E'] = data_region[key_offset +
                                          rsa_len: key_offset + rsa_len*2]
                else:
                    kl['E'] = bytearray([0x01, 0x0, 0x01])
            elif kl['TYPE'] == AES_OEM:
                kl['AES'] = data_region[kl['OFFSET']: kl['OFFSET']+32]
            elif kl['TYPE'] == AES_VAULT:
                kl['AES1'] = data_region[kl['OFFSET']: kl['OFFSET']+32]
                kl['AES2'] = data_region[kl['OFFSET']+32: kl['OFFSET']+64]
            elif kl['TYPE'] == ECDSA_PUB:
                kl['Qx'] = data_region[kl['OFFSET']: kl['OFFSET']+0x30]
                kl['Qy'] = data_region[kl['OFFSET']+0x30: kl['OFFSET']+0x60]
            elif kl['TYPE'] == ECDSA_PARMETER:
                kl['Gx'] = data_region[kl['OFFSET']: kl['OFFSET']+0x30]
                kl['Gy'] = data_region[kl['OFFSET']+0x30: kl['OFFSET']+0x60]
                kl['p'] = data_region[kl['OFFSET']+0x60: kl['OFFSET']+0x90]
                kl['n'] = data_region[kl['OFFSET']+0x90: kl['OFFSET']+0xc0]

        return key_list

    def mode2_verify(self, sec_image, sign_image_size, signature_offset,
                     alg_data, key_list, rsa_key_order):
        verify_pass = 0
        v_id = 0
        _signature = sec_image[signature_offset:signature_offset +
                               alg_data.rsa_num_bytes]
        signature = int.from_bytes(
            _signature, byteorder=rsa_key_order, signed=False)
        sign_image = sec_image[:sign_image_size]
        sha = alg_data.hash_alg.new(sign_image)
        image_hash = sha.digest()
        for kl in key_list:
            if kl['TYPE'] != RSA_OEM:
                continue
            if kl['RETIRE'] == 1:
                continue
            M = int.from_bytes(kl['M'], byteorder=rsa_key_order, signed=False)
            E = int.from_bytes(kl['E'], byteorder=rsa_key_order, signed=False)
            sign_dec = pow(signature, E, M).to_bytes(
                alg_data.rsa_num_bytes, byteorder=rsa_key_order, signed=False)

            if alg_data.rsa_padding == 'pkcs1':
                if rsa_key_order == 'little':
                    dig = sign_dec[:alg_data.hash_num_bytes]
                else:
                    dig = sign_dec[len(sign_dec)-alg_data.hash_num_bytes:]
                if dig == image_hash:
                    v_id = kl['ID']
                    verify_pass = 1
                    break
            else:
                if rsa_pss_em_ver(alg_data, sign_dec, image_hash):
                    v_id = kl['ID']
                    verify_pass = 1
                    break

        if verify_pass == 0:
            raise SecError("Mode 2 verify failed")

        return v_id

    def mode2_decrypt(self, sec_image, sign_image_size, enc_offset,
                      aes_data_offset, v_id, alg_data, key_list, rsa_key_order):
        option = 0
        for kl in key_list:
            if kl['TYPE'] == AES_OEM:
                key = kl
                option = 1
                break
        if option == 0:
            for kl in key_list:
                if kl['TYPE'] in [RSA_SOC_PUB, RSA_SOC_PRI]:
                    key = kl
                    option = 2
                    break
        if option == 0:
            for kl in key_list:
                if kl['ID'] == v_id:
                    key = kl
                    option = 3
                    break

        if option == 1:
            aes_key = key['AES']
            aes_iv = sec_image[aes_data_offset:aes_data_offset+16]
        elif option in [2, 3]:
            rsa_key_length = alg_data.rsa_num_bytes
            _key_obj = sec_image[aes_data_offset:aes_data_offset + rsa_key_length]
            key_obj = int.from_bytes(
                _key_obj, byteorder=rsa_key_order, signed=False)
            M = int.from_bytes(key['M'], byteorder=rsa_key_order, signed=False)
            E = int.from_bytes(key['E'], byteorder=rsa_key_order, signed=False)

            D = pow(key_obj, E, M)
            aes_object = D.to_bytes(
                alg_data.rsa_num_bytes, byteorder=rsa_key_order, signed=False)
            if rsa_key_order == 'little':
                aes_key = bytes(aes_object[0:0x20])
                aes_iv = bytes(aes_object[0x20:0x30])
            else:
                aes_key = bytes(aes_object[-0x40:-0x20])
                aes_iv = bytes(aes_object[-0x20:-0x10])
        else:
            raise SecError("Cannot find decrypt key.")

        ctr = Counter.new(128, initial_value=int.from_bytes(
            aes_iv, byteorder='big'))
        aes = AES.new(aes_key, AES.MODE_CTR, counter=ctr)
        dec_image = bytearray(aes.decrypt(
            bytes(sec_image[enc_offset:sign_image_size])))

        return sec_image[:enc_offset] + dec_image

    def modeGCM_verify_n_decrypt(self, sec_image, sign_image_size,
                                 signature_offset, enc_offset, aes_data_offset,
                                 key_list):
        v_id = 0

        image_signature = sec_image[signature_offset:signature_offset+16]
        rev_signature = bytearray(16)
        for i in range(0, 15, 4):
            rev_signature[i] = image_signature[12-i]
            rev_signature[i+1] = image_signature[13-i]
            rev_signature[i+2] = image_signature[14-i]
            rev_signature[i+3] = image_signature[15-i]

        aes_iv = sec_image[aes_data_offset:aes_data_offset+12]

        for kl in key_list:
            if kl['TYPE'] != AES_OEM:
                continue
            verify_pass = 1
            try:
                aes = AES.new(kl['AES'], AES.MODE_GCM, nonce=aes_iv[0:12])
                aes.update(sec_image[:enc_offset])
                plaintext = aes.decrypt_and_verify(
                    sec_image[enc_offset:sign_image_size], rev_signature)
            except (ValueError, KeyError):
                verify_pass = 0
            if verify_pass == 1:
                v_id = kl['ID']
                break

        if verify_pass == 0:
            raise SecError("Mode GCM verify failed")

        return sec_image[:enc_offset] + plaintext, v_id

    def modeecdsa_verify(self, sec_image, sign_image_size, signature_offset,
                         key_list, rsa_key_order):
        verify_pass = 0
        v_id = 0
        _signature = sec_image[signature_offset:signature_offset + 0x60]
        sign_image = sec_image[:sign_image_size]
        sha = SHA384.new(sign_image)
        image_hash = sha.digest()
        for kl in key_list:
            if kl['TYPE'] != ECDSA_PUB:
                continue
            if kl['RETIRE'] == 1:
                continue
            if kl['TYPE'] == ECDSA_PUB:
                Qx = int.from_bytes(kl['Qx'], byteorder='big', signed=False)
                Qy = int.from_bytes(kl['Qy'], byteorder='big', signed=False)
                Q = Point(NIST384p.curve, Qx, Qy)
                vk = VerifyingKey.from_public_point(Q, curve=NIST384p)
                try:
                    ret = vk.verify_digest(_signature, image_hash)
                except:
                    ret = 0
                if ret:
                    verify_pass = 1
                    v_id = kl['ID']

        if verify_pass == 0:
            raise SecError("Mode ECDSA verify failed")

        return v_id

    def verify_rot_image(self, sec_image, header_offset, alg_data, key_list, rsa_key_order):
        dec_image = None

        header = sec_image[header_offset:header_offset +
                           self.sec.ROT_HEADER_SIZE]
        (aes_data_offset, enc_offset, sign_image_size, signature_offset,
         _, _, _, _) = struct.unpack(self.sec.ROT_HEADER_FORMAT, header)

        if alg_data.algorithm_type == RSA_SHA and enc_offset != 0:
            raise SecError(
                "The secure image is encrypted, the OTP image is not match")
        elif alg_data.algorithm_type in [AES_RSA_SHA, AES_GCM] and enc_offset == 0:
            raise SecError(
                "The OTP config is enable encryption mode, but the secure image is not encrypted")

        if alg_data.algorithm_type in [RSA_SHA, AES_RSA_SHA]:
            v_id = self.mode2_verify(sec_image, sign_image_size, signature_offset,
                                     alg_data, key_list, rsa_key_order)
            for kl in key_list:
                if kl['TYPE'] == RSA_OEM and kl['ID'] == v_id:
                    print('Verify key ...')
                    print('Key Type: OEM DSS RSA public keys')
                    print('ID: {}'.format(v_id))
                    print('M:')
                    hexdump(kl['M'])
                    print('E:')
                    hexdump(kl['E'])
                    break

            if alg_data.algorithm_type == AES_RSA_SHA:
                dec_image = self.mode2_decrypt(sec_image, sign_image_size,
                                               enc_offset, aes_data_offset,
                                               v_id, alg_data, key_list,
                                               rsa_key_order)
        elif alg_data.algorithm_type == AES_GCM:
            dec_image, v_id = \
                self.modeGCM_verify_n_decrypt(sec_image, sign_image_size,
                                              signature_offset, enc_offset,
                                              aes_data_offset, key_list)
        elif alg_data.algorithm_type in [ECDSA_P384, AES_ECDSA_P384]:
            v_id = self.modeecdsa_verify(sec_image, sign_image_size, signature_offset,
                                         key_list, 'big')
            for kl in key_list:
                if kl['TYPE'] == ECDSA_PUB and kl['ID'] == v_id:
                    print('Verify key ...')
                    print('Key Type: OEM DSS ECDSA public keys')
                    print('ID: {}'.format(v_id))
                    print('Qx:')
                    hexdump(kl['Qx'])
                    print('Qy:')
                    hexdump(kl['Qy'])
                    break
            if alg_data.algorithm_type == AES_ECDSA_P384:
                dec_image = self.mode2_decrypt(sec_image, sign_image_size,
                                               enc_offset, aes_data_offset,
                                               v_id, alg_data, key_list,
                                               'big')

        return dec_image

    # def verify_cot_image(self, sec_image, header_offset):
    #     rot_cot_header = sec_image[header_offset:header_offset+0x8]
    #     (cot_info, data_offset) = struct.unpack(
    #         self.sec.COT_INFO_FORMAT, rot_cot_header)

    def verify_secure_image(self, sec_image_fd, output_fd, otp_image_fd, cot_offset):
        otp_image = otp_image_fd.read()
        sec_image = sec_image_fd.read()
        info_struct, data_region, config_region = self.parse_otp(otp_image)

        alg_data, header_offset, retire_list = self.parse_config(info_struct['version'],
                                                                 config_region)

        key_list = self.parse_data(info_struct, alg_data, data_region,
                                   retire_list)
        header = sec_image[header_offset:header_offset +
                           self.sec.ROT_HEADER_SIZE]
        (aes_data_offset, enc_offset, sign_image_size, signature_offset,
         revision_low, revision_high, reserved, bl1_header_checksum) = \
            struct.unpack(self.sec.ROT_HEADER_FORMAT, header)

        if((aes_data_offset + enc_offset + sign_image_size +
            signature_offset + revision_low + revision_high +
                reserved + bl1_header_checksum) & 0xffffffff) != 0:
            raise SecError("header checksum verify failed")
        if sign_image_size % 512:
            raise SecError("The sign_image_size should be 512 bytes aligned")

        print("check RoT header PASS")
        dec_image = self.verify_rot_image(sec_image[:sign_image_size+1024],
                                          header_offset, alg_data, key_list,
                                          info_struct['rsa_key_order'])
        print("check RoT integrity PASS")

        if dec_image != None and output_fd != None:
            print("write decrypt image to {}".format(output_fd.name))
            output_fd.write(bytes(dec_image + sec_image[sign_image_size:]))
            output_fd.flush()
            output_fd.close()

        if cot_offset == None:
            return

        # offset_list = cot_offset.split(':')


class secTool(object):
    """Object for sectool command-line tool."""

    def __init__(self):
        """Initializer method."""
        self.sec = Sec()
        self.verify = SecureBootVerify()

    def run(self, argv):
        """Command-line processor.

        Arguments:
            argv: Pass sys.argv from main.
        """
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(title='subcommands',
                                           dest='subparser_name')

        sub_parser = subparsers.add_parser('make_secure_bl1_image',
                                           help='Makes a signed bl1 image.')
        sub_parser.add_argument('--soc',
                                help='soc id (e.g. 2600, 1030)',
                                metavar='SOC',
                                default='2600')
        sub_parser.add_argument('--bl1_image',
                                help='Bootloader 1 Image (e.g. u-boot-spl.bin), which will be verified by soc',
                                type=argparse.FileType('rb'),
                                required=False)
        stack_intersects_verification_region_help = '''By default, the
        maximum size of SPL images socsec will sign is 60KB, since,
        historically, the SoCs have been using the top of the SRAM
        for the SPL execution stack. However, on 2600 (A1) and above
        SoCs, an additional 24KB SRAM can be used for the stack,
        allowing the verification region to occupy the entire 64KB
        (including signature). For these models of boards, this
        layout will also be the default in future SDK releases.
        Use this parameter to explicitly indicate that the SPL image
        being signed has (=true) or has not (=false) the SPL stack
        overlapping the 64KB verification region. With this argument
        set to \'false\', socsec will sign SPL images up towards
        64KB (including 512B signature)'''
        sub_parser.add_argument('--stack_intersects_verification_region',
                                dest='stack_intersects_verification_region',
                                choices=['true', 'false'], default='false',
                                help=stack_intersects_verification_region_help)
        sub_parser.add_argument('--header_offset',
                                help='RoT header offset',
                                type=parse_number,
                                default=None)
        sub_parser.add_argument('--rsa_sign_key',
                                help='Path to RSA private key file, which will use to sign BL1_IMAGE')
        sub_parser.add_argument('--ecdsa_sign_key',
                                help='Path to ECDSA private key file, which will use to sign BL1_IMAGE')
        sub_parser.add_argument('--rsa_key_order',
                                help='This value the OTP setting(e.g. little, big), default value is "little". \
                                      If RSA padding mode is PSS, rsa_key_order will be big endian',
                                metavar='ORDER',
                                default="little")
        sub_parser.add_argument('--gcm_aes_key',
                                type=argparse.FileType('rb'),
                                help='Path to aes private key file, which will use to sign BL1_IMAGE')
        sub_parser.add_argument('--output',
                                help='Output file name',
                                type=argparse.FileType('w+b'),
                                required=False)
        sub_parser.add_argument('--algorithm',
                                help='Algorithm to use (default: NONE e.g. AES_GCM, AES_RSA2048_SHA256, RSA2048_SHA256, ...), \
                                      RSA algo support RSA1024, RSA2048, RSA3072 and RSA4096, HASH algo support SHA224, SHA256, SHA384 and SHA512',
                                metavar='ALGORITHM',
                                default='NONE')
        sub_parser.add_argument('--rsa_padding',
                                help='Algorithm to use (default: pkcs1 e.g. pkcs1, pss), \
                                      RSA support pkcs1 padding or pss padding',
                                metavar='PADDING',
                                default='pkcs1')
        sub_parser.add_argument('--revision_id',
                                help='Revision id for rollback prevention (0 <= REVISION_ID <= 64)',
                                type=parse_number,
                                default=0)
        sub_parser.add_argument('--signing_helper',
                                help='Path to helper used for signing',
                                metavar='APP',
                                nargs='?',
                                default=None,
                                required=False)
        sub_parser.add_argument('--signing_helper_with_files',
                                help='Path to helper used for signing using files',
                                metavar='APP',
                                nargs='?',
                                default=None,
                                required=False)

        # UNSAFE: IVs and other input data are read from deterministic sources.
        # Used to implement the test suite
        sub_parser.add_argument('--deterministic',
                                help=argparse.SUPPRESS,
                                default=False,
                                action='store_true',
                                required=False)

        enc_group = sub_parser.add_argument_group(
            'enc_group', 'Enable aes encryption in mode 2')

        enc_group.add_argument('--enc_offset',
                               help='Offset where encryption start',
                               type=parse_number,
                               default=None)
        enc_group.add_argument('--aes_key',
                               help='Path to aes key file',
                               type=argparse.FileType('rb'),
                               nargs='?',
                               required=False)
        enc_group.add_argument('--key_in_otp',
                               help='aes key is storing in otp',
                               action='store_true',
                               required=False)
        enc_group.add_argument('--rsa_aes',
                               help='Path to RSA public key file, which is used to encrypt aes key',
                               nargs='?')
        sub_parser.add_argument('--flash_patch_offset',
                                help='Flash patch offset for ast2605',
                                type=parse_number,
                                default=None)

        cot_group = sub_parser.add_argument_group(
            'cot_group', '(deprecated)Chain of trust argument')

        cot_group.add_argument('--cot_algorithm',
                               help='Algorithm to use (default: NONE e.g. RSA2048_SHA256), \
                                      RSA algo support RSA1024, RSA2048, RSA3072 and RSA4096, HASH algo support SHA224, SHA256, SHA384 and SHA512',
                               metavar='ALGORITHM',
                               nargs='?')
        cot_mut = cot_group.add_mutually_exclusive_group()
        cot_mut.add_argument('--cot_verify_key',
                             help='Path to RSA public key file, which will use to verify next chain image (BL2)',
                             nargs='?')
        cot_mut.add_argument('--cot_digest',
                             type=argparse.FileType('rb'),
                             help='Path to digest result of next chain image')

        sub_parser.set_defaults(func=self.make_secure_bl1_image)

        sub_parser = subparsers.add_parser('make_sv_chain_image',
                                           help='(deprecated)Makes a signature verified cot image.')
        sub_parser.add_argument('--algorithm',
                                help='Algorithm to use (default: NONE e.g. RSA2048_SHA256, RSA3072_SHA384, ...), \
                                      RSA algo support RSA1024, RSA2048, RSA3072 and RSA4096, HASH algo support SHA224, SHA256, SHA384 and SHA512',
                                metavar='ALGORITHM',
                                default='NONE')
        sub_parser.add_argument('--rsa_key_order',
                                help='This value the OTP setting(e.g. little, big), default value is "little"',
                                metavar='ORDER',
                                default="little")
        sub_parser.add_argument('--cot_part',
                                help='',
                                nargs='+',
                                metavar='BL2_IMAGE:BL2_OUT:BL2_SIGN_KEY:BL2_VERIFY_KEY BL3_IMAGE:BL3_OUT:BL3_SIGN_KEY:BL3_VERIFY_KEY')
        sub_parser.add_argument('--image_relative_path',
                                help='Image relative path',
                                type=parse_path,
                                default='')
        sub_parser.add_argument('--signing_helper',
                                help='Path to helper used for signing',
                                metavar='APP',
                                nargs='?',
                                default=None,
                                required=False)
        sub_parser.add_argument('--signing_helper_with_files',
                                help='Path to helper used for signing using files',
                                metavar='APP',
                                nargs='?',
                                default=None,
                                required=False)
        sub_parser.set_defaults(func=self.make_sv_chain_image)

        sub_parser = subparsers.add_parser('verify',
                                           help='verify the image')
        sub_parser.add_argument('--sec_image',
                                help='Path to secure image',
                                type=argparse.FileType('rb'),
                                metavar='IMAGE',
                                required=True)
        sub_parser.add_argument('--output',
                                help='Output non-secure image',
                                type=argparse.FileType('w+b'),
                                metavar='IMAGE',
                                required=False)
        sub_parser.add_argument('--otp_image',
                                help='Path to otp image',
                                type=argparse.FileType('rb'),
                                metavar='IMAGE',
                                required=True)
        sub_parser.add_argument('--cot_offset',
                                help='Offset for every image, e.g. 0x10000:0x100000',
                                metavar='IMAGE',
                                default=None,
                                required=False)
        sub_parser.set_defaults(func=self.verify_secure_image)

        sub_parser = subparsers.add_parser('version',
                                           help='print otptool version.')
        sub_parser.set_defaults(func=self.print_version)

        args = parser.parse_args(argv[1:])

        if(len(argv) == 1):
            parser.print_usage()
            sys.exit(1)

        args.func(args)

    def make_secure_bl1_image(self, args):
        """Implements the 'make_secure_bl1_image' sub-command."""
        self.sec.make_secure_bl1_image(args.soc,
                                       args.bl1_image, args.rsa_sign_key,
                                       args.ecdsa_sign_key,
                                       args.gcm_aes_key,
                                       args.output, args.algorithm,
                                       args.rsa_padding,
                                       args.header_offset,
                                       args.revision_id,
                                       args.enc_offset,
                                       args.aes_key,
                                       args.rsa_aes,
                                       args.key_in_otp,
                                       args.rsa_key_order,
                                       args.flash_patch_offset,
                                       args.cot_algorithm,
                                       args.cot_verify_key,
                                       args.cot_digest,
                                       args.signing_helper,
                                       args.signing_helper_with_files,
                                       args.stack_intersects_verification_region,
                                       args.deterministic)

    def make_sv_chain_image(self, args):
        """Implements the 'make_sv_chain_image' sub-command."""
        self.sec.make_sv_chain_image(args.algorithm,
                                     args.cot_part,
                                     args.image_relative_path,
                                     args.rsa_key_order,
                                     args.signing_helper,
                                     args.signing_helper_with_files)

    def verify_secure_image(self, args):
        """Implements the 'verify' sub-command."""
        self.verify.verify_secure_image(args.sec_image,
                                        args.output,
                                        args.otp_image,
                                        args.cot_offset)

    def print_version(self, args):
        print(__version__)
