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

from bitarray import bitarray
import os
from ecdsa.keys import VerifyingKey
from pkg_resources import resource_filename as pkgdata
import struct
from Crypto.PublicKey import RSA
import binascii
from enum import Enum

__version__ = "2.2.0"


def version2int(version):
    major, minor, patch = [int(x, 10) for x in version.split('.')]
    return (major << 24) + (minor << 12) + patch


def int2version(ver_int):
    major = (ver_int >> 24) & 0xff
    minor = (ver_int >> 12) & 0xfff
    patch = ver_int & 0xfff
    return "{}.{}.{}".format(major, minor, patch)


def parse_path(path):
    if path is None or path == '':
        return os.path.abspath(os.path.curdir)+'/'
    if path[-1] != '/':
        path += '/'
    return path


def insert_bytearray(src, dst, offset):
    if offset+len(src) > len(dst):
        dst.extend(bytearray(offset-len(dst)+len(src)))

    dst[offset:offset+len(src)] = src


def rsa_importkey(key_file):
    with open(key_file, 'r') as f:
        pos = 0
        for line in f:
            if line.find('-----BEGIN', 0) == 0:
                print("Found PEM header at position {}".format(pos))
                break
            pos += len(line)
        f.seek(pos)
        key_file_str = f.read()
        f.close()
    return RSA.importKey(key_file_str)


def _rsa_bit_length(rsa_key, var):
    if var == 'n':
        key_bit_length = len(bitarray(bin(rsa_key.n)[2:]))
    elif var == 'e':
        key_bit_length = len(bitarray(bin(rsa_key.e)[2:]))
    elif var == 'd':
        key_bit_length = len(bitarray(bin(rsa_key.d)[2:]))
    return key_bit_length


def rsa_bit_length(rsa_key_file: str, var: str) -> int:
    rsa_key = rsa_importkey(rsa_key_file)

    return _rsa_bit_length(rsa_key, var)


def rsa_key_to_bin(rsa_key_file, types, order='little'):
    if order not in ['little', 'big']:
        raise ValueError("order error")

    rsa_key = rsa_importkey(rsa_key_file)
    rsa_len = _rsa_bit_length(rsa_key, 'n')

    m_len = int(rsa_len/8)

    n = bitarray(bin(rsa_key.n)[2:])
    e = bitarray(bin(rsa_key.e)[2:])
    n_remain = (8-(len(n) % 8)) % 8
    e_remain = (8-(len(e) % 8)) % 8
    for _ in range(0, n_remain):
        n.insert(0, 0)
    for _ in range(0, e_remain):
        e.insert(0, 0)

    n = n.tobytes()
    e = e.tobytes()
    n_b = bytearray(n)
    e_b = bytearray(e)
    if order == 'little':
        n_b.reverse()
        e_b.reverse()

    if types == 'public':
        exp = bytearray([0x01, 0x0, 0x01])
        if e_b != exp:
            raise ValueError("Incorrect public key, e must be \"0x10001\"")
        key_bin = bytearray(m_len)
        insert_bytearray(n_b, key_bin, 0)
    elif types == 'private':
        d = bitarray(bin(rsa_key.d)[2:])
        d_remain = (8-(len(d) % 8)) % 8
        for _ in range(0, d_remain):
            d.insert(0, 0)
        d = d.tobytes()
        d_b = bytearray(d)
        if order == 'little':
            d_b.reverse()
        key_bin = bytearray(m_len * 2)
        insert_bytearray(n_b, key_bin, 0)
        insert_bytearray(d_b, key_bin, m_len)
    else:
        raise ValueError("types error")

    return key_bin

def ecdsa_key_to_bin(ecdsa_key_file):
    with open(ecdsa_key_file, 'r') as f:
        ecdsa_key_str = f.read()
    vk = VerifyingKey.from_pem(ecdsa_key_str)
    _x = vk.pubkey.point.x()
    _y = vk.pubkey.point.y()
    x = bitarray(bin(_x)[2:])
    y = bitarray(bin(_y)[2:])
    x_remain = (8-(len(x) % 8)) % 8
    y_remain = (8-(len(y) % 8)) % 8
    for _ in range(0, x_remain):
        x.insert(0, 0)
    for _ in range(0, y_remain):
        y.insert(0, 0)

    x = x.tobytes()
    y = y.tobytes()
    x_b = bytearray(x)
    y_b = bytearray(y)

    key_bin = bytearray(48 * 2)
    insert_bytearray(x_b, key_bin, 0)
    insert_bytearray(y_b, key_bin, 48)

    return key_bin


def chunks(seq, size):
    '''Generator that cuts sequence (bytes, memoryview, etc.)
       into chunks of given size. If `seq` length is not multiply
       of `size`, the length of the last chunk returned will be
       less than requested.

       >>> list( chunks([1,2,3,4,5,6,7], 3) )
       [[1, 2, 3], [4, 5, 6], [7]]
    '''
    d, m = divmod(len(seq), size)
    for i in range(d):
        yield seq[i*size:(i+1)*size]
    if m:
        yield seq[d*size:]


def hexdump(data):
    '''
    Transform binary data to the hex dump text format:

    00000000: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  ................
    '''
    generator = chunks(data, 16)
    for addr, d in enumerate(generator):
        # 00000000:
        line = '%08X: ' % (addr*16)
        # 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
        dumpstr = ' '.join(
            chunks(binascii.hexlify(d).decode('ascii').upper(), 2))
        line += dumpstr[:8*3]
        if len(d) > 8:  # insert separator if needed
            line += ' ' + dumpstr[8*3:]
        # ................
        # calculate indentation, which may be different for the last line
        pad = 2
        if len(d) < 16:
            pad += 3*(16 - len(d))
        if len(d) <= 8:
            pad += 1
        line += ' '*pad

        for byte in d:
            # printable ASCII range 0x20 to 0x7E
            if 0x20 <= byte <= 0x7E:
                line += chr(byte)
            else:
                line += '.'
        print(line)


class key_type(object):
    def __init__(self, value, key_type, need_id, information):
        self.value = value
        self.key_type = key_type
        self.need_id = need_id
        self.information = information

# OTP image header
#  0x0┌──────────────────────┐
#     │                      │
#     │       "SOCOTP"       │
#     │                      │
#  0x8├──────────────────────┤
#     │                      │
#     │     soc Version      │
#     │                      │
#  0xc├──────────────────────┤
#     │                      │
#     │   otptool Version    │
#     │                      │
# 0x10├──────────────────────┤
#     │                      │
#     │      Image Info      │
#     │                      │
# 0x14├──────────────────────┤
#     │                      │
#     │   Data Region Info   │
#     │                      │
# 0x18├──────────────────────┤
#     │                      │
#     │  Config Region Info  │
#     │                      │
# 0x1c├──────────────────────┤
#     │                      │
#     │  Strap Region Info   │
#     │                      │
# 0x20├──────────────────────┤
#     │                      │
#     │  SCU protect Info    │
#     │                      │
# 0x24├──────────────────────┤
#     │                      │
#     │     Digest offset    │
#     │                      │
#     └──────────────────────┘

# Image Info
# 31 : include data region
# 30 : include config region
# 29 : include strap region
# 28 : Data region ecc enable
# 27 : dump image
# 26 : RSA key order
#      0: little endian
#      1: big endian
# 15:0 : image size

# Region Info
# 31:16 : region size
# 15:0  : region offset


class OTP_info(object):
    MAGIC_WORD_OTP = 'SOCOTP'
    HEADER_FORMAT = '<8s8I'
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
    HEADER_FORMAT_2700 = '<8s11I'
    HEADER_SIZE_2700 = struct.calcsize(HEADER_FORMAT_2700)
    CHECKSUM_LEN = 32
    OTP_KEY_TYPE_RSA_PUB = 1
    OTP_KEY_TYPE_RSA_PRIV = 2
    OTP_KEY_TYPE_AES = 3
    OTP_KEY_TYPE_VAULT = 4
    OTP_KEY_TYPE_HMAC = 5
    OTP_KEY_ECDSA384 = 6
    OTP_KEY_ECDSA384P = 7
    SOC_AST2600A0 = 0
    SOC_AST2600A1 = 1
    SOC_AST2600A2 = 2
    SOC_AST2600A3 = 3
    SOC_AST1030A0 = 4
    SOC_AST1030A1 = 5
    SOC_AST1060A1 = 6
    SOC_AST1060A2 = 7
    SOC_AST2700A0 = 8
    SOC_AST2700A1 = 9
    SOC_AST2700A2 = 10
    INC_DATA = 1 << 31
    INC_CONF = 1 << 30
    INC_STRAP = 1 << 29
    HEADER_ECC = 1 << 28
    HEADER_DUMP = 1 << 27
    HEADER_ORDER = 1 << 26
    INC_SCU_PROTECT = 1 << 25

    # For AST2700
    class OTP_INFO_INC_2700:
        INC_ROM = 1 << 31
        INC_RBP = 1 << 30
        INC_CONF = 1 << 29
        INC_STRAP = 1 << 28
        INC_STRAPEXT = 1 << 27
        INC_SECURE = 1 << 26
        INC_CALIPTRA = 1 << 25

    class OTP_KEY_TYPE_2700(Enum):
        OTP_KEY_TYPE_SOC_ECDSA_PUB = 1
        OTP_KEY_TYPE_SOC_LMS_PUB = 2
        OTP_KEY_TYPE_CAL_MANU_PUB_HASH = 3
        OTP_KEY_TYPE_CAL_OWN_PUB_HASH = 4
        OTP_KEY_TYPE_SOC_VAULT = 5
        OTP_KEY_TYPE_SOC_VAULT_SEED = 6

    OTP_KEY_TYPE_NAME_2700 = [
        "soc_ecdsa_pub",
        "soc_lms_pub",
        "cal_manu_pub_hash",
        "cal_own_pub_hash",
        "soc_vault",
        "soc_vault_seed",
    ]

    OTP_INFO = {
        'A0': {
            'config': pkgdata('socsec', 'otp_info/a0_config.json'),
            'strap': pkgdata('socsec', 'otp_info/a0_strap.json'),
            'data_region_size': 8192,
            'ecc_region_offset': 7168,
            'config_region_size': 64,
            'otp_strap_bit_size': 64,
        },
        'A1': {
            'config': pkgdata('socsec', 'otp_info/a1_config.json'),
            'strap': pkgdata('socsec', 'otp_info/a1_strap.json'),
            'data_region_size': 8192,
            'ecc_region_offset': 7168,
            'config_region_size': 64,
            'otp_strap_bit_size': 64,
        },
        'A2': {
            'config': pkgdata('socsec', 'otp_info/a2_config.json'),
            'strap': pkgdata('socsec', 'otp_info/a1_strap.json'),
            'data_region_size': 8192,
            'ecc_region_offset': 7168,
            'config_region_size': 64,
            'otp_strap_bit_size': 64,
        },
        'A3': {
            'config': pkgdata('socsec', 'otp_info/a3_config.json'),
            'strap': pkgdata('socsec', 'otp_info/a1_strap.json'),
            'data_region_size': 8192,
            'ecc_region_offset': 7168,
            'config_region_size': 64,
            'otp_strap_bit_size': 64,
        },
        '1030A0': {
            'config': pkgdata('socsec', 'otp_info/1030a0_config.json'),
            'strap': pkgdata('socsec', 'otp_info/1030a0_strap.json'),
            'data_region_size': 8192,
            'ecc_region_offset': 7168,
            'config_region_size': 64,
            'otp_strap_bit_size': 64,
        },
        '1030A1': {
            'config': pkgdata('socsec', 'otp_info/1030a1_config.json'),
            'strap': pkgdata('socsec', 'otp_info/1030a0_strap.json'),
            'data_region_size': 8192,
            'ecc_region_offset': 7168,
            'config_region_size': 64,
            'otp_strap_bit_size': 64,
        },
        '2700A1': {
            'rbp': pkgdata('socsec', 'otp_info/2700a1_rbp.json'),
            'config': pkgdata('socsec', 'otp_info/2700a1_config.json'),
            'strap': pkgdata('socsec', 'otp_info/2700a1_strap.json'),
            'caliptra': pkgdata('socsec', 'otp_info/2700a1_caliptra.json'),
            'rom_region_size': 1984,
            'rbp_region_size': 64,
            'config_region_size': 64,
            'strap_bit_size': 32,
            'strap_ext_bit_size': 128,
            'secure_region_size': 6144,
            'caliptra_region_size': 1792,
        },
        '2700A2': {
            'rbp': pkgdata('socsec', 'otp_info/2700a2_rbp.json'),
            'config': pkgdata('socsec', 'otp_info/2700a2_config.json'),
            'strap': pkgdata('socsec', 'otp_info/2700a2_strap.json'),
            'caliptra': pkgdata('socsec', 'otp_info/2700a2_caliptra.json'),
            'rom_region_size': 1984,
            'rbp_region_size': 64,
            'config_region_size': 64,
            'strap_bit_size': 32,
            'strap_ext_bit_size': 128,
            'secure_region_size': 6144,
            'caliptra_region_size': 1792,
        }
    }

    a0_key_type = [
        key_type(0, OTP_KEY_TYPE_AES, 0,
                 'AES-256 as OEM platform key for image encryption/decryption'),
        key_type(1, OTP_KEY_TYPE_VAULT, 0,
                 'AES-256 as secret vault key'),
        key_type(4, OTP_KEY_TYPE_HMAC, 1,
                 'HMAC as encrypted OEM HMAC keys in Mode 1'),
        key_type(8, OTP_KEY_TYPE_RSA_PUB, 1,
                 'RSA-public as OEM DSS public keys in Mode 2'),
        key_type(9, OTP_KEY_TYPE_RSA_PUB, 0,
                 'RSA-public as SOC public key'),
        key_type(10, OTP_KEY_TYPE_RSA_PUB, 0,
                 'RSA-public as AES key decryption key'),
        key_type(13, OTP_KEY_TYPE_RSA_PRIV, 0,
                 'RSA-private as SOC private key'),
        key_type(14, OTP_KEY_TYPE_RSA_PRIV, 0,
                 'RSA-private as AES key decryption key'),
    ]
    a1_key_type = [
        key_type(1, OTP_KEY_TYPE_VAULT, 0,
                 'AES-256 as secret vault key'),
        key_type(2, OTP_KEY_TYPE_AES, 1,
                 'AES-256 as OEM platform key for image encryption/decryption in Mode 2 or AES-256 as OEM DSS keys for Mode GCM'),
        key_type(8, OTP_KEY_TYPE_RSA_PUB, 1,
                 'RSA-public as OEM DSS public keys in Mode 2'),
        key_type(10, OTP_KEY_TYPE_RSA_PUB, 0,
                 'RSA-public as AES key decryption key'),
        key_type(14, OTP_KEY_TYPE_RSA_PRIV, 0,
                 'RSA-private as AES key decryption key'),
    ]
    a3_key_type = [
        key_type(1, OTP_KEY_TYPE_VAULT, 0,
                 'AES-256 as secret vault key'),
        key_type(2, OTP_KEY_TYPE_AES, 1,
                 'AES-256 as OEM platform key for image encryption/decryption in Mode 2 or AES-256 as OEM DSS keys for Mode GCM'),
        key_type(8, OTP_KEY_TYPE_RSA_PUB, 1,
                 'RSA-public as OEM DSS public keys in Mode 2'),
        key_type(9, OTP_KEY_TYPE_RSA_PUB, 1,
                 'RSA-public as OEM DSS public keys in Mode 2(big endian)'),
        key_type(10, OTP_KEY_TYPE_RSA_PUB, 0,
                 'RSA-public as AES key decryption key'),
        key_type(11, OTP_KEY_TYPE_RSA_PUB, 0,
                 'RSA-public as AES key decryption key(big endian)'),
        key_type(12, OTP_KEY_TYPE_RSA_PRIV, 0,
                 'RSA-private as AES key decryption key'),
        key_type(13, OTP_KEY_TYPE_RSA_PRIV, 0,
                 'RSA-private as AES key decryption key(big endian)'),
    ]
    ast1030a1_key_type = [
        key_type(1, OTP_KEY_TYPE_VAULT, 0,
                 'AES-256 as secret vault key'),
        key_type(2, OTP_KEY_TYPE_AES, 1,
                 'AES-256 as OEM platform key for image encryption/decryption in Mode 2 or AES-256 as OEM DSS keys for Mode GCM'),
        key_type(8, OTP_KEY_TYPE_RSA_PUB, 1,
                 'RSA-public as OEM DSS public keys in Mode 2'),
        key_type(9, OTP_KEY_TYPE_RSA_PUB, 1,
                 'RSA-public as OEM DSS public keys in Mode 2(big endian)'),
        key_type(10, OTP_KEY_TYPE_RSA_PUB, 0,
                 'RSA-public as AES key decryption key'),
        key_type(11, OTP_KEY_TYPE_RSA_PUB, 0,
                 'RSA-public as AES key decryption key(big endian)'),
        key_type(12, OTP_KEY_TYPE_RSA_PRIV, 0,
                 'RSA-private as AES key decryption key'),
        key_type(13, OTP_KEY_TYPE_RSA_PRIV, 0,
                 'RSA-private as AES key decryption key(big endian)'),
        key_type(5, OTP_KEY_ECDSA384P, 0,
                 'ECDSA384 cure parameter'),
        key_type(7, OTP_KEY_ECDSA384, 1,
                 'ECDSA-public as OEM DSS public keys'),
    ]
    ast2700a1_key_type = [
        key_type(1, OTP_KEY_TYPE_2700.OTP_KEY_TYPE_SOC_ECDSA_PUB.value, 1,
                 'ECDSA384 as SoC OEM DSS public keys'),
        key_type(2, OTP_KEY_TYPE_2700.OTP_KEY_TYPE_SOC_LMS_PUB.value, 1,
                 'LMS as SoC OEM DSS public keys'),
        key_type(4, OTP_KEY_TYPE_2700.OTP_KEY_TYPE_CAL_OWN_PUB_HASH.value, 1,
                 'Digest as Caliptra Owner public key hash'),
        key_type(5, OTP_KEY_TYPE_2700.OTP_KEY_TYPE_SOC_VAULT.value, 0,
                 'AES-256 as secret vault key'),
        key_type(6, OTP_KEY_TYPE_2700.OTP_KEY_TYPE_SOC_VAULT_SEED.value, 0,
                 'AES-256 as secret vault key seed'),
    ]
    ast2700a2_key_type = [
        key_type(4, OTP_KEY_TYPE_2700.OTP_KEY_TYPE_CAL_OWN_PUB_HASH.value, 1,
                 'Digest as Caliptra Owner public key hash'),
        key_type(5, OTP_KEY_TYPE_2700.OTP_KEY_TYPE_SOC_VAULT.value, 0,
                 'AES-256 as secret vault key'),
        key_type(6, OTP_KEY_TYPE_2700.OTP_KEY_TYPE_SOC_VAULT_SEED.value, 0,
                 'AES-256 as secret vault key seed'),
    ]
