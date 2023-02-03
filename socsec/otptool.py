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
import array
import jstyleson
import struct
import os
import math
from bitarray import bitarray
from jsonschema import validate
from Crypto.Hash import SHA384
from socsec import parse_path
from socsec import insert_bytearray
from socsec import rsa_bit_length
from socsec import rsa_key_to_bin
from socsec import ecdsa_key_to_bin
from socsec import hexdump
from socsec import OTP_info
from socsec import __version__
from socsec import version2int
from socsec import int2version
from ecdsa import SigningKey, NIST384p


class OtpError(Exception):
    """Application-specific errors.

    These errors represent issues for which a stack-trace should not be
    presented.

    Attributes:
        message: Error message.
    """

    def __init__(self, message):
        Exception.__init__(self, message)


class ECC (object):
    def byte2bits(self, data_bytearray: bytearray) -> array:
        bits = ''
        bits_array = []
        for data_byte in data_bytearray:
            data_bits = bin(data_byte)[2:].zfill(8)[::-1]
            bits += data_bits
        for binary in bits:
            bits_array.append(int(binary, 2))
        return bits_array

    def xor_array(self, bits_array: array, x: int, y: int) -> int:
        out = 0
        if x < y:
            for i in range(x, y + 1):
                out ^= bits_array[i]
        elif x > y:
            for i in range(y, x + 1):
                out ^= bits_array[i]
        else:
            return bits_array[x]
        return out

    def bitsarray_to_bytes(self, s: array) -> int:
        r = 0
        offset = 0
        for bits in s:
            r += bits << offset
            offset += 1
        return r

    def do_ecc(self, data: bytearray) -> bytearray:
        result = bytearray(1024)
        offset = 0
        for cursor in range(0, len(data), 8):
            eight_bytes = data[cursor:cursor+8]
            bits = self.byte2bits(eight_bytes)
            tmp = [0, 0, 0, 0, 0, 0, 0, 0]
            tmp[0] = bits[0] ^ bits[1] ^ bits[3] ^ bits[4] ^ bits[6] ^ \
                bits[8] ^ bits[10] ^ bits[11] ^ bits[13] ^ bits[15] ^ \
                bits[17] ^ bits[19] ^ bits[21] ^ bits[23] ^ bits[25] ^ \
                bits[26] ^ bits[28] ^ bits[30] ^ bits[32] ^ bits[34] ^ \
                bits[36] ^ bits[38] ^ bits[40] ^ bits[42] ^ bits[44] ^ \
                bits[46] ^ bits[48] ^ bits[50] ^ bits[52] ^ bits[54] ^ \
                bits[56] ^ bits[57] ^ bits[59] ^ bits[61] ^ bits[63]
            tmp[1] = bits[0] ^ bits[2] ^ bits[3] ^ bits[5] ^ bits[6] ^ \
                bits[9] ^ bits[10] ^ bits[12] ^ bits[13] ^ bits[16] ^ \
                bits[17] ^ bits[20] ^ bits[21] ^ bits[24] ^ bits[25] ^ \
                bits[27] ^ bits[28] ^ bits[31] ^ bits[32] ^ bits[35] ^ \
                bits[36] ^ bits[39] ^ bits[40] ^ bits[43] ^ bits[44] ^ \
                bits[47] ^ bits[48] ^ bits[51] ^ bits[52] ^ bits[55] ^ \
                bits[56] ^ bits[58] ^ bits[59] ^ bits[62] ^ bits[63]
            tmp[2] = self.xor_array(bits, 3, 1) ^ self.xor_array(bits, 10, 7) ^ \
                self.xor_array(bits, 17, 14) ^ self.xor_array(bits, 25, 22) ^ \
                self.xor_array(bits, 32, 29) ^ self.xor_array(bits, 40, 37) ^ \
                self.xor_array(bits, 48, 45) ^ self.xor_array(bits, 56, 53) ^ \
                self.xor_array(bits, 63, 60)
            tmp[3] = self.xor_array(bits, 10, 4) ^ self.xor_array(bits, 25, 18) ^ \
                self.xor_array(bits, 40, 33) ^ self.xor_array(bits, 56, 49)
            tmp[4] = self.xor_array(
                bits, 25, 11) ^ self.xor_array(bits, 56, 41)
            tmp[5] = self.xor_array(bits, 56, 26)
            tmp[6] = self.xor_array(bits, 63, 57)
            tmp[7] = self.xor_array(bits, 63, 0)
            result[offset] = self.bitsarray_to_bytes(tmp)
            offset += 1
        return result


def BIT(off):
    return 1 << off


def load_file(file_path: str):
    with open(file_path, 'rb') as f:
        file_bin = f.read()
        f.close()
    return file_bin


def dw_hex_to_bin(dw_hex_bytes: bytes):
    dw_hex_bytearray = bytearray(dw_hex_bytes.replace(b'\n', b''))
    if len(dw_hex_bytearray) % 8 != 0:
        raise ValueError("input string is not dw aligned")

    bin_array = bytearray()
    for i in range(0, len(dw_hex_bytearray), 8):
        dw_string = dw_hex_bytearray[i:i+8]
        dw_bytes = bytearray.fromhex(dw_string.decode())
        dw_bytes.reverse()
        bin_array += dw_bytes
    return bin_array


def writeBinFile(in_bin: bytearray, dst_path: str):
    with open(dst_path, 'w+b')as outf:
        outf.write(bytes(in_bin))
        outf.close()


def writeHexFile(in_bin: bytearray, dst_path: str):
    output = ''
    for c in in_bin:
        output += "{0:#0{1}x}".format(c, 4)[2:]
        output += '\n'
    with open(dst_path, 'w+b')as outf:
        outf.write(output.encode())
        outf.close()


def writeDWHexFile(in_bin: bytearray, dst_path: str):
    output = ''
    sub_output = ''
    bc = 0
    for c in bytes(in_bin):
        sub_output = "{0:#0{1}x}".format(c, 4)[2:] + sub_output
        bc += 1
        if bc == 4:
            output += sub_output + '\n'
            sub_output = ''
            bc = 0
    with open(dst_path, 'w+b')as outf:
        outf.write(output.encode())
        outf.close()


class image_header(object):
    def __init__(self, header):
        (self.magic, self.soc_ver, self.otptool_ver, self.image_info, self.data_info,
         self.config_info, self.strap_info, self.scu_protect_info,
         self.checksum_offset) = struct.unpack(OTP.otp_info.HEADER_FORMAT, header)


class strap_sts(object):
    def __init__(self):
        self.value = 0
        self.option_array = [0] * 7
        self.remain_times = 0
        self.writeable_option = -1
        self.protected = 0


class OTP(object):
    """otptool command-line tool."""
    otp_info = OTP_info

    def OTPValidate(self, otp_config, otp_info):
        schema = {
            "type": "object",
            "required": [
                "name",
                "version"
            ],
            "additionalProperties": False,
            "properties": {
                "name": {
                    "type": "string"
                },
                "version": {
                    "type": "string",
                    "enum": [
                        "A0",
                        "A1",
                        "A2",
                        "A3",
                        "1030A0",
                        "1030A1",
                        "1060A1",
                        "1060A2",
                    ]
                },
                "data_region": {
                    "type": "object",
                    "additionalProperties": False,
                    "required": [
                        "ecc_region"
                    ],
                    "properties": {
                        "patch": {
                            "type": "boolean"
                        },
                        "ecc_region": {
                            "type": "boolean"
                        },
                        "rsa_key_order": {
                            "type": "string",
                            "enum": [
                                "little",
                                "big",
                            ]
                        },
                        "key": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "properties": {
                                    "types": {
                                        "type": "string",
                                        "enum": [
                                            "aes_oem",
                                            "aes_vault",
                                            "rsa_pub_oem",
                                            "rsa_pub_aes",
                                            "rsa_priv_aes",
                                            "ecdsa_pub",
                                            "ecdsa_parameters",
                                            "reserved"
                                        ]
                                    },
                                    "key_bin": {
                                        "type": "string"
                                    },
                                    "key_bin2": {
                                        "type": "string"
                                    },
                                    "iv_bin": {
                                        "type": "string"
                                    },
                                    "key_pem": {
                                        "type": "string"
                                    },
                                    "rsa_pem": {
                                        "type": "string"
                                    },
                                    "number_id": {
                                        "type": "integer",
                                        "minimum": 0,
                                        "maximum": 7
                                    },
                                    "sha_mode": {
                                        "type": "string",
                                        "enum": [
                                            "SHA224",
                                            "SHA256",
                                            "SHA384",
                                            "SHA512"
                                        ]
                                    },
                                    "offset": {
                                        "type": "string",
                                        "pattern": "0[xX][0-9a-fA-F]+"
                                    },
                                    "key_length": {
                                        "type": "integer"
                                    }
                                }
                            }
                        },
                        "user_data": {
                            "type": "array",
                            "additionalProperties": False,
                            "items": {
                                "type": "object",
                                "additionalProperties": False,
                                "properties": {
                                    "types": {
                                        "type": "string",
                                        "enum": [
                                            "hex",
                                            "dw_hex",
                                            "bin"
                                        ]
                                    },
                                    "file": {
                                        "type": "string"
                                    },
                                    "offset": {
                                        "type": "string",
                                        "pattern": "0[xX][0-9a-fA-F]+"
                                    }
                                }
                            }
                        }
                    }
                },
                "config_region": {
                },
                "otp_strap": {},
                "scu_protect": {}
            }
        }
        config_schema = {}
        strap_schema = {}
        scu_protect_schema = {}

        with open(otp_info['config'], 'r') as config_info_fd:
            config_info = jstyleson.load(config_info_fd)

        with open(otp_info['strap'], 'r') as strap_info_fd:
            strap_info = jstyleson.load(strap_info_fd)

        for i in config_info:
            if i['type'] == 'boolean':
                config_schema[i['key']] = {
                    'type': 'boolean'
                }
            elif i['type'] == 'string':
                config_schema[i['key']] = {
                    'type': 'string',
                    'enum': []
                }
                for j in i['value']:
                    config_schema[i['key']]['enum'].append(j['value'])
            elif i['type'] == 'bit_shift':
                config_schema[i['key']] = {
                    'type': 'integer',
                    'minimum': 0,
                    'maximum': i['bit_length'] - 1
                }
            elif i['type'] == 'hex':
                config_schema[i['key']] = {
                    'type': 'string',
                    'pattern': '0[xX][0-9a-fA-F]+'
                }
            elif i['type'] == 'rev_id':
                config_schema[i['key']] = {
                    'type': 'string',
                    'pattern': '0[xX][0-9a-fA-F]+'
                }

        for i in strap_info:
            val = {}
            if i['type'] == 'boolean':
                val = {
                    'type': 'boolean'
                }
            elif i['type'] == 'string':
                val = {
                    'type': 'string',
                    'enum': []
                }
                for j in i['value']:
                    val['enum'].append(j['value'])

            strap_schema[i['key']] = {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "value"
                ],
                "properties": {
                    "otp_protect": {
                        "type": "boolean"
                    },
                    "ignore": {
                        "type": "boolean"
                    },
                    "value": val
                }
            }

        for i in strap_info:
            val = {}
            if 'scu_mapping' not in i:
                continue

            scu_protect_schema[i['key']] = {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "protect",
                    "ignore"
                ],
                "properties": {
                    "protect": {
                        "type": "boolean"
                    },
                    "ignore": {
                        "type": "boolean"
                    }
                }
            }

        schema['properties']['config_region'] = {
            "type": "object",
            "additionalProperties": False,
            "properties": config_schema
        }
        schema['properties']['otp_strap'] = {
            "type": "object",
            "additionalProperties": False,
            "properties": strap_schema
        }
        schema['properties']['scu_protect'] = {
            "type": "object",
            "additionalProperties": False,
            "properties": scu_protect_schema
        }
        validate(otp_config, schema)

    def genKeyHeader_a0(self, key_config, key_folder):
        types = key_config['types']
        header = 0

        if types == 'reserved':
            return header

        offset = int(key_config['offset'], 16)
        header |= offset

        if types == 'aes_oem':
            header |= 0
        elif types == 'aes_vault':
            header |= 1 << 14
        elif types == 'rsa_pub_oem':
            header |= 8 << 14
        elif types == 'rsa_pub_aes':
            header |= 10 << 14
        elif types == 'rsa_priv_aes':
            header |= 14 << 14

        if 'number_id' in key_config:
            number_id = key_config['number_id']
            header |= number_id

        if types in ['rsa_pub_oem', 'rsa_pub_soc', 'rsa_pub_aes', 'rsa_priv_soc', 'rsa_priv_aes']:
            rsa_key_file = key_folder + key_config['key_pem']
            mod_length = rsa_bit_length(rsa_key_file, 'n')
            if mod_length == 1024:
                header |= 0 << 18
            elif mod_length == 2048:
                header |= 1 << 18
            elif mod_length == 3072:
                header |= 2 << 18
            elif mod_length == 4096:
                header |= 3 << 18
            else:
                raise ValueError("key_length is not supported")

            if types in ['rsa_pub_oem', 'rsa_pub_soc', 'rsa_pub_aes']:
                exp_length = rsa_bit_length(rsa_key_file, 'e')
            else:
                exp_length = rsa_bit_length(rsa_key_file, 'd')
            header |= exp_length << 20
        return header

    def genKeyHeader_a1(self, key_config, key_folder):
        types = key_config['types']
        header = 0

        if types == 'reserved':
            return header

        offset = int(key_config['offset'], 16)
        header |= offset

        if types == 'aes_vault':
            header |= 1 << 14
        elif types == 'aes_oem':
            header |= 2 << 14
        elif types == 'rsa_pub_oem':
            header |= 8 << 14
        elif types == 'rsa_pub_aes':
            header |= 10 << 14
        elif types == 'rsa_priv_aes':
            header |= 14 << 14

        if 'number_id' in key_config:
            number_id = key_config['number_id']
            header |= number_id

        if types in ['rsa_pub_oem', 'rsa_pub_aes', 'rsa_priv_aes']:
            rsa_key_file = key_folder + key_config['key_pem']
            mod_length = rsa_bit_length(rsa_key_file, 'n')
            if mod_length == 1024:
                header |= 0 << 18
            elif mod_length == 2048:
                header |= 1 << 18
            elif mod_length == 3072:
                header |= 2 << 18
            elif mod_length == 4096:
                header |= 3 << 18
            else:
                raise ValueError("key_length is not supported")

            if types in ['rsa_pub_oem', 'rsa_pub_aes']:
                exp_length = rsa_bit_length(rsa_key_file, 'e')
            else:
                exp_length = rsa_bit_length(rsa_key_file, 'd')
            header |= exp_length << 20
        return header

    def genKeyHeader_a3_big(self, key_config, key_folder):
        types = key_config['types']
        header = 0

        if types == 'reserved':
            return header

        offset = int(key_config['offset'], 16)
        header |= offset

        if types == 'aes_vault':
            header |= 1 << 14
        elif types == 'aes_oem':
            header |= 2 << 14
        elif types == 'rsa_pub_oem':
            header |= 9 << 14
        elif types == 'rsa_pub_aes':
            header |= 11 << 14
        elif types == 'rsa_priv_aes':
            header |= 13 << 14

        if 'number_id' in key_config:
            number_id = key_config['number_id']
            header |= number_id

        if types in ['rsa_pub_oem', 'rsa_pub_aes', 'rsa_priv_aes']:
            rsa_key_file = key_folder + key_config['key_pem']
            mod_length = rsa_bit_length(rsa_key_file, 'n')
            if mod_length == 1024:
                header |= 0 << 18
            elif mod_length == 2048:
                header |= 1 << 18
            elif mod_length == 3072:
                header |= 2 << 18
            elif mod_length == 4096:
                header |= 3 << 18
            else:
                raise ValueError("key_length is not supported")

            if types in ['rsa_pub_oem', 'rsa_pub_aes']:
                exp_length = rsa_bit_length(rsa_key_file, 'e')
            else:
                exp_length = rsa_bit_length(rsa_key_file, 'd')
            header |= exp_length << 20
        return header

    def genKeyHeader_a3_little(self, key_config, key_folder):
        types = key_config['types']
        header = 0

        if types == 'reserved':
            return header

        offset = int(key_config['offset'], 16)
        header |= offset

        if types == 'aes_vault':
            header |= 1 << 14
        elif types == 'aes_oem':
            header |= 2 << 14
        elif types == 'rsa_pub_oem':
            header |= 8 << 14
        elif types == 'rsa_pub_aes':
            header |= 10 << 14
        elif types == 'rsa_priv_aes':
            header |= 12 << 14

        if 'number_id' in key_config:
            number_id = key_config['number_id']
            header |= number_id

        if types in ['rsa_pub_oem', 'rsa_pub_aes', 'rsa_priv_aes']:
            rsa_key_file = key_folder + key_config['key_pem']
            mod_length = rsa_bit_length(rsa_key_file, 'n')
            if mod_length == 1024:
                header |= 0 << 18
            elif mod_length == 2048:
                header |= 1 << 18
            elif mod_length == 3072:
                header |= 2 << 18
            elif mod_length == 4096:
                header |= 3 << 18
            else:
                raise ValueError("key_length is not supported")

            if types in ['rsa_pub_oem', 'rsa_pub_aes']:
                exp_length = rsa_bit_length(rsa_key_file, 'e')
            else:
                exp_length = rsa_bit_length(rsa_key_file, 'd')
            header |= exp_length << 20
        return header

    def genKeyHeader_1030a1_big(self, key_config, key_folder):
        types = key_config['types']
        header = 0

        if types == 'reserved':
            return header

        offset = int(key_config['offset'], 16)
        header |= offset

        if types == 'aes_vault':
            header |= 1 << 14
        elif types == 'aes_oem':
            header |= 2 << 14
        elif types == 'rsa_pub_oem':
            header |= 9 << 14
        elif types == 'rsa_pub_aes':
            header |= 11 << 14
        elif types == 'rsa_priv_aes':
            header |= 13 << 14
        elif types == 'ecdsa_parameters':
            header |= 5 << 14
        elif types == 'ecdsa_pub':
            header |= 7 << 14

        if 'number_id' in key_config:
            number_id = key_config['number_id']
            header |= number_id

        if types in ['rsa_pub_oem', 'rsa_pub_aes', 'rsa_priv_aes']:
            rsa_key_file = key_folder + key_config['key_pem']
            mod_length = rsa_bit_length(rsa_key_file, 'n')
            if mod_length == 1024:
                header |= 0 << 18
            elif mod_length == 2048:
                header |= 1 << 18
            elif mod_length == 3072:
                header |= 2 << 18
            elif mod_length == 4096:
                header |= 3 << 18
            else:
                raise ValueError("key_length is not supported")

            if types in ['rsa_pub_oem', 'rsa_pub_aes']:
                exp_length = rsa_bit_length(rsa_key_file, 'e')
            else:
                exp_length = rsa_bit_length(rsa_key_file, 'd')
            header |= exp_length << 20
        return header

    def key_to_bytearray_a0(self, key_config, key_folder):
        types = key_config['types']

        if types in ['rsa_pub_oem', 'rsa_pub_soc', 'rsa_pub_aes', 'rsa_priv_soc', 'rsa_priv_aes']:
            rsa_key_file = key_folder + key_config['key_pem']
            if types in ['rsa_pub_oem', 'rsa_pub_soc', 'rsa_pub_aes']:
                insert_key_bin = rsa_key_to_bin(rsa_key_file, 'public')
            else:
                insert_key_bin = rsa_key_to_bin(rsa_key_file, 'private')
        elif types in ['aes_vault', 'aes_oem']:
            aes_key_bin = load_file(key_folder + key_config['key_bin'])
            aes_iv_bin = load_file(key_folder + key_config['iv_bin'])
            insert_key_bin = bytearray(aes_key_bin)
            insert_bytearray(bytearray(aes_iv_bin), insert_key_bin, 0x20)
        else:
            return None

        return insert_key_bin

    def key_to_bytearray_a1(self, key_config, key_folder):
        types = key_config['types']

        if types in ['rsa_pub_oem', 'rsa_pub_aes', 'rsa_priv_aes']:
            rsa_key_file = key_folder + key_config['key_pem']
            if types in ['rsa_pub_oem', 'rsa_pub_aes']:
                insert_key_bin = rsa_key_to_bin(rsa_key_file, 'public')
            else:
                insert_key_bin = rsa_key_to_bin(rsa_key_file, 'private')
        elif types in ['aes_vault']:
            aes_key_bin = load_file(key_folder + key_config['key_bin'])
            aes_key_bin2 = load_file(key_folder + key_config['key_bin2'])
            insert_key_bin = bytearray(aes_key_bin)
            insert_bytearray(bytearray(aes_key_bin2), insert_key_bin, 0x20)
        elif types == 'aes_oem':
            insert_key_bin = load_file(key_folder + key_config['key_bin'])
        else:
            return None

        return insert_key_bin

    def key_to_bytearray_a3_big(self, key_config, key_folder):
        types = key_config['types']

        if types in ['rsa_pub_oem', 'rsa_pub_aes', 'rsa_priv_aes']:
            rsa_key_file = key_folder + key_config['key_pem']
            if types in ['rsa_pub_oem', 'rsa_pub_aes']:
                insert_key_bin = rsa_key_to_bin(
                    rsa_key_file, 'public', order='big')
            else:
                insert_key_bin = rsa_key_to_bin(
                    rsa_key_file, 'private', order='big')
        elif types in ['aes_vault']:
            aes_key_bin = load_file(key_folder + key_config['key_bin'])
            aes_key_bin2 = load_file(key_folder + key_config['key_bin2'])
            insert_key_bin = bytearray(aes_key_bin)
            insert_bytearray(bytearray(aes_key_bin2), insert_key_bin, 0x20)
        elif types == 'aes_oem':
            insert_key_bin = load_file(key_folder + key_config['key_bin'])
        else:
            return None

        return insert_key_bin

    def key_to_bytearray_1030a1_big(self, key_config, key_folder):
        types = key_config['types']

        if types in ['rsa_pub_oem', 'rsa_pub_aes', 'rsa_priv_aes']:
            rsa_key_file = key_folder + key_config['key_pem']
            if types in ['rsa_pub_oem', 'rsa_pub_aes']:
                insert_key_bin = rsa_key_to_bin(
                    rsa_key_file, 'public', order='big')
            else:
                insert_key_bin = rsa_key_to_bin(
                    rsa_key_file, 'private', order='big')
        elif types in ['aes_vault']:
            aes_key_bin = load_file(key_folder + key_config['key_bin'])
            aes_key_bin2 = load_file(key_folder + key_config['key_bin2'])
            insert_key_bin = bytearray(aes_key_bin)
            insert_bytearray(bytearray(aes_key_bin2), insert_key_bin, 0x20)
        elif types == 'ecdsa_pub':
            ecdsa_key_bin = ecdsa_key_to_bin(
                key_folder + key_config['key_pem'])
            insert_key_bin = bytearray(ecdsa_key_bin)
        elif types == 'ecdsa_parameters':
            gx = NIST384p.generator.x().to_bytes(48, byteorder='big', signed=False)
            gy = NIST384p.generator.y().to_bytes(48, byteorder='big', signed=False)
            p = NIST384p.curve.p().to_bytes(48, byteorder='big', signed=False)
            n = NIST384p.order.to_bytes(48, byteorder='big', signed=False)
            insert_key_bin = bytearray(gx)
            insert_bytearray(bytearray(gy), insert_key_bin, 0x30)
            insert_bytearray(bytearray(p), insert_key_bin, 0x60)
            insert_bytearray(bytearray(n), insert_key_bin, 0x90)
        elif types == 'aes_oem':
            insert_key_bin = load_file(key_folder + key_config['key_bin'])
        else:
            return None

        return insert_key_bin

    def file_to_bytearray(self, data_config, user_data_folder):
        types = data_config['types']

        with open(user_data_folder + data_config['file'], 'rb') as data_bin_file:
            file_bin = data_bin_file.read()
            data_bin_file.close()

        if types == 'bin':
            return bytearray(file_bin)

        if types == 'dw_hex':
            return dw_hex_to_bin(file_bin)

        return None

    def genDataMask(self, data_region_ignore, src, offset, ecc_region_enable, data_region_size, ecc_region_offset):
        if ecc_region_enable:
            if (offset + len(src) - 1 >= ecc_region_offset):
                raise OtpError("Data region is out off range")
            start = int(offset / 8)
            end = int((offset + len(src) - 1) / 8)
            for i in range(start, end + 1):
                data_region_ignore[ecc_region_offset+i] = 0
        else:
            if (offset + len(src) >= data_region_size):
                raise OtpError("Data region is out off range")

        start = offset
        end = offset + len(src)
        for i in range(start, end):
            if data_region_ignore[i] == 0:
                raise OtpError("Data region is overlapping")

            data_region_ignore[i] = 0

    def genUserRegion(self, data_config, user_data_folder, data_region, data_region_ignore, ecc_region_enable, data_region_size, ecc_region_offset):
        for conf in data_config:
            offset = int(conf['offset'], 16)

            data_bin = self.file_to_bytearray(conf, user_data_folder)
            insert_bytearray(data_bin, data_region, offset)
            self.genDataMask(data_region_ignore, data_bin,
                             offset, ecc_region_enable, data_region_size, ecc_region_offset)

    def genKeyRegion(self, key_config, key_folder, data_region, data_region_ignore,
                     genKeyHeader, key_to_bytearray, ecc_region_enable, data_region_size,
                     ecc_region_offset, no_last_bit):

        key_header = []
        header_ignore = []
        header_ecc_ignore = bytearray(8)

        for conf in key_config:
            key_type = conf['types']
            if key_type == 'reserved' and ecc_region_enable:
                print(
                    "WARNING: Key type include 'reserved' type, use default value to calculate the ecc")
                break

        header_offset = -1
        for conf in key_config:
            header_offset = header_offset + 1
            key_type = conf['types']
            kh = 0
            if key_type == 'reserved':
                if header_offset % 2 == 0:
                    kh = 0
                else:
                    # remove last header bit(BIT 13) to prevent secure boot fail
                    kh = 0xffffdfff
            else:
                kh = genKeyHeader(conf, key_folder)
            key_header.append(kh)

        if not no_last_bit:
            if key_header[-1] != 0:
                key_header[-1] |= 1 << 13

        if len(key_config) % 2 != 0 and ecc_region_enable:
            print("WARNING: ECC region is enable, but the key header is not 8 byte align, append 0xffffdfff to calculate the ecc")
            key_header.append(0xffffdfff)

        header_byteArray = bytearray(array.array('I', key_header).tobytes())
        insert_bytearray(header_byteArray, data_region, 0)

        header_offset = -1
        for conf in key_config:
            header_offset = header_offset + 1
            key_type = conf['types']
            if key_type == 'reserved':
                if ecc_region_enable:
                    # if ecc_region enable, otptool will use default otp value to generate the image
                    header_ignore.append(0)
                else:
                    # if ecc_region disable, otptool will set mask to ignore the setting
                    if header_offset % 2 == 0:
                        header_ignore.append(0xffffffff)
                    else:
                        # still need to program last header bit(BIT 13) to 0 to prevent secure boot fail
                        header_ignore.append(0xffffdfff)
            else:
                header_ignore.append(0)

                offset = int(conf['offset'], 16)
                key_bin = key_to_bytearray(conf, key_folder)
                insert_bytearray(key_bin, data_region, offset)
                self.genDataMask(data_region_ignore, key_bin,
                                offset, ecc_region_enable, data_region_size, ecc_region_offset)

        if len(key_config) % 2 != 0 and ecc_region_enable:
                header_ignore.append(0)

        header_ignore_byteArray = bytearray(
            array.array('I', header_ignore).tobytes())
        insert_bytearray(header_ignore_byteArray, data_region_ignore, 0)

        if ecc_region_enable:
            for i in range(8):
                header_ecc_ignore[i] = 0xff
            for i in range(int((len(key_config)+1)/2)):
                header_ecc_ignore[i] = 0
            insert_bytearray(header_ecc_ignore,
                             data_region_ignore, ecc_region_offset)

    def make_data_region(self, data_config, key_folder, user_data_folder, genKeyHeader,
                         key_to_bytearray, data_region_size, ecc_region_offset, no_last_bit):
        patch_reserved_offset = 0x1B80
        patch_reserved_lne = 0x80

        data_region = bytearray(data_region_size)
        data_region_ignore = bytearray(data_region_size)
        for i in range(0, data_region_size):
            data_region_ignore[i] = 0xff

        if data_config['ecc_region']:
            ecc_region_enable = True
        else:
            ecc_region_enable = False

        if 'key' in data_config:
            self.genKeyRegion(data_config['key'], key_folder,
                              data_region, data_region_ignore,
                              genKeyHeader, key_to_bytearray, ecc_region_enable,
                              data_region_size, ecc_region_offset, no_last_bit)
        if 'user_data' in data_config:
            self.genUserRegion(
                data_config['user_data'], user_data_folder, data_region, data_region_ignore, ecc_region_enable, data_region_size, ecc_region_offset)
        if 'patch' not in data_config:
            for i in data_region_ignore[patch_reserved_offset:patch_reserved_offset+patch_reserved_lne]:
                if i != 0xff:
                    raise OtpError('region {0:#08x} to {1:#08x} is reserved for patch'.format(
                        patch_reserved_offset, patch_reserved_offset+patch_reserved_lne))

        if ecc_region_enable:
            ecc_byteArray = ECC().do_ecc(data_region)
            insert_bytearray(ecc_byteArray, data_region, ecc_region_offset)

        return data_region, data_region_ignore

    def make_config_region(self, config_region_config, config_info, config_region_size):
        config_region = bitarray(config_region_size*8, endian='little')
        config_region_ignore = bitarray(config_region_size*8, endian='little')

        config_region.setall(False)
        config_region_ignore.setall(True)

        for i in config_info:
            if 'default' in i and i['type'] == 'boolean':
                dw_offset = i['dw_offset']
                bit_offset = i['bit_offset']
                offset = dw_offset*4+bit_offset
                if i['default']:
                    config_region[offset] = 1
                    config_region_ignore[offset] = 0

        for config in config_region_config:
            info = None
            key = config
            value = config_region_config[config]
            for i in config_info:
                if key == i['key']:
                    info = i
                    break
            if not info:
                raise OtpError('"{}" config is not supported'.format(key))

            if info['type'] == 'boolean':
                dw_offset = info['dw_offset']
                bit_offset = info['bit_offset']
                offset = dw_offset*32+bit_offset
                if value:
                    in_val = 1
                else:
                    in_val = 0
                config_region[offset] = in_val
                config_region_ignore[offset] = 0
                if dw_offset == 0:
                    offset = 32+bit_offset
                    config_region[offset] = in_val
                    config_region_ignore[offset] = 0
            elif info['type'] == 'string':
                info_value = info['value']
                dw_offset = info['dw_offset']
                bit_offset = info['bit_offset']
                bit_length = info['bit_length']
                offset = dw_offset*32+bit_offset

                for t in info_value:
                    if t['value'] == value:
                        bit = t['bit']
                bit_value = bitarray(bin(bit)[2:][::-1])
                tmp = bitarray(bit_length)
                tmp.setall(False)
                config_region_ignore[offset:offset+bit_length] = tmp
                config_region[offset:offset+bit_length] = tmp
                config_region[offset:offset+len(bit_value)] = bit_value
                if dw_offset == 0:
                    offset = 32+bit_offset
                    config_region_ignore[offset:offset+bit_length] = tmp
                    config_region[offset:offset+bit_length] = tmp
                    config_region[offset:offset+len(bit_value)] = bit_value
            elif info['type'] == 'hex':
                dw_offset = info['dw_offset']
                bit_offset = info['bit_offset']
                bit_length = info['bit_length']
                hex_value = int(value, 16)
                offset = dw_offset*32+bit_offset

                if hex_value > 2 ** bit_length:
                    raise OtpError(
                        '"{}": config value out of range'.format(key))
                bit_value = bitarray(bin(hex_value)[2:][::-1])
                tmp = bitarray(bit_length)
                tmp.setall(False)
                config_region_ignore[offset:offset+bit_length] = tmp
                config_region[offset:offset+bit_length] = tmp
                config_region[offset:offset+len(bit_value)] = bit_value
                if dw_offset == 0:
                    offset = 32+bit_offset
                    config_region_ignore[offset:offset+bit_length] = tmp
                    config_region[offset:offset+bit_length] = tmp
                    config_region[offset:offset+len(bit_value)] = bit_value
            elif info['type'] == 'bit_shift':
                dw_offset = info['dw_offset']
                bit_offset = info['bit_offset']
                offset = dw_offset*32 + bit_offset
                bit_length = info['bit_length']
                value_start = info['value_start']
                offset_value = value - value_start

                if offset_value < 0 or offset_value > bit_length:
                    raise OtpError('"{}": value is out of range'.format(key))

                config_region_ignore[offset+offset_value] = 0
                config_region[offset+offset_value] = 1
            elif info['type'] == 'rev_id':
                dw_offset = info['dw_offset']
                bit_offset = info['bit_offset']
                offset = dw_offset*32 + bit_offset
                bit_length = info['bit_length']
                offset_value = int(value, 16) - value_start

                if offset_value < 0 or offset_value > bit_length:
                    raise OtpError('"{}": value is out of range'.format(key))

                for i in range(bit_length):
                    config_region_ignore[offset+i] = 0
                for i in range(offset_value):
                    config_region[offset+i] = 1
            else:
                raise OtpError('"{}": value is invalid'.format(key))

        return bytearray(config_region.tobytes()), \
            bytearray(config_region_ignore.tobytes())

    def make_otp_strap(self, otp_strap_config, strap_info, otp_strap_bit_size):
        otp_strap = bitarray(otp_strap_bit_size, endian='little')
        otp_strap_protect = bitarray(otp_strap_bit_size, endian='little')
        otp_strap_ignore = bitarray(otp_strap_bit_size, endian='little')

        otp_strap.setall(False)
        otp_strap_protect.setall(False)
        otp_strap_ignore.setall(True)

        for i in strap_info:
            if i['type'] == 'reserved':
                bit_length = i['bit_length']
                bit_offset = i['bit_offset']
                tmp = bitarray(bit_length)
                tmp.setall(True)
                otp_strap_protect[bit_offset:bit_offset+bit_length] = tmp
                tmp.setall(False)
                otp_strap_ignore[bit_offset:bit_offset+bit_length] = tmp

        for config in otp_strap_config:
            info = None
            key = config
            value = otp_strap_config[config]['value']

            for i in strap_info:
                if key == i['key']:
                    info = i
                    break
            if not info:
                raise OtpError('"{}" strap is not supported'.format(key))
            bit_offset = info['bit_offset']
            if info['type'] == 'boolean':
                bit_length = 1
                if value:
                    otp_strap[bit_offset] = 1
            elif info['type'] == 'string':
                info_value = info['value']
                bit_length = info['bit_length']

                for t in info_value:
                    if t['value'] == str(value):
                        bit = t['bit']
                        break

                tmp = bitarray(bit_length)
                tmp.setall(False)
                bit_value = bitarray(bin(bit)[2:][::-1])
                otp_strap[bit_offset:bit_offset+bit_length] = tmp
                otp_strap[bit_offset:bit_offset+len(bit_value)] = bit_value
            elif info['type'] == 'reserved':
                bit_length = info['bit_length']
                tmp = bitarray(bit_length)
                tmp.setall(False)
                otp_strap[bit_offset:bit_offset+bit_length] = tmp
                if value:
                    tmp.setall(True)
                    otp_strap[bit_offset:bit_offset+len(bit_value)] = bit_value

            tmp = bitarray(bit_length)
            tmp.setall(False)
            otp_strap_ignore[bit_offset:bit_offset+bit_length] = tmp

            if 'otp_protect' in otp_strap_config[config]:
                if otp_strap_config[config]['otp_protect']:
                    tmp.setall(True)
                    otp_strap_protect[bit_offset:bit_offset+bit_length] = \
                        tmp
                else:
                    tmp.setall(False)
                    otp_strap_protect[bit_offset:bit_offset+bit_length] = \
                        tmp
            if 'ignore' in otp_strap_config[config]:
                if otp_strap_config[config]['ignore']:
                    tmp.setall(True)
                    otp_strap_ignore[bit_offset:bit_offset+bit_length] = \
                        tmp
                else:
                    tmp.setall(False)
                    otp_strap_ignore[bit_offset:bit_offset+bit_length] = \
                        tmp

        return bytearray(otp_strap.tobytes()), \
            bytearray(otp_strap_protect.tobytes()), \
            bytearray(otp_strap_ignore.tobytes())

    def make_scu_protect_image(self, scu_protect_config, strap_info):
        scu_protect = bitarray(64, endian='little')
        scu_ignore = bitarray(64, endian='little')
        scu_protect.setall(False)
        scu_ignore.setall(True)
        for config in scu_protect_config:
            info = None
            key = config

            for i in strap_info:
                if key == i['key']:
                    info = i
                    break
            sm = info['scu_mapping']
            if sm['scu'] == '500':
                bit_offset = sm['bit_offset']
            else:
                bit_offset = sm['bit_offset'] + 32
            if 'bit_length' in info:
                bit_length = info['bit_length']
            else:
                bit_length = 1

            tmp = bitarray(bit_length)
            tmp.setall(False)
            scu_ignore[bit_offset:bit_offset+bit_length] = tmp
            if scu_protect_config[key]['protect']:
                tmp.setall(True)
                scu_protect[bit_offset:bit_offset+bit_length] = tmp

            if scu_protect_config[key]['ignore']:
                tmp.setall(True)
                scu_ignore[bit_offset:bit_offset+bit_length] = tmp

        return bytearray(scu_protect.tobytes()), \
            bytearray(scu_ignore.tobytes())

    def make_otp_image(self, config_file, key_folder,
                       user_data_folder, output_folder,
                       no_last_bit=False, no_pre_production=False):
        otp_config = jstyleson.load(config_file)

        if no_pre_production:
            if otp_config['version'] in ['A0',
                                         'A1',
                                         'A2',
                                         '1030A0']:
                raise OtpError('SOC version is incorrect in OTP config')

        if otp_config['version'] == 'A0':
            otp_info = self.otp_info.OTP_INFO['A0']
            version = OTP_info.SOC_AST2600A0
            genKeyHeader = self.genKeyHeader_a0
            key_to_bytearray = self.key_to_bytearray_a0
        elif otp_config['version'] == 'A1':
            otp_info = self.otp_info.OTP_INFO['A1']
            version = OTP_info.SOC_AST2600A1
            genKeyHeader = self.genKeyHeader_a1
            key_to_bytearray = self.key_to_bytearray_a1
        elif otp_config['version'] == 'A2':
            otp_info = self.otp_info.OTP_INFO['A2']
            version = OTP_info.SOC_AST2600A2
            genKeyHeader = self.genKeyHeader_a1
            key_to_bytearray = self.key_to_bytearray_a1
        elif otp_config['version'] == 'A3':
            otp_info = self.otp_info.OTP_INFO['A3']
            version = OTP_info.SOC_AST2600A3
            order = 'little'
            if 'data_region' in otp_config:
                if 'rsa_key_order' in otp_config['data_region']:
                    order = otp_config['data_region']['rsa_key_order']
            if order == 'little':
                key_to_bytearray = self.key_to_bytearray_a1
                genKeyHeader = self.genKeyHeader_a3_little
            else:
                key_to_bytearray = self.key_to_bytearray_a3_big
                genKeyHeader = self.genKeyHeader_a3_big
        elif otp_config['version'] == '1030A0':
            otp_info = self.otp_info.OTP_INFO['1030A0']
            version = OTP_info.SOC_AST1030A0
            genKeyHeader = self.genKeyHeader_a1
            key_to_bytearray = self.key_to_bytearray_a1
        elif otp_config['version'] == '1030A1':
            otp_config['data_region']['rsa_key_order'] = 'big'
            otp_info = self.otp_info.OTP_INFO['1030A1']
            version = OTP_info.SOC_AST1030A1
            genKeyHeader = self.genKeyHeader_1030a1_big
            key_to_bytearray = self.key_to_bytearray_1030a1_big
        elif otp_config['version'] == '1060A1':
            otp_config['data_region']['rsa_key_order'] = 'big'
            otp_info = self.otp_info.OTP_INFO['1030A1']
            version = OTP_info.SOC_AST1060A1
            genKeyHeader = self.genKeyHeader_1030a1_big
            key_to_bytearray = self.key_to_bytearray_1030a1_big
        elif otp_config['version'] == '1060A2':
            otp_config['data_region']['rsa_key_order'] = 'big'
            otp_info = self.otp_info.OTP_INFO['1030A1']
            version = OTP_info.SOC_AST1060A2
            genKeyHeader = self.genKeyHeader_1030a1_big
            key_to_bytearray = self.key_to_bytearray_1030a1_big
        else:
            raise OtpError('SOC version is invalid')

        self.OTPValidate(otp_config, otp_info)
        os.system('mkdir -p '+output_folder)

        all_image_output = output_folder + 'otp-all.image'
        data_image_output = output_folder + 'otp-data.image'
        data_binary_output = output_folder + 'otp-data.bin'
        data_hex_output = output_folder + 'otp-data.hex'
        config_image_output = output_folder + 'otp-conf.image'
        config_binary_output = output_folder + 'otp-conf.bin'
        strap_image_output = output_folder + 'otp-strap.image'
        strap_binary_output = output_folder + 'otp-strap.bin'
        scu_protect_image_output = output_folder + 'otp-scu_protect.image'
        scu_protect_binary_output = output_folder + 'otp-scu_protect.bin'

        data_region = bytearray()
        data_region_ignore = bytearray()
        data_all = bytearray()
        config_region = bytearray()
        config_region_ignore = bytearray()
        config_all = bytearray()
        otp_strap = bytearray()
        otp_strap_protect = bytearray()
        otp_strap_ignore = bytearray()
        otp_strap_all = bytearray()
        scu_protect = bytearray()
        scu_ignore = bytearray()
        scu_protect_all = bytearray()

        image_info_all = 0
        data_size = 0
        config_size = 0
        strap_size = 0
        scu_protect_size = 0

        if 'data_region' in otp_config:
            print("Generating Data Image ...")
            data_region, data_region_ignore = self.make_data_region(
                otp_config['data_region'], key_folder,
                user_data_folder, genKeyHeader,
                key_to_bytearray, otp_info['data_region_size'],
                otp_info['ecc_region_offset'], no_last_bit)

            ecc_region = otp_config['data_region']['ecc_region']
            if 'rsa_key_order' in otp_config['data_region']:
                rsa_key_order = otp_config['data_region']['rsa_key_order']
            else:
                rsa_key_order = 'little'

            data_size = len(data_region) + len(data_region_ignore)
            image_size = self.otp_info.HEADER_SIZE + data_size
            image_info = image_size | self.otp_info.INC_DATA
            image_info_all = image_info_all | self.otp_info.INC_DATA
            if rsa_key_order == 'big':
                image_info = image_info | self.otp_info.HEADER_ORDER
                image_info_all = image_info_all | self.otp_info.HEADER_ORDER
            if ecc_region:
                image_info = image_info | self.otp_info.HEADER_ECC
                image_info_all = image_info_all | self.otp_info.HEADER_ECC
            data_offset = self.otp_info.HEADER_SIZE
            data_info = data_offset | (data_size << 16)
            checksum_offset = data_offset + data_size
            header = struct.pack(
                self.otp_info.HEADER_FORMAT,
                self.otp_info.MAGIC_WORD_OTP.encode(),
                version,
                version2int(__version__),
                image_info,
                data_info,
                0,
                0,
                0,
                checksum_offset
            )

            data_all = data_region + data_region_ignore

            sha = SHA384.new(header+data_all)
            checksum = sha.digest()

            writeBinFile(header+data_all+checksum, data_image_output)
            writeBinFile(data_region, data_binary_output)
            writeDWHexFile(data_region, data_hex_output)
            writeBinFile(data_region_ignore,
                         output_folder + 'otp-data_mask.bin')

        if 'config_region' in otp_config:
            print("Generating Config Image ...")
            with open(otp_info['config'], 'r') as config_info_fd:
                config_info = jstyleson.load(config_info_fd)

            config_region, config_region_ignore = self.make_config_region(
                otp_config['config_region'], config_info,
                otp_info['config_region_size'])

            config_size = len(config_region) + len(config_region_ignore)
            image_size = self.otp_info.HEADER_SIZE + config_size
            image_info = image_size | self.otp_info.INC_CONF
            image_info_all = image_info_all | self.otp_info.INC_CONF
            config_offset = self.otp_info.HEADER_SIZE
            config_header = config_offset | (config_size << 16)
            checksum_offset = config_offset + config_size
            header = struct.pack(
                self.otp_info.HEADER_FORMAT,
                self.otp_info.MAGIC_WORD_OTP.encode(),
                version,
                version2int(__version__),
                image_info,
                0,
                config_header,
                0,
                0,
                checksum_offset
            )

            config_all = config_region + config_region_ignore

            sha = SHA384.new(header+config_all)
            checksum = sha.digest()

            writeBinFile(header+config_all+checksum, config_image_output)
            writeBinFile(config_region, config_binary_output)

        if 'otp_strap' in otp_config:
            print("Generating Strap Image ...")
            with open(otp_info['strap'], 'r') as strap_info_fd:
                strap_info = jstyleson.load(strap_info_fd)

            otp_strap, otp_strap_protect, otp_strap_ignore = self.make_otp_strap(
                otp_config['otp_strap'], strap_info,
                otp_info['otp_strap_bit_size'])

            strap_size = len(otp_strap) + len(otp_strap_protect) + \
                len(otp_strap_ignore)
            image_size = self.otp_info.HEADER_SIZE + strap_size
            image_info = image_size | self.otp_info.INC_STRAP
            image_info_all = image_info_all | self.otp_info.INC_STRAP
            strap_offset = self.otp_info.HEADER_SIZE
            strap_header = strap_offset | (strap_size << 16)
            checksum_offset = strap_offset + strap_size
            header = struct.pack(
                self.otp_info.HEADER_FORMAT,
                self.otp_info.MAGIC_WORD_OTP.encode(),
                version,
                version2int(__version__),
                image_info,
                0,
                0,
                strap_header,
                0,
                checksum_offset
            )

            otp_strap_all = otp_strap + otp_strap_protect + otp_strap_ignore

            sha = SHA384.new(header+otp_strap_all)
            checksum = sha.digest()

            writeBinFile(header+otp_strap_all+checksum, strap_image_output)
            writeBinFile(otp_strap, strap_binary_output)

        if 'scu_protect' in otp_config:
            print("Generating SCU Protect ...")
            with open(otp_info['strap'], 'r') as strap_info_fd:
                strap_info = jstyleson.load(strap_info_fd)
            scu_protect, scu_ignore = self.make_scu_protect_image(
                otp_config['scu_protect'], strap_info)

            scu_protect_size = len(scu_protect) + len(scu_ignore)
            image_size = self.otp_info.HEADER_SIZE + scu_protect_size
            image_info = image_size | self.otp_info.INC_SCU_PROTECT
            image_info_all = image_info_all | self.otp_info.INC_SCU_PROTECT

            scu_protect_offset = self.otp_info.HEADER_SIZE
            scu_protect_header = scu_protect_offset | (strap_size << 16)
            checksum_offset = scu_protect_offset + strap_size
            header = struct.pack(
                self.otp_info.HEADER_FORMAT,
                self.otp_info.MAGIC_WORD_OTP.encode(),
                version,
                version2int(__version__),
                image_info,
                0,
                0,
                0,
                scu_protect_header,
                checksum_offset
            )

            scu_protect_all = scu_protect + scu_ignore

            sha = SHA384.new(header+scu_protect_all)
            checksum = sha.digest()

            writeBinFile(header+scu_protect_all+checksum,
                         scu_protect_image_output)
            writeBinFile(scu_protect, scu_protect_binary_output)

        print("Generating OTP-all Image ...")
        image_size_all = self.otp_info.HEADER_SIZE + \
            data_size + config_size + strap_size
        image_info_all = image_info_all | image_size_all
        data_offset = self.otp_info.HEADER_SIZE
        config_offset = data_offset + data_size
        strap_offset = config_offset + config_size
        scu_protect_offset = strap_offset + strap_size
        checksum_offset = scu_protect_offset + scu_protect_size
        data_header = data_offset | (data_size << 16)
        config_header = config_offset | (config_size << 16)
        strap_header = strap_offset | (strap_size << 16)
        scu_protect_header = scu_protect_offset | (scu_protect_size << 16)

        header = struct.pack(
            self.otp_info.HEADER_FORMAT,
            self.otp_info.MAGIC_WORD_OTP.encode(),
            version,
            version2int(__version__),
            image_info_all,
            data_header,
            config_header,
            strap_header,
            scu_protect_header,
            checksum_offset
        )

        sha = SHA384.new(header+data_all+config_all +
                         otp_strap_all)
        checksum = sha.digest()

        writeBinFile(header + data_all + config_all +
                     otp_strap_all + scu_protect_all +
                     checksum, all_image_output)

    def otp_print_image_data(self, key_type_list, data_region, config_region):
        key_header = []
        find_last = 0
        for i in range(16):
            h = struct.unpack('<I', data_region[(i*4):(i*4+4)])[0]
            key_header.append(h)
            if h & (1 << 13):
                find_last = 1
                break

        if find_last == 0:
            print("Can not find Last Key List in OTP data region")
        i = 0
        for h in key_header:
            key_id = h & 0x7
            key_offset = ((h >> 3) & 0x3ff) << 3
            key_type_h = (h >> 14) & 0xf
            key_length = (h >> 18) & 0x3
            exp_length = (h >> 20) & 0xfff
            key_type = None
            info = None
            need_id = None

            for kt in key_type_list:
                if key_type_h == kt.value:
                    key_type = kt.key_type
                    info = kt.information
                    need_id = kt.need_id

            if key_type == None:
                print('key type cannot recognize')
                continue

            if kt.information == '':
                continue

            print('key[{}]:'.format(i))
            print("Key Type: {}".format(info))

            if key_type in [self.otp_info.OTP_KEY_TYPE_RSA_PRIV,
                            self.otp_info.OTP_KEY_TYPE_RSA_PUB]:
                if key_length == 0:
                    rsa_len = 1024//8
                    rsa_type = 'RSA1024'
                elif key_length == 1:
                    rsa_len = 2048//8
                    rsa_type = 'RSA2048'
                elif key_length == 2:
                    rsa_len = 3072//8
                    rsa_type = 'RSA3072'
                else:
                    rsa_len = 4096//8
                    rsa_type = 'RSA4096'
                exp_length = math.ceil(exp_length/8)
                rsa_mod = data_region[key_offset: key_offset+rsa_len]
                if key_type == self.otp_info.OTP_KEY_TYPE_RSA_PRIV:
                    rsa_exp = data_region[key_offset +
                                          rsa_len: key_offset+rsa_len+exp_length]
                else:
                    rsa_exp = bytearray([0x01, 0x0, 0x01])
                print('RSA Length: {}'.format(rsa_type))
                print('RSA exponent bit length: {}'.format(exp_length))
                if need_id == 1:
                    print('Key Number ID: {}'.format(key_id))
                print('Key Value:')
                print('RSA mod:')
                hexdump(rsa_mod)
                print('RSA exp:')
                hexdump(rsa_exp)
            elif key_type == self.otp_info.OTP_KEY_TYPE_AES:
                print('Key Value:')
                print('AES Key:')
                hexdump(data_region[key_offset: key_offset+32])
            elif key_type == self.otp_info.OTP_KEY_TYPE_VAULT:
                print('Key Value:')
                print('AES Key 1:')
                hexdump(data_region[key_offset: key_offset+32])
                print('AES Key 2:')
                hexdump(data_region[key_offset+32: key_offset+64])
            elif key_type == self.otp_info.OTP_KEY_ECDSA384:
                print('ASN1 OID: secp384r1')
                print('NIST CURVE: P-384')
                print('Qx:')
                hexdump(data_region[key_offset: key_offset+0x30])
                print('Qy:')
                hexdump(data_region[key_offset+0x30: key_offset+0x60])
            elif key_type == self.otp_info.OTP_KEY_ECDSA384P:
                print('ASN1 OID: secp384r1')
                print('NIST CURVE: P-384')
                print('Gx:')
                hexdump(data_region[key_offset: key_offset+0x30])
                print('Gy:')
                hexdump(data_region[key_offset+0x30: key_offset+0x60])
                print('p:')
                hexdump(data_region[key_offset+0x60: key_offset+0x90])
                print('n:')
                hexdump(data_region[key_offset+0x90: key_offset+0xc0])

            print('')
            i = i + 1

        if config_region == None:
            return True
        conf = []
        for i in range(16):
            h = struct.unpack('<I', config_region[(i*4):(i*4+4)])[0]
            conf.append(h)
        patch_size = (((conf[14] >> 11) & 0x3f) + 1) * 4
        patch_offset = (conf[14] & 0x7ff) * 4

        if patch_size == 4 and patch_offset == 0:
            return True

        print('OTP Patch:')
        hexdump(data_region[patch_offset:patch_offset+patch_size])

    def otp_print_revid(self, rid):
        print("     0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f")
        print("___________________________________________________")
        for i in range(64):
            if i < 32:
                j = 0
                bit_offset = i
            else:
                j = 1
                bit_offset = i - 32
            if i % 16 == 0:
                print("{:<2X} | ".format(i), end='')
            print("{}  ".format((rid[j] >> bit_offset) & 0x1), end='')
            if (i + 1) % 16 == 0:
                print("\n", end='')

    def otp_print_image_config(self, config_info, config_region, config_ignore):
        print("DW    BIT        Value       Description")
        print("__________________________________________________________________________")
        OTPCFG = []
        OTPCFG_IGNORE = []
        for i in range(16):
            h = struct.unpack('<I', config_region[(i*4):(i*4+4)])[0]
            hm = struct.unpack('<I', config_ignore[(i*4):(i*4+4)])[0]
            OTPCFG.append(h)
            OTPCFG_IGNORE.append(hm)

        rid_flag = False
        rid = [0] * 2
        rid_offset = 0
        for ci in config_info:
            dw_offset = ci['dw_offset']
            bit_offset = ci['bit_offset']
            info_type = ci['type']
            if info_type == 'boolean':
                bit_length = 1
                dw_length = 1
            else:
                bit_length = ci['bit_length']
                dw_length = math.ceil(bit_length / 32)
            mask = (1 << bit_length) - 1
            ov = 0
            oi = 0
            i = 0
            for o in range(dw_offset, dw_offset+dw_length):
                ov = ov | (OTPCFG[o] << (32*i))
                oi = oi | (OTPCFG_IGNORE[o] << (32*i))
                i = i + 1
            otp_value = (ov >> bit_offset) & mask
            otp_ignore = (oi >> bit_offset) & mask
            if otp_ignore == mask:
                continue
            ret = True
            if info_type in ['boolean', 'string', 'hex']:
                if otp_ignore != 0:
                    ret = False
            elif info_type == 'bit_shift':
                if (otp_value + otp_ignore) & mask != mask:
                    ret = False
            elif info_type == 'rev_id':
                if OTPCFG_IGNORE[dw_offset] != 0 or \
                   OTPCFG_IGNORE[dw_offset+1] != 0:
                    ret = False
                else:
                    rid_flag = True
                    rid[0] = OTPCFG[dw_offset]
                    rid[1] = OTPCFG[dw_offset+1]
                    rid_offset = dw_offset
                    continue
            if not ret:
                print('bit_length: {}'.format(bit_length))
                print('otp_ignore: 0x{:X}'.format(otp_ignore))
                print('otp_value: 0x{:X}'.format(otp_value))
                print('mask: 0x{:X}'.format(mask))
                print('Ignore mask error')
                return False

            if info_type == 'boolean':
                if otp_value == 0:
                    info = ci['info'][0]
                else:
                    info = ci['info'][1]
            elif info_type == 'string':
                vl = ci['value']
                for v in vl:
                    if otp_value == v['bit']:
                        info = ci['info'].format(v['value'])
            elif info_type == 'hex':
                h = '0x{}'.format(otp_value)
                info = ci['info'].format(h)
                if info == '':
                    info = 'error: 0x{:X}'.format(otp_value)
            elif info_type == 'bit_shift':
                val = ''
                for j in range(7):
                    if otp_value == (1 << j):
                        val = val + '1 '
                    else:
                        val = val + '0 '
                info = ci['info'].format(val)

            if info != '':
                print('0x{:<4X}'.format(dw_offset), end='')
                if bit_length == 1:
                    print('0x{:<9X}'.format(bit_offset), end='')
                else:
                    print('0x{:<2X}:0x{:<4X}'.format(
                        bit_offset + bit_length - 1, bit_offset), end='')
                print('0x{:<10X}'.format(otp_value), end='')
                print('{}'.format(info))
        print()
        if rid_flag:
            print('OTP Manifest ID(revision id), OTPCFG{:X}, OTPCFG{:X}'.format(
                rid_offset, rid_offset+1))
            self.otp_print_revid(rid)
            print()

    def otp_print_image_strap(self, strap_info, strap, strap_pro, strap_ignore):
        OTPSTRAP = struct.unpack('<Q', strap)[0]
        OTPSTRAP_PRO = struct.unpack('<Q', strap_pro)[0]
        OTPSTRAP_IGNORE = struct.unpack('<Q', strap_ignore)[0]

        print("BIT(hex)   Value       Protect     Description")
        print("__________________________________________________________________________________________")

        for si in strap_info:
            info_type = si['type']
            if info_type == 'reg_protect':
                continue
            if info_type == 'boolean':
                bit_length = 1
            else:
                bit_length = si['bit_length']

            bit_offset = si['bit_offset']

            mask = BIT(bit_length) - 1
            otp_value = (OTPSTRAP >> bit_offset) & mask
            otp_protect = (OTPSTRAP_PRO >> bit_offset) & mask
            otp_ignore = (OTPSTRAP_IGNORE >> bit_offset) & mask

            if otp_ignore == mask:
                continue
            elif otp_ignore != 0:
                return False
            info = ''
            if info_type == 'boolean':
                if otp_value == 0:
                    info = si['info'][0]
                else:
                    info = si['info'][1]
            elif info_type == 'string':
                vl = si['value']
                for v in vl:
                    if otp_value == v['bit']:
                        info = si['info'].format(v['value'])
            elif info_type == 'reserved':
                info = 'Reserved'

            if info != '':
                if bit_length == 1:
                    print('0x{:<9X}'.format(bit_offset), end='')
                else:
                    print('0x{:<2X}:0x{:<4X}'.format(
                        bit_offset + bit_length - 1, bit_offset), end='')
                print('0x{:<10X}'.format(otp_value), end='')
                print('0x{:<10X}'.format(otp_protect), end='')
                print('{}'.format(info))

    def otp_print_image_scu(self, strap_info, scu_pro, scu_ignore):
        OTPSCU_PRO = struct.unpack('<Q', scu_pro)[0]
        OTPSCU_IGNORE = struct.unpack('<Q', scu_ignore)[0]

        print('SCU     BIT          reg_protect     Description')
        print('____________________________________________________________________')
        for si in strap_info:
            if 'scu_mapping' not in si:
                continue
            sm = si['scu_mapping']
            if sm['scu'] == '500':
                scu_offset = 0x500
                bit_offset = sm['bit_offset']
            else:
                scu_offset = 0x510
                bit_offset = sm['bit_offset'] + 32
            if 'bit_length' in si:
                bit_length = si['bit_length']
            else:
                bit_length = 1

            mask = BIT(bit_length) - 1
            scu_protect = (OTPSCU_PRO >> bit_offset) & mask
            scu_ignore = (OTPSCU_IGNORE >> bit_offset) & mask

            if scu_ignore == mask:
                continue
            elif scu_ignore != 0:
                return False
            if scu_protect != 0 and scu_protect != mask:
                return False

            print('0x{:<6X}'.format(scu_offset), end='')
            if bit_length == 1:
                print('0x{:<11X}'.format(sm['bit_offset']), end='')
            else:
                print('0x{:<2X}:0x{:<6X}'.format(
                    sm['bit_offset'], sm['bit_offset'] + bit_length), end='')
            print('0x{:<14X}'.format(scu_protect), end='')
            print('{}'.format(si['key']))

    def otp_strap_status(self, soc_ver, strap_dw):
        ret = []

        if soc_ver == OTP_info.SOC_AST2600A0:
            for i in range(64):
                otpstrap = strap_sts()
                otpstrap.value = 0
                otpstrap.remain_times = 7
                otpstrap.writeable_option = -1
                otpstrap.protected = 0
                ret.append(otpstrap)
            strap_end = 14
        else:
            for i in range(64):
                otpstrap = strap_sts()
                otpstrap.value = 0
                otpstrap.remain_times = 6
                otpstrap.writeable_option = -1
                otpstrap.protected = 0
                ret.append(otpstrap)
            strap_end = 12

        for i in range(0, strap_end, 2):
            option = int(i / 2)
            for j in range(32):
                bit_value = (strap_dw[i] >> j) & 0x1
                if bit_value == 0 and ret[j].writeable_option == -1:
                    ret[j].writeable_option = option
                if bit_value == 1:
                    ret[j].remain_times = ret[j].remain_times - 1
                ret[j].value = ret[j].value ^ bit_value
                ret[j].option_array[option] = bit_value

            for j in range(32, 64):
                bit_value = (strap_dw[i+1] >> (j - 32)) & 0x1
                if bit_value == 0 and ret[j].writeable_option == -1:
                    ret[j].writeable_option = option
                if bit_value == 1:
                    ret[j].remain_times = ret[j].remain_times - 1
                ret[j].value = ret[j].value ^ bit_value
                ret[j].option_array[option] = bit_value

        for j in range(32):
            if ((strap_dw[14] >> j) & 0x1) == 1:
                ret[j].protected = 1
        for j in range(32, 64):
            if ((strap_dw[15] >> (j - 32)) & 0x1) == 1:
                ret[j].protected = 1
        return ret

    def otp_print_strap_info(self, soc_ver, strap_info, strap_dw):
        strap_status = self.otp_strap_status(soc_ver, strap_dw)

        print("BIT(hex) Value  Remains  Protect   Description")
        print("___________________________________________________________________________________________________")

        for si in strap_info:
            otp_value = 0
            otp_protect = 0
            bit_offset = si['bit_offset']
            info_type = si['type']
            if info_type == 'boolean':
                length = 1
            else:
                length = si['bit_length']
            for j in range(length):
                otp_value |= strap_status[bit_offset + j].value << j
                otp_protect |= strap_status[bit_offset + j].protected << j

            info = ''
            if info_type == 'boolean':
                if otp_value == 0:
                    info = si['info'][0]
                else:
                    info = si['info'][1]
            elif info_type == 'string':
                vl = si['value']
                for v in vl:
                    if otp_value == v['bit']:
                        info = si['info'].format(v['value'])
                if info == '':
                    info = 'error: 0x{:X}'.format(otp_value)
            if info == '':
                continue
            for j in range(length):
                print(
                    '0x{:<7X}'.format(si['bit_offset'] + j), end='')
                print(
                    '0x{:<5X}'.format(strap_status[bit_offset + j].value), end='')
                print(
                    '{:<9}'.format(strap_status[bit_offset + j].remain_times), end='')
                print(
                    '0x{:<7X}'.format(strap_status[bit_offset + j].protected), end='')
                if length == 1:
                    print(' {}'.format(info))
                    continue

                if j == 0:
                    print('/{}'.format(info))
                elif j == length - 1:
                    print('\\ \"')
                else:
                    print('| \"')

    def check_image(self, otp_image):
        header = image_header(otp_image[0:self.otp_info.HEADER_SIZE])

        magic = header.magic[0:len(self.otp_info.MAGIC_WORD_OTP)].decode()
        if magic != self.otp_info.MAGIC_WORD_OTP:
            raise OtpError('OTP image magic word is invalid')

        image_size = header.image_info & 0xffff
        sha = SHA384.new(otp_image[:image_size])
        digest = sha.digest()
        co = header.checksum_offset
        if digest != otp_image[co:co+48]:
            raise OtpError('OTP image checksum is invalid')

        return 0

    def _parse_image_soc_ver(self, soc_ver):
        if soc_ver == OTP_info.SOC_AST2600A0:
            ver = "AST2600A0"
            key_type_list = self.otp_info.a0_key_type
            otp_info = self.otp_info.OTP_INFO['A0']
        elif soc_ver == OTP_info.SOC_AST2600A1:
            ver = "AST2600A1"
            key_type_list = self.otp_info.a1_key_type
            otp_info = self.otp_info.OTP_INFO['A1']
        elif soc_ver == OTP_info.SOC_AST2600A2:
            ver = "AST2600A2"
            key_type_list = self.otp_info.a1_key_type
            otp_info = self.otp_info.OTP_INFO['A2']
        elif soc_ver == OTP_info.SOC_AST2600A3:
            ver = "AST2600A3"
            key_type_list = self.otp_info.a3_key_type
            otp_info = self.otp_info.OTP_INFO['A3']
        elif soc_ver == OTP_info.SOC_AST1030A0:
            ver = "AST1030A0"
            key_type_list = self.otp_info.a1_key_type
            otp_info = self.otp_info.OTP_INFO['1030A0']
        elif soc_ver == OTP_info.SOC_AST1030A1:
            ver = "AST1030A1"
            key_type_list = self.otp_info.ast1030a1_key_type
            otp_info = self.otp_info.OTP_INFO['1030A1']
        elif soc_ver == OTP_info.SOC_AST1060A1:
            ver = "AST1060A1"
            key_type_list = self.otp_info.ast1030a1_key_type
            otp_info = self.otp_info.OTP_INFO['1030A1']
        elif soc_ver == OTP_info.SOC_AST1060A2:
            ver = "AST1060A2"
            key_type_list = self.otp_info.ast1030a1_key_type
            otp_info = self.otp_info.OTP_INFO['1030A1']
        else:
            print('SOC version is invalid: {:X}'.format(soc_ver))
            return None, None

        print('SOC version: {}'.format(ver))
        return key_type_list, otp_info

    def _print_otp_image(self, otp_image):
        header = image_header(otp_image[0:self.otp_info.HEADER_SIZE])

        key_type_list, otp_info = self._parse_image_soc_ver(header.soc_ver)

        if key_type_list == None or otp_info == None:
            return False

        print('otptool version: {}'.format(int2version(header.otptool_ver)))

        with open(otp_info['strap'], 'r') as strap_info_fd:
            strap_info = jstyleson.load(strap_info_fd)

        with open(otp_info['config'], 'r') as config_info_fd:
            config_info = jstyleson.load(config_info_fd)

        data_offset = header.data_info & 0xffff
        data_region = otp_image[data_offset:data_offset+8192]
        # data_region_ignore = otp_image[data_offset+8219:data_offset+8192*2]
        conf_offset = header.config_info & 0xffff
        config_region = otp_image[conf_offset:conf_offset+64]
        config_region_ignore = otp_image[conf_offset+64:conf_offset+64*2]
        strap_offset = header.strap_info & 0xffff
        strap_region = otp_image[strap_offset:strap_offset+8]
        strap_region_pro = otp_image[strap_offset+8:strap_offset+16]
        strap_region_ignore = otp_image[strap_offset+16:strap_offset+24]
        scu_offset = header.scu_protect_info & 0xffff
        scu_pro = otp_image[scu_offset:scu_offset+8]
        scu_ignore = otp_image[scu_offset+8:scu_offset+16]

        if header.image_info & self.otp_info.INC_DATA:
            print('OTP data region :')
            if header.image_info & self.otp_info.INC_CONF:
                self.otp_print_image_data(
                    key_type_list, data_region, config_region)
            else:
                self.otp_print_image_data(
                    key_type_list, data_region, None)

        if header.image_info & self.otp_info.INC_CONF:
            print('OTP config region :')
            self.otp_print_image_config(
                config_info, config_region, config_region_ignore)

        if header.image_info & self.otp_info.INC_STRAP:
            print('OTP strap :')
            self.otp_print_image_strap(
                strap_info, strap_region, strap_region_pro, strap_region_ignore)

        if header.image_info & self.otp_info.INC_SCU_PROTECT:
            print('OTP scu protect :')
            self.otp_print_image_scu(strap_info, scu_pro, scu_ignore)

    def _print_dump_image(self, otp_image):
        header = image_header(otp_image[0:self.otp_info.HEADER_SIZE])

        key_type_list, otp_info = self._parse_image_soc_ver(header.soc_ver)

        if key_type_list == None or otp_info == None:
            return False

        with open(otp_info['strap'], 'r') as strap_info_fd:
            strap_info = jstyleson.load(strap_info_fd)

        with open(otp_info['config'], 'r') as config_info_fd:
            config_info = jstyleson.load(config_info_fd)

        data_offset = header.data_info & 0xffff
        data_region = otp_image[data_offset:data_offset+8192]
        conf_offset = header.config_info & 0xffff
        config_region = otp_image[conf_offset:conf_offset+64]
        config_region_ignore = bytearray(64)
        strap_region = otp_image[conf_offset+64:conf_offset+128]

        print('OTP data region :')
        self.otp_print_image_data(
            header.soc_ver, key_type_list, data_region, config_region)

        print('OTP config region :')
        self.otp_print_image_config(
            config_info, config_region, config_region_ignore)

        print('OTP strap :')
        strap_region_dw = []
        for i in range(0, 16):
            h = struct.unpack('<I', strap_region[(i*4):(i*4+4)])[0]
            strap_region_dw.append(h)
        self.otp_print_strap_info(header.soc_ver, strap_info, strap_region_dw)

    def print_otp_image(self, otp_image_fd):
        otp_image = bytearray(otp_image_fd.read())
        header = image_header(otp_image[0:self.otp_info.HEADER_SIZE])

        self.check_image(otp_image)

        if header.image_info & self.otp_info.HEADER_DUMP:
            self._print_dump_image(otp_image)
        else:
            self._print_otp_image(otp_image)


class otpTool(object):
    """Object for otptool command-line tool."""

    def __init__(self):
        """Initializer method."""
        self.otp = OTP()

    def run(self, argv):
        """Command-line processor.

        Arguments:
            argv: Pass sys.argv from main.
        """
        parser = argparse.ArgumentParser()

        subparsers = parser.add_subparsers(title='subcommands',
                                           dest='subparser_name')

        sub_parser = subparsers.add_parser('make_otp_image',
                                           help='Makes otp image.')
        sub_parser.add_argument('config',
                                help='configuration file',
                                type=argparse.FileType('r'))

        sub_parser.add_argument('--key_folder',
                                help='key folder',
                                type=parse_path,
                                default='')
        sub_parser.add_argument('--user_data_folder',
                                help='user data folder',
                                type=parse_path,
                                default='')
        sub_parser.add_argument('--output_folder',
                                help='output folder',
                                type=parse_path,
                                default='')
        sub_parser.add_argument('--no_last_bit',
                                help='(develop)remove last bit in OTP header',
                                action='store_true',
                                required=False)
        sub_parser.add_argument('--no_pre_production',
                                help='check no pre production version',
                                action='store_true',
                                required=False)
        sub_parser.set_defaults(func=self.make_otp_image)

        sub_parser = subparsers.add_parser('print',
                                           help='print otp image information.')
        sub_parser.add_argument('otp_image',
                                help='OTP image',
                                type=argparse.FileType('rb'))
        sub_parser.set_defaults(func=self.print_otp_image)

        sub_parser = subparsers.add_parser('version',
                                           help='print otptool version.')
        sub_parser.set_defaults(func=self.print_version)

        args = parser.parse_args(argv[1:])

        if(len(argv) == 1):
            parser.print_usage()
            sys.exit(1)

        args.func(args)

    def make_otp_image(self, args):
        self.otp.make_otp_image(args.config,
                                args.key_folder,
                                args.user_data_folder,
                                args.output_folder,
                                args.no_last_bit,
                                args.no_pre_production)

    def print_otp_image(self, args):
        self.otp.print_otp_image(args.otp_image)

    def print_version(self, args):
        print(__version__)
