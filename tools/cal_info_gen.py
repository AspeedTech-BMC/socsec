# Copyright (c) 2024 ASPEED Technology Inc.

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

from ecdsa.keys import VerifyingKey
from bitarray import bitarray
from Crypto.Hash import SHA384
import argparse
import jstyleson
import json
import sys
import os
import struct
import binascii

VEN_ECC_PUB_KEYS_NAME = [
    "vnd-pub-key-0.pem",
    "vnd-pub-key-1.pem",
    "vnd-pub-key-2.pem",
    "vnd-pub-key-3.pem",
]

VEN_LMS_PUB_KEYS_NAME = [
    "vnd-lms-pub-key-0.pem",
    "vnd-lms-pub-key-1.pem",
    "vnd-lms-pub-key-2.pem",
    "vnd-lms-pub-key-3.pem",
    "vnd-lms-pub-key-4.pem",
    "vnd-lms-pub-key-5.pem",
    "vnd-lms-pub-key-6.pem",
    "vnd-lms-pub-key-7.pem",
    "vnd-lms-pub-key-8.pem",
    "vnd-lms-pub-key-9.pem",
    "vnd-lms-pub-key-10.pem",
    "vnd-lms-pub-key-11.pem",
    "vnd-lms-pub-key-12.pem",
    "vnd-lms-pub-key-13.pem",
    "vnd-lms-pub-key-14.pem",
    "vnd-lms-pub-key-15.pem",
    "vnd-lms-pub-key-16.pem",
    "vnd-lms-pub-key-17.pem",
    "vnd-lms-pub-key-18.pem",
    "vnd-lms-pub-key-19.pem",
    "vnd-lms-pub-key-20.pem",
    "vnd-lms-pub-key-21.pem",
    "vnd-lms-pub-key-22.pem",
    "vnd-lms-pub-key-23.pem",
    "vnd-lms-pub-key-24.pem",
    "vnd-lms-pub-key-25.pem",
    "vnd-lms-pub-key-26.pem",
    "vnd-lms-pub-key-27.pem",
    "vnd-lms-pub-key-28.pem",
    "vnd-lms-pub-key-29.pem",
    "vnd-lms-pub-key-30.pem",
    "vnd-lms-pub-key-31.pem",
]

OWN_ECC_PUB_KEY_NAME = "own-pub-key.pem"
OWN_LMS_PUB_KEY_NAME = "own-lms-pub-key.pem"

VEN_ECC_KEY_SIZE = 96 * 4
VEN_LMS_KEY_SIZE = 48 * 32
OWN_ECC_KEY_SIZE = 96
OWN_LMS_KEY_SIZE = 48

def parse_path(path):
    if path is None or path == '':
        return os.path.abspath(os.path.curdir)+'/'
    if path[-1] != '/':
        path += '/'
    return path

def load_file(file_path: str):
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            file_bin = f.read()
            f.close()
    else:
        raise ValueError("File is not exists", file_path)

    return file_bin

def insert_bytearray(src, dst, offset):
    if offset+len(src) > len(dst):
        dst.extend(bytearray(offset-len(dst)+len(src)))

    dst[offset:offset+len(src)] = src

def ecdsa_key_to_bin(ecdsa_key_file, order="little"):
    if order not in ['little', 'big']:
        raise ValueError("order error")

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

    if order == "big":
        x_rev = bytearray(48)
        for i in range(12):
                # print(binascii.hexlify(x_b[i*4:(i+1)*4]))
                tmp = int.from_bytes(x_b[i*4:(i+1)*4], byteorder="little")
                # print(hex(tmp))
                # tmp = x_b[i*4:(i+1)*4].reverse()
                x_rev[i*4:i*4+4] = tmp.to_bytes(4, byteorder="big")
                # print(binascii.hexlify(x_rev[i*4:(i+1)*4]))
        x_b = x_rev
        y_rev = bytearray(48)
        for i in range(12):
                # print(binascii.hexlify(x_b[i*4:(i+1)*4]))
                tmp = int.from_bytes(y_b[i*4:(i+1)*4], byteorder="little")
                # print(hex(tmp))
                # tmp = x_b[i*4:(i+1)*4].reverse()
                y_rev[i*4:i*4+4] = tmp.to_bytes(4, byteorder="big")
                # print(binascii.hexlify(y_rev[i*4:(i+1)*4]))
        y_b = y_rev

    key_bin = bytearray(48 * 2)
    insert_bytearray(x_b, key_bin, 0)
    insert_bytearray(y_b, key_bin, 48)

    return key_bin

def writeBinFile(in_bin: bytearray, dst_path: str):
    with open(dst_path, 'w+b')as outf:
        outf.write(bytes(in_bin))
        outf.close()

class genTool(object):

    def gen_sample(self):
        cal_keys = dict()
        vendor_keys = dict()
        owner_keys = dict()

        ecc_keys = []
        for x in range(4):
            ecc_key = dict()
            ecc_key["key_file"] = VEN_ECC_PUB_KEYS_NAME[x]
            ecc_keys.append(ecc_key)

        vendor_keys["ecc_keys"] = ecc_keys

        lms_keys = []
        for x in range(32):
            lms_key = dict()
            lms_key["key_file"] = VEN_LMS_PUB_KEYS_NAME[x]
            lms_keys.append(lms_key)

        vendor_keys["lms_keys"] = lms_keys

        cal_keys["vendor"] = vendor_keys

        ecc_keys = []
        ecc_key = dict()
        ecc_key["key_file"] = OWN_ECC_PUB_KEY_NAME
        ecc_keys.append(ecc_key)
        owner_keys["ecc_keys"] = ecc_keys

        lms_keys = []
        lms_key = dict()
        lms_key["key_file"] = OWN_LMS_PUB_KEY_NAME
        lms_keys.append(lms_key)
        owner_keys["lms_keys"] = lms_keys

        cal_keys["owner"] = owner_keys

        filename = "sample_caliptra.json"
        with open(filename, "w", encoding="utf-8") as writeJsonfile:
            json.dump(cal_keys, writeJsonfile, indent=4, default=str)

    def gen_keyhash(self, config, key_folder, output_folder):
        os.system('mkdir -p '+output_folder)

        vendor_binary_outout = output_folder + 'vendor_key.bin'
        vendor_kh_binary_outout = output_folder + 'vendor_key_hash.bin'
        owner_binary_outout = output_folder + 'owner_key.bin'
        owner_kh_binary_outout = output_folder + 'owner_key_hash.bin'

        key_bin = bytearray(VEN_ECC_KEY_SIZE + VEN_LMS_KEY_SIZE)
        print("size of key_bin", len(key_bin))

        vendor_ecc_keys = config["vendor"]["ecc_keys"]
        for i in range(len(vendor_ecc_keys)):
                print(vendor_ecc_keys[i]["key_file"])
                offset = i * 96
                ecdsa_key_bin = ecdsa_key_to_bin(key_folder + vendor_ecc_keys[i]["key_file"], "big")
                insert_key_bin = bytearray(ecdsa_key_bin)
                insert_bytearray(insert_key_bin, key_bin, offset)

        if "lms_keys" in config["vendor"]:
                vendor_lms_keys = config["vendor"]["lms_keys"]
                for i in range(len(vendor_lms_keys)):
                        print(vendor_lms_keys[i]["key_file"])
                        offset = 4 * 96 + i * 48
                        lms_key_bin = load_file(key_folder + vendor_lms_keys[i]["key_file"])
                        insert_key_bin = bytearray(lms_key_bin)
                        insert_bytearray(insert_key_bin, key_bin, offset)

        sha = SHA384.new(key_bin)
        digest_bin = sha.digest()

        writeBinFile(key_bin, vendor_binary_outout)
        writeBinFile(digest_bin, vendor_kh_binary_outout)

        key_bin = bytearray(OWN_ECC_KEY_SIZE + OWN_LMS_KEY_SIZE)
        print("size of key_bin", len(key_bin))

        owner_ecc_keys = config["owner"]["ecc_keys"]
        ecdsa_key_bin = ecdsa_key_to_bin(key_folder + owner_ecc_keys[0]["key_file"], "big")
        insert_key_bin = bytearray(ecdsa_key_bin)
        insert_bytearray(insert_key_bin, key_bin, 0)

        if "lms_keys" in config["owner"]:
                owner_lms_keys = config["owner"]["lms_keys"]
                lms_key_bin = load_file(key_folder + owner_lms_keys[0]["key_file"])
                insert_key_bin = bytearray(lms_key_bin)
                insert_bytearray(insert_key_bin, key_bin, OWN_ECC_KEY_SIZE)

        sha = SHA384.new(key_bin)
        digest_bin = sha.digest()

        writeBinFile(key_bin, owner_binary_outout)
        writeBinFile(digest_bin, owner_kh_binary_outout)

def gen_sample(tool, args):
        tool.gen_sample()

def gen_keyhash(tool, args):
        config = jstyleson.load(args.config)
        tool.gen_keyhash(config, args.key_folder, args.output_folder)

if __name__ == '__main__':

        tool = genTool()
        parser = argparse.ArgumentParser()

        subparsers = parser.add_subparsers(title='subcommands',
                                           dest='subparser_name')

        sub_parser = subparsers.add_parser('gen_sample',
                                        help='Makes caliptra sample json file')

        sub_parser.set_defaults(func=gen_sample)

        sub_parser = subparsers.add_parser('gen_keyhash',
                                            help='Makes caliptra key hash binary file')

        sub_parser.add_argument('--key_folder',
                                help='key folder',
                                type=parse_path,
                                default='')

        sub_parser.add_argument('--output_folder',
                                help='output folder',
                                type=parse_path,
                                default='')

        sub_parser.add_argument('config',
                                help='configuration json file',
                                type=argparse.FileType('r'))

        sub_parser.set_defaults(func=gen_keyhash)

        args = parser.parse_args(sys.argv[1:])
        # print("args", args)

        if (len(sys.argv) == 1):
            parser.print_usage()
            sys.exit(1)

        args.func(tool, args)