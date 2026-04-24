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

from enum import Enum
import xlrd
from collections import OrderedDict
import json
import re
import os
import argparse
import sys

OTPRBP_SHEET_NAME = 'OTPRBP'
OTPCFG_SHEET_NAME = 'OTPCFG'
OTPSTRAP_SHEET_NAME = 'OTPSTRAP'
OTPSTRAP_EXT_SHEET_NAME = 'OTPSTRAP_EXT'
SECURE_SHEET_NAME = 'OTPSEC'
CALIPTRA_SHEET_NAME = 'OTPCAL'
AST_CHIP_NAME = 'AST'
AST_CHIP_VER = '2700a2'

class KeyType(Enum):
        SOC_ECDSA_PUB = 1
        SOC_LMS_PUB = 2
        CAL_MANU_PUB_HASH = 3
        CAL_OWN_PUB_HASH = 4
        SOC_VAULT = 5
        SOC_VAULT_SEED = 6

OTP_KEY_TYPE_NAME = [
        "soc_ecdsa_pub",
        "soc_lms_pub",
        "cal_manu_pub_hash",
        "cal_own_pub_hash",
        "soc_vault",
        "soc_vault_seed",
]

OTP_KEY_NAME = [
        "OEM DSS ECDSA Key",
        "OEM DSS LMS Key",
        "Manufacture Key Hash",
        "Owner Key Hash",
        "Vault Key",
        "Vault Key Seed"
]

OTP_KEY_FILE_NAME = [
        "test_oem_dss_public_key_ecdsa384_",
        "test_oem_dss_lms_key_",
        "test_manu_key_hash.bin",
        "test_owner_key_hash.bin",
        "test_vault_key.bin",
        "test_vault_key_seed.bin"
]



def parse_int(val, default=0):
    """Safely parse an integer from Excel value."""
    if isinstance(val, (int, float)):
        return int(val)
    s = str(val).strip()
    if not s:
        return default
    # Handle ranges like '9: 8' by taking the first number
    if ':' in s:
        try:
            return int(s.split(':')[0])
        except ValueError:
            return default
    try:
        # Handle cases like '400.0', '0x100', or '1C00'
        if s.startswith('0x') or s.startswith('0X'):
            return int(s, 16)
        # Try hex first if it contains A-F
        if any(c in 'ABCDEFabcdef' for c in s):
            try:
                return int(s, 16)
            except ValueError:
                pass
        return int(float(s))
    except ValueError:
        return default


def parse_bit_size(val):
    """Parse bit size which could be an int, or a string like '15: 0' or '16'."""
    if isinstance(val, (int, float)):
        return int(val)
    s = str(val).strip()
    if not s:
        return 0
    if ':' in s:
        try:
            parts = s.split(':')
            return abs(int(parts[0].strip()) - int(parts[1].strip())) + 1
        except (ValueError, IndexError):
            return 0
    try:
        return int(float(s))
    except ValueError:
        return 0


def otprbp_handler_info(sheet, list):
        sh = sheet

        for rownum in range(0, sh.nrows):
                if rownum < 1:
                        continue

                row_values = sh.row_values(rownum)
                #print(row_values)

                otp_addr = row_values[0]
                otp_name = row_values[1]
                otp_size = row_values[2]
                otp_desc = row_values[6]

                name_str = str(otp_name).strip()
                # reserved skip
                if name_str.lower() == "reserved" or name_str in ["Sum", "Actual"]:
                        continue

                name = str(otp_name).replace(' ', '_')
                bit_length = parse_bit_size(otp_size)
                offset = parse_int(otp_addr) - 0x3e0

                idx = str(otp_desc).find('\n')
                if idx != -1:
                        desc = str(otp_desc)[:idx]
                else:
                        desc = str(otp_desc)

                if bit_length > 32:
                        for i in range (0, int(bit_length / 32)):
                                rbp = OrderedDict()
                                # print(i)
                                rbp['type'] = "string"
                                rbp['key'] = name + "_" + str(i)
                                rbp['w_offset'] = offset + i * 2
                                rbp['bit_offset'] = 0
                                rbp['bit_length'] = 32
                                rbp['info'] = "[" + str((i + 1) * 32 - 1) + ":" + str(i * 32) + "] " + desc
                                # print(rbp['key'])
                                list.append(rbp)
                else:
                        rbp = OrderedDict()
                        rbp['type'] = "string"
                        rbp['key'] = name
                        rbp['w_offset'] = offset
                        rbp['bit_offset'] = 0
                        rbp['bit_length'] = bit_length
                        rbp['info'] = desc
                        list.append(rbp)

def otprbp_handler(sheet, data):
        sh = sheet

        rbp_region = OrderedDict()
        for rownum in range(0, sh.nrows):
                if rownum < 1:
                        continue

                row_values = sh.row_values(rownum)
                # print(row_values)

                otp_addr = parse_int(row_values[0]) - 0x3e0
                otp_name = row_values[1]
                otp_bit_size = parse_bit_size(row_values[2])

                name_str = str(otp_name).strip()
                # reserved skip
                if name_str.lower() == "reserved" or name_str in ["Sum", "Actual"]:
                        continue

                if otp_addr == 32:
                        break

                desc = "// " + "OTPRBP" + str(otp_addr) + " - " +str(otp_bit_size) + " bits"

                rbp_region[desc] = ""
                keys = str(otp_name).replace(" ", "_")
                if otp_bit_size <= 32:
                        rbp_region[keys] = "0x0"
                else:
                        for i in range(0, int(otp_bit_size / 32)):
                          keys_num = keys + "_"+ str(i)
                          rbp_region[keys_num] = "0x0"

                data["rbp_region"] = rbp_region
        return

def otpcfg_handler_info(sheet, list):
        sh = sheet

        for rownum in range(0, sh.nrows):
                conf = OrderedDict()
                bit_length = 0

                row_values = sh.row_values(rownum)
                # print(row_values)

                otp_addr = row_values[0]
                otp_num = row_values[8]
                otp_bit_msb = row_values[2]
                otp_bit_lsb = row_values[2]
                otp_bit_name = row_values[1]
                otp_bit_desc = row_values[6]

                if rownum < 1:
                        continue

                # skip Sum and Actual
                if str(otp_bit_name).strip() in ["Sum", "Actual"]:
                        continue

                if otp_bit_msb == "":
                        break


                if otp_num != "":
                        parts = str(otp_num).split("/")
                        otpcfg_num = parts[0] if parts else ""
                else:
                        otpcfg_num = ""

                # reserved skip
                if str(otp_bit_name).lower() == "reserved":
                        continue

                msb = parse_int(otp_bit_msb)
                lsb = parse_int(otp_bit_lsb)
                if ':' in str(otp_bit_msb):
                        parts = str(otp_bit_msb).split(':')
                        msb = int(parts[0].strip())
                        lsb = int(parts[1].strip())

                if msb != lsb:
                        multi_value = True
                        bit_length = msb - lsb + 1
                else:
                        multi_value = False

                descs_raw = str(otp_bit_desc)
                descs_raw = re.sub(r'(?<!\n)\s+(?=\d+:)', '\n', descs_raw)
                descs = descs_raw.split('\n')
                desc = descs[0]

                name = str(otp_bit_name).replace(' ', '_')

                conf['key'] = name
                if multi_value:
                        conf['type'] = "string"
                else:
                        conf['type'] = "boolean"

                nums = re.findall(r'-?\d+', str(otpcfg_num))
                conf['w_offset'] = int(nums[0]) if nums else 0
                conf['bit_offset'] = lsb
                if bit_length != 0:
                        conf['bit_length'] = bit_length

                desc_list = []
                matches_a = ["enable", "Enable"]
                matches_b = ["disable", "Disable"]
                for x in matches_a:
                        if x in desc:
                                desc_list.append(desc.replace(x, matches_b[matches_a.index(x)]))
                                desc_list.append(desc)
                for x in matches_b:
                        if x in desc:
                                desc_list.append(desc.replace(x, matches_a[matches_b.index(x)]))
                                desc_list.append(desc)

                if bit_length != 0 and bit_length < 8 and desc_list == []:
                        has_title = ':' not in descs[0] and len(descs) > 1
                        start_idx = 1 if has_title else 0

                        for i in range(0, int(2 ** bit_length)):
                                idx_val = start_idx + i
                                if idx_val >= len(descs):
                                        break
                                desc_val = descs[idx_val].split(':')
                                if len(desc_val) < 2:
                                        break
                                desc_list.append(desc + " = " + desc_val[1].strip())

                if desc_list == []:
                        desc_list.append(desc)

                conf['info'] = desc_list
                list.append(conf)
        return

def otpcfg_handler(sheet, data):
        sh = sheet

        conf_region = OrderedDict()
        for rownum in range(0, sh.nrows):
                if rownum < 1:
                        continue

                row_values = sh.row_values(rownum)
                # print(row_values)

                otp_addr = row_values[0]
                otp_num = row_values[8]
                otp_bit_msb = row_values[2]
                otp_bit_lsb = row_values[2]
                otp_bit_name = row_values[1]


                if otp_num != "":
                        parts = str(otp_num).split("/")
                        otpcfg_num = parts[0] if parts else ""
                else:
                        otpcfg_num = ""

                # reserved skip
                if str(otp_bit_name).lower() == "reserved":
                        continue
                if otp_bit_msb == "":
                        break

                msb = parse_int(otp_bit_msb)
                lsb = parse_int(otp_bit_lsb)
                if ':' in str(otp_bit_msb):
                        parts = str(otp_bit_msb).split(':')
                        msb = int(parts[0].strip())
                        lsb = int(parts[1].strip())

                if msb != lsb:
                        desc = "// " + otpcfg_num + "[" + str(msb) + ":" + str(lsb) + "]"
                        multi_value = True
                else:
                        desc = "// " + otpcfg_num + "[" + str(lsb) + "]"
                        multi_value = False

                conf_region[desc] = ""
                keys = str(otp_bit_name).replace(" ", "_")
                if multi_value:
                        conf_region[keys] = "0x0"
                else:
                        conf_region[keys] = False

                data["config_region"] = conf_region
        return

def otpstrap_handler_info(sheet, list):
        sh = sheet

        strap_list = []
        strap_ext_list = []

        for rownum in range(0, sh.nrows):
                strap = OrderedDict()

                if rownum < 1:
                        continue

                row_values = sh.row_values(rownum)
                # print(row_values)

                is_strapext = False
                is_strap = False

                # OTPSTRAP & OTPSTRAP_EXT only
                if str(row_values[8]).startswith("OTPSTRAP_EXT"):
                        is_strapext = True
                elif str(row_values[8]).startswith("OTPSTRAP"):
                        is_strap = True
                else:
                        continue

                name_str = str(row_values[1]).strip()
                # reserved skip
                if name_str.lower() == "reserved" or name_str in ["Sum", "Actual"]:
                        continue

                strap['key'] = str(row_values[1]).strip()

                if is_strap:
                        strap['key_type'] = "strap"
                elif is_strapext:
                        strap['key_type'] = "strap_ext"

                bit_length = parse_bit_size(row_values[3])
                nums = re.findall(r'-?\d+', str(row_values[8]))
                if bit_length == 1:
                        strap['type'] = "boolean"
                        strap_num = int(nums[0]) if nums else 0
                else:
                        strap['type'] = "string"
                        strap_num = int(nums[1]) if len(nums) > 1 else (int(nums[0]) if nums else 0)

                if is_strap:
                        strap['w_offset'] = parse_int(row_values[0]) - 422
                elif is_strapext:
                        strap['w_offset'] = parse_int(row_values[0]) - 430

                bit_str = str(row_values[2])
                if ':' in bit_str:
                        strap['bit_offset'] = int(bit_str.split(':')[1].strip())
                else:
                        strap['bit_offset'] = parse_int(bit_str)

                if bit_length > 1:
                        strap['bit_length'] = bit_length

                idx = str(row_values[6]).find('\n')
                if idx != -1:
                        desc = str(row_values[6])[:idx]
                else:
                        desc = str(row_values[6])

                desc_list = []
                matches_a = ["enable", "Enable"]
                matches_b = ["disable", "Disable"]
                for x in matches_a:
                        if x in desc:
                                desc_list.append(desc.replace(x, matches_b[matches_a.index(x)]))
                                desc_list.append(desc)
                for x in matches_b:
                        if x in desc:
                                desc_list.append(desc.replace(x, matches_a[matches_b.index(x)]))
                                desc_list.append(desc)

                descs_raw = str(row_values[6])
                descs_raw = re.sub(r'(?<!\n)\s+(?=\d+:)', '\n', descs_raw)
                descs = re.split(r'\n|, ', descs_raw)
                if bit_length != 0 and desc_list == []:
                        has_title = ':' not in descs[0] and len(descs) > 1
                        start_idx = 1 if has_title else 0

                        for i in range(0, int(2 ** bit_length)):
                                idx_val = start_idx + i
                                if idx_val < len(descs):
                                        desc_val = descs[idx_val].split(':')
                                        if len(desc_val) < 2:
                                                desc_list.append(desc)
                                        else:
                                                desc_list.append(desc + " = " + desc_val[1].strip())
                                else:
                                        desc_list.append(desc)

                if desc_list == []:
                        desc_list.append(desc)

                strap['info'] = desc_list

                # strap['key_type']
                # strap['type']
                # strap['w_offset']
                # strap['bit_offset']
                # strap['bit_length']
                # strap['info']

                if is_strap:
                        strap_list.append(strap)
                elif is_strapext:
                        strap_ext_list.append(strap)

        for x in strap_list:
                list.append(x)
        for x in strap_ext_list:
                list.append(x)

def otpstrap_handler(sheet, data):
        sh = sheet

        strap_region = OrderedDict()
        strap_ext_region = OrderedDict()
        for rownum in range(0, sh.nrows):
                if rownum < 1:
                        continue

                row_values = sh.row_values(rownum)
                # print(row_values)

                is_strapext = False
                is_strap = False

                # OTPSTRAP & OTPSTRAP_EXT only
                if str(row_values[8]).startswith("OTPSTRAP_EXT"):
                        is_strapext = True
                elif str(row_values[8]).startswith("OTPSTRAP"):
                        is_strap = True
                else:
                        continue

                # reserved skip
                if str(row_values[1]).lower() == "reserved":
                        continue

                strap_details = OrderedDict()
                if is_strap:
                        strap_region["// " + str(row_values[8])] = ""
                elif is_strapext:
                        strap_ext_region["// " + str(row_values[8])] = ""

                # if isinstance(row_values[0], int) and int(row_values[0]) == 1:
                if parse_int(row_values[3]) == 1:
                        strap_details["value"] = False
                else:
                        strap_details["value"] = "0x0"
                        if is_strap:
                                strap_region["// " + str(row_values[6])] = ""
                        elif is_strapext:
                                strap_ext_region["// " + str(row_values[6])] = ""

                if is_strap:
                        strap_details["protect"] = False
                        strap_region[str(row_values[1]).strip()] = strap_details
                elif is_strapext:
                        strap_details["valid"] = False
                        strap_ext_region[str(row_values[1]).strip()] = strap_details

        data["strap_region"] = strap_region
        data["strap_ext_region"] = strap_ext_region

def otpsec_handler(sheet, data):
        sh = sheet
        key_list = []
        sec_region = OrderedDict()
        for rownum in range(0, sh.nrows):
                if rownum < 22:
                        continue

                keys = OrderedDict()
                row_values = sh.row_values(rownum)
                #print(row_values)

                # reserved skip
                if row_values[0] == "reserved" or row_values[0] == "Reserved":
                        continue

                #keys = sec_region
                for i in range (len(OTP_KEY_NAME)):
                        if str(row_values[7]).startswith(OTP_KEY_NAME[i]):
                                print("Found key", row_values[7])
                                if i == 0:
                                        number = re.search(r'\d+', str(row_values[7])).group()
                                        key_file = OTP_KEY_FILE_NAME[i] + number + ".pem"
                                        keys["key_file"] = key_file
                                elif i == 1:
                                        number = re.search(r'\d+', str(row_values[7])).group()
                                        key_file = OTP_KEY_FILE_NAME[i] + number + ".pub"
                                        keys["key_file"] = key_file
                                else:
                                        keys["key_file"] = OTP_KEY_FILE_NAME[i]

                                keys["type"] = OTP_KEY_TYPE_NAME[i]
                                keys["w_offset"] = hex(parse_int(row_values[0]) - 4096)
                                nums = re.findall(r'\d+', str(row_values[1]))
                                keys["number_id"] = int(nums[0]) if nums else 0

                                if OTP_KEY_TYPE_NAME[i] == "cal_manu_pub_hash":
                                        keys["ecc_key_mask"] = "0x0"
                                        keys["lms_key_mask"] = "0x0"

                                key_list.append(keys)

        sec_region["keys"] = key_list
        data["secure_region"] = sec_region

def otpcal_handler_info(sheet, list):
        sh = sheet

        for rownum in range(0, sh.nrows):
                cal = OrderedDict()
                if rownum < 1:
                        continue

                row_values = sh.row_values(rownum)
                #print(row_values)

                otp_name = row_values[1]
                otp_size = row_values[3]
                otp_desc = row_values[6]

                name_str = str(otp_name).strip()
                # skip reserved, Sum, Actual
                if name_str.lower() == "reserved" or name_str in ["Sum", "Actual"]:
                        continue

                name = str(otp_name).replace(' ', '_')
                cal['key'] = name
                bit_length = parse_bit_size(otp_size)
                if bit_length == 0:
                        continue

                if bit_length > 1:
                        cal['type'] = "string"
                else:
                        cal['type'] = "boolean"

                offset = parse_int(row_values[0]) - 0x1c00
                cal['w_offset'] = offset
                cal['bit_offset'] = 0
                if bit_length > 1:
                        cal['bit_length'] = bit_length

                descs = str(otp_name).split('\n')
                desc = descs[0]

                desc_list = []
                matches_a = ["enable", "Enable"]
                matches_b = ["disable", "Disable"]
                for x in matches_a:
                        if x in desc:
                                desc_list.append(desc.replace(x, matches_b[matches_a.index(x)]))
                                desc_list.append(desc)
                for x in matches_b:
                        if x in desc:
                                desc_list.append(desc.replace(x, matches_a[matches_b.index(x)]))
                                desc_list.append(desc)

                if bit_length == 1 and desc_list == []:
                        has_title = ':' not in descs[0] and len(descs) > 1
                        start_idx = 1 if has_title else 0

                        for i in range(0, int(2 ** bit_length)):
                                idx_val = start_idx + i
                                if idx_val < len(descs):
                                        desc_val = descs[idx_val].split(':')
                                        if len(desc_val) > 1:
                                                desc_list.append(desc_val[1].strip())
                                        else:
                                                desc_list.append(desc)
                                else:
                                        desc_list.append(desc)

                if desc_list == []:
                        desc_list.append(desc)

                cal['info'] = desc_list

                list.append(cal)

def otpcal_handler(sheet, data):
        sh = sheet
        cal_region = OrderedDict()

        for rownum in range(0, sh.nrows):
                if rownum < 1:
                        continue

                row_values = sh.row_values(rownum)
                # print(row_values)

                otp_addr = parse_int(row_values[0]) - 0x1c00
                otp_name = row_values[1]
                otp_size = row_values[3]

                # reserved skip
                if str(otp_name).lower() == "reserved":
                        continue

                if str(otp_name).strip() == "Sum":
                        break

                name = str(otp_name).strip().replace(" ", "_")

                cal_region["// OTPCAL" + str(otp_addr)] = ""
                if int(otp_size) == 1:
                        cal_region[name] = False
                elif int(otp_size) > 1:
                        cal_region[name] = ""
                else:
                        break

        data["caliptra_region"] = cal_region

if __name__ == '__main__':
        parser = argparse.ArgumentParser()
        parser.add_argument('--input',
                            help='input file',
                            type=argparse.FileType('r'),
                            default='')

        parser.add_argument('--strap',
                            help='input strap file',
                            type=argparse.FileType('r'),
                            default='')

        args = parser.parse_args(sys.argv[1:])
        # print("args", args)

        if (len(sys.argv) == 1):
            parser.print_usage()
            sys.exit(1)

        # print(args.input)
        wb = xlrd.open_workbook(args.input.name)
        wb_strap = xlrd.open_workbook(args.strap.name)

        data = OrderedDict()
        data["name"] = "2700-a2_sample-full"
        data["version"] = AST_CHIP_VER.upper()

        # OTP ROM
        rom = dict()
        # rom["file_name"] = "FILE"
        # rom["w_offset"] = "0x0"
        data["rom_region"] = rom

        for sheetnum in range(0, wb.nsheets):
                sh = wb.sheet_by_index(sheetnum)
                # print("sheet %d name: %s" % (sheetnum, sh.name))

                # OTPRBP
                if sh.name == OTPRBP_SHEET_NAME:
                        otprbp_handler(sh, data)
                        continue

                # OTPCFG
                if sh.name == OTPCFG_SHEET_NAME:
                        otpcfg_handler(sh, data)
                        continue
                # OTPSEC
                elif sh.name == SECURE_SHEET_NAME:
                        otpsec_handler(sh, data)
                        continue
                # OTPCAL
                elif sh.name == CALIPTRA_SHEET_NAME:
                        otpcal_handler(sh, data)
                        continue
                else:
                        continue

        for sheetnum in range(0, wb_strap.nsheets):
                sh = wb_strap.sheet_by_index(sheetnum)
                # print("sheet %d name: %s" % (sheetnum, sh.name))

                # OTPSTRAP & OTPSTRAPEXT
                if sh.name == OTPSTRAP_SHEET_NAME or sh.name == OTPSTRAP_EXT_SHEET_NAME:
                        otpstrap_handler(sh, data)
                        continue

        filename = AST_CHIP_NAME + AST_CHIP_VER + "_tmp.json"
        with open(filename, "w", encoding="utf-8") as writeJsonfile:
                json.dump(data, writeJsonfile, indent=4, default=str)

        sampleJsonfile = open(filename, 'r')
        lines = sampleJsonfile.readlines()
        sampleJsonfile.close()

        if os.path.exists(filename):
                os.remove(filename)

        sampleJsonfile = open(AST_CHIP_NAME + AST_CHIP_VER + "_Sample.json", 'w')
        #sampleJsonfile.seek(0, 0)
        for line in lines:
                if "// " in line:
                        s = line.split("\"")
                        # print("s", s[1])
                        sampleJsonfile.write(s[0] + s[1] + "\n")
                else:
                        sampleJsonfile.write(line)

        sampleJsonfile.close()

        # For config info
        print("config info")
        conf_list = []
        for sheetnum in range(0, wb.nsheets):
                sh = wb.sheet_by_index(sheetnum)
                print("sheet %d name: %s" % (sheetnum, sh.name))

                # OTPCFG
                if sh.name == OTPCFG_SHEET_NAME:
                        otpcfg_handler_info(sh, conf_list)
                else:
                        continue

        with open(AST_CHIP_VER + "_config.json", "w", encoding="utf-8") as writeJsonfile:
                json.dump(conf_list, writeJsonfile, indent=4, default=str)

        # For strap info
        print("strap info")
        strap_list = []
        for sheetnum in range(0, wb_strap.nsheets):
                sh = wb_strap.sheet_by_index(sheetnum)
                print("sheet %d name: %s" % (sheetnum, sh.name))

                # OTPSTRAP & OTPSTRAP_EXT
                if sh.name == OTPSTRAP_SHEET_NAME or sh.name == OTPSTRAP_EXT_SHEET_NAME:
                        otpstrap_handler_info(sh, strap_list)
                        continue

        with open(AST_CHIP_VER + "_strap.json", "w", encoding="utf-8") as writeJsonfile:
                json.dump(strap_list, writeJsonfile, indent=4, default=str)

        # For caliptra info
        print("caliptra info")
        caliptra_list = []
        for sheetnum in range(0, wb.nsheets):
                sh = wb.sheet_by_index(sheetnum)
                print("sheet %d name: %s" % (sheetnum, sh.name))

                # OTPCFG
                if sh.name == CALIPTRA_SHEET_NAME:
                        otpcal_handler_info(sh, caliptra_list)
                else:
                        continue

        with open(AST_CHIP_VER + "_caliptra.json", "w", encoding="utf-8") as writeJsonfile:
                json.dump(caliptra_list, writeJsonfile, indent=4, default=str)

        # For rbp info
        print("rbp info")
        rbp_list = []
        for sheetnum in range(0, wb.nsheets):
                sh = wb.sheet_by_index(sheetnum)
                print("sheet %d name: %s" % (sheetnum, sh.name))

                # OTPCFG
                if sh.name == OTPRBP_SHEET_NAME:
                        otprbp_handler_info(sh, rbp_list)
                else:
                        continue

        with open(AST_CHIP_VER + "_rbp.json", "w", encoding="utf-8") as writeJsonfile:
                json.dump(rbp_list, writeJsonfile, indent=4, default=str)