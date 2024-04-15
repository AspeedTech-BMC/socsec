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

Input_file = './otp_memory_map_A1.xlsx'
OTPCFG_SHEET_NAME = 'OTPCFG'
OTPSTRAP_SHEET_NAME = 'OTPSTRAP-OTPFLASHSTRAP'
SECURE_SHEET_NAME = 'SECURE'
CALIPTRA_SHEET_NAME = 'CALIPTRA'
AST_CHIP_NAME = 'AST'
AST_CHIP_VER = '2700a1'

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
        "ECDSA OEM DSS Key",
        "LMS OEM DSS Key",
        "Manufacture Key Hash",
        "Owner Key Hash",
        "Vault Key",
        "Vault Key Seed"
]

OTP_KEY_FILE_NAME = [
        "test_oem_dss_public_key_ecdsa384.pem",
        "test_oem_dss_public_key_lms.pem",
        "test_manu_key_hash.bin",
        "test_owner_key_hash.bin",
        "test_vault_key.bin",
        "test_vault_key_seed.bin"
]

def otpcfg_handler_info(sheet, list):
        sh = sheet

        for rownum in range(0, sh.nrows):
                conf = OrderedDict()
                bit_length = 0

                if rownum < 4:
                        continue

                row_values = sh.row_values(rownum)
                #print(row_values)

                # OTPCFG1 & OTPCFG3 skip
                if row_values[0] == "401" or row_values[0] == "403":
                        continue
                otpcfg_addr = row_values[0]

                if row_values[2] != "":
                        otpcfg_num = row_values[2]
                # reserved skip
                if row_values[7] == "reserved":
                        continue
                if row_values[3] == "" and row_values[4] == "":
                        break

                if row_values[3] != row_values[4]:
                        multi_value = True
                        bit_length =  int(row_values[3]) - int(row_values[4]) + 1
                else:
                        multi_value = False

                idx = row_values[8].find('\n')
                if idx != -1:
                        desc = str(row_values[8])[:idx]
                else:
                        desc = str(row_values[8])

                name = row_values[7].replace(' ', '_')
                conf['key'] = name
                if multi_value:
                        conf['type'] = "string"
                else:
                        conf['type'] = "boolean"

                conf['w_offset'] = int(re.findall(r'-?\d+', otpcfg_num)[0])
                conf['bit_offset'] = int(row_values[4])
                if bit_length != 0:
                        conf['bit_length'] = bit_length
                        desc += " = {}"

                desc_list = []
                matches_a = ["enable", "Enable"]
                matches_b = ["disable", "Disable"]
                for x in matches_a:
                        if x in desc:
                                desc_list.append(desc.replace("enable", "disable"))
                                desc_list.append(desc.replace("Enable", "Disable"))
                for x in matches_b:
                        if x in desc:
                                desc_list.append(desc.replace("disable", "enable"))
                                desc_list.append(desc.replace("Disable", "Enable"))

                if desc_list == []:
                        desc_list.append(desc)

                conf['info'] = desc_list
                list.append(conf)
        return

def otpcfg_handler(sheet, data):
        sh = sheet

        conf_region = OrderedDict()
        for rownum in range(0, sh.nrows):
                if rownum < 4:
                        continue

                row_values = sh.row_values(rownum)
                #print(row_values)

                # OTPCFG1 & OTPCFG3 skip
                if row_values[0] == "401" or row_values[0] == "403":
                        continue
                otpcfg_addr = row_values[0]

                if row_values[2] != "":
                        otpcfg_num = row_values[2]
                # reserved skip
                if row_values[7] == "reserved":
                        continue
                if row_values[3] == "" and row_values[4] == "":
                        break

                if row_values[2] != "":
                        otpcfg_num = row_values[2]

                if row_values[3] != row_values[4]:
                        desc = "// " + otpcfg_num + "[" + str(int(row_values[3])) + ":" + str(int(row_values[4])) + "]"
                        multi_value = True
                else:
                        desc = "// " + otpcfg_num + "[" + str(int(row_values[4])) + "]"
                        multi_value = False

                conf_region[desc] = ""
                keys = row_values[7].replace(" ", "_")
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

                if rownum < 5:
                        continue

                row_values = sh.row_values(rownum)
                #print(row_values)

                is_strapext = False
                is_strap = False

                # OTPSTRAP & OTPFLASHSTRAP only
                if str(row_values[7]).startswith("OTPSTRAP"):
                        is_strap = True
                elif str(row_values[7]).startswith("OTPFLASHSTRAP"):
                        is_strapext = True
                else:
                        continue

                # reserved skip
                if row_values[1] == "reserved" or row_values[1] == "Reserved":
                        continue

                strap['key'] = row_values[1].strip()

                if is_strap:
                        strap['key_type'] = "strap"
                elif is_strapext:
                        strap['key_type'] = "strap_ext"

                if int(row_values[0]) == 1:
                        strap['type'] = "boolean"
                        strap_num = int(re.findall(r'-?\d+', row_values[7])[0])
                else:
                        strap['type'] = "string"
                        strap_num = int(re.findall(r'-?\d+', row_values[7])[1])

                strap['w_offset'] = strap_num // 16
                strap['bit_offset'] = strap_num % 16

                if int(row_values[0]) > 1:
                        strap['bit_length'] = int(row_values[0])

                idx = row_values[2].find('\n')
                if idx != -1:
                        desc = str(row_values[2])[:idx]
                else:
                        desc = str(row_values[2])

                desc_list = []
                matches_a = ["enable", "Enable"]
                matches_b = ["disable", "Disable"]
                for x in matches_a:
                        if x in desc:
                                desc_list.append(desc.replace("enable", "disable"))
                                desc_list.append(desc.replace("Enable", "Disable"))
                for x in matches_b:
                        if x in desc:
                                desc_list.append(desc.replace("disable", "enable"))
                                desc_list.append(desc.replace("Disable", "Enable"))

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
                if rownum < 5:
                        continue

                row_values = sh.row_values(rownum)
                #print(row_values)

                is_strapext = False
                is_strap = False

                # OTPSTRAP & OTPFLASHSTRAP only
                if str(row_values[7]).startswith("OTPSTRAP"):
                        is_strap = True
                elif str(row_values[7]).startswith("OTPFLASHSTRAP"):
                        is_strapext = True
                else:
                        continue

                # reserved skip
                if row_values[1] == "reserved" or row_values[1] == "Reserved":
                        continue

                strap_details = OrderedDict()
                if is_strap:
                        strap_region["// " + row_values[7]] = ""
                elif is_strapext:
                        strap_ext_region["// " + row_values[7]] = ""

                if int(row_values[0]) == 1:
                        strap_details["value"] = False
                else:
                        strap_details["value"] = "0x0"
                        if is_strap:
                                strap_region["// " + row_values[3]] = ""
                        elif is_strapext:
                                strap_ext_region["// " + row_values[3]] = ""

                if is_strap:
                        strap_details["protect"] = False
                        strap_region[row_values[1].strip()] = strap_details
                elif is_strapext:
                        strap_details["valid"] = False
                        strap_ext_region[row_values[1].strip()] = strap_details

        data["strap_region"] = strap_region
        data["strap_ext_region"] = strap_ext_region

def otpsec_handler(sheet, data):
        sh = sheet
        key_list = []
        sec_region = OrderedDict()
        for rownum in range(0, sh.nrows):
                if rownum < 55:
                        continue

                keys = OrderedDict()
                row_values = sh.row_values(rownum)
                #print(row_values)

                # reserved skip
                if row_values[0] == "reserved" or row_values[0] == "Reserved":
                        continue

                #keys = sec_region
                for i in range (len(OTP_KEY_NAME)):
                        if str(row_values[6]).startswith(OTP_KEY_NAME[i]):
                                print("Found key", row_values[6])
                                keys["type"] = OTP_KEY_TYPE_NAME[i]
                                keys["key_file"] = OTP_KEY_FILE_NAME[i]
                                keys["w_offset"] = hex(int(str(row_values[1])[:4], 16) - 4096)
                                keys["number_id"] = int(re.findall(r'\d+', str(row_values[6]))[0])

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

                # reserved skip
                if row_values[2] == "reserved" or row_values[2] == "Reserved":
                        continue

                if row_values[2] == "Sum":
                        break

                name = row_values[1].replace(' ', '_')
                cal['key'] = name
                bit_length = int(row_values[3])
                if bit_length > 1:
                        cal['type'] = "string"
                else:
                        cal['type'] = "boolean"

                offset = int(row_values[1], 16) - 0x1c00
                #print("offset", offset)
                cal['w_offset'] = offset
                cal['bit_offset'] = 0
                if int(row_values[3]) > 1:
                        cal['bit_length'] = int(row_values[3])

                idx = row_values[7].find('\n')
                if idx != -1:
                        desc = str(row_values[7])[:idx]
                else:
                        desc = str(row_values[7])

                desc_list = []
                matches_a = ["enable", "Enable"]
                matches_b = ["disable", "Disable"]
                for x in matches_a:
                        if x in desc:
                                desc_list.append(desc.replace("enable", "disable"))
                                desc_list.append(desc.replace("Enable", "Disable"))
                for x in matches_b:
                        if x in desc:
                                desc_list.append(desc.replace("disable", "enable"))
                                desc_list.append(desc.replace("Disable", "Enable"))

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

                # reserved skip
                if row_values[2] == "reserved" or row_values[2] == "Reserved":
                        continue

                if row_values[2] == "Sum":
                        break

                name = row_values[1].strip().replace(" ", "_")

                cal_region["// " + row_values[0]] = ""
                if int(row_values[3]) == 1:
                        cal_region[name] = False
                elif int(row_values[3]) > 1:
                        cal_region[name] = "0x0"
                else:
                        break

        data["caliptra_region"] = cal_region

if __name__ == '__main__':
        wb = xlrd.open_workbook(Input_file)

        data = OrderedDict()
        data["name"] = AST_CHIP_NAME
        data["version"] = AST_CHIP_VER.upper()

        # OTP ROM
        rom = dict()
        rom["file_name"] = "FILE"
        rom["w_offset"] = "0x0"
        data["rom_region"] = rom

        for sheetnum in range(0, wb.nsheets):
                sh = wb.sheet_by_index(sheetnum)
                print("sheet %d name: %s" % (sheetnum, sh.name))

                # OTPCFG
                if sh.name == OTPCFG_SHEET_NAME:
                        otpcfg_handler(sh, data)
                        continue
                # OTPSTRAP & OTPSTRAPEXT
                elif sh.name == OTPSTRAP_SHEET_NAME:
                        otpstrap_handler(sh, data)
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
        strap_list = []
        for sheetnum in range(0, wb.nsheets):
                sh = wb.sheet_by_index(sheetnum)
                print("sheet %d name: %s" % (sheetnum, sh.name))

                # OTPCFG
                if sh.name == OTPSTRAP_SHEET_NAME:
                        otpstrap_handler_info(sh, strap_list)
                else:
                        continue

        with open(AST_CHIP_VER + "_strap.json", "w", encoding="utf-8") as writeJsonfile:
                json.dump(strap_list, writeJsonfile, indent=4, default=str)

        # For caliptra info
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