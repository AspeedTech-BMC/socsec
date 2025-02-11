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

import sys
import xlrd
import re

def gen_line_info(w_offset, bit_offset, width, value, desc):
    line_str = "\t{ "

    if w_offset is None:
        line_str += str(bit_offset) + ", " + str(int(width)) + ", " + str(value) + ", \"" + desc + "\" },\n"
    else:
        line_str += str(w_offset) + ", " + str(bit_offset) + ", " + str(int(width)) + ", " + str(value) + ", \"" + desc + "\" },\n"

    return line_str

def strap_handler(worksheet, otp_type, output_file):

    # Iterate the rows and columns
    for i in range(worksheet.nrows):
        name = worksheet.cell_value(i, 1).strip()
        otpstrap_val = worksheet.cell_value(i, 7)

        if name == "" or name == "Reserved":
            continue

        if otp_type == "strap":
            if otpstrap_val.startswith("OTPSTRAP"):
                print(otpstrap_val)
            else:
                continue
        elif otp_type == "strap_ext":
            if otpstrap_val.startswith("OTPFLASHSTRAP"):
                print(otpstrap_val)
            else:
                continue
        else:
            print("Wrong usage")
            break

        otp_desc = worksheet.cell_value(i, 2)
        width = worksheet.cell_value(i, 0)

        bit_str = otpstrap_val[otpstrap_val.index('[') + 1:otpstrap_val.index(']')]

        bit_str = bit_str.split(':')
        if len(bit_str) == 1:
            bit_offset = bit_str[0]
        else:
            bit_offset = bit_str[1]

        if int(width) == 1:
            line_str = gen_line_info(None, bit_offset, width, 1, otp_desc)
            output_file.writelines(line_str)
            #print(otp_desc)

            if "Enable" in otp_desc:
                otp_desc = otp_desc.replace("Enable", "Disable")
            elif "Disable" in otp_desc:
                otp_desc = otp_desc.replace("Disable", "Enable")

            #print(otp_desc)
            line_str = gen_line_info(None, bit_offset, width, 0, otp_desc)
            output_file.writelines(line_str)
            continue

        for j in range(2 ** int(width)):
            line_str = gen_line_info(None, bit_offset, width, j, otp_desc)
            output_file.writelines(line_str)

def conf_handler(worksheet, output_file):

    # Iterate the rows and columns
    for i in range(worksheet.nrows):
        if i < 4:
            continue

        # print(worksheet.cell_value(i, 1))
        if worksheet.cell_value(i, 1) == "OTP001" or worksheet.cell_value(i, 1) == "OTP003":
            continue

        if worksheet.cell_value(i, 2) != "":
            conf_val = worksheet.cell_value(i, 2)

        if worksheet.cell_value(i, 5) == "reserved" or worksheet.cell_value(i, 5) == "Reserved":
            continue

        msb = int(worksheet.cell_value(i, 3))
        lsb = int(worksheet.cell_value(i, 4))
        # print(conf_val, msb, lsb)

        w_offset = int(re.findall(r'-?\d+', conf_val)[0])
        width = msb - lsb + 1
        bit_offset = lsb
        idx = worksheet.cell_value(i, 6).find('\n')
        if idx != -1:
            otp_desc = worksheet.cell_value(i, 6)[:idx]
        else:
            otp_desc = worksheet.cell_value(i, 6)

        if int(width) == 1:
            line_str = gen_line_info(w_offset, bit_offset, width, 1, otp_desc)
            output_file.writelines(line_str)

            if "Enable" in otp_desc:
                otp_desc = otp_desc.replace("Enable", "Disable")
            elif "enable" in otp_desc:
                otp_desc = otp_desc.replace("enable", "disable")
            elif "Disable" in otp_desc:
                otp_desc = otp_desc.replace("Disable", "Enable")
            elif "disable" in otp_desc:
                otp_desc = otp_desc.replace("disable", "enable")

            line_str = gen_line_info(w_offset, bit_offset, width, 0, otp_desc)
            output_file.writelines(line_str)
            continue
        else:
            line_str = gen_line_info(w_offset, bit_offset, width, "OTP_REG_VALUE", otp_desc + ": 0x%x")
            output_file.writelines(line_str)

        if worksheet.cell_value(i, 1) == "OTP031" or worksheet.cell_value(i + 1, 5) == "":
            return

def caliptra_handler(worksheet, output_file):

    # Iterate the rows and columns
    for i in range(worksheet.nrows):
        if i < 1:
            continue

        if worksheet.cell_value(i, 2) == "reserved" or worksheet.cell_value(i, 2) == "Reserved":
            continue

        if worksheet.cell_value(i, 2) == "Sum":
            break

        print(worksheet.cell_value(i, 0))
        if worksheet.cell_value(i, 0) != "":
            cal_val = worksheet.cell_value(i, 0)
        width = int(worksheet.cell_value(i, 3))

        # w_offset = int(re.findall(r'-?\d+', cal_val)[0])
        w_offset = int(cal_val)
        bit_offset = 0
        otp_desc = worksheet.cell_value(i, 2)

        if int(width) == 1:
            line_str = gen_line_info(w_offset, bit_offset, width, 1, otp_desc)
            output_file.writelines(line_str)

            if "Enable" in otp_desc:
                otp_desc = otp_desc.replace("Enable", "Disable")
            elif "enable" in otp_desc:
                otp_desc = otp_desc.replace("enable", "disable")
            elif "Disable" in otp_desc:
                otp_desc = otp_desc.replace("Disable", "Enable")
            elif "disable" in otp_desc:
                otp_desc = otp_desc.replace("disable", "enable")

            line_str = gen_line_info(w_offset, bit_offset, width, 0, otp_desc)
            output_file.writelines(line_str)
            continue
        else:
            line_str = gen_line_info(w_offset, bit_offset, width, "OTP_REG_VALUE", otp_desc + ": 0x%x")
            output_file.writelines(line_str)

        if worksheet.cell_value(i, 0) == "OTPCAL78":
            return

if __name__ == '__main__':

    print("Generate OTPSTRAP/OTPSTRAP_EXT info...")
    print("Usage:\n\tpython3 otp_info_gen.py {workbook} {sheet} {output} {type: conf/strap/strap_ext/caliptra}")

    # Open the workbook
    workbook = xlrd.open_workbook(sys.argv[1])

    # Open the worksheet
    worksheet = workbook.sheet_by_name(sys.argv[2])

    output_file = open(sys.argv[3], "w")
    otp_type = sys.argv[4]

    if otp_type == "strap" or otp_type == "strap_ext":
        strap_handler(worksheet, otp_type, output_file)
    elif otp_type == "conf":
        conf_handler(worksheet, output_file)
    elif otp_type == "caliptra":
        caliptra_handler(worksheet, output_file)

    output_file.close()

    print("Done")
