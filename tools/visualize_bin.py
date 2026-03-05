#!/usr/bin/env python3
import sys
import argparse
import os

def hex_to_color(val):
    # Map byte value to an ANSI code
    if val == 0:
        return "\033[90m" # Dark gray for zeros
    elif val == 0xff:
        return "\033[37m" # White/Light gray for 0xFF
    else:
        # Generate a color based on the byte value
        # ANSI 256 color range: 16 to 231 are colors
        # Let's use a nice range
        color_index = 16 + (val % 216)
        return f"\033[38;5;{color_index}m"

def get_region_name(offset):
    # Map byte offset to OTP region exactly matching the layout:
    # ROM: 1984 bytes
    # RBP: 64 bytes
    # CFG: 64 bytes
    # STRAP: 32 bytes
    # STRAP_EXT: 32 bytes
    # USR: 6016 bytes
    # SEC: 6144 bytes
    # CAL: 1792 bytes
    # PUF: 256 bytes
    if offset < 1984:
        return "ROM"
    elif offset < 1984 + 64:
        return "RBP"
    elif offset < 1984 + 64 + 64:
        return "CFG"
    elif offset < 1984 + 64 + 64 + 32:
        return "STRAP"
    elif offset < 1984 + 64 + 64 + 32 + 32:
        return "STRAP_EXT"
    elif offset < 1984 + 64 + 64 + 32 + 32 + 6016:
        return "USR"
    elif offset < 1984 + 64 + 64 + 32 + 32 + 6016 + 6144:
        return "SEC"
    elif offset < 1984 + 64 + 64 + 32 + 32 + 6016 + 6144 + 1792:
        return "CAL"
    elif offset < 1984 + 64 + 64 + 32 + 32 + 6016 + 6144 + 1792 + 256:
        return "PUF"

    return "UNKNOWN"

def print_memory_map(filepath, width=16, use_color=False):
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.")
        return

    with open(filepath, 'rb') as f:
        data = f.read()

    size = len(data)
    print(f"Visualizing memory layout of: {filepath} ({size} bytes / {size//2} words)")
    if use_color:
        print("Legend: [\033[90m·\033[0m] 0x00 (Empty)   [\033[37m▒\033[0m] 0xFF (Erased)   [█] Data values")
    else:
        print("Displaying: Raw Hex Data (use -c for colored block view)")

    # Header
    print(f"{'Byte':<8} {'Word':<8} {'Region':<10} | {'Data'}")
    print("-" * (33 + width + width//8))

    last_chunk = None
    first_skip = True

    for offset in range(0, size, width):
        chunk = data[offset:offset+width]

        is_empty = all(b == 0x00 for b in chunk)
        is_erased = all(b == 0xFF for b in chunk)

        region_name = get_region_name(offset)
        word_offset = offset // 2

        if (is_empty or is_erased) and chunk == last_chunk:
            if first_skip:
                print(f"0x{offset:04X}   0x{word_offset:04X}   {region_name:<10} | \033[90m...\033[0m")
                first_skip = False
            continue

        first_skip = True
        last_chunk = chunk

        line_str = f"0x{offset:04X}   0x{word_offset:04X}   {region_name:<10} | "
        for i, byte in enumerate(chunk):
            if i > 0 and i % 8 == 0:
                line_str += " "

            if use_color:
                if byte == 0x00:
                    char = "·"
                    color = hex_to_color(byte)
                elif byte == 0xFF:
                    char = "▒"
                    color = hex_to_color(byte)
                else:
                    char = "█"
                    color = hex_to_color(byte)
                line_str += f"{color}{char}\033[0m"
            else:
                line_str += f"{byte:02X} "

        print(line_str.rstrip())

    print("-" * (10 + width + width//8))

def compare_memory_maps(file1, file2, width=16):
    if not os.path.exists(file1):
        print(f"Error: File '{file1}' not found.")
        return
    if not os.path.exists(file2):
        print(f"Error: File '{file2}' not found.")
        return

    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        data1 = f1.read()
        data2 = f2.read()

    size1 = len(data1)
    size2 = len(data2)
    max_size = max(size1, size2)

    print(f"Comparing memory layout:\n  [1] {file1} ({size1} bytes)\n  [2] {file2} ({size2} bytes)")
    print("Displaying: \033[91mDifferences\033[0m only")

    # Header
    print(f"{'Byte':<8} {'Word':<8} {'Region':<10} | {'Data Differing (File1 -> File2)'}")
    print("-" * 60)

    diff_found = False
    for offset in range(0, max_size, width):
        chunk1 = data1[offset:offset+width] if offset < size1 else b''
        chunk2 = data2[offset:offset+width] if offset < size2 else b''

        # Pad chunks with 00 if one file is shorter than the other
        if len(chunk1) < width: chunk1 += bytes([0x00] * (width - len(chunk1)))
        if len(chunk2) < width: chunk2 += bytes([0x00] * (width - len(chunk2)))

        if chunk1 == chunk2:
            continue

        diff_found = True
        region_name = get_region_name(offset)
        word_offset = offset // 2

        line_str1 = f"0x{offset:04X}   0x{word_offset:04X}   {region_name:<10} | [1] "
        line_str2 = f"{' ':6}   {' ':6}   {' ':10} | [2] "

        for i in range(width):
            b1 = chunk1[i]
            b2 = chunk2[i]

            # Add spaces between bytes
            if i > 0 and i % 8 == 0:
                line_str1 += " "
                line_str2 += " "

            if b1 != b2:
                line_str1 += f"\033[91m{b1:02X}\033[0m " # Red for difference
                line_str2 += f"\033[91m{b2:02X}\033[0m "
            else:
                line_str1 += f"\033[90m{b1:02X}\033[0m " # Gray for same
                line_str2 += f"\033[90m{b2:02X}\033[0m "

        print(line_str1.rstrip())
        print(line_str2.rstrip())
        print()

    if not diff_found:
        print("\033[92mNo differences found between the two memory maps.\033[0m")

def main():
    parser = argparse.ArgumentParser(description="Visualize binary file memory layout.")
    parser.add_argument("file", help="Path to the binary file")
    parser.add_argument("-w", "--width", type=int, default=16, help="Bytes per line (default: 16)")
    parser.add_argument("-c", "--color", action="store_true", help="Use colored block visualization instead of hex data")
    parser.add_argument("-d", "--diff", metavar="FILE2", help="Compare the input file with this second binary file")
    args = parser.parse_args()

    if args.diff:
        # User typed: python visualize_bin.py -d dummy.bin otp-all.bin
        # So args.diff is 'dummy.bin', args.file is 'otp-all.bin'
        compare_memory_maps(args.diff, args.file, args.width)
    else:
        print_memory_map(args.file, args.width, args.color)

if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        # Python flushes standard streams on exit; redirect remaining output to devnull
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(1)
