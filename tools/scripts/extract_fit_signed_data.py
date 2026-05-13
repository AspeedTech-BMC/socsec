#!/usr/bin/env python3
import struct
import sys
import hashlib
import argparse

def get_string(dt_strings, offset):
    end = dt_strings.find(b'\0', offset)
    if end == -1: return ""
    return dt_strings[offset:end].decode('ascii')

def extract_properties(fdt_bytes, conf_node_name, sig_node_name="signature-1"):
    magic, totalsize, off_dt_struct, off_dt_strings, off_mem_rsvmap, version, last_comp_version, boot_cpuid_phys, size_dt_strings, size_dt_struct = struct.unpack(">10I", fdt_bytes[:40])
    dt_struct = fdt_bytes[off_dt_struct:off_dt_struct + size_dt_struct]
    dt_strings = fdt_bytes[off_dt_strings:off_dt_strings + size_dt_strings]
    
    offset = 0
    path = []
    
    target_path = f"/configurations/{conf_node_name}/{sig_node_name}"
    
    hashed_nodes = []
    hashed_strings_region = None
    hash_algo = "sha256" # default
    
    while offset < len(dt_struct):
        tag = struct.unpack(">I", dt_struct[offset:offset+4])[0]
        offset += 4
        
        if tag == 1: # FDT_BEGIN_NODE
            name_start = offset
            name_end = dt_struct.find(b'\0', offset)
            name = dt_struct[name_start:name_end].decode('ascii')
            offset = (name_end + 1 + 3) & ~3
            path.append(name)
            
        elif tag == 2: # FDT_END_NODE
            if path:
                path.pop()
                
        elif tag == 3: # FDT_PROP
            length, nameoff = struct.unpack(">II", dt_struct[offset:offset+8])
            offset += 8
            prop_name = get_string(dt_strings, nameoff)
            prop_data = dt_struct[offset:offset+length]
            offset = (offset + length + 3) & ~3
            
            current_path = "/" + "/".join(path[1:]) if len(path) > 1 else "/"
            if current_path == target_path:
                if prop_name == "hashed-nodes":
                    hashed_nodes = [n.decode('ascii') for n in prop_data.split(b'\0') if n]
                elif prop_name == "hashed-strings":
                    str_offset, str_len = struct.unpack(">II", prop_data)
                    hashed_strings_region = (off_dt_strings + str_offset, str_len)
                elif prop_name == "algo":
                    algo_str = prop_data.decode('ascii').strip('\0')
                    # Extract hashing algorithm part (e.g., from "sha384,ecdsa384")
                    hash_algo = algo_str.split(',')[0]
                    
        elif tag == 4: # FDT_NOP
            pass
        elif tag == 9: # FDT_END
            break
            
    return hashed_nodes, hashed_strings_region, hash_algo

def parse_fdt(fdt_bytes, inc_list, exc_prop_list):
    magic, totalsize, off_dt_struct, off_dt_strings, off_mem_rsvmap, version, last_comp_version, boot_cpuid_phys, size_dt_strings, size_dt_struct = struct.unpack(">10I", fdt_bytes[:40])
    dt_struct = fdt_bytes[off_dt_struct:off_dt_struct + size_dt_struct]
    dt_strings = fdt_bytes[off_dt_strings:off_dt_strings + size_dt_strings]
    
    regions = []
    offset = 0
    path = []
    want = 0
    stack = []
    start_region = -1
    base = off_dt_struct
    
    current_region_nodes = set()
    
    def add_region(start, end, nodes):
        if start != -1 and end > start:
            # If contiguous, merge
            if regions and regions[-1]['start'] + regions[-1]['size'] == start + base:
                regions[-1]['size'] += end - start
                regions[-1]['nodes'].update(nodes)
            else:
                regions.append({
                    'start': start + base,
                    'size': end - start,
                    'nodes': set(nodes)
                })

    while offset < len(dt_struct):
        tag_offset = offset
        tag = struct.unpack(">I", dt_struct[offset:offset+4])[0]
        offset += 4
        
        include = False
        stop_at = offset
        
        if tag == 1: # FDT_BEGIN_NODE
            name_start = offset
            name_end = dt_struct.find(b'\0', offset)
            name = dt_struct[name_start:name_end].decode('ascii')
            offset = (name_end + 1 + 3) & ~3
            
            path.append(name)
            current_path = "/" + "/".join(path[1:]) if len(path) > 1 else "/"
            
            stack.append(want)
            if want == 1:
                stop_at = tag_offset
                
            if current_path in inc_list:
                want = 2
            elif want > 0:
                want -= 1
            else:
                stop_at = tag_offset
                
            include = (want > 0)
            
        elif tag == 2: # FDT_END_NODE
            include = (want > 0)
            current_path = "/" + "/".join(path[1:]) if len(path) > 1 else "/"
            if stack:
                want = stack.pop()
            if path:
                path.pop()
                
        elif tag == 3: # FDT_PROP
            length, nameoff = struct.unpack(">II", dt_struct[offset:offset+8])
            offset += 8
            
            prop_name = get_string(dt_strings, nameoff)
            offset = (offset + length + 3) & ~3
            
            include = (want >= 2)
            stop_at = tag_offset
            current_path = "/" + "/".join(path[1:]) if len(path) > 1 else "/"
            
            # Explicitly exclude certain properties (like "data")
            if prop_name in exc_prop_list:
                include = False
                
        elif tag == 4: # FDT_NOP
            include = (want >= 2)
            stop_at = tag_offset
            current_path = "/" + "/".join(path[1:]) if len(path) > 1 else "/"
            
        elif tag == 9: # FDT_END
            include = True
            current_path = "<FDT_END>"
            
        if include:
            current_region_nodes.add(current_path)
            
        if include and start_region == -1:
            start_region = tag_offset
            
        if not include and start_region != -1:
            add_region(start_region, stop_at, current_region_nodes)
            start_region = -1
            current_region_nodes.clear()
            
        if tag == 9:
            break
            
    if start_region != -1:
        add_region(start_region, offset, current_region_nodes)
        
    return regions

def main():
    parser = argparse.ArgumentParser(description="Extract signed data from FIT image offline")
    parser.add_argument("fit_image", help="Path to FIT image")
    parser.add_argument("config_name", help="Configuration node name (e.g. conf-ast2700-evb.dtb)")
    parser.add_argument("-o", "--output", help="Output file for extracted binary data", default="signed_data.bin")
    args = parser.parse_args()

    with open(args.fit_image, "rb") as f:
        data = f.read()

    print(f"[*] Parsing FIT Image: {args.fit_image}")
    print(f"[*] Target Configuration: {args.config_name}")

    hashed_nodes, hashed_strings_region, algo = extract_properties(data, args.config_name)
    if not hashed_nodes:
        print(f"[-] Error: Could not find hashed-nodes in /configurations/{args.config_name}/signature-1")
        sys.exit(1)

    print(f"[*] Hash Algorithm: {algo}")
    print(f"[*] Hashed Nodes: {hashed_nodes}")
    if hashed_strings_region:
        print(f"[*] Hashed Strings Offset: 0x{hashed_strings_region[0]:08x}, Size: 0x{hashed_strings_region[1]:04x}")

    # Exclude the "data" property per u-boot signature rules
    regions = parse_fdt(data, hashed_nodes, ["data"])

    if hashed_strings_region:
        regions.append({
            'start': hashed_strings_region[0],
            'size': hashed_strings_region[1],
            'nodes': {"<String Table>"}
        })

    signed_data = bytearray()
    print("\n[+] Extracted Regions:")
    for i, r in enumerate(regions):
        print(f"    Region {i+1}: Offset 0x{r['start']:08x}, Size 0x{r['size']:04x}")
        signed_data.extend(data[r['start']:r['start']+r['size']])

    print(f"\n[+] Total signed data size: {len(signed_data)} bytes")
    
    with open(args.output, "wb") as f:
        f.write(signed_data)
    print(f"[+] Saved extracted byte stream to '{args.output}'")

    if hasattr(hashlib, algo):
        h = hashlib.new(algo)
        h.update(signed_data)
        print(f"[+] Calculated {algo.upper()} digest: {h.hexdigest()}")
    else:
        print(f"[-] Warning: Python hashlib does not support {algo}")

if __name__ == "__main__":
    main()
