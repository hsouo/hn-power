import sys
sys.path.insert(0, r"C:\Users\hs-desktop\.dsh\dsh-runtimes\dsh-primary-runtime\dependencies\python\Lib\site-packages")
import pefile, struct
p = sys.argv[1]
pe = pefile.PE(p); base = pe.OPTIONAL_HEADER.ImageBase
img = pe.get_memory_mapped_image()
# GUID via movdqa xmm0,[rip+0xf5f5] @0x18000e2e3 (len 8) -> next 0x18000e2eb; va = next+0xf5f5
va = 0x18000e2eb + 0xf5f5
b = img[va-base:va+16]
d1, d2, d3 = struct.unpack('<III', b[:12]); d4 = b[12:16]
print("GUID raw:", b.hex())
print("interface GUID: {:08X}-{:04X}-{:04X}-{}-{}".format(d1, d2, d3, d4[:2].hex().upper(), d4[2:].hex().upper()))
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
name_by_rva = {}
mod_by_rva = {}
for mod in pe.DIRECTORY_ENTRY_IMPORT:
    for e in mod.imports:
        if e.address:
            name_by_rva[e.address-base] = e.name.decode() if e.name else f'ord{e.ordinal}'
            mod_by_rva[e.address-base] = mod.dll.decode()
# call sites: (instr_va, instr_len, rip_disp)
sites = [
    ("ipc_exec?", 0x18000e353, 6, 0xccd7),
    ("pre_call",  0x18000e32b, 6, 0xcdcf),
    ("ifc_init",  0x18000e2b0, 6, 0xcd8a),
    ("reg_open",  0x18000dff2, 6, 0xd118),
]
for tag, cv, ln, disp in sites:
    tv = cv + ln + disp
    print(f"{tag}: IAT {hex(tv)} -> {mod_by_rva.get(tv-base,'?')}!{name_by_rva.get(tv-base,'?')}")
