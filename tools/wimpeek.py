import re, sys, struct
path = sys.argv[1]
b = open(path, 'rb').read()
print('size', len(b))
# WIM header check
print('magic', b[:8])
# XML resource pointer: offset 200(0xC8): u64 xml_off, u64 xml_size, u64 xml_flags? (header: after resource struct)
xml_off, xml_size = struct.unpack_from('<QQ', b, 200)
flags, = struct.unpack_from('<I', b, 216)
print('xml_off', xml_off, 'xml_size', xml_size, 'flags', hex(flags))
try:
    res = b[xml_off:xml_off+16]
    print('at off bytes', res.hex())
    # resource header: u64 size, u64 packed_size, u32 flags
    sz, pck, fl = struct.unpack_from('<QQI', b, xml_off)
    print('res hdr size', sz, 'packed', pck, 'flags', hex(fl))
    payload = b[xml_off+24: xml_off+24+min(pck, 200000)]
    if fl & 0x000000FF:  # compressed
        print('compressed; try LZX via wimlib absent -> fallback scan')
    txt = payload.decode('utf-16-le', errors='ignore')
    i = txt.find('<?xml')
    if i < 0:
        # try uncompressed from xml_off+0? scan file for utf16 <?xml
        t2 = b.decode('utf-16-le', errors='ignore')
        i2 = t2.find('<?xml')
        print('scan fallback xml at', i2)
        if i2 >= 0:
            seg = t2[i2:i2+6000]
            print(re.sub(r'[^\x20-\x7e\n]', ' ', seg)[:5000])
    else:
        seg = txt[i:i+6000]
        print(re.sub(r'[^\x20-\x7e\n]', ' ', seg)[:5000])
except Exception as e:
    print('ERR', e)
    t2 = b.decode('utf-16-le', errors='ignore')
    i2 = t2.find('<?xml')
    print('scan fallback xml at', i2)
    if i2 >= 0:
        seg = t2[i2:i2+6000]
        print(re.sub(r'[^\x20-\x7e\n]', ' ', seg)[:5000])
