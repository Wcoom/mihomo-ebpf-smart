import struct, sys, binascii

def parse(path):
    f = open(path, 'rb')
    magic = f.read(4)
    endian = '<' if magic == b'\xd4\xc3\xb2\xa1' else '>'
    f.read(8)
    sigfigs, snaplen, network = struct.unpack(endian + 'III', f.read(12))
    pkts = []
    while True:
        hdr = f.read(16)
        if len(hdr) < 16: break
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + 'IIII', hdr)
        data = f.read(incl_len)
        if network == 1:
            if len(data) < 34: continue
            ip = data[14:]
        elif network == 276:  # SLL2
            if len(data) < 40: continue
            proto = struct.unpack('>H', data[0:2])[0]
            if proto != 0x0800: continue
            ip = data[20:]
        else:
            continue
        if (ip[0] >> 4) != 4: continue
        ihl = (ip[0] & 0x0f) * 4
        if ip[9] != 6: continue
        tcp = ip[ihl:]
        sp, dp = struct.unpack('>HH', tcp[0:4])
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        if payload:
            pkts.append((sp, dp, payload))
    return pkts

def clienthellos(pkts):
    streams = {}
    for sp, dp, p in pkts:
        key = (min(sp, dp), max(sp, dp))
        streams.setdefault(key, [[], []])
        streams[key][0 if sp == key[0] else 1].append(p)
    out = []
    for key, (c2s_list, s2c_list) in streams.items():
        c2s = b''.join(c2s_list)
        i = 0
        while i < len(c2s) - 5:
            i = c2s.find(b'\x16\x03', i)
            if i < 0: break
            if len(c2s) > i + 9 and c2s[i+5] == 0x01:
                out.append((key, c2s[i:]))
                break
            i += 1
    return out

for path in sys.argv[1:]:
    print('=' * 60)
    print(path)
    pkts = parse(path)
    chs = clienthellos(pkts)
    print(f'{len(pkts)} tcp payload pkts, {len(chs)} ClientHello(s)')
    for key, data in chs:
        print(f'--- stream {key}, len={len(data)}, first 140 bytes hex:')
        print(binascii.hexlify(data[:140]).decode())
