#!/usr/bin/env python3
"""Dump or clear oplus-netd bpf maps via bpf syscall (corrected attr layout:
pathname is a __aligned_u64 POINTER, not inline array)."""
import ctypes, struct, sys, os

SYS = 280  # arm64
BPF_MAP_GET_NEXT_KEY, BPF_MAP_LOOKUP_ELEM, BPF_MAP_DELETE_ELEM, BPF_OBJ_GET = 11, 12, 3, 20
libc = ctypes.CDLL(None, use_errno=True)

def sys_bpf(cmd, attr_bytes, size):
    buf = ctypes.create_string_buffer(size)
    if attr_bytes:
        ctypes.memmove(buf, attr_bytes, min(len(attr_bytes), size))
    r = libc.syscall(SYS, cmd, ctypes.byref(buf), size)
    return r, buf

def obj_get(path):
    pb = ctypes.create_string_buffer(path.encode() + b'\x00')
    attr = struct.pack('<QII', ctypes.addressof(pb), 0, 0)
    r, buf = sys_bpf(BPF_OBJ_GET, attr, 16)
    if r != 0:
        return None, ctypes.get_errno()
    fd = struct.unpack_from('<I', buf.raw, 8)[0]
    return fd, 0

def iter_keys(fd, key_size, limit=200000):
    keys = []
    next_buf = ctypes.create_string_buffer(64)
    cur = None
    while True:
        kbuf = ctypes.create_string_buffer(64)
        if cur is not None:
            ctypes.memmove(kbuf, cur, key_size)
        attr = struct.pack('<I4xQQQ', fd, ctypes.addressof(kbuf) if cur is not None else 0,
                           ctypes.addressof(next_buf), 0)
        r, _ = sys_bpf(BPF_MAP_GET_NEXT_KEY, attr, 32)
        if r != 0:
            break
        key = bytes(next_buf.raw[:key_size])
        keys.append(key)
        cur = key
        if len(keys) >= limit:
            break
    return keys

def lookup(fd, key):
    kb = ctypes.create_string_buffer(key)
    vb = ctypes.create_string_buffer(256)
    attr = struct.pack('<I4xQQQ', fd, ctypes.addressof(kb), ctypes.addressof(vb), 0)
    r, buf = sys_bpf(BPF_MAP_LOOKUP_ELEM, attr, 32)
    if r != 0:
        return None
    return bytes(vb.raw)

def delete(fd, key):
    kb = ctypes.create_string_buffer(key)
    attr = struct.pack('<I4xQQQ', fd, ctypes.addressof(kb), 0, 0)
    r, _ = sys_bpf(BPF_MAP_DELETE_ELEM, attr, 32)
    return r == 0

if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'dump'
    maps = sys.argv[2:] if len(sys.argv) > 2 else [
        'map_oplus-netd_app_drop_wlan_socket_uid_limit_map',
        'map_oplus-netd_app_drop_cell_socket_uid_limit_map',
        'map_oplus-netd_app_freeze_config_map',
        'map_oplus-netd_app_hans_limit_map',
        'map_oplus-netd_app_mtk_socket_uid_limit_map',
        'map_oplus-netd_app_qcom_socket_uid_limit_map',
        'map_oplus-netd_app_net_disconn_limit_map',
        'map_oplus-netd_app_tcp_fin_drop_map',
        'map_oplus-netd_app_accept_cell_socket_uid_limit_map',
        'map_oplus-netd_app_accept_network_socket_uid_limit_map',
        'map_oplus-netd_app_accept_wlan_socket_uid_limit_map',
        'map_oplus-netd_app_allow_socket_uid_limit_map',
    ]
    base = '/sys/fs/bpf/'
    for m in maps:
        path = m if m.startswith('/') else base + m
        fd, err = obj_get(path)
        if fd is None:
            print(f'{m}: OPEN FAIL errno={err}')
            continue
        done = 0
        for ks in (4, 8):
            try:
                keys = iter_keys(fd, ks)
            except Exception as e:
                print(f'{m}: iter err {e}')
                keys = []
            if keys:
                break
        if mode == 'clear':
            n = 0
            for k in keys:
                if delete(fd, k):
                    n += 1
            print(f'{m}: CLEARED {n}/{len(keys)} entries')
        else:
            vals = [lookup(fd, k) for k in keys[:30]]
            fmt = [f'{int.from_bytes(k,"little")}:{v.hex() if v else None}' for k, v in zip(keys[:30], vals)]
            print(f'{m}: {len(keys)} entries -> {fmt}')
        os.close(fd)
