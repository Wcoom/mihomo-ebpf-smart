#!/usr/bin/env python3
"""Read/dump oplus-netd uid limit maps via bpf syscall. READ-ONLY dump mode."""
import ctypes, struct, sys, os

SYS = 280  # arm64 bpf
BPF_OBJ_GET, BPF_MAP_GET_NEXT_KEY, BPF_MAP_LOOKUP_ELEM, BPF_MAP_DELETE_ELEM = 20, 11, 12, 3

class bpf_attr(ctypes.Union):
    class _map_op(ctypes.Structure):
        _fields_ = [("map_fd", ctypes.c_uint32), ("key", ctypes.c_uint64),
                    ("value", ctypes.c_uint64), ("flags", ctypes.c_uint64)]
    class _obj_get(ctypes.Structure):
        _fields_ = [("pathname", ctypes.c_char * 256), ("bpf_fd", ctypes.c_uint32),
                    ("file_flags", ctypes.c_uint32)]
    _fields_ = [("map_op", _map_op), ("obj_get", _obj_get)]

libc = ctypes.CDLL(None, use_errno=True)

def obj_get(path):
    a = bpf_attr()
    a.obj_get.pathname = path.encode()
    r = libc.syscall(SYS, BPF_OBJ_GET, ctypes.byref(a), ctypes.sizeof(a))
    if r != 0:
        return None, ctypes.get_errno()
    return a.obj_get.bpf_fd, 0

def dump_map(fd, key_size, val_size, max_entries=4096):
    keys = []
    nk = ctypes.create_string_buffer(16)
    cur = None
    for _ in range(max_entries):
        kbuf = ctypes.create_string_buffer(16)
        if cur is not None:
            ctypes.memmove(kbuf, cur, key_size)
        a = bpf_attr()
        a.map_op.map_fd = fd
        a.map_op.key = ctypes.addressof(kbuf) if cur is not None else 0
        a.map_op.value = ctypes.addressof(nk)
        r = libc.syscall(SYS, BPF_MAP_GET_NEXT_KEY, ctypes.byref(a), ctypes.sizeof(a))
        if r != 0:
            break
        key = int.from_bytes(nk.raw[:key_size], 'little')
        vb = ctypes.create_string_buffer(16)
        a2 = bpf_attr()
        a2.map_op.map_fd = fd
        a2.map_op.key = ctypes.addressof(nk)
        a2.map_op.value = ctypes.addressof(vb)
        r2 = libc.syscall(SYS, BPF_MAP_LOOKUP_ELEM, ctypes.byref(a2), ctypes.sizeof(a2))
        val = int.from_bytes(vb.raw[:val_size], 'little') if r2 == 0 else None
        keys.append((key, val))
        cur = nk
    return keys

if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else 'dump'
    maps = sys.argv[2:] if len(sys.argv) > 2 else [
        'map_oplus-netd_app_drop_wlan_socket_uid_limit_map',
        'map_oplus-netd_app_drop_cell_socket_uid_limit_map',
        'map_oplus-netd_app_freeze_config_map',
        'map_oplus-netd_app_mtk_socket_uid_limit_map',
        'map_oplus-netd_app_qcom_socket_uid_limit_map',
        'map_oplus-netd_app_accept_wlan_socket_uid_limit_map',
        'map_oplus-netd_app_accept_cell_socket_uid_limit_map',
        'map_oplus-netd_app_allow_socket_uid_limit_map',
        'map_oplus-netd_app_net_disconn_limit_map',
    ]
    base = '/sys/fs/bpf/'
    for m in maps:
        path = m if m.startswith('/') else base + m
        fd, err = obj_get(path)
        if fd is None:
            print(f'{m}: OPEN FAIL errno={err}')
            continue
        entries = dump_map(fd, 4, 4)
        print(f'{m}: {len(entries)} entries -> {entries[:40]}')
        os.close(fd)
