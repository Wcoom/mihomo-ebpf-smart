// bpfmap_ctl.c - dump/clear oplus-netd bpf uid maps (static, runs on Android)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>

#define BPF_OBJ_GET 20
#define BPF_MAP_GET_NEXT_KEY 11
#define BPF_MAP_LOOKUP_ELEM 12
#define BPF_MAP_DELETE_ELEM 3

union bpf_attr {
    struct { uint32_t map_fd; uint64_t key; uint64_t value; uint64_t flags; } map_op;
    struct { uint64_t pathname; uint32_t bpf_fd; uint32_t file_flags; } obj_get;
};

static long bpf_sys(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(280, cmd, attr, size);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s dump|clear /sys/fs/bpf/map_name [...]\n", argv[0]);
        return 1;
    }
    int clear = strcmp(argv[1], "clear") == 0;
    for (int i = 2; i < argc; i++) {
        union bpf_attr a;
        memset(&a, 0, sizeof(a));
        a.obj_get.pathname = (uint64_t)(uintptr_t)argv[i];
        long fd = bpf_sys(BPF_OBJ_GET, &a, 16);
        if (fd < 0) { printf("%s: OPEN FAIL errno=%d\n", argv[i], errno); continue; }
        int ks = 4, got = 0;
        while (ks <= 8) {
            uint8_t cur[16] = {0}, nk[16] = {0};
            long cnt = 0, first_errno = 0;
            while (1) {
                union bpf_attr q; memset(&q, 0, sizeof(q));
                q.map_op.map_fd = (uint32_t)fd;
                q.map_op.key = (uint64_t)(uintptr_t)(cur[0] ? cur : NULL);
                q.map_op.value = (uint64_t)(uintptr_t)nk;
                long r = bpf_sys(BPF_MAP_GET_NEXT_KEY, &q, 32);
                if (r != 0) { first_errno = errno; break; }
                memcpy(cur, nk, ks);
                uint64_t key = 0; memcpy(&key, nk, ks);
                if (clear) {
                    union bpf_attr d; memset(&d, 0, sizeof(d));
                    d.map_op.map_fd = (uint32_t)fd;
                    d.map_op.key = (uint64_t)(uintptr_t)nk;
                    if (bpf_sys(BPF_MAP_DELETE_ELEM, &d, 32) == 0) cnt++;
                } else {
                    union bpf_attr l; memset(&l, 0, sizeof(l));
                    l.map_op.map_fd = (uint32_t)fd;
                    l.map_op.key = (uint64_t)(uintptr_t)nk;
                    uint8_t vb[64] = {0};
                    l.map_op.value = (uint64_t)(uintptr_t)vb;
                    long rl = bpf_sys(BPF_MAP_LOOKUP_ELEM, &l, 32);
                    if (got < 30) printf("  key=%llu val=%s\n",
                        (unsigned long long)key, rl == 0 ? (char*)vb : "(lookup fail)");
                    got++;
                }
            }
            if (clear) { printf("%s: CLEARED %ld (ks=%d)\n", argv[i], cnt, ks); break; }
            if (got > 0 || first_errno != 22) { printf("%s: %d entries (ks=%d)\n", argv[i], got, ks); break; }
            ks += 4; got = 0;
        }
        close((int)fd);
    }
    return 0;
}
