#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

static long bpf(int cmd, void *attr, int size){ return syscall(280, cmd, attr, size); }

int main(int argc, char **argv){
    unsigned char a[256];
    uint32_t first=0, total=0, last_err=0, maxid=0;
    for (uint32_t id = 1; id <= 50000; id++) {
        memset(a,0,sizeof(a));
        *(uint32_t*)(a+0)=id;
        errno=0;
        long fd = bpf(13,a,12); // GET_FD_BY_ID
        if (fd < 0) { last_err=errno; continue; }
        if (!first) first=id;
        total++;
        maxid=id;
        unsigned char info[256]; memset(info,0,sizeof(info));
        memset(a,0,sizeof(a));
        *(uint32_t*)(a+0)=(uint32_t)fd;
        *(uint32_t*)(a+4)=sizeof(info);
        *(uint64_t*)(a+8)=(uint64_t)(uintptr_t)info;
        long r = bpf(15,a,16);
        if (r == 0) {
            char name[17]; memcpy(name, info+24, 16); name[16]=0;
            if (strstr(name,"oplus-netd")) {
                uint32_t ksz=*(uint32_t*)(info+8), vsz=*(uint32_t*)(info+12), maxe=*(uint32_t*)(info+16);
                printf("MATCH id=%u name=%s key=%u val=%u max=%u\n", id, name, ksz, vsz, maxe);
            }
        }
        close(fd);
        if (id > 30000 && total > 200) break;
    }
    printf("first=%u total=%u last_errno=%u maxid=%u\n", first, total, last_err, maxid);
    return 0;
}
