#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

static long bpf(int cmd, void *attr, int size){ return syscall(280, cmd, attr, size); }

int main(void){
    unsigned char a[256];
    for (uint32_t id = 1; id <= 50000; id++) {
        memset(a,0,sizeof(a));
        *(uint32_t*)(a+0)=id;
        long fd = bpf(13,a,12);
        if (fd < 0) continue;
        unsigned char info[256]; memset(info,0,sizeof(info));
        memset(a,0,sizeof(a));
        *(uint32_t*)(a+0)=(uint32_t)fd;
        *(uint32_t*)(a+4)=sizeof(info);
        *(uint64_t*)(a+8)=(uint64_t)(uintptr_t)info;
        if (bpf(15,a,16) == 0) {
            char name[17]; memcpy(name, info+64, 16); name[16]=0;
            uint32_t ksz=*(uint32_t*)(info+8), vsz=*(uint32_t*)(info+12);
            printf("id=%u %s k=%u v=%u\n", id, name, ksz, vsz);
        }
        close(fd);
    }
    return 0;
}
