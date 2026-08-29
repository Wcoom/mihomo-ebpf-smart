#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

static long bpf(int cmd, void *attr, int size){ return syscall(280, cmd, attr, size); }

int main(void){
    unsigned char a[256];
    // id=2 的 map
    memset(a,0,sizeof(a));
    *(uint32_t*)(a+0)=2;
    long fd = bpf(13,a,12);
    printf("GET_FD_BY_ID(2) fd=%ld errno=%d\n", fd, errno);
    if (fd < 0) return 1;
    unsigned char info[128]; memset(info,0,sizeof(info));
    uint32_t info_len = 128;
    memset(a,0,sizeof(a));
    *(uint32_t*)(a+0)=(uint32_t)fd;
    *(uint32_t*)(a+4)=info_len;
    *(uint64_t*)(a+8)=(uint64_t)(uintptr_t)info;
    errno=0;
    long r = bpf(15,a,16);
    printf("GET_INFO r=%ld errno=%d info_len=%u\n", r, errno, *(uint32_t*)(a+4));
    for (int i=0;i<96;i+=16){
        printf("%02x: ", i);
        for (int j=0;j<16;j++) printf("%02x ", info[i+j]);
        printf("\n");
    }
    close(fd);
    return 0;
}
