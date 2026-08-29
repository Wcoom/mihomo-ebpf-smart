#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/syscall.h>

static long bpf(int cmd, void *attr, int size){ return syscall(280, cmd, attr, size); }

int main(){
    unsigned char a[256]; memset(a,0,sizeof(a));
    // BPF_MAP_CREATE=0: HASH key=4 val=4 max=16
    *(uint32_t*)(a+0)=1; *(uint32_t*)(a+4)=4; *(uint32_t*)(a+8)=4; *(uint32_t*)(a+12)=16;
    errno=0;
    long fd=bpf(0,a,128);
    printf("CREATE fd=%ld errno=%d(%s)\n",fd,errno,strerror(errno));
    if(fd<0) return 1;
    // BPF_OBJ_PIN=19
    memset(a,0,sizeof(a));
    *(uint64_t*)(a+0)=(uint64_t)(uintptr_t)"/sys/fs/bpf/zz_test_map";
    *(uint32_t*)(a+8)=(uint32_t)fd;
    errno=0;
    long r=bpf(19,a,16);
    printf("PIN r=%ld errno=%d(%s)\n",r,errno,strerror(errno));
    // BPF_OBJ_GET=20
    memset(a,0,sizeof(a));
    *(uint64_t*)(a+0)=(uint64_t)(uintptr_t)"/sys/fs/bpf/zz_test_map";
    errno=0;
    long fd2=bpf(20,a,16);
    printf("GET r=%ld errno=%d(%s)\n",fd2,errno,strerror(errno));
    if(fd2>=0) close(fd2);
    // 清理 pin 文件
    memset(a,0,sizeof(a));
    *(uint64_t*)(a+0)=(uint64_t)(uintptr_t)"/sys/fs/bpf/zz_test_map";
    bpf(18,a,16); // BPF_OBJ_UNLINK? no, BPF_OBJ_PIN=19, unlink via fs
    unlink("/sys/fs/bpf/zz_test_map");
    close(fd);
    return 0;
}
