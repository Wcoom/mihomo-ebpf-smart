// bpf_skfilter.c - dump/clear AOSP netd skfilter uid maps by map id
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/syscall.h>

static long bpf(int cmd, void *attr, int size){ return syscall(280, cmd, attr, size); }

static int get_fd(uint32_t id){
    unsigned char a[64]; memset(a,0,sizeof(a));
    *(uint32_t*)(a+0)=id;
    return (int)bpf(13,a,12);
}

// 尝试 key_size 4 或 8 遍历，返回找到的 key 数
static long walk(int fd, int key_size, uint32_t *keys, long maxk){
    uint8_t cur[16]={0}, nk[16]={0};
    long n=0, prev=0;
    for (;;){
        unsigned char a[64]; memset(a,0,sizeof(a));
        *(uint32_t*)(a+0)=(uint32_t)fd;
        *(uint64_t*)(a+8)=(uint64_t)(uintptr_t)(cur[0]?cur:NULL);
        *(uint64_t*)(a+16)=(uint64_t)(uintptr_t)nk;
        errno=0;
        long r=bpf(11,a,32); // GET_NEXT_KEY
        if (r!=0) break;
        memcpy(cur,nk,key_size);
        if (n<maxk){ memcpy(&keys[n],nk,key_size); n++; }
        if (n>1000000) break;
        if (n==prev){ break; } prev=n;
    }
    return n;
}

int main(int argc, char **argv){
    if (argc < 2){ fprintf(stderr,"usage: %s dump|clear id [...]\n", argv[0]); return 1; }
    int clear = strcmp(argv[1],"clear")==0;
    for (int i=2;i<argc;i++){
        uint32_t id=(uint32_t)strtoul(argv[i],NULL,0);
        int fd=get_fd(id);
        if (fd<0){ printf("id=%u OPEN FAIL errno=%d\n",id,errno); continue; }
        uint32_t keys[100000];
        long n=walk(fd,4,keys,100000);
        long n8=0;
        if (n==0){ n8=walk(fd,8,keys,100000); }
        if (clear){
            long del=0;
            for (long j=0;j<n;j++){
                unsigned char a[64]; memset(a,0,sizeof(a));
                *(uint32_t*)(a+0)=(uint32_t)fd;
                *(uint64_t*)(a+8)=(uint64_t)(uintptr_t)(&keys[j]);
                if (bpf(3,a,32)==0) del++; // DELETE_ELEM
            }
            if (n8){ uint8_t cur[16]={0},nk[16]={0}; long d2=0;
                for(;;){ unsigned char b[64]; memset(b,0,sizeof(b));
                    *(uint32_t*)(b+0)=(uint32_t)fd;
                    *(uint64_t*)(b+8)=(uint64_t)(uintptr_t)(cur[0]?cur:NULL);
                    *(uint64_t*)(b+16)=(uint64_t)(uintptr_t)nk;
                    if (bpf(11,b,32)!=0) break;
                    memcpy(cur,nk,8);
                    unsigned char c[64]; memset(c,0,sizeof(c));
                    *(uint32_t*)(c+0)=(uint32_t)fd;
                    *(uint64_t*)(c+8)=(uint64_t)(uintptr_t)nk;
                    if (bpf(3,c,32)==0) d2++;
                }
                printf("id=%u CLEARED %ld (ks4) + %ld (ks8)\n",id,del,d2);
            } else {
                printf("id=%u CLEARED %ld (ks=%d)\n",id,del,n?4:8);
            }
        } else {
            if (n==0 && n8==0) printf("id=%u EMPTY\n",id);
            else if (n) printf("id=%u %ld keys ks4: ",id,n);
            else printf("id=%u %ld keys ks8\n",id,n8);
            long show = n?n:n8;
            for (long j=0;j<show && j<50;j++){
                uint32_t k=(uint32_t)keys[j];
                unsigned char vb[64]; memset(vb,0,sizeof(vb));
                unsigned char a[64]; memset(a,0,sizeof(a));
                *(uint32_t*)(a+0)=(uint32_t)fd;
                *(uint64_t*)(a+8)=(uint64_t)(uintptr_t)(&keys[j]);
                *(uint64_t*)(a+16)=(uint64_t)(uintptr_t)vb;
                long rl=bpf(12,a,32);
                printf("  uid=%u val=%s\n", k, rl==0?(char*)vb:"?");
            }
            if (n==0) printf("\n");
        }
        close(fd);
    }
    return 0;
}
