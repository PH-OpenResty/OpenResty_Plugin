#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static int (*actual_fsync)(int);
static char fault_marker[4096],fault_journal[4096];
static char crash_marker[4096];
static void *(*actual_memcpy)(void *,const void *,size_t);

__attribute__((constructor)) static void initialize(void)
{
    actual_memcpy=(void *(*)(void *,const void *,size_t))dlsym(RTLD_NEXT,"memcpy");
    actual_fsync=(int (*)(int))dlsym(RTLD_NEXT,"fsync");
    if(actual_fsync==NULL)_exit(127);
    /* nginx intentionally filters the worker environment. Capture immutable
     * test paths before main rather than rely on getenv from worker threads. */
    {
        const char *value=getenv("SCDN_TEST_FSYNC_FAULT");
        if(value!=NULL && strlen(value)<sizeof(fault_marker))strcpy(fault_marker,value);
        value=getenv("SCDN_TEST_FSYNC_JOURNAL");
        if(value!=NULL && strlen(value)<sizeof(fault_journal))strcpy(fault_journal,value);
        value=getenv("SCDN_TEST_CRASH_MARKER");
        if(value!=NULL && strlen(value)<sizeof(crash_marker))strcpy(crash_marker,value);
    }
}

void *memcpy(void *destination,const void *source,size_t length)
{
    if(length==4096 && crash_marker[0]!=0
       && strncmp((const char *)source,"/kill-in-mutation/",18)==0
       && access(crash_marker,F_OK)==0)kill(getpid(),SIGKILL);
    if(actual_memcpy!=NULL)return actual_memcpy(destination,source,length);
    /* The dynamic linker may copy before constructors have initialized dlsym. */
    {
        volatile unsigned char *out=destination;
        const volatile unsigned char *in=source;
        size_t i;
        for(i=0;i<length;i++)out[i]=in[i];
    }
    return destination;
}

int fsync(int fd)
{
    char link[64],target[4096];
    ssize_t length;
    if(fault_marker[0]!=0 && fault_journal[0]!=0 && access(fault_marker,F_OK)==0) {
        snprintf(link,sizeof(link),"/proc/self/fd/%d",fd);
        length=readlink(link,target,sizeof(target)-1);
        if(length>=0) {
            target[length]=0;
            if(strcmp(target,fault_journal)==0) { errno=EIO;return -1; }
        }
    }
    return actual_fsync(fd);
}
