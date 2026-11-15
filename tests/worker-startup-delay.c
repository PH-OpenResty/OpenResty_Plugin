/* Test-only interposer: hold the second child before Nginx initializes it.
 * Compiled into a temporary directory, never linked into production modules. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static char gate[4096];
static unsigned int forks;

__attribute__((constructor)) static void capture_gate(void)
{
    const char *value=getenv("SCDN_TEST_WORKER_GATE");
    size_t length;
    if(value==NULL)return;
    length=strlen(value);
    if(length<sizeof(gate))memcpy(gate,value,length+1);
}

pid_t fork(void)
{
    static pid_t (*next_fork)(void);
    unsigned int ordinal;
    pid_t result;
    char waiting[sizeof(gate)+sizeof(".waiting")];
    size_t length;
    int descriptor;
    unsigned int attempt;
    if(next_fork==NULL)next_fork=(pid_t (*)(void))dlsym(RTLD_NEXT,"fork");
    if(next_fork==NULL) { errno=ENOSYS;return -1; }
    ordinal=++forks;
    result=next_fork();
    if(result!=0 || ordinal!=2 || gate[0]==0)return result;
    length=strlen(gate);
    memcpy(waiting,gate,length);memcpy(waiting+length,".waiting",sizeof(".waiting"));
    descriptor=open(waiting,O_WRONLY|O_CREAT|O_TRUNC,0600);
    if(descriptor<0)_exit(121);
    close(descriptor);
    for(attempt=0;attempt<20000;attempt++) {
        if(access(gate,F_OK)==0)return 0;
        usleep(1000);
    }
    _exit(122);
}
