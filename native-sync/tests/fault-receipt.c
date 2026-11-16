#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static __thread int fail_directory;
static int mode(int dir, const char *expected)
{
    char value[64] = {0};
    int fd = openat(dir, ".fault-mode", O_RDONLY|O_CLOEXEC);
    ssize_t n;
    if (fd < 0) return 0;
    n = read(fd, value, sizeof(value) - 1); close(fd);
    return n > 0 && !strcmp(value, expected);
}
static int temporary_mode(int fd, const char *expected)
{
    char proc[64], path[PATH_MAX], *name;
    ssize_t n;
    int dir, result;
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", fd);
    n = readlink(proc, path, sizeof(path) - 1);
    if (n <= 0) return 0;
    path[n] = 0; name = strrchr(path, '/');
    if (!name || strncmp(name + 1, ".applied.state.", 15)) return 0;
    *name = 0; dir = open(path, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (dir < 0) return 0;
    result = mode(dir, expected); close(dir); return result;
}
ssize_t write(int fd, const void *data, size_t size)
{
    ssize_t (*real_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
    if (temporary_mode(fd, "receipt-write")) { errno = EIO; return -1; }
    return real_write(fd, data, size);
}
int fsync(int fd)
{
    int (*real_fsync)(int) = dlsym(RTLD_NEXT, "fsync");
    struct stat st;
    if (temporary_mode(fd, "receipt-fsync")) { errno = EIO; return -1; }
    if (fail_directory && !fstat(fd, &st) && S_ISDIR(st.st_mode)) {
        fail_directory = 0; errno = EIO; return -1;
    }
    return real_fsync(fd);
}
int renameat(int fromdir, const char *from, int todir, const char *to)
{
    int (*real_renameat)(int, const char *, int, const char *) = dlsym(RTLD_NEXT, "renameat");
    int receipt = !strcmp(to, "applied.state") && !strncmp(from, ".applied.state.", 15);
    int result;
    if (receipt && mode(todir, "receipt-rename")) { errno = EIO; return -1; }
    result = real_renameat(fromdir, from, todir, to);
    if (!result && receipt && mode(todir, "receipt-directory-fsync")) fail_directory = 1;
    return result;
}
int unlinkat(int dir, const char *name, int flags)
{
    int (*real_unlinkat)(int, const char *, int) = dlsym(RTLD_NEXT, "unlinkat");
    int result;
    if (!strcmp(name, "apply.pending") && mode(dir, "crash-before-unlink")) {
        int fd = openat(dir, ".fault-fired", O_WRONLY|O_CREAT|O_CLOEXEC, 0600);
        if (fd >= 0) close(fd);
        real_unlinkat(dir, ".fault-mode", 0);
        raise(SIGSTOP); /* Test controller kills only its recorded fixture PIDs. */
    }
    if (!strcmp(name, "apply.pending") && mode(dir, "pending-unlink")) { errno = EIO; return -1; }
    result = real_unlinkat(dir, name, flags);
    if (!result && !strcmp(name, "apply.pending") && mode(dir, "pending-directory-fsync")) fail_directory = 1;
    return result;
}
