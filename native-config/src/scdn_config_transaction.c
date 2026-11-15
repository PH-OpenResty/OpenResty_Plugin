#include "scdn_config.h"
#include <sys/file.h>

/* An unfinished Sync transaction must restore its verified previous file
 * before nginx parses bootstrap configuration or forks any worker. */
int scdn_config_recover(const char *directory)
{
    int dir = -1, pending = -1, backup = -1, output = -1, lock = -1, ok = 0;
    struct stat st;
    u_char marker[40], digest[32], *bytes = NULL;
    unsigned digest_length;
    ssize_t n;
    size_t length, used = 0;
    char path[4096], part[256];
    const char *p = directory, *start;
    int next;
    if (!p || *p++ != '/') return 0;
    dir = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    while (dir >= 0 && *p) {
        start = p; while (*p && *p != '/') p++;
        length = (size_t) (p - start);
        if (!length || length >= sizeof(part) || (length == 1 && *start == '.')
            || (length == 2 && !memcmp(start, "..", 2))) goto finish;
        memcpy(part, start, length); part[length] = 0;
        next = openat(dir, part, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        close(dir); dir = next; if (*p) p++;
    }
    if (dir < 0 || fstat(dir, &st) || (st.st_mode & 077)) goto finish;
    pending = openat(dir, "apply.pending", O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    if (pending < 0) { ok = errno == ENOENT; goto finish; }
    lock = openat(dir, "apply.lock", O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600);
    if (lock < 0 || flock(lock, LOCK_EX|LOCK_NB)) goto finish;
    if (fstat(pending, &st) || !S_ISREG(st.st_mode) || st.st_size != 40 || (st.st_mode & 077)
        || read(pending, marker, 40) != 40 || memcmp(marker, "SCNDP01", 8)) goto finish;
    backup = openat(dir, "previous.conf", O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    if (backup < 0 || fstat(backup, &st) || !S_ISREG(st.st_mode) || (st.st_mode & 077)
        || st.st_size <= 0 || st.st_size > SCDN_CONFIG_BYTES) goto finish;
    length = (size_t) st.st_size; bytes = malloc(length);
    if (!bytes) goto finish;
    while (used < length) {
        n = read(backup, bytes + used, length - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto finish;
        used += (size_t) n;
    }
    if (EVP_Digest(bytes, length, digest, &digest_length, EVP_sha256(), NULL) != 1
        || digest_length != 32 || memcmp(digest, marker + 8, 32)) goto finish;
    snprintf(path, sizeof(path), ".recover.%ld", (long) getpid());
    output = openat(dir, path, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
    if (output < 0) goto finish;
    used = 0;
    while (used < length) {
        n = write(output, bytes + used, length - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto finish;
        used += (size_t) n;
    }
    if (fsync(output) || renameat(dir, path, dir, "active.conf") || fsync(dir)
        || unlinkat(dir, "apply.pending", 0) || fsync(dir)) goto finish;
    ok = 1;
finish:
    if (output >= 0) { close(output); unlinkat(dir, path, 0); }
    if (backup >= 0) close(backup);
    if (pending >= 0) close(pending);
    if (dir >= 0) close(dir);
    if (lock >= 0) close(lock);
    free(bytes); return ok;
}
