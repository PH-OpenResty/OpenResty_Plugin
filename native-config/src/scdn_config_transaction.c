#include "scdn_config.h"
#include <sys/file.h>

/* Pending recovery restores BOTH source and application receipt. Removing the
 * marker commits the new durable pair; its presence always selects the old pair. */
static int transaction_hash(const void *bytes, size_t size, u_char digest[32])
{
    unsigned length;
    return EVP_Digest(bytes, size, digest, &length, EVP_sha256(), NULL) == 1 && length == 32;
}
static u_char *transaction_read(int dir, const char *name, size_t limit, size_t *length)
{
    struct stat st;
    u_char *bytes = NULL;
    size_t used = 0;
    ssize_t n;
    int fd = openat(dir, name, O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    if (fd < 0) return NULL;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1 || (st.st_mode & 077)
        || st.st_size <= 0 || (uint64_t) st.st_size > limit) { errno = EINVAL; goto finish; }
    bytes = malloc((size_t) st.st_size);
    if (!bytes) goto finish;
    while (used < (size_t) st.st_size) {
        n = read(fd, bytes + used, (size_t) st.st_size - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { free(bytes); bytes = NULL; errno = EIO; goto finish; }
        used += (size_t) n;
    }
    *length = used;
finish:
    close(fd); return bytes;
}
static int transaction_write(int dir, const char *name, const u_char *bytes, size_t length)
{
    char temporary[128];
    struct timespec now;
    size_t used = 0;
    ssize_t n;
    int fd, ok = 0;
    struct stat owner;
    clock_gettime(CLOCK_MONOTONIC, &now);
    snprintf(temporary, sizeof(temporary), ".recover.%s.%ld.%ld", name, (long) getpid(), now.tv_nsec);
    fd = openat(dir, temporary, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    if (fstat(dir, &owner) || (geteuid() == 0 && fchown(fd, owner.st_uid, owner.st_gid))) goto finish;
    while (used < length) {
        n = write(fd, bytes + used, length - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto finish;
        used += (size_t) n;
    }
    if (!fsync(fd) && !renameat(dir, temporary, dir, name) && !fsync(dir)) ok = 1;
finish:
    close(fd); unlinkat(dir, temporary, 0); return ok;
}

/* Caller holds apply.lock. finalize=0 retains the marker until live Workers
 * adopt the restored source. Bootstrap recovery can finalize immediately. */
int scdn_config_recover_locked(int dir, int finalize)
{
    size_t marker_size = 0, backup_size = 0, receipt_size = 0;
    u_char *marker = NULL, *backup = NULL, *receipt = NULL, digest[32], zero[112] = {0};
    const u_char *old_receipt;
    int modern, ok = 0;
    marker = transaction_read(dir, "apply.pending", SCDN_CONFIG_PENDING_BYTES, &marker_size);
    if (!marker) return errno == ENOENT && fsync(dir) == 0;
    modern = marker_size == SCDN_CONFIG_PENDING_BYTES && !memcmp(marker, "SCNDP02", 8);
    if (!modern && (marker_size != 40 || memcmp(marker, "SCNDP01", 8))) goto finish;
    if (modern && (!transaction_hash(marker, marker_size - 32, digest)
        || memcmp(digest, marker + marker_size - 32, 32))) goto finish;
    backup = transaction_read(dir, "previous.conf", SCDN_CONFIG_BYTES, &backup_size);
    if (!backup || !transaction_hash(backup, backup_size, digest) || memcmp(digest, marker + 8, 32)) goto finish;
    if (modern) {
        old_receipt = marker + 40;
        if (memcmp(old_receipt, zero, sizeof(zero))
            && (memcmp(old_receipt, "SCNDST02", 8) || !transaction_hash(old_receipt, 80, digest)
                || memcmp(digest, old_receipt + 80, 32))) goto finish;
        /* Do not rewrite an already-correct receipt during an unrelated fault. */
        receipt = transaction_read(dir, "applied.state", sizeof(zero), &receipt_size);
        if (!memcmp(old_receipt, zero, sizeof(zero))) {
            if (unlinkat(dir, "applied.state", 0) && errno != ENOENT) goto finish;
            if (fsync(dir)) goto finish;
        } else if (!receipt || receipt_size != sizeof(zero) || memcmp(receipt, old_receipt, sizeof(zero))) {
            if (!transaction_write(dir, "applied.state", old_receipt, sizeof(zero))) goto finish;
        }
    }
    if (!transaction_write(dir, "active.conf", backup, backup_size)) goto finish;
    if (finalize && (unlinkat(dir, "apply.pending", 0) || fsync(dir))) goto finish;
    ok = 1;
finish:
    free(marker); free(backup); free(receipt); return ok;
}

int scdn_config_recover(const char *directory)
{
    int dir = -1, lock = -1, next, ok = 0;
    struct stat st, owner;
    size_t length;
    char part[256];
    const char *p = directory, *start;
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
    if (dir < 0 || fstat(dir, &owner) || (owner.st_mode & 077)) goto finish;
    lock = openat(dir, "apply.lock", O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0600);
    if (lock < 0 || fstat(lock, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1
        || (st.st_mode & 077) || (geteuid() == 0 && fchown(lock, owner.st_uid, owner.st_gid))
        || flock(lock, LOCK_EX|LOCK_NB)) goto finish;
    ok = scdn_config_recover_locked(dir, 1);
finish:
    if (dir >= 0) close(dir);
    if (lock >= 0) close(lock);
    return ok;
}
