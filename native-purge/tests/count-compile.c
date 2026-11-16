#define _GNU_SOURCE
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

static int audit_fd = -1;
static pcre2_code *(*real_compile)(PCRE2_SPTR, PCRE2_SIZE, uint32_t, int *, PCRE2_SIZE *, pcre2_compile_context *);
__attribute__((constructor)) static void start(void) {
    const char *path = getenv("AUDIT_PCRE_TRACE");
    real_compile = dlsym(RTLD_NEXT, "pcre2_compile_8");
    if (path) audit_fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0600);
}
pcre2_code *pcre2_compile_8(PCRE2_SPTR pattern, PCRE2_SIZE length, uint32_t options,
                         int *error, PCRE2_SIZE *offset, pcre2_compile_context *context) {
    if (audit_fd >= 0) { pid_t pid = getpid(); (void) write(audit_fd, &pid, sizeof(pid)); }
    return real_compile(pattern, length, options, error, offset, context);
}
