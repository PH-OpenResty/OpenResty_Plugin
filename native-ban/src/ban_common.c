#define _GNU_SOURCE
#include "ban_common.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

_Static_assert(sizeof(ban_record) % 8 == 0, "atomic record words");
_Static_assert(__atomic_always_lock_free(8, 0),
               "64-bit atomic shared memory required");
uint64_t ban_now(void) {
  struct timespec t;
  if (clock_gettime(CLOCK_BOOTTIME, &t))
    return 0;
  return (uint64_t)t.tv_sec * 1000000000u + t.tv_nsec;
}
int ban_uuid(const char *s, uint8_t out[16]) {
  unsigned i, n = 0, a = 0;
  if (strlen(s) != 36)
    return 0;
  for (i = 0; i < 36; i++) {
    unsigned c = (unsigned char)s[i];
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (c != '-')
        return 0;
      continue;
    }
    c = c >= '0' && c <= '9'   ? c - '0'
        : c >= 'a' && c <= 'f' ? c - 'a' + 10
        : c >= 'A' && c <= 'F' ? c - 'A' + 10
                               : 255;
    if (c > 15)
      return 0;
    if (!(n & 1))
      a = c << 4;
    else
      out[n / 2] = (uint8_t)(a | c);
    n++;
  }
  return n == 32;
}
int ban_address_parse(const char *s, ban_address *out) {
  memset(out, 0, sizeof(*out));
  if (inet_pton(AF_INET, s, out->address + 12) == 1) {
    out->family = 4;
    return 1;
  }
  if (inet_pton(AF_INET6, s, out->address) == 1) {
    static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
    if (!memcmp(out->address, mapped, 12)) {
      memset(out->address, 0, 12);
      out->family = 4;
    } else
      out->family = 6;
    return 1;
  }
  return 0;
}
int ban_address_socket(int fd, ban_address *out) {
  struct sockaddr_storage a;
  socklen_t n = sizeof(a);
  char text[INET6_ADDRSTRLEN];
  if (getpeername(fd, (struct sockaddr *)&a, &n))
    return 0;
  if (a.ss_family == AF_INET)
    inet_ntop(AF_INET, &((struct sockaddr_in *)&a)->sin_addr, text,
              sizeof(text));
  else if (a.ss_family == AF_INET6)
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&a)->sin6_addr, text,
              sizeof(text));
  else
    return 0;
  return ban_address_parse(text, out);
}
/* SipHash-2-4: keyed indexing only; full keys are always compared. */
static uint64_t rotate(uint64_t n, unsigned b) {
  return (n << b) | (n >> (64 - b));
}
#define ROUND                                                                  \
  do {                                                                         \
    v0 += v1;                                                                  \
    v1 = rotate(v1, 13);                                                       \
    v1 ^= v0;                                                                  \
    v0 = rotate(v0, 32);                                                       \
    v2 += v3;                                                                  \
    v3 = rotate(v3, 16);                                                       \
    v3 ^= v2;                                                                  \
    v0 += v3;                                                                  \
    v3 = rotate(v3, 21);                                                       \
    v3 ^= v0;                                                                  \
    v2 += v1;                                                                  \
    v1 = rotate(v1, 17);                                                       \
    v1 ^= v2;                                                                  \
    v2 = rotate(v2, 32);                                                       \
  } while (0)
uint64_t ban_hash(const void *bytes, size_t n, const uint8_t seed[16]) {
  uint64_t k0, k1, m, b = (uint64_t)n << 56, v0, v1, v2, v3;
  size_t i;
  const uint8_t *p = bytes;
  memcpy(&k0, seed, 8);
  memcpy(&k1, seed + 8, 8);
  v0 = UINT64_C(0x736f6d6570736575) ^ k0;
  v1 = UINT64_C(0x646f72616e646f6d) ^ k1;
  v2 = UINT64_C(0x6c7967656e657261) ^ k0;
  v3 = UINT64_C(0x7465646279746573) ^ k1;
  for (i = 0; i + 8 <= n; i += 8) {
    memcpy(&m, p + i, 8);
    v3 ^= m;
    ROUND;
    ROUND;
    v0 ^= m;
  }
  for (size_t j = 0; i + j < n; j++)
    b |= (uint64_t)p[i + j] << (8 * j);
  v3 ^= b;
  ROUND;
  ROUND;
  v0 ^= b;
  v2 ^= 255;
  ROUND;
  ROUND;
  ROUND;
  ROUND;
  return v0 ^ v1 ^ v2 ^ v3;
}
#undef ROUND
static int read_slot(const ban_slot *s, ban_record *out) {
  uint64_t a, b, words[BAN_WORDS];
  unsigned retry, i;
  for (retry = 0; retry < 3; retry++) {
    a = __atomic_load_n(&s->commit, __ATOMIC_SEQ_CST);
    for (i = 0; i < BAN_WORDS; i++)
      words[i] = __atomic_load_n(&s->bank[a & 1][i], __ATOMIC_SEQ_CST);
    b = __atomic_load_n(&s->commit, __ATOMIC_SEQ_CST);
    if (a == b) {
      memcpy(out, words, sizeof(*out));
      return 1;
    }
  }
  return 0;
}
static size_t index_for(const ban_view *v, const ban_address *a,
                        const char *scope) {
  uint8_t key[116] = {0};
  memcpy(key, a, 20);
  memcpy(key + 20, scope, strnlen(scope, 96));
  return (size_t)ban_hash(key, sizeof(key), v->hash_key) & (BAN_SLOTS - 1);
}
int ban_view_valid(const ban_view *v, size_t n, const uint8_t boot[16]) {
  return n == sizeof(*v) && v->magic == BAN_VIEW_MAGIC &&
         v->version == BAN_VERSION && v->slots == BAN_SLOTS &&
         !memcmp(v->boot, boot, 16);
}
int ban_view_lookup(const ban_view *v, const ban_address *a, const char *scope,
                    uint64_t now, ban_record *out) {
  size_t i, start = index_for(v, a, scope);
  ban_record r;
  for (i = 0; i < 64; i++) {
    if (!read_slot(&v->table[(start + i) & (BAN_SLOTS - 1)], &r))
      return -1;
    if (!r.layer)
      return 0;
    if (r.layer != 1 && !memcmp(&r.ip, a, 20) && !strncmp(r.scope, scope, 96)) {
      if (r.deadline <= now)
        return 0;
      *out = r;
      return 1;
    }
  }
  return 0;
}
int ban_view_write(ban_view *v, const ban_record *r, int remove) {
  size_t i, start = index_for(v, &r->ip, r->scope), chosen = BAN_SLOTS;
  ban_record old, value = *r;
  uint64_t words[BAN_WORDS], commit;
  ban_slot *s;
  for (i = 0; i < 64; i++) {
    size_t at = (start + i) & (BAN_SLOTS - 1);
    if (!read_slot(&v->table[at], &old))
      return 0;
    if (!old.layer || old.layer == 1) {
      if (chosen == BAN_SLOTS)
        chosen = at;
      if (!old.layer)
        break;
    } else if (!memcmp(&old.ip, &r->ip, 20) &&
               !strncmp(old.scope, r->scope, 96)) {
      chosen = at;
      break;
    }
  }
  if (chosen == BAN_SLOTS)
    return 0;
  if (remove) {
    memset(&value, 0, sizeof(value));
    value.layer = 1;
  }
  s = &v->table[chosen];
  commit = __atomic_load_n(&s->commit, __ATOMIC_SEQ_CST);
  if (commit > UINT64_MAX - 4)
    return 0;
  commit++;
  memcpy(words, &value, sizeof(value));
  for (i = 0; i < BAN_WORDS; i++)
    __atomic_store_n(&s->bank[commit & 1][i], words[i], __ATOMIC_SEQ_CST);
  __atomic_store_n(&s->commit, commit, __ATOMIC_SEQ_CST);
  return 1;
}
