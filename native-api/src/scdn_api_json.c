#include "scdn_api.h"

typedef struct {
    const u_char *p, *end;
    ngx_uint_t depth;
    scdn_api_json_t *signals;
} api_json_parser_t;

static ngx_flag_t api_json_value(api_json_parser_t *p, ngx_uint_t *type);

static void
api_json_space(api_json_parser_t *p)
{
    while (p->p < p->end && (*p->p == ' ' || *p->p == '\t'
           || *p->p == '\r' || *p->p == '\n')) { p->p++; }
}

static ngx_int_t
api_json_hex(u_char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    c = (u_char) (c | 0x20);
    return c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}

/* Keys are decoded into a small ASCII buffer. Other string contents are never
 * retained, logged or searched for apparent JSON keys. */
static ngx_flag_t
api_json_string(api_json_parser_t *p, u_char *key, size_t capacity,
    size_t *length)
{
    ngx_uint_t code, j, low;
    ngx_int_t digit;
    u_char *utf8;
    size_t used = 0;
    u_char c;
    if (p->p == p->end || *p->p++ != '"') { return 0; }
    while (p->p < p->end) {
        c = *p->p++;
        if (c == '"') {
            if (length != NULL) { *length = used; }
            return 1;
        }
        if (c < 0x20) { return 0; }
        code = c;
        if (c >= 0x80) {
            utf8 = (u_char *) p->p - 1;
            code = ngx_utf8_decode(&utf8, p->end - (p->p - 1));
            if (code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) { return 0; }
            p->p = utf8;
        }
        if (c == '\\') {
            if (p->p == p->end) { return 0; }
            c = *p->p++;
            switch (c) {
            case '"': case '\\': case '/': code = c; break;
            case 'b': code = '\b'; break;
            case 'f': code = '\f'; break;
            case 'n': code = '\n'; break;
            case 'r': code = '\r'; break;
            case 't': code = '\t'; break;
            case 'u':
                code = 0;
                for (j = 0; j < 4; j++) {
                    if (p->p == p->end || (digit = api_json_hex(*p->p++)) < 0) { return 0; }
                    code = code * 16 + (ngx_uint_t) digit;
                }
                if (code >= 0xd800 && code <= 0xdbff) {
                    if (p->end - p->p < 6 || p->p[0] != '\\' || p->p[1] != 'u') { return 0; }
                    p->p += 2; low = 0;
                    for (j = 0; j < 4; j++) {
                        digit = api_json_hex(*p->p++);
                        if (digit < 0) { return 0; }
                        low = low * 16 + (ngx_uint_t) digit;
                    }
                    if (low < 0xdc00 || low > 0xdfff) { return 0; }
                    code = 0x10000;
                } else if (code >= 0xdc00 && code <= 0xdfff) { return 0; }
                break;
            default: return 0;
            }
        }
        if (key != NULL && used < capacity) { key[used] = code < 128 ? (u_char) code : 0xff; }
        used++;
    }
    return 0;
}

static ngx_flag_t
api_json_object(api_json_parser_t *p)
{
    u_char key[16];
    size_t length;
    ngx_uint_t type;
    ngx_flag_t top = p->depth == 1;
    ngx_flag_t model, input, stream;
    p->p++; api_json_space(p);
    if (p->p < p->end && *p->p == '}') { p->p++; return 1; }
    for (;;) {
        if (!api_json_string(p, key, sizeof(key), &length)) { return 0; }
        model = top && length == 5 && ngx_memcmp(key, "model", 5) == 0;
        input = top && ((length == 8 && ngx_memcmp(key, "messages", 8) == 0)
            || (length == 5 && ngx_memcmp(key, "input", 5) == 0)
            || (length == 6 && ngx_memcmp(key, "prompt", 6) == 0));
        stream = top && length == 6 && ngx_memcmp(key, "stream", 6) == 0;
        api_json_space(p);
        if (p->p == p->end || *p->p++ != ':') { return 0; }
        api_json_space(p);
        if (!api_json_value(p, &type)) { return 0; }
        if (model && type == 's') { p->signals->model = 1; }
        if (input && (type == 's' || type == '[' || type == '{')) { p->signals->input = 1; }
        if (stream && type == 't') { p->signals->stream = 1; }
        api_json_space(p);
        if (p->p == p->end) { return 0; }
        if (*p->p == '}') { p->p++; return 1; }
        if (*p->p++ != ',') { return 0; }
        api_json_space(p);
    }
}

static ngx_flag_t
api_json_array(api_json_parser_t *p)
{
    ngx_uint_t type;
    p->p++; api_json_space(p);
    if (p->p < p->end && *p->p == ']') { p->p++; return 1; }
    for (;;) {
        if (!api_json_value(p, &type)) { return 0; }
        api_json_space(p);
        if (p->p == p->end) { return 0; }
        if (*p->p == ']') { p->p++; return 1; }
        if (*p->p++ != ',') { return 0; }
        api_json_space(p);
    }
}

static ngx_flag_t
api_json_number(api_json_parser_t *p)
{
    if (*p->p == '-') { p->p++; }
    if (p->p == p->end) { return 0; }
    if (*p->p == '0') { p->p++; }
    else {
        if (*p->p < '1' || *p->p > '9') { return 0; }
        do { p->p++; } while (p->p < p->end && *p->p >= '0' && *p->p <= '9');
    }
    if (p->p < p->end && *p->p == '.') {
        p->p++;
        if (p->p == p->end || *p->p < '0' || *p->p > '9') { return 0; }
        do { p->p++; } while (p->p < p->end && *p->p >= '0' && *p->p <= '9');
    }
    if (p->p < p->end && (*p->p == 'e' || *p->p == 'E')) {
        p->p++;
        if (p->p < p->end && (*p->p == '+' || *p->p == '-')) { p->p++; }
        if (p->p == p->end || *p->p < '0' || *p->p > '9') { return 0; }
        do { p->p++; } while (p->p < p->end && *p->p >= '0' && *p->p <= '9');
    }
    return 1;
}

static ngx_flag_t
api_json_value(api_json_parser_t *p, ngx_uint_t *type)
{
    ngx_flag_t ok;
    const char *literal;
    size_t length;
    api_json_space(p);
    if (p->p == p->end || ++p->depth > 32) { return 0; }
    *type = *p->p;
    if (*p->p == '{') { ok = api_json_object(p); }
    else if (*p->p == '[') { ok = api_json_array(p); }
    else if (*p->p == '"') { *type = 's'; ok = api_json_string(p, NULL, 0, NULL); }
    else if (*p->p == 't' || *p->p == 'f' || *p->p == 'n') {
        literal = *p->p == 't' ? "true" : (*p->p == 'f' ? "false" : "null");
        length = ngx_strlen(literal);
        ok = (size_t) (p->end - p->p) >= length && ngx_memcmp(p->p, literal, length) == 0;
        if (ok) { p->p += length; }
    } else { ok = api_json_number(p); }
    p->depth--;
    return ok;
}

ngx_flag_t
scdn_api_json(const u_char *bytes, size_t length, scdn_api_json_t *signals)
{
    api_json_parser_t p;
    ngx_uint_t type;
    ngx_memzero(signals, sizeof(*signals));
    p.p = bytes; p.end = bytes + length; p.depth = 0; p.signals = signals;
    api_json_space(&p);
    if (p.p == p.end || *p.p != '{' || !api_json_value(&p, &type)) { return 0; }
    api_json_space(&p);
    return p.p == p.end;
}
