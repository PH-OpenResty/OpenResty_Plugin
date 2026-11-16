#include "scdn_purge.h"

#if !(NGX_PCRE2)
#error "scdn_purge requires PCRE2"
#endif
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#define REGEX_CACHE SCDN_PURGE_PREFIXES
#define REGEX_LENGTH 1024
#define MATCH_BUDGET 100000

typedef struct {
    pcre2_code *code;
    ngx_str_t pattern;
    uint64_t used;
} purge_regex_t;
static purge_regex_t regex_cache[REGEX_CACHE];
static uint64_t regex_clock;
static pcre2_match_context *match_context;
static pcre2_match_data *match_data;

static pcre2_code *
compile_regex(const ngx_str_t *pattern)
{
    int error;
    PCRE2_SIZE offset;
    size_t size;
    pcre2_code *code;
    if(pattern->len>REGEX_LENGTH)return NULL;
    code=pcre2_compile(pattern->data,pattern->len,PCRE2_NEVER_UTF|PCRE2_NEVER_UCP,
                       &error,&offset,NULL);
    if(code && (pcre2_pattern_info(code,PCRE2_INFO_SIZE,&size)!=0 || size>131072)) {
        pcre2_code_free(code);return NULL;
    }
    return code;
}

ngx_flag_t
scdn_purge_pattern_valid(u_char mode, const ngx_str_t *pattern)
{
    size_t i;
    pcre2_code *code;
    if(pattern->len==0)return mode=='S' || mode=='A';
    if(mode=='R') {
        code=compile_regex(pattern);
        if(code==NULL)return 0;
        pcre2_code_free(code);
    } else if(mode=='W') {
        if(pattern->len>REGEX_LENGTH)return 0;
        for(i=0;i<pattern->len;i++)if(pattern->data[i]=='\\' && ++i==pattern->len)return 0;
    } else if(mode=='D' || mode=='T') {
        for(i=0;i<pattern->len;i++)if(pattern->data[i]=='?' || pattern->data[i]=='#')return 0;
    }
    return 1;
}

static ngx_int_t
regex_match(const ngx_str_t *pattern, const ngx_str_t *key)
{
    purge_regex_t *entry,*selected=&regex_cache[0];
    ngx_uint_t i;
    int rc;
    if(match_context==NULL || match_data==NULL) {
        if(match_context)pcre2_match_context_free(match_context);
        if(match_data)pcre2_match_data_free(match_data);
        match_context=pcre2_match_context_create(NULL);
        match_data=pcre2_match_data_create(1,NULL);
        if(match_context==NULL || match_data==NULL)return NGX_ERROR;
        pcre2_set_match_limit(match_context,MATCH_BUDGET);
        pcre2_set_depth_limit(match_context,128);
        pcre2_set_heap_limit(match_context,1024);
    }
    for(i=0;i<REGEX_CACHE;i++) {
        entry=&regex_cache[i];
        if(entry->code && entry->pattern.len==pattern->len
           && ngx_memcmp(entry->pattern.data,pattern->data,pattern->len)==0) {
            selected=entry;goto compiled;
        }
        if(entry->used<selected->used)selected=entry;
    }
    if(selected->code)pcre2_code_free(selected->code);
    if(selected->pattern.data)ngx_free(selected->pattern.data);
    ngx_memzero(selected,sizeof(*selected));
    selected->code=compile_regex(pattern);
    selected->pattern.data=ngx_alloc(pattern->len,ngx_cycle->log);
    if(selected->code==NULL || selected->pattern.data==NULL) {
        if(selected->code)pcre2_code_free(selected->code);
        if(selected->pattern.data)ngx_free(selected->pattern.data);
        ngx_memzero(selected,sizeof(*selected));return NGX_ERROR;
    }
    selected->pattern.len=pattern->len;
    ngx_memcpy(selected->pattern.data,pattern->data,pattern->len);
compiled:
    selected->used=++regex_clock;
    rc=pcre2_match(selected->code,key->data,key->len,0,0,match_data,match_context);
    if(rc>=0)return 1;
    if(rc==PCRE2_ERROR_NOMATCH)return 0;
    return NGX_ERROR;
}

static ngx_int_t
wildcard_match(const ngx_str_t *pattern, const ngx_str_t *key)
{
    size_t p=0,k=0,star=SIZE_MAX,retry=0,steps=0;
    u_char byte;
    ngx_flag_t literal;
    while(k<key->len) {
        if(++steps>MATCH_BUDGET)return NGX_ERROR;
        if(p<pattern->len) {
            byte=pattern->data[p];literal=0;
            if(byte=='\\') {
                if (++p == pattern->len) return NGX_ERROR;
                literal=1;byte=pattern->data[p];
            }
            if(!literal && byte=='*') { star=++p;retry=k;continue; }
            if((!literal && byte=='?') || byte==key->data[k]) { p++;k++;continue; }
            /* Restore the escape prefix when retrying from a star. */
            if(literal)p--;
        }
        if(star==SIZE_MAX)return 0;
        p=star;k=++retry;
    }
    while(p<pattern->len && pattern->data[p]=='*')p++;
    return p==pattern->len;
}

ngx_int_t
scdn_purge_match(u_char mode, const ngx_str_t *pattern, const ngx_str_t *key)
{
    size_t length=key->len,n=pattern->len,i;
    if(mode=='R')return regex_match(pattern,key);
    if(mode=='W')return wildcard_match(pattern,key);
    if(mode=='P')return n<=length && ngx_memcmp(pattern->data,key->data,n)==0;
    for(i=0;i<length;i++)if(key->data[i]=='?') { length=i;break; }
    if(mode=='T')return n<=length && ngx_memcmp(pattern->data,key->data+length-n,n)==0;
    if(mode=='D') {
        if(n>1 && pattern->data[n-1]=='/')n--;
        if(n>length || ngx_memcmp(pattern->data,key->data,n)!=0)return 0;
        return n==length || (n==1 && pattern->data[0]=='/') || key->data[n]=='/';
    }
    return NGX_ERROR;
}

void
scdn_purge_match_exit(void)
{
    ngx_uint_t i;
    for(i=0;i<REGEX_CACHE;i++) {
        if(regex_cache[i].code)pcre2_code_free(regex_cache[i].code);
        if(regex_cache[i].pattern.data)ngx_free(regex_cache[i].pattern.data);
    }
    if(match_context)pcre2_match_context_free(match_context);
    if(match_data)pcre2_match_data_free(match_data);
}
