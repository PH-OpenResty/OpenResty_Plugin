#include "auth_internal.h"

static ngx_http_output_header_filter_pt next_header;
static ngx_http_request_body_filter_pt next_body;
static ngx_event_t sweep_event;
static auth_main *worker_main;
static void *create_main(ngx_conf_t *);
static void *create_location(ngx_conf_t *);
static char *merge_location(ngx_conf_t *, void *, void *);
static char *policy_directive(ngx_conf_t *, ngx_command_t *, void *);
static char *guard_directive(ngx_conf_t *, ngx_command_t *, void *);
static char *zone_directive(ngx_conf_t *, ngx_command_t *, void *);
static char *control_directive(ngx_conf_t *, ngx_command_t *, void *);
static char *status_directive(ngx_conf_t *, ngx_command_t *, void *);
static ngx_int_t postconfiguration(ngx_conf_t *);
static ngx_int_t preconfiguration(ngx_conf_t *);
static ngx_int_t init_worker(ngx_cycle_t *);
static void exit_worker(ngx_cycle_t *);
static ngx_int_t header_filter(ngx_http_request_t *);
static ngx_int_t body_filter(ngx_http_request_t *, ngx_chain_t *);
static ngx_int_t control_handler(ngx_http_request_t *);
static ngx_int_t status_handler(ngx_http_request_t *);
static ngx_int_t reply(ngx_http_request_t *, auth_request *, ngx_int_t, const char *);
static ngx_int_t finish_prepare(ngx_http_request_t *, auth_request *);
static ngx_int_t auth_variable(ngx_http_request_t *, ngx_http_variable_value_t *, uintptr_t);
static ngx_conf_enum_t modes[] = {{ngx_string("enforce"),1},{ngx_string("observe"),0},{ngx_null_string,0}};
#define AUTH_LOC (NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF)
static ngx_command_t commands[] = {
    {ngx_string("scdn_auth_policy"),NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,policy_directive,NGX_HTTP_MAIN_CONF_OFFSET,0,NULL},
    {ngx_string("scdn_auth_zone"),NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,zone_directive,NGX_HTTP_MAIN_CONF_OFFSET,0,NULL},
    {ngx_string("scdn_auth_guard"),AUTH_LOC|NGX_CONF_TAKE1,guard_directive,NGX_HTTP_LOC_CONF_OFFSET,0,NULL},
    {ngx_string("scdn_auth_mode"),AUTH_LOC|NGX_CONF_TAKE1,ngx_conf_set_enum_slot,NGX_HTTP_LOC_CONF_OFFSET,offsetof(auth_location,mode),modes},
    {ngx_string("scdn_auth_control"),NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,control_directive,NGX_HTTP_LOC_CONF_OFFSET,0,NULL},
    {ngx_string("scdn_auth_status"),NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,status_directive,NGX_HTTP_LOC_CONF_OFFSET,0,NULL},
    ngx_null_command
};
static ngx_http_module_t module_context = {
    preconfiguration,postconfiguration,create_main,NULL,NULL,NULL,create_location,merge_location
};
ngx_module_t ngx_http_scdn_auth_guard_module = {
    NGX_MODULE_V1,&module_context,commands,NGX_HTTP_MODULE,
    NULL,NULL,init_worker,NULL,NULL,exit_worker,NULL,NGX_MODULE_V1_PADDING
};
static ngx_flag_t text_equal(ngx_str_t *text, const char *value) {
    size_t n = ngx_strlen(value);
    return text->len == n && !ngx_memcmp(text->data,value,n);
}
static auth_realm *realm_by_name(auth_main *m, ngx_str_t *name) {
    ngx_uint_t i;
    for (i=0;i<m->realm_count;i++) if (m->realms[i].id.len==name->len && !ngx_memcmp(m->realms[i].id.data,name->data,name->len)) return &m->realms[i];
    return NULL;
}
static void *create_main(ngx_conf_t *cf) {
    return ngx_pcalloc(cf->pool,sizeof(auth_main));
}
static void *create_location(ngx_conf_t *cf) {
    auth_location *l=ngx_pcalloc(cf->pool,sizeof(*l));
    if (l) {l->realm=NGX_CONF_UNSET;l->mode=NGX_CONF_UNSET_UINT;}
    return l;
}
static char *merge_location(ngx_conf_t *cf, void *parent, void *child) {
    auth_location *p=parent,*l=child;
    auth_main *m=ngx_http_conf_get_module_main_conf(cf,ngx_http_scdn_auth_guard_module);
    ngx_conf_merge_value(l->realm,p->realm,-2);ngx_conf_merge_uint_value(l->mode,p->mode,1);
    if (l->realm>=0) m->configured=1;
    return NGX_CONF_OK;
}
static char *policy_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *data) {
    auth_main *m=data;ngx_str_t *v=cf->args->elts;(void)cmd;
    if (m->policy_loaded || auth_load_policy(cf,m,&v[1])!=NGX_OK) return "invalid scdn_auth_policy, secret file permissions or weak-password data";
    return NGX_CONF_OK;
}
static char *guard_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *data) {
    auth_location *l=data;auth_main *m=ngx_http_conf_get_module_main_conf(cf,ngx_http_scdn_auth_guard_module);
    ngx_str_t *v=cf->args->elts;auth_realm *realm;(void)cmd;
    if (l->realm!=NGX_CONF_UNSET) return "duplicate scdn_auth_guard";
    if (text_equal(&v[1],"off")) {l->realm=-2;return NGX_CONF_OK;}
    realm=realm_by_name(m,&v[1]);
    if (!realm) return "scdn_auth_guard requires a previously loaded policy realm";
    l->realm=realm-m->realms;return NGX_CONF_OK;
}
static char *zone_directive(ngx_conf_t *cf, ngx_command_t *cmd, void *data) {
    auth_main *m=data;ngx_str_t *v=cf->args->elts;ssize_t size=ngx_parse_size(&v[2]);(void)cmd;
    if (m->zone || size<1048576 || size>268435456) return "scdn_auth_zone requires one zone of 1m to 256m";
    m->zone=ngx_shared_memory_add(cf,&v[1],size,&ngx_http_scdn_auth_guard_module);
    if (!m->zone) return NGX_CONF_ERROR;
    m->zone->data=m;m->zone->init=auth_state_init;return NGX_CONF_OK;
}
static void sweep_handler(ngx_event_t *event) {
    if (worker_main) auth_sweep(worker_main);
    if (!ngx_quit && !ngx_terminate && !ngx_exiting) ngx_add_timer(event,1000);
}
static ngx_int_t init_worker(ngx_cycle_t *cycle) {
    if(ngx_process!=NGX_PROCESS_WORKER && ngx_process!=NGX_PROCESS_SINGLE)return NGX_OK;
    worker_main=ngx_http_cycle_get_module_main_conf(cycle,ngx_http_scdn_auth_guard_module);
    if (!worker_main || !worker_main->configured) return NGX_OK;
    ngx_memzero(&sweep_event,sizeof(sweep_event));sweep_event.handler=sweep_handler;sweep_event.log=cycle->log;sweep_event.cancelable=1;
    ngx_add_timer(&sweep_event,1000);return NGX_OK;
}
static void exit_worker(ngx_cycle_t *cycle) {(void)cycle;if(sweep_event.timer_set)ngx_del_timer(&sweep_event);}
static auth_request *request_context(ngx_http_request_t *r) {
    return ngx_http_get_module_ctx(r,ngx_http_scdn_auth_guard_module);
}
static void request_cleanup(void *data) {
    auth_request *ctx=data;
    if (ctx->deadline.timer_set) ngx_del_timer(&ctx->deadline);
    if (!ctx->control) auth_release(ctx);
}
static auth_request *find_context(ngx_http_request_t *r) {
    ngx_pool_cleanup_t *p;auth_request *ctx=request_context(r);
    if (ctx && ctx->owner==r) return ctx;
    for(p=r->pool->cleanup;p;p=p->next)if(p->handler==request_cleanup && ((auth_request *)p->data)->owner==r) {
        ngx_http_set_ctx(r,p->data,ngx_http_scdn_auth_guard_module);return p->data;
    }
    return NULL;
}
static auth_request *new_context(ngx_http_request_t *r, auth_main *m) {
    ngx_pool_cleanup_t *cleanup=ngx_pool_cleanup_add(r->pool,sizeof(auth_request));auth_request *ctx;
    if(!cleanup)return NULL;
    cleanup->handler=request_cleanup;ctx=cleanup->data;ngx_memzero(ctx,sizeof(*ctx));ctx->owner=r;ctx->main=m;
    ngx_http_set_ctx(r,ctx,ngx_http_scdn_auth_guard_module);return ctx;
}
static ngx_uint_t route_flow(auth_realm *realm, ngx_http_request_t *r) {
    typedef struct {const char *path;ngx_uint_t method,flow;} route;
    static const route sub[]={
        {"/api/v1/auth/login",NGX_HTTP_POST,AUTH_LOGIN},{"/api/v1/auth/register",NGX_HTTP_POST,AUTH_REGISTER},
        {"/api/v1/auth/send-verify-code",NGX_HTTP_POST,AUTH_MAIL},{"/api/v1/auth/login/2fa",NGX_HTTP_POST,AUTH_FACTOR},
        {"/api/v1/auth/passkey/login/begin",NGX_HTTP_POST,AUTH_FACTOR},{"/api/v1/auth/passkey/login/finish",NGX_HTTP_POST,AUTH_FACTOR},
        {"/api/v1/auth/forgot-password",NGX_HTTP_POST,AUTH_RESET},{"/api/v1/auth/reset-password",NGX_HTTP_POST,AUTH_RESET},
        {"/api/v1/auth/refresh",NGX_HTTP_POST,AUTH_REFRESH},{"/api/v1/auth/validate-promo-code",NGX_HTTP_POST,AUTH_ENUM},
        {"/api/v1/auth/validate-invitation-code",NGX_HTTP_POST,AUTH_ENUM},{NULL,0,0}};
    static const route newer[]={
        {"/api/user/login",NGX_HTTP_POST,AUTH_LOGIN},{"/api/user/register",NGX_HTTP_POST,AUTH_REGISTER},
        {"/api/verification",NGX_HTTP_GET,AUTH_MAIL},{"/api/user/login/2fa",NGX_HTTP_POST,AUTH_FACTOR},
        {"/api/user/login/verify",NGX_HTTP_POST,AUTH_FACTOR},{"/api/user/login/passkey/begin",NGX_HTTP_POST,AUTH_FACTOR},
        {"/api/user/login/passkey/finish",NGX_HTTP_POST,AUTH_FACTOR},{"/api/user/passkey/login/begin",NGX_HTTP_POST,AUTH_FACTOR},
        {"/api/user/passkey/login/finish",NGX_HTTP_POST,AUTH_FACTOR},{"/api/reset_password",NGX_HTTP_GET,AUTH_RESET},
        {"/api/user/reset",NGX_HTTP_POST,AUTH_RESET},{"/api/user/auth/refresh",NGX_HTTP_POST,AUTH_REFRESH},
        {"/api/oauth/state",NGX_HTTP_POST,AUTH_OAUTH},{NULL,0,0}};
    const route *routes=text_equal(&realm->adapter,"sub2api")?sub:newer;
    size_t length=r->uri.len,n;ngx_uint_t i;
    if(length>1 && r->uri.data[length-1]=='/')length--;
    for(i=0;routes[i].path;i++) {
        n=ngx_strlen(routes[i].path);
        if(length==n && r->method==routes[i].method && !ngx_memcmp(r->uri.data,routes[i].path,n))return routes[i].flow;
    }
    if(text_equal(&realm->adapter,"sub2api")) {
        if(length>18 && !ngx_memcmp(r->uri.data,"/api/v1/auth/oauth/",18) && (r->method&(NGX_HTTP_GET|NGX_HTTP_POST)))return AUTH_OAUTH;
    } else if(length>11 && !ngx_memcmp(r->uri.data,"/api/oauth/",11) && (r->method&(NGX_HTTP_GET|NGX_HTTP_POST)))return AUTH_OAUTH;
    return AUTH_NONE;
}
static ngx_int_t add_header(ngx_http_request_t *r,const char *name,const char *value) {
    ngx_table_elt_t *header=ngx_list_push(&r->headers_out.headers);
    if(!header)return NGX_ERROR;
    ngx_memzero(header,sizeof(*header));header->hash=1;
    header->key.data=(u_char *)name;header->key.len=ngx_strlen(name);
    header->value.data=(u_char *)value;header->value.len=ngx_strlen(value);return NGX_OK;
}
static ngx_int_t reply(ngx_http_request_t *r,auth_request *ctx,ngx_int_t status,const char *code) {
    ngx_buf_t *buffer;ngx_chain_t out;ngx_int_t rc;
    const char *message = status==200 ? "Allowed." : status==429 ? "Too many authentication attempts. Try again later."
        : !ngx_strcmp(code,"WEAK_PASSWORD") ? "Choose a less common password."
        : !ngx_strcmp(code,"EMAIL_NOT_ALLOWED") ? "This email domain is not supported."
        : status>=500 ? "Authentication is temporarily unavailable." : "Request did not meet the authentication policy.";
    if(ctx)ctx->rejection=status;
    /* An early rejection must not turn an unread credential body into the
     * next keepalive request line (which nginx may log verbatim). */
    if(!r->request_body && (r->headers_in.content_length_n>0 || r->headers_in.chunked))r->keepalive=0;
    buffer=ngx_create_temp_buf(r->pool,512);if(!buffer)return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if(ctx && ctx->realm && text_equal(&ctx->realm->adapter,"newapi"))
        buffer->last=ngx_sprintf(buffer->last,"{\"success\":%s,\"code\":\"%s\",\"message\":\"%s\"}\n",status==200?"true":"false",code,message);
    else buffer->last=ngx_sprintf(buffer->last,"{\"code\":%i,\"reason\":\"%s\",\"message\":\"%s\"}\n",status,code,message);
    if((!ctx || !ctx->realm || ctx->control) && add_header(r,"Cache-Control","no-store")!=NGX_OK)return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if(status==429)if(add_header(r,"Retry-After","60")!=NGX_OK)return NGX_HTTP_INTERNAL_SERVER_ERROR;
    r->headers_out.status=status;r->headers_out.content_length_n=buffer->last-buffer->pos;
    ngx_str_set(&r->headers_out.content_type,"application/json");buffer->last_buf=r==r->main;buffer->last_in_chain=1;
    rc=ngx_http_send_header(r);
    if(rc==NGX_ERROR || rc>NGX_OK || r->header_only){ngx_http_finalize_request(r,rc);return NGX_DONE;}
    out.buf=buffer;out.next=NULL;rc=ngx_http_output_filter(r,&out);ngx_http_finalize_request(r,rc);return NGX_DONE;
}
static void deadline_handler(ngx_event_t *event) {
    auth_request *ctx=event->data;
    ctx->rejection=NGX_HTTP_GATEWAY_TIME_OUT;
    ngx_http_finalize_request(ctx->owner,NGX_HTTP_GATEWAY_TIME_OUT);
}
static ngx_int_t capture(auth_request *ctx,ngx_chain_t *in) {
    ngx_chain_t *item;size_t n,maximum=ctx->control?4096:AUTH_BODY_LIMIT;
    for(item=in;item;item=item->next) {
        if(item->buf->in_file || !ngx_buf_in_memory(item->buf)) {
            if(ngx_buf_size(item->buf))return NGX_HTTP_SERVICE_UNAVAILABLE;
            continue;
        }
        n=item->buf->last-item->buf->pos;
        if(n>maximum-ctx->body_len)return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
        if(n)ngx_memcpy(ctx->body+ctx->body_len,item->buf->pos,n);
        ctx->body_len+=n;
    }
    return NGX_OK;
}
static ngx_int_t body_filter(ngx_http_request_t *r,ngx_chain_t *in) {
    auth_request *ctx=find_context(r);ngx_int_t rc;
    if(ctx && ctx->capturing) {rc=capture(ctx,in);if(rc!=NGX_OK)return rc;}
    return next_body(r,in);
}
static void body_ready(ngx_http_request_t *r) {
    auth_request *ctx=find_context(r);ngx_buf_t *buffer;ngx_chain_t *chain;
    if(!ctx){ngx_http_finalize_request(r,NGX_HTTP_INTERNAL_SERVER_ERROR);return;}
    ctx->capturing=0;ctx->ready=1;
    buffer=ngx_calloc_buf(r->pool);chain=ngx_alloc_chain_link(r->pool);
    if(!buffer || !chain){ngx_http_finalize_request(r,NGX_HTTP_INTERNAL_SERVER_ERROR);return;}
    buffer->pos=ctx->body;buffer->last=ctx->body+ctx->body_len;buffer->memory=1;buffer->last_buf=1;chain->buf=buffer;chain->next=NULL;
    r->request_body->bufs=chain;r->preserve_body=1;
    r->write_event_handler=ngx_http_core_run_phases;ngx_http_core_run_phases(r);
}

static ngx_uint_t credential_key(const u_char *key,size_t length) {
    static const char *names[]={"email","username","password","new_password","temp_token","flow_token"};
    u_char folded[64];size_t i=0,n=0;ngx_uint_t j;
    while(i<length && n<sizeof(folded)) {
        if(key[i]<128){folded[n++]=ngx_tolower(key[i]);i++;}
        else if(i+1<length && key[i]==0xc5 && key[i+1]==0xbf){folded[n++]='s';i+=2;}
        else if(i+2<length && key[i]==0xe2 && key[i+1]==0x84 && key[i+2]==0xaa){folded[n++]='k';i+=3;}
        else return 0;
    }
    if(i!=length)return 0;
    for(j=0;j<6;j++)if(n==ngx_strlen(names[j]) && !ngx_memcmp(folded,names[j],n))return j+1;
    return 0;
}
static ngx_int_t unique_credentials(const u_char *body,size_t length) {
    size_t i=0,start;ngx_uint_t depth=0,seen=0,kind,fields=0;ngx_flag_t key=0;
    json_object *decoded;const char *text;size_t n;
    while(i<length) {
        u_char c=body[i++];
        if(c=='{' || c=='['){depth++;if(depth==1)key=1;continue;}
        if(c=='}' || c==']'){if(depth)depth--;continue;}
        if(c==',' && depth==1){key=1;continue;}
        if(c!='"')continue;
        start=i-1;
        while(i<length) {
            c=body[i++];
            if(c=='\\'){if(i<length)i++;continue;}
            if(c=='"')break;
        }
        if(depth!=1 || !key)continue;
        key=0;if(++fields>128)return NGX_ERROR;
        {
            json_tokener *parser=json_tokener_new_ex(8);
            if(!parser)return NGX_ERROR;
            decoded=json_tokener_parse_ex(parser,(const char *)body+start,(int)(i-start));
            if(json_tokener_get_error(parser)==json_tokener_continue)decoded=json_tokener_parse_ex(parser," ",1);
            if(json_tokener_get_error(parser)!=json_tokener_success){if(decoded)json_object_put(decoded);decoded=NULL;}
            json_tokener_free(parser);
        }
        if(!decoded || json_object_get_type(decoded)!=json_type_string){if(decoded)json_object_put(decoded);return NGX_ERROR;}
        text=json_object_get_string(decoded);n=json_object_get_string_len(decoded);
        if(ngx_strlen(text)!=n){json_object_put(decoded);return NGX_ERROR;}
        kind=credential_key((const u_char *)text,n);json_object_put(decoded);
        if(kind && (seen&(1u<<kind)))return NGX_ERROR;
        if(kind)seen|=1u<<kind;
    }
    return NGX_OK;
}
static ngx_int_t value_string(ngx_http_request_t *r,json_object *object,ngx_uint_t wanted,ngx_str_t *out,size_t maximum) {
    json_object_object_foreach(object,key,value) {
        size_t n;
        if(credential_key((const u_char *)key,ngx_strlen(key))!=wanted)continue;
        if(json_object_get_type(value)!=json_type_string)return NGX_ERROR;
        n=json_object_get_string_len(value);
        if(n>maximum)return NGX_ERROR;
        out->data=ngx_pnalloc(r->pool,n?n:1);if(!out->data)return NGX_ERROR;
        ngx_memcpy(out->data,json_object_get_string(value),n);out->len=n;return NGX_OK;
    }
    return NGX_OK;
}
static ngx_flag_t ascii(ngx_str_t *value) {
    size_t i;for(i=0;i<value->len;i++)if(value->data[i]>=128 || !value->data[i])return 0;
    return 1;
}
static void trim(ngx_str_t *value) {
    while(value->len && (value->data[0]==' ' || value->data[0]=='\t' || value->data[0]=='\r' || value->data[0]=='\n')){value->data++;value->len--;}
    while(value->len && (value->data[value->len-1]==' ' || value->data[value->len-1]=='\t' || value->data[value->len-1]=='\r' || value->data[value->len-1]=='\n'))value->len--;
}
static ngx_int_t query_email(ngx_http_request_t *r,ngx_str_t *email) {
    size_t start=0,end,key_end,i,n;ngx_uint_t found=0;u_char decoded[320],key[32];
    while(start<r->args.len) {
        end=start;while(end<r->args.len && r->args.data[end]!='&')end++;
        key_end=start;while(key_end<end && r->args.data[key_end]!='=')key_end++;
        n=0;
        for(i=start;i<key_end;i++) {
            u_char c=r->args.data[i];
            if(c=='%' && i+2<key_end){ngx_int_t v=ngx_hextoi(r->args.data+i+1,2);if(v==NGX_ERROR)return NGX_ERROR;c=(u_char)v;i+=2;}
            else if(c=='%')return NGX_ERROR;
            if(n<sizeof(key))key[n++]=c;
        }
        if(n==5 && !ngx_memcmp(key,"email",5)) {
            if(found++ || key_end==end)return NGX_ERROR;
            n=0;
            for(i=key_end+1;i<end;i++) {
                u_char c=r->args.data[i];
                if(c=='+')c=' ';
                else if(c=='%' && i+2<end){ngx_int_t v=ngx_hextoi(r->args.data+i+1,2);if(v==NGX_ERROR)return NGX_ERROR;c=(u_char)v;i+=2;}
                else if(c=='%')return NGX_ERROR;
                if(n==sizeof(decoded))return NGX_ERROR;
                decoded[n++]=c;
            }
            email->data=ngx_pnalloc(r->pool,n?n:1);if(!email->data)return NGX_ERROR;
            ngx_memcpy(email->data,decoded,n);email->len=n;
        }
        start=end+1;
    }
    return NGX_OK;
}
static ngx_table_elt_t *input_header(ngx_http_request_t *r,const char *name,ngx_flag_t *duplicate) {
    ngx_list_part_t *part=&r->headers_in.headers.part;ngx_table_elt_t *items=part->elts,*found=NULL;
    ngx_uint_t i;size_t n=ngx_strlen(name);
    for(i=0;;i++) {
        if(i>=part->nelts){if(!part->next)break;part=part->next;items=part->elts;i=0;}
        if(items[i].hash && items[i].key.len==n && !ngx_strncasecmp(items[i].key.data,(u_char *)name,n)) {
            if(found){if(duplicate)*duplicate=1;return NULL;}
            found=&items[i];
        }
    }
    return found;
}
static ngx_int_t set_private_request(ngx_http_request_t *r,auth_request *ctx) {
    ngx_list_t filtered;ngx_list_part_t *part;ngx_table_elt_t *items,*out;
    ngx_uint_t i;u_char metadata[1400],id[32],subject[64],body_hmac[64],mac[32],*end,*input;
    ngx_str_t plain,encoded,header;size_t length;
    if(ngx_list_init(&filtered,r->pool,20,sizeof(ngx_table_elt_t))!=NGX_OK)return NGX_ERROR;
    part=&r->headers_in.headers.part;items=part->elts;
    for(i=0;;i++) {
        if(i>=part->nelts){if(!part->next)break;part=part->next;items=part->elts;i=0;}
        if(items[i].key.len>=12 && !ngx_strncasecmp(items[i].key.data,(u_char *)"X-SCDN-Auth-",12))continue;
        out=ngx_list_push(&filtered);if(!out)return NGX_ERROR;*out=items[i];
    }
    r->headers_in.headers=filtered;
    if(filtered.last==&filtered.part)r->headers_in.headers.last=&r->headers_in.headers.part;
    length=r->method_name.len+r->unparsed_uri.len+ctx->body_len+2;
    if(length>32000)return NGX_ERROR;
    input=ngx_pnalloc(r->pool,length);if(!input)return NGX_ERROR;
    end=ngx_cpymem(input,r->method_name.data,r->method_name.len);*end++='\n';
    end=ngx_cpymem(end,r->unparsed_uri.data,r->unparsed_uri.len);*end++='\n';
    if(ctx->body_len)ngx_memcpy(end,ctx->body,ctx->body_len);
    if(auth_hmac(ctx->realm,"body",input,length,ctx->body_hmac)!=NGX_OK){OPENSSL_cleanse(input,length);return NGX_ERROR;}
    OPENSSL_cleanse(input,length);
    ngx_hex_dump(id,ctx->id,16);ngx_hex_dump(subject,ctx->subject,32);ngx_hex_dump(body_hmac,ctx->body_hmac,32);
    end=ngx_snprintf(metadata,sizeof(metadata),
        "{\"version\":1,\"node\":\"%V\",\"realm\":\"%V\",\"attempt\":\"%*s\",\"policy\":\"%V\",\"flow\":%ui,\"expires\":%T,\"subject\":\"%*s\",\"body\":\"%*s\",\"client_ip\":\"%V\"}",
        &ctx->main->node_id,&ctx->realm->id,(size_t)32,id,&ctx->realm->revision,ctx->flow,ctx->expires,
        (size_t)64,subject,(size_t)64,body_hmac,&ctx->client);
    plain.data=metadata;plain.len=end-metadata;
    encoded.data=ngx_pnalloc(r->pool,ngx_base64_encoded_length(plain.len));if(!encoded.data)return NGX_ERROR;
    ngx_encode_base64url(&encoded,&plain);
    if(auth_hmac(ctx->realm,"request",encoded.data,encoded.len,mac)!=NGX_OK)return NGX_ERROR;
    header.len=3+encoded.len+1+64;header.data=ngx_pnalloc(r->pool,header.len);if(!header.data)return NGX_ERROR;
    end=ngx_cpymem(header.data,"v1.",3);end=ngx_cpymem(end,encoded.data,encoded.len);*end++='.';ngx_hex_dump(end,mac,32);
    out=ngx_list_push(&r->headers_in.headers);if(!out)return NGX_ERROR;ngx_memzero(out,sizeof(*out));out->hash=1;
    ngx_str_set(&out->key,"X-SCDN-Auth-Request");out->value=header;
    out->lowcase_key=ngx_pnalloc(r->pool,out->key.len);if(!out->lowcase_key)return NGX_ERROR;
    out->hash=ngx_hash_strlow(out->lowcase_key,out->key.data,out->key.len);return NGX_OK;
}
static ngx_flag_t policy_ready(auth_realm *realm) {
    return realm->checked>0 && realm->max_age>0 && ngx_time()>=realm->checked && ngx_time()-realm->checked<=realm->max_age;
}
static ngx_int_t finish_prepare(ngx_http_request_t *r,auth_request *ctx) {
    json_object *object=NULL;ngx_str_t password=ngx_null_string,session=ngx_null_string,domain,subject;
    ngx_int_t rc;size_t i,at=0;ngx_flag_t have_at=0,ascii_email;
    if(ctx->account_ready)return ctx->rejection?NGX_DONE:NGX_DECLINED;
    if(ctx->body_len) {
        object=auth_json(ctx->body,ctx->body_len);
        if(!object || unique_credentials(ctx->body,ctx->body_len)!=NGX_OK)goto invalid;
        if(value_string(r,object,1,&ctx->email,320)!=NGX_OK || value_string(r,object,2,&ctx->username,320)!=NGX_OK
            || value_string(r,object,ctx->flow==AUTH_RESET?4:3,&password,4096)!=NGX_OK
            || value_string(r,object,5,&session,4096)!=NGX_OK)goto invalid;
        if(!session.len && value_string(r,object,6,&session,4096)!=NGX_OK)goto invalid;
    } else if(r->method==NGX_HTTP_GET && query_email(r,&ctx->email)!=NGX_OK)goto invalid;
    if(object){json_object_put(object);object=NULL;}
    if(ctx->flow==AUTH_REGISTER && !password.len)goto invalid;
    trim(&ctx->email);trim(&ctx->username);ascii_email=ascii(&ctx->email);
    if(ctx->email.len && ascii_email)for(i=0;i<ctx->email.len;i++)ctx->email.data[i]=ngx_tolower(ctx->email.data[i]);
    subject=ctx->email.len?ctx->email:ctx->username;
    if(ctx->flow==AUTH_LOGIN && text_equal(&ctx->realm->adapter,"newapi"))subject=ctx->username;
    if(ctx->flow==AUTH_FACTOR && session.len) {
        if(auth_hmac(ctx->realm,"session",session.data,session.len,ctx->subject)!=NGX_OK)return reply(r,ctx,503,"AUTH_SERVICE_UNAVAILABLE");
        ctx->subject_ready=1;
    } else if(subject.len && ascii(&subject)) {
        for(i=0;i<subject.len;i++)subject.data[i]=ngx_tolower(subject.data[i]);
        if(auth_subject(ctx->realm,&subject,ctx->subject)!=NGX_OK)return reply(r,ctx,503,"AUTH_SERVICE_UNAVAILABLE");
        ctx->subject_ready=1;
    } else if(session.len) {
        if(auth_hmac(ctx->realm,"session",session.data,session.len,ctx->subject)!=NGX_OK)return reply(r,ctx,503,"AUTH_SERVICE_UNAVAILABLE");
        ctx->subject_ready=1;
    }
    rc=auth_reserve_subject(ctx);if(rc!=NGX_OK)return reply(r,ctx,rc,rc==403?"REGISTRATION_TEMPORARILY_BLOCKED":rc==429?"TOO_MANY_ATTEMPTS":"AUTH_SERVICE_UNAVAILABLE");
    if(ctx->flow==AUTH_REGISTER || ctx->flow==AUTH_MAIL) {
        if(!ctx->realm->registration)return reply(r,ctx,403,"REGISTRATION_DISABLED");
        if(ctx->realm->strict && (!policy_ready(ctx->realm) || !ctx->realm->allowed->nelts || !ctx->realm->email_verify))
            return reply(r,ctx,503,"REGISTRATION_TEMPORARILY_UNAVAILABLE");
        if(!ctx->email.len)goto invalid;
        if(ascii_email) {
            for(i=0;i<ctx->email.len;i++)if(ctx->email.data[i]=='@'){if(have_at)goto invalid;have_at=1;at=i;}
            if(!have_at || !at || at+1>=ctx->email.len)goto invalid;
            for(i=0;i<ctx->email.len;i++)if(ctx->email.data[i]<=32 || ctx->email.data[i]>=127)goto invalid;
            domain.data=ctx->email.data+at+1;domain.len=ctx->email.len-at-1;
            if(text_equal(&ctx->realm->adapter,"sub2api"))while(domain.len && domain.data[domain.len-1]=='.')domain.len--;
            if(ctx->realm->strict && !auth_domain(ctx->realm,&domain)) {
                auth_outcome(ctx,AUTH_RESULT_REG_POLICY);if(!ctx->observe)return reply(r,ctx,403,"EMAIL_NOT_ALLOWED");
            }
            if(ctx->realm->alias_restriction)for(i=0;i<at;i++)if(ctx->email.data[i]=='+' || ctx->email.data[i]=='.') {
                auth_outcome(ctx,AUTH_RESULT_REG_POLICY);if(!ctx->observe)return reply(r,ctx,403,"EMAIL_ALIAS_NOT_ALLOWED");break;
            }
        }
    }
    if(password.len) {
        rc=auth_weak(ctx->main,password.data,password.len);
        if(rc==NGX_ERROR)return reply(r,ctx,503,"AUTH_SERVICE_UNAVAILABLE");
        ctx->weak_guess=rc;
        if(rc && (ctx->flow==AUTH_REGISTER || ctx->flow==AUTH_RESET)) {
            auth_outcome(ctx,AUTH_RESULT_REG_POLICY);if(!ctx->observe)return reply(r,ctx,400,"WEAK_PASSWORD");
        }
    }
    if(set_private_request(r,ctx)!=NGX_OK)return reply(r,ctx,503,"AUTH_SERVICE_UNAVAILABLE");
    ctx->account_ready=1;return NGX_DECLINED;
invalid:
    if(object)json_object_put(object);
    return reply(r,ctx,400,"INVALID_AUTH_REQUEST");
}
static ngx_str_t json_text(json_object *object,const char *key) {
    ngx_str_t result=ngx_null_string;json_object *value=NULL;
    if(json_object_object_get_ex(object,key,&value) && json_object_get_type(value)==json_type_string) {
        result.data=(u_char *)json_object_get_string(value);result.len=json_object_get_string_len(value);
    }
    return result;
}
static ngx_int_t decode_hex(ngx_str_t *text,u_char *out,size_t bytes) {
    size_t i;ngx_int_t value;
    if(text->len!=bytes*2)return NGX_ERROR;
    for(i=0;i<bytes;i++){value=ngx_hextoi(text->data+i*2,2);if(value==NGX_ERROR)return NGX_ERROR;out[i]=(u_char)value;}
    return NGX_OK;
}
static json_object *private_payload(ngx_http_request_t *r,auth_realm *realm,ngx_str_t *wire,const char *purpose) {
    ngx_str_t encoded,signature,decoded;u_char expected[32],supplied[32];
    if(wire->len<70 || wire->len>2048 || ngx_memcmp(wire->data,"v1.",3) || wire->data[wire->len-65]!='.')return NULL;
    encoded.data=wire->data+3;encoded.len=wire->len-68;signature.data=wire->data+wire->len-64;signature.len=64;
    if(decode_hex(&signature,supplied,32)!=NGX_OK || auth_hmac(realm,purpose,encoded.data,encoded.len,expected)!=NGX_OK
        || CRYPTO_memcmp(expected,supplied,32))return NULL;
    decoded.data=ngx_pnalloc(r->pool,ngx_base64_decoded_length(encoded.len));if(!decoded.data)return NULL;
    if(ngx_decode_base64url(&decoded,&encoded)!=NGX_OK)return NULL;
    return auth_json(decoded.data,decoded.len);
}
static ngx_uint_t outcome_code(ngx_str_t *code) {
    if(text_equal(code,"invalid_credentials"))return AUTH_RESULT_CREDENTIALS;
    if(text_equal(code,"invalid_second_factor"))return AUTH_RESULT_FACTOR;
    if(text_equal(code,"email_policy_rejected") || text_equal(code,"weak_password_rejected"))return AUTH_RESULT_REG_POLICY;
    if(text_equal(code,"invalid_email_code"))return AUTH_RESULT_EMAIL_CODE;
    if(text_equal(code,"login_complete"))return AUTH_RESULT_LOGIN_OK;
    if(text_equal(code,"registration_complete"))return AUTH_RESULT_REG_OK;
    return AUTH_RESULT_OTHER;
}
static ngx_int_t header_filter(ngx_http_request_t *r) {
    auth_request *ctx=find_context(r);ngx_list_part_t *part;ngx_table_elt_t *headers;ngx_str_t wire=ngx_null_string,nonce,code;
    ngx_uint_t i,count=0,outcome;u_char id[16];json_object *payload;ngx_flag_t valid=0;
    if(!ctx || !ctx->realm || ctx->control || r!=r->main)return next_header(r);
    part=&r->headers_out.headers.part;headers=part->elts;
    for(i=0;;i++) {
        if(i>=part->nelts){if(!part->next)break;part=part->next;headers=part->elts;i=0;}
        if(headers[i].key.len>=12 && !ngx_strncasecmp(headers[i].key.data,(u_char *)"X-SCDN-Auth-",12)) {
            if(headers[i].key.len==18 && !ngx_strncasecmp(headers[i].key.data,(u_char *)"X-SCDN-Auth-Result",18)){wire=headers[i].value;count++;}
            headers[i].hash=0;
        }
    }
    if(!ctx->finished && r->upstream && ctx->reserved) {
        ctx->finished=1;
        payload=count==1?private_payload(r,ctx->realm,&wire,"response"):NULL;
        if(payload) {
            nonce=json_text(payload,"attempt");code=json_text(payload,"code");
            if(decode_hex(&nonce,id,16)==NGX_OK && !CRYPTO_memcmp(id,ctx->id,16)) {
                outcome=outcome_code(&code);
                if(r->headers_out.status==429 || r->headers_out.status>=500)outcome=AUTH_RESULT_OTHER;
                if((outcome==AUTH_RESULT_LOGIN_OK || outcome==AUTH_RESULT_REG_OK)
                    && (r->headers_out.status<200 || r->headers_out.status>=300))outcome=AUTH_RESULT_OTHER;
                if((ctx->flow==AUTH_REGISTER || ctx->flow==AUTH_OAUTH) && outcome==AUTH_RESULT_CREDENTIALS)outcome=AUTH_RESULT_OTHER;
                if(outcome==AUTH_RESULT_FACTOR && ctx->flow!=AUTH_FACTOR)outcome=AUTH_RESULT_OTHER;
                auth_outcome(ctx,outcome);valid=1;ctx->feedback_valid=1;
                ctx->result.data=ngx_pnalloc(r->pool,code.len?code.len:1);
                if(ctx->result.data){ngx_memcpy(ctx->result.data,code.data,code.len);ctx->result.len=code.len;}
            }
            json_object_put(payload);
        }
        ngx_shmtx_lock(&ctx->main->slab->mutex);
        if(valid)ctx->main->shared->feedback_ok++;else ctx->main->shared->feedback_bad++;
        ngx_shmtx_unlock(&ctx->main->slab->mutex);
    }
    if(add_header(r,"Cache-Control","no-store")!=NGX_OK)return NGX_ERROR;
    return next_header(r);
}
static ngx_int_t preconfiguration(ngx_conf_t *cf) {
    static ngx_str_t names[]={ngx_string("scdn_auth_realm"),ngx_string("scdn_auth_client_ip"),ngx_string("scdn_auth_result")};
    ngx_http_variable_t *variable;ngx_uint_t i;
    for(i=0;i<3;i++) {
        variable=ngx_http_add_variable(cf,&names[i],NGX_HTTP_VAR_NOCACHEABLE);
        if(!variable)return NGX_ERROR;
        variable->get_handler=auth_variable;variable->data=i;
    }
    return NGX_OK;
}
static ngx_int_t auth_variable(ngx_http_request_t *r,ngx_http_variable_value_t *v,uintptr_t data) {
    auth_request *ctx=find_context(r);ngx_str_t *value;
    if(!ctx || !ctx->realm || ctx->control){v->not_found=1;return NGX_OK;}
    value=data==0?&ctx->realm->id:data==1?&ctx->client:&ctx->result;
    v->data=value->len?value->data:(u_char *)"";v->len=value->len;v->valid=1;v->not_found=0;v->no_cacheable=1;
    return NGX_OK;
}
static ngx_int_t postconfiguration(ngx_conf_t *cf) {
    auth_main *m=ngx_http_conf_get_module_main_conf(cf,ngx_http_scdn_auth_guard_module);
    ngx_http_core_main_conf_t *core=ngx_http_conf_get_module_main_conf(cf,ngx_http_core_module);ngx_http_handler_pt *handler;
    if(m->configured && (!m->policy_loaded || !m->zone || !m->weak)) {
        ngx_conf_log_error(NGX_LOG_EMERG,cf,0,"scdn_auth_guard requires policy, zone and weak-password data");return NGX_ERROR;
    }
    handler=ngx_array_push(&core->phases[NGX_HTTP_PREACCESS_PHASE].handlers);if(!handler)return NGX_ERROR;
    *handler=ngx_http_scdn_auth_prepare;
    next_header=ngx_http_top_header_filter;ngx_http_top_header_filter=header_filter;
    next_body=ngx_http_top_request_body_filter;ngx_http_top_request_body_filter=body_filter;return NGX_OK;
}
static void control_ready(ngx_http_request_t *r) {
    auth_request *ctx=find_context(r);auth_main *m=ctx->main;json_object *object=auth_json(ctx->body,ctx->body_len),*value=NULL;
    ngx_str_t realm_id,operation,nonce,subject,domain,signature,ip_text;auth_realm *realm;auth_realm admin;
    ngx_table_elt_t *header;u_char expected[32],supplied[32],id[16],subject_bytes[32];time_t when;ngx_int_t rc=NGX_HTTP_FORBIDDEN;
    ctx->capturing=0;ctx->ready=1;
    if(!object)goto done;
    realm_id=json_text(object,"realm");operation=json_text(object,"operation");realm=realm_by_name(m,&realm_id);
    if(!realm)goto done;
    header=input_header(r,"X-SCDN-Auth-Control",NULL);if(!header)goto done;
    signature=header->value;
    if(decode_hex(&signature,supplied,32)!=NGX_OK)goto done;
    if(text_equal(&operation,"unban")) {
        if(!m->admin_ready)goto done;
        ngx_memzero(&admin,sizeof(admin));ngx_memcpy(admin.key,m->admin_key,32);
        if(auth_hmac(&admin,"admin",ctx->body,ctx->body_len,expected)!=NGX_OK)goto done;
        OPENSSL_cleanse(admin.key,32);
    } else if(text_equal(&operation,"pre-create")) {
        if(auth_hmac(realm,"control",ctx->body,ctx->body_len,expected)!=NGX_OK)goto done;
    } else goto done;
    if(CRYPTO_memcmp(expected,supplied,32))goto done;
    if(!json_object_object_get_ex(object,"time",&value) || json_object_get_type(value)!=json_type_int)goto done;
    when=(time_t)json_object_get_int64(value);
    if(when<ngx_time()-30 || when>ngx_time()+30)goto done;
    if(text_equal(&operation,"unban")) {
        scdn_sec_ip ip;ip_text=json_text(object,"ip");
        if(scdn_sec_parse_ip(r->pool,ip_text,&ip)!=NGX_OK)goto done;
        rc=auth_unban(m,realm,&ip)==NGX_OK?NGX_HTTP_OK:NGX_HTTP_SERVICE_UNAVAILABLE;
    } else {
        nonce=json_text(object,"attempt");subject=json_text(object,"subject");domain=json_text(object,"domain");
        if(decode_hex(&nonce,id,16)!=NGX_OK || decode_hex(&subject,subject_bytes,32)!=NGX_OK
            || !policy_ready(realm) || !realm->registration || !realm->email_verify || !auth_domain(realm,&domain))goto done;
        if(!json_object_object_get_ex(object,"verified",&value) || json_object_get_type(value)!=json_type_boolean || !json_object_get_boolean(value))goto done;
        if(!json_object_object_get_ex(object,"weak",&value) || json_object_get_type(value)!=json_type_boolean || json_object_get_boolean(value))goto done;
        rc=auth_precreate(m,realm,id,subject_bytes,1)==NGX_OK?NGX_HTTP_OK:NGX_HTTP_FORBIDDEN;
    }
done:
    if(object)json_object_put(object);
    (void)reply(r,ctx,rc,rc==200?"ALLOWED":"CREATION_NOT_ALLOWED");
}
static ngx_int_t control_handler(ngx_http_request_t *r) {
    auth_main *m=ngx_http_get_module_main_conf(r,ngx_http_scdn_auth_guard_module);auth_request *ctx;ngx_int_t rc;
    if(r->method!=NGX_HTTP_POST)return NGX_HTTP_NOT_ALLOWED;
    if(!m->shared || !m->policy_loaded)return NGX_HTTP_SERVICE_UNAVAILABLE;
    ctx=new_context(r,m);if(!ctx)return NGX_HTTP_SERVICE_UNAVAILABLE;ctx->control=1;
    if(r->headers_in.content_length_n>4096)return reply(r,ctx,413,"CONTROL_REQUEST_TOO_LARGE");
    ctx->body=ngx_pnalloc(r->pool,4096);if(!ctx->body)return NGX_HTTP_SERVICE_UNAVAILABLE;
    ctx->capturing=1;
    if(r->request_body){rc=capture(ctx,r->request_body->bufs);if(rc!=NGX_OK)return reply(r,ctx,rc,"CONTROL_BODY_UNAVAILABLE");control_ready(r);return NGX_DONE;}
    rc=ngx_http_read_client_request_body(r,control_ready);
    if(rc>=NGX_HTTP_SPECIAL_RESPONSE)return rc;
    return NGX_DONE;
}
static ngx_int_t status_handler(ngx_http_request_t *r) {
    auth_main *m=ngx_http_get_module_main_conf(r,ngx_http_scdn_auth_guard_module);ngx_buf_t *buffer;ngx_chain_t out;ngx_int_t rc;
    if(!(r->method&(NGX_HTTP_GET|NGX_HTTP_HEAD)))return NGX_HTTP_NOT_ALLOWED;
    buffer=ngx_create_temp_buf(r->pool,2048);if(!buffer)return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if(m->shared)ngx_shmtx_lock(&m->slab->mutex);
    buffer->last=ngx_sprintf(buffer->last,"{\"version\":1,\"realms\":%ui,\"weak_values\":%ui,\"active\":%ui,\"buckets\":%ui,\"admitted\":%uL,\"rejected\":%uL,\"ip_blocks\":%uL,\"feedback_ok\":%uL,\"feedback_bad\":%uL,\"precreated\":%uL,\"capabilities\":{\"local_shared_state\":true,\"precreate_endpoint\":true,\"durable_ip_bans\":false,\"global_quota\":false}}\n",
        m->realm_count,m->weak_count,m->shared?m->shared->active:0,m->shared?m->shared->bucket_count:0,
        m->shared?m->shared->admitted:0,m->shared?m->shared->rejected:0,m->shared?m->shared->banned:0,
        m->shared?m->shared->feedback_ok:0,m->shared?m->shared->feedback_bad:0,m->shared?m->shared->precreated:0);
    if(m->shared)ngx_shmtx_unlock(&m->slab->mutex);
    if(add_header(r,"Cache-Control","no-store")!=NGX_OK)return NGX_HTTP_INTERNAL_SERVER_ERROR;
    r->headers_out.status=200;r->headers_out.content_length_n=buffer->last-buffer->pos;
    ngx_str_set(&r->headers_out.content_type,"application/json");buffer->last_buf=r==r->main;buffer->last_in_chain=1;
    rc=ngx_http_send_header(r);if(rc==NGX_ERROR || rc>NGX_OK || r->header_only)return rc;
    out.buf=buffer;out.next=NULL;return ngx_http_output_filter(r,&out);
}
static char *control_directive(ngx_conf_t *cf,ngx_command_t *cmd,void *data) {
    ngx_http_core_loc_conf_t *core=ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);(void)cmd;(void)data;
    if(core->handler)return "scdn_auth_control conflicts with content handler";
    core->handler=control_handler;return NGX_CONF_OK;
}
static char *status_directive(ngx_conf_t *cf,ngx_command_t *cmd,void *data) {
    ngx_http_core_loc_conf_t *core=ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);(void)cmd;(void)data;
    if(core->handler)return "scdn_auth_status conflicts with content handler";
    core->handler=status_handler;return NGX_CONF_OK;
}
ngx_int_t ngx_http_scdn_auth_prepare(ngx_http_request_t *r) {
    auth_main *m=ngx_http_get_module_main_conf(r,ngx_http_scdn_auth_guard_module);
    auth_location *l;auth_request *ctx;scdn_sec_ip peer;ngx_flag_t forwarded,duplicate=0;
    ngx_uint_t flow;ngx_int_t rc;ngx_table_elt_t *encoding;
    if(!m->configured || r!=r->main)return NGX_DECLINED;
    ctx=find_context(r);
    if(ctx) {
        if(ctx->control || !ctx->realm)return NGX_DECLINED;
        if(ctx->ready)return finish_prepare(r,ctx);
        return NGX_DONE;
    }
    l=ngx_http_get_module_loc_conf(r,ngx_http_scdn_auth_guard_module);
    if(l->realm<0) {
        ctx=new_context(r,m);if(!ctx)return NGX_HTTP_SERVICE_UNAVAILABLE;ctx->account_ready=1;return NGX_DECLINED;
    }
    flow=route_flow(&m->realms[l->realm],r);if(!flow)return NGX_DECLINED;
    ctx=new_context(r,m);if(!ctx)return NGX_HTTP_SERVICE_UNAVAILABLE;
    ctx->realm=&m->realms[l->realm];ctx->flow=flow;ctx->observe=!l->mode;
    if(scdn_sec_client(r,m->proxies,&peer,&ctx->ip,&forwarded)!=NGX_OK)return reply(r,ctx,400,"INVALID_CLIENT_ADDRESS");
    ctx->client=scdn_sec_text(r->pool,&ctx->ip);
    if(!ctx->client.data || RAND_bytes(ctx->id,16)!=1)return reply(r,ctx,503,"AUTH_SERVICE_UNAVAILABLE");
    rc=auth_reserve(ctx);if(rc!=NGX_OK)return reply(r,ctx,rc,rc==403?"REGISTRATION_TEMPORARILY_BLOCKED":rc==429?"TOO_MANY_ATTEMPTS":"AUTH_SERVICE_UNAVAILABLE");
    ngx_memzero(&ctx->deadline,sizeof(ctx->deadline));ctx->deadline.handler=deadline_handler;ctx->deadline.data=ctx;ctx->deadline.log=r->connection->log;
    ngx_add_timer(&ctx->deadline,AUTH_DEADLINE);
    encoding=input_header(r,"Content-Encoding",&duplicate);
    if(duplicate || (encoding && !text_equal(&encoding->value,"identity")))return reply(r,ctx,415,"UNSUPPORTED_AUTH_ENCODING");
    if(r->headers_in.content_length_n>AUTH_BODY_LIMIT)return reply(r,ctx,413,"AUTH_REQUEST_TOO_LARGE");
    ctx->body=ngx_pnalloc(r->pool,AUTH_BODY_LIMIT);if(!ctx->body)return reply(r,ctx,503,"AUTH_SERVICE_UNAVAILABLE");
    if(r->request_body) {
        if(r->request_body->temp_file || capture(ctx,r->request_body->bufs)!=NGX_OK)return reply(r,ctx,503,"AUTH_BODY_UNAVAILABLE");
        ctx->ready=1;return finish_prepare(r,ctx);
    }
    if(r->method==NGX_HTTP_GET || (r->headers_in.content_length_n==0 && !r->headers_in.chunked)) {
        ctx->ready=1;return finish_prepare(r,ctx);
    }
    ctx->capturing=1;r->request_body_in_single_buf=1;
    rc=ngx_http_read_client_request_body(r,body_ready);
    if(rc>=NGX_HTTP_SPECIAL_RESPONSE)return rc;
    ngx_http_finalize_request(r,NGX_DONE);return NGX_DONE;
}
