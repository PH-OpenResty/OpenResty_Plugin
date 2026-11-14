#include "scdn_purge.h"

typedef struct {
    uint32_t hash;
    uint64_t sequence, used;
    ngx_str_t scope,key,resource,value;
    u_char *allocation;
} scdn_purge_lru_t;

typedef struct {
    ngx_http_request_t *request;
    scdn_purge_location_t *location;
    ngx_str_t value;
} scdn_purge_request_t;

static scdn_purge_lru_t *purge_lru;
static ngx_uint_t purge_lru_count;
static uint64_t purge_clock,purge_hits,purge_misses;

static void *purge_main(ngx_conf_t *cf);
static void *purge_location(ngx_conf_t *cf);
static char *purge_merge(ngx_conf_t *cf,void *parent,void *child);
static char *purge_zone(ngx_conf_t *cf,ngx_command_t *cmd,void *data);
static char *purge_key(ngx_conf_t *cf,ngx_command_t *cmd,void *data);
static char *purge_api(ngx_conf_t *cf,ngx_command_t *cmd,void *data);
static ngx_int_t purge_preconfiguration(ngx_conf_t *cf);
static ngx_int_t purge_postconfiguration(ngx_conf_t *cf);
static ngx_int_t purge_worker(ngx_cycle_t *cycle);
static void purge_exit(ngx_cycle_t *cycle);
static ngx_int_t purge_handler(ngx_http_request_t *r);
static ngx_int_t purge_variable(ngx_http_request_t *r,ngx_http_variable_value_t *v,uintptr_t data);

static ngx_command_t purge_commands[]={
    {ngx_string("scdn_purge_zone"),NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
     purge_zone,NGX_HTTP_MAIN_CONF_OFFSET,0,NULL},
    {ngx_string("scdn_purge_journal"),NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,NGX_HTTP_MAIN_CONF_OFFSET,offsetof(scdn_purge_main_t,journal),NULL},
    {ngx_string("scdn_purge_token_file"),NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,NGX_HTTP_MAIN_CONF_OFFSET,offsetof(scdn_purge_main_t,token_file),NULL},
    {ngx_string("scdn_purge_cache_entries"),NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_num_slot,NGX_HTTP_MAIN_CONF_OFFSET,offsetof(scdn_purge_main_t,lru_entries),NULL},
    {ngx_string("scdn_purge_allow_all"),NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
     ngx_conf_set_flag_slot,NGX_HTTP_MAIN_CONF_OFFSET,offsetof(scdn_purge_main_t,allow_all),NULL},
    {ngx_string("scdn_purge_checkpoint"),NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
     ngx_conf_set_size_slot,NGX_HTTP_MAIN_CONF_OFFSET,offsetof(scdn_purge_main_t,checkpoint),NULL},
    {ngx_string("scdn_purge_key"),NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2|NGX_CONF_TAKE3,
     purge_key,NGX_HTTP_LOC_CONF_OFFSET,0,NULL},
    {ngx_string("scdn_purge_api"),NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
     purge_api,NGX_HTTP_LOC_CONF_OFFSET,1,NULL},
    {ngx_string("scdn_purge_status"),NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
     purge_api,NGX_HTTP_LOC_CONF_OFFSET,2,NULL},
    ngx_null_command
};

static ngx_http_module_t purge_context={
    purge_preconfiguration,purge_postconfiguration,purge_main,NULL,
    NULL,NULL,purge_location,purge_merge
};
ngx_module_t ngx_http_scdn_purge_module={
    NGX_MODULE_V1,&purge_context,purge_commands,NGX_HTTP_MODULE,
    NULL,NULL,purge_worker,NULL,NULL,purge_exit,NULL,NGX_MODULE_V1_PADDING
};

static void *purge_main(ngx_conf_t *cf)
{
    scdn_purge_main_t *main=ngx_pcalloc(cf->pool,sizeof(*main));
    if(main==NULL) return NULL;
    main->lru_entries=NGX_CONF_UNSET_UINT;main->allow_all=NGX_CONF_UNSET;main->checkpoint=NGX_CONF_UNSET_SIZE;main->owner_fd=-1;
    if(ngx_array_init(&main->locations,cf->pool,4,sizeof(scdn_purge_location_t *))!=NGX_OK) return NULL;
    return main;
}
static void *purge_location(ngx_conf_t *cf)
{ return ngx_pcalloc(cf->pool,sizeof(scdn_purge_location_t)); }

static char *purge_merge(ngx_conf_t *cf,void *parent,void *child)
{
    scdn_purge_location_t *previous=parent,*conf=child;
    ngx_http_core_loc_conf_t *core;
    if(!conf->configured && previous->configured) {
        conf->scope=previous->scope;conf->key=previous->key;conf->configured=1;
        conf->resource=previous->resource;conf->has_resource=previous->has_resource;
    }
    core=ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);
    if(conf->api && core->handler!=purge_handler) return "scdn_purge endpoint conflicts with another content handler";
    return NGX_CONF_OK;
}

static char *purge_zone(ngx_conf_t *cf,ngx_command_t *cmd,void *data)
{
    scdn_purge_main_t *main=data;
    ngx_str_t *values=cf->args->elts;
    ssize_t size=ngx_parse_size(&values[2]);
    (void)cmd;
    if(main->zone) return "is duplicate";
    if(size<1024*1024 || size>64*1024*1024) return "requires a zone from 1m to 64m";
    main->zone=ngx_shared_memory_add(cf,&values[1],size,&ngx_http_scdn_purge_module);
    if(main->zone==NULL) return NGX_CONF_ERROR;
    main->zone->data=main;main->zone->init=scdn_purge_zone_init;
    return NGX_CONF_OK;
}

static char *purge_key(ngx_conf_t *cf,ngx_command_t *cmd,void *data)
{
    scdn_purge_location_t *conf=data,**entry;
    scdn_purge_main_t *main;
    ngx_str_t *values=cf->args->elts;
    ngx_http_compile_complex_value_t compile;
    (void)cmd;
    if(conf->configured) return "is duplicate";
    if(ngx_strstr(values[1].data,"$scdn_purge_key") || ngx_strstr(values[2].data,"$scdn_purge_key"))
        return "cannot recursively reference $scdn_purge_key";
    ngx_memzero(&compile,sizeof(compile));compile.cf=cf;
    compile.value=&values[1];compile.complex_value=&conf->scope;
    if(ngx_http_compile_complex_value(&compile)!=NGX_OK) return NGX_CONF_ERROR;
    if(cf->args->nelts==4) {
        if(ngx_strstr(values[3].data,"$scdn_purge_key"))return "cannot recursively reference $scdn_purge_key";
        compile.value=&values[3];compile.complex_value=&conf->resource;
        if(ngx_http_compile_complex_value(&compile)!=NGX_OK)return NGX_CONF_ERROR;
        conf->has_resource=1;
    }
    compile.value=&values[2];compile.complex_value=&conf->key;
    if(ngx_http_compile_complex_value(&compile)!=NGX_OK) return NGX_CONF_ERROR;
    conf->configured=1;
    main=ngx_http_conf_get_module_main_conf(cf,ngx_http_scdn_purge_module);
    entry=ngx_array_push(&main->locations);if(entry==NULL) return NGX_CONF_ERROR;
    *entry=conf;
    return NGX_CONF_OK;
}

static char *purge_api(ngx_conf_t *cf,ngx_command_t *cmd,void *data)
{
    scdn_purge_location_t *conf=data,**entry;
    scdn_purge_main_t *main;
    ngx_http_core_loc_conf_t *core=ngx_http_conf_get_module_loc_conf(cf,ngx_http_core_module);
    if(conf->api || core->handler) return "conflicts with another content handler";
    conf->api=cmd->offset;core->handler=purge_handler;
    main=ngx_http_conf_get_module_main_conf(cf,ngx_http_scdn_purge_module);
    entry=ngx_array_push(&main->locations);if(entry==NULL) return NGX_CONF_ERROR;
    *entry=conf;
    return NGX_CONF_OK;
}

static void clear_token(void *data)
{
    ngx_str_t *token=data;
    volatile u_char *p=token->data;
    size_t n=token->len;
    while(n--) *p++=0;
}

static int load_token(ngx_conf_t *cf,scdn_purge_main_t *main)
{
    int fd;
    struct stat st;
    ssize_t n;
    size_t i,length;
    u_char bytes[131];
    ngx_pool_cleanup_t *cleanup;
    if(main->token_file.len<2 || main->token_file.data[0]!='/') return 0;
    fd=open((char *)main->token_file.data,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    if(fd<0) return 0;
    if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || (st.st_mode&077)!=0 || st.st_size<43 || st.st_size>130) {
        close(fd);return 0;
    }
    n=read(fd,bytes,sizeof(bytes));close(fd);
    if(n<43) return 0;
    length=(size_t)n;
    if(bytes[length-1]=='\n') { length--;if(length && bytes[length-1]=='\r')length--; }
    if(length<43 || length>128) return 0;
    for(i=0;i<length;i++) if(!((bytes[i]>='a'&&bytes[i]<='z')||(bytes[i]>='A'&&bytes[i]<='Z')
        ||(bytes[i]>='0'&&bytes[i]<='9')||bytes[i]=='_'||bytes[i]=='-')) return 0;
    main->token.data=ngx_pnalloc(cf->pool,length);
    cleanup=ngx_pool_cleanup_add(cf->pool,0);
    if(main->token.data==NULL || cleanup==NULL) return 0;
    main->token.len=length;ngx_memcpy(main->token.data,bytes,length);ngx_memzero(bytes,sizeof(bytes));
    cleanup->handler=clear_token;cleanup->data=&main->token;
    return 1;
}

static void close_owner(void *data)
{
    scdn_purge_main_t *main=data;
    if(main->owner_fd>=0) { close(main->owner_fd);main->owner_fd=-1; }
}

static ngx_int_t own_journal(ngx_conf_t *cf,scdn_purge_main_t *main)
{
    ngx_cycle_t *old_cycle=cf->cycle->old_cycle;
    ngx_list_part_t *part;
    ngx_shm_zone_t *zones;
    scdn_purge_main_t *previous=NULL;
    ngx_uint_t i;
    u_char *path;
    struct stat st;
    ngx_pool_cleanup_t *cleanup;
    if(old_cycle!=NULL && old_cycle->shared_memory.part.elts!=NULL) {
        part=&old_cycle->shared_memory.part;zones=part->elts;
        for(i=0;;i++) {
            if(i>=part->nelts) { if(part->next==NULL)break;part=part->next;zones=part->elts;i=0; }
            if(zones[i].tag==&ngx_http_scdn_purge_module) { previous=zones[i].data;break; }
        }
    }
    if(previous!=NULL
       && (previous->zone->shm.name.len!=main->zone->shm.name.len
           || ngx_memcmp(previous->zone->shm.name.data,main->zone->shm.name.data,main->zone->shm.name.len)!=0
           || previous->zone->shm.size!=main->zone->shm.size
           || previous->journal.len!=main->journal.len
           || ngx_memcmp(previous->journal.data,main->journal.data,main->journal.len)!=0)) {
        ngx_conf_log_error(NGX_LOG_EMERG,cf,0,"scdn_purge state identity/size changes require a full stop and restart");return NGX_ERROR;
    }
    if(ngx_test_config || ngx_process==NGX_PROCESS_SIGNALLER)return NGX_OK;
    if(previous!=NULL && previous->owner_fd>=0)main->owner_fd=dup(previous->owner_fd);
    else {
        path=ngx_pnalloc(cf->pool,main->journal.len+7);if(path==NULL)return NGX_ERROR;
        ngx_memcpy(path,main->journal.data,main->journal.len);ngx_memcpy(path+main->journal.len,".owner",7);
        main->owner_fd=open((char *)path,O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
        if(main->owner_fd<0 || fstat(main->owner_fd,&st)!=0 || !S_ISREG(st.st_mode)
           || (st.st_mode&077)!=0 || flock(main->owner_fd,LOCK_EX|LOCK_NB)!=0) {
            close_owner(main);
            ngx_conf_log_error(NGX_LOG_EMERG,cf,0,"scdn_purge journal already owned or owner lock unavailable");return NGX_ERROR;
        }
    }
    if(main->owner_fd<0)return NGX_ERROR;
    if(fcntl(main->owner_fd,F_SETFD,FD_CLOEXEC)<0) { close_owner(main);return NGX_ERROR; }
    cleanup=ngx_pool_cleanup_add(cf->pool,0);if(cleanup==NULL) { close_owner(main);return NGX_ERROR; }
    cleanup->handler=close_owner;cleanup->data=main;
    return NGX_OK;
}

static ngx_int_t purge_postconfiguration(ngx_conf_t *cf)
{
    scdn_purge_main_t *main=ngx_http_conf_get_module_main_conf(cf,ngx_http_scdn_purge_module);
    scdn_purge_location_t **locations=main->locations.elts;
    ngx_str_t pool=ngx_string("scdn_cache_purge");
    ngx_uint_t i;
    ngx_flag_t api=0;
    if(main->locations.nelts==0 && main->zone==NULL && main->journal.len==0) return NGX_OK;
    if(main->zone==NULL || main->journal.len<2 || main->journal.data[0]!='/') {
        ngx_conf_log_error(NGX_LOG_EMERG,cf,0,"scdn_purge requires a shared zone and absolute journal path");return NGX_ERROR;
    }
    ngx_conf_init_uint_value(main->lru_entries,1024);ngx_conf_init_value(main->allow_all,0);
    ngx_conf_init_size_value(main->checkpoint,SCDN_PURGE_JOURNAL);
    if(main->checkpoint<65536 || main->checkpoint>SCDN_PURGE_JOURNAL)return NGX_ERROR;
    if(main->lru_entries<64 || main->lru_entries>16384 || (main->lru_entries&(main->lru_entries-1))) {
        ngx_conf_log_error(NGX_LOG_EMERG,cf,0,"scdn_purge cache entries must be a power of two from 64 to 16384");return NGX_ERROR;
    }
    for(i=0;i<main->locations.nelts;i++) if(locations[i]->api)api=1;
    if(api && !load_token(cf,main)) {
        ngx_conf_log_error(NGX_LOG_EMERG,cf,0,"scdn_purge API requires a private regular token file (43 to 128 base64url characters)");return NGX_ERROR;
    }
    if(api) {
        main->threads=ngx_thread_pool_add(cf,&pool);
        if(main->threads==NULL) return NGX_ERROR;
    }
    return own_journal(cf,main);
}

static ngx_int_t purge_preconfiguration(ngx_conf_t *cf)
{
    ngx_str_t name=ngx_string("scdn_purge_key");
    ngx_http_variable_t *variable=ngx_http_add_variable(cf,&name,NGX_HTTP_VAR_NOCACHEABLE);
    if(variable==NULL) return NGX_ERROR;
    variable->get_handler=purge_variable;
    return NGX_OK;
}

static ngx_int_t purge_worker(ngx_cycle_t *cycle)
{
    scdn_purge_main_t *main;
    if(ngx_process!=NGX_PROCESS_WORKER && ngx_process!=NGX_PROCESS_SINGLE) return NGX_OK;
    main=ngx_http_cycle_get_module_main_conf(cycle,ngx_http_scdn_purge_module);
    if(main==NULL || main->zone==NULL) return NGX_OK;
    purge_lru_count=main->lru_entries;
    purge_lru=ngx_calloc(purge_lru_count*sizeof(*purge_lru),cycle->log);
    return purge_lru!=NULL?NGX_OK:NGX_ERROR;
}
static void purge_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t i;(void)cycle;
    if(purge_lru) {
        for(i=0;i<purge_lru_count;i++) if(purge_lru[i].allocation)ngx_free(purge_lru[i].allocation);
        ngx_free(purge_lru);purge_lru=NULL;
    }
}

static void request_key_cleanup(void *data) { (void)data; }
static int valid_bytes(ngx_str_t *value,size_t maximum)
{
    size_t i;
    if(value->len==0 || value->len>maximum) return 0;
    for(i=0;i<value->len;i++) if(value->data[i]<32 || value->data[i]==127) return 0;
    return 1;
}

static int valid_scope(ngx_str_t *value)
{
    return valid_bytes(value,SCDN_PURGE_SCOPE)
           && value->data[0]!=' ' && value->data[value->len-1]!=' ';
}

static ngx_int_t purge_variable(ngx_http_request_t *r,ngx_http_variable_value_t *v,uintptr_t data)
{
    scdn_purge_main_t *main;
    scdn_purge_location_t *location;
    scdn_purge_request_t *context;
    scdn_purge_lru_t *entry,*selected;
    ngx_pool_cleanup_t *cleanup;
    ngx_str_t scope,key,resource;
    uint32_t hash;
    uint64_t sequence,epoch;
    ngx_uint_t i,bucket;
    u_char *out;
    size_t length;
    ngx_flag_t distinct;
    (void)data;
    main=ngx_http_get_module_main_conf(r,ngx_http_scdn_purge_module);
    location=ngx_http_get_module_loc_conf(r,ngx_http_scdn_purge_module);
    if(!location->configured || main->shared==NULL || purge_lru==NULL) return NGX_ERROR;
    for(cleanup=r->pool->cleanup;cleanup;cleanup=cleanup->next) {
        if(cleanup->handler==request_key_cleanup) {
            context=cleanup->data;
            if(context->request==r && context->location==location) goto found;
        }
    }
    if(ngx_http_complex_value(r,&location->scope,&scope)!=NGX_OK
       || ngx_http_complex_value(r,&location->key,&key)!=NGX_OK
       || !valid_scope(&scope) || !valid_bytes(&key,SCDN_PURGE_KEY)) return NGX_ERROR;
    resource=key;
    if(location->has_resource
       && (ngx_http_complex_value(r,&location->resource,&resource)!=NGX_OK
           || !valid_bytes(&resource,SCDN_PURGE_KEY)))return NGX_ERROR;
    distinct=resource.len!=key.len || ngx_memcmp(resource.data,key.data,key.len)!=0;
    hash=scdn_purge_hash('E',&scope,&resource);
    sequence=(uint64_t)main->shared->sequence;ngx_memory_barrier();
    bucket=(hash%(purge_lru_count/4))*4;selected=&purge_lru[bucket];
    for(i=0;i<4;i++) {
        entry=&purge_lru[bucket+i];
        if(entry->allocation && entry->sequence==sequence && entry->hash==hash
           && entry->scope.len==scope.len && entry->key.len==key.len && entry->resource.len==resource.len
           && ngx_memcmp(entry->scope.data,scope.data,scope.len)==0
           && ngx_memcmp(entry->key.data,key.data,key.len)==0
           && ngx_memcmp(entry->resource.data,resource.data,resource.len)==0) {
            selected=entry;purge_hits++;goto cached;
        }
        if(entry->used<selected->used)selected=entry;
    }
    purge_misses++;
    epoch=scdn_purge_epoch(main,&scope,&resource,&sequence);
    if(selected->allocation)ngx_free(selected->allocation);
    ngx_memzero(selected,sizeof(*selected));
    length=scope.len+key.len+(distinct?resource.len:0)+128;
    selected->allocation=ngx_alloc(scope.len+key.len+(distinct?resource.len:0)+length,r->connection->log);
    if(selected->allocation==NULL) return NGX_ERROR;
    selected->scope.data=selected->allocation;selected->scope.len=scope.len;
    selected->key.data=selected->allocation+scope.len;selected->key.len=key.len;
    selected->resource.data=distinct?selected->allocation+scope.len+key.len:selected->key.data;
    selected->resource.len=resource.len;
    ngx_memcpy(selected->scope.data,scope.data,scope.len);ngx_memcpy(selected->key.data,key.data,key.len);
    if(distinct)ngx_memcpy(selected->resource.data,resource.data,resource.len);
    selected->value.data=selected->allocation+scope.len+key.len+(distinct?resource.len:0);
    out=ngx_snprintf(selected->value.data,length,"SCDN1:%s:%uz:%V:%016xL:%uz:%V",
        main->shared->identity_hex,scope.len,&scope,epoch,key.len,&key);
    if(distinct) {
        out=ngx_snprintf(out,selected->value.data+length-out,":%uz:%V",resource.len,&resource);
    }
    selected->value.len=out-selected->value.data;
    selected->sequence=sequence;selected->hash=hash;
cached:
    selected->used=++purge_clock;
    cleanup=ngx_pool_cleanup_add(r->pool,sizeof(*context));if(cleanup==NULL)return NGX_ERROR;
    context=cleanup->data;context->request=r;context->location=location;
    context->value.data=ngx_palloc(r->pool,ngx_align(selected->value.len,NGX_ALIGNMENT));
    if(context->value.data==NULL)return NGX_ERROR;
    context->value.len=selected->value.len;ngx_memcpy(context->value.data,selected->value.data,selected->value.len);
    cleanup->handler=request_key_cleanup;
found:
    v->data=context->value.data;v->len=context->value.len;v->valid=1;v->no_cacheable=1;v->not_found=0;
    return NGX_OK;
}

static ngx_int_t reply(ngx_http_request_t *r,ngx_uint_t status,const char *error,
    uint64_t sequence,ngx_uint_t count)
{
    ngx_buf_t *buffer=ngx_create_temp_buf(r->pool,1024);
    ngx_chain_t chain;
    ngx_table_elt_t *header;
    ngx_int_t rc;
    if(buffer==NULL)return NGX_HTTP_INTERNAL_SERVER_ERROR;
    if(status>=400)r->keepalive=0;
    if(error)buffer->last=ngx_snprintf(buffer->last,1024,"{\"ok\":false,\"error\":\"%s\"}\n",error);
    else buffer->last=ngx_snprintf(buffer->last,1024,
        "{\"ok\":true,\"sequence\":%uL,\"operations\":%ui,\"durable\":true,\"physical_deleted\":false}\n",sequence,count);
    header=ngx_list_push(&r->headers_out.headers);if(header==NULL)return NGX_HTTP_INTERNAL_SERVER_ERROR;
    header->hash=1;ngx_str_set(&header->key,"Cache-Control");ngx_str_set(&header->value,"no-store");
    if(status==401) {
        header=ngx_list_push(&r->headers_out.headers);if(header==NULL)return NGX_HTTP_INTERNAL_SERVER_ERROR;
        header->hash=1;ngx_str_set(&header->key,"WWW-Authenticate");
        ngx_str_set(&header->value,"Bearer realm=\"scdn-cache-purge\"");
    }
    ngx_str_set(&r->headers_out.content_type,"application/json");
    r->headers_out.status=status;r->headers_out.content_length_n=buffer->last-buffer->pos;
    buffer->last_buf=r==r->main;buffer->last_in_chain=1;chain.buf=buffer;chain.next=NULL;
    rc=ngx_http_send_header(r);if(rc==NGX_ERROR || rc>NGX_OK || r->header_only)return rc;
    return ngx_http_output_filter(r,&chain);
}

static ngx_flag_t local_transport(ngx_http_request_t *r)
{
    struct sockaddr_storage peer;socklen_t length=sizeof(peer);
    if(getpeername(r->connection->fd,(struct sockaddr *)&peer,&length)!=0)return 0;
    if(peer.ss_family==AF_UNIX)return 1;
    if(peer.ss_family==AF_INET)return (ntohl(((struct sockaddr_in *)&peer)->sin_addr.s_addr)>>24)==127;
#if (NGX_HAVE_INET6)
    if(peer.ss_family==AF_INET6)return IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *)&peer)->sin6_addr);
#endif
    return 0;
}

static ngx_str_t *find_header(ngx_http_request_t *r,const char *name)
{
    ngx_list_part_t *part=&r->headers_in.headers.part;
    ngx_table_elt_t *headers=part->elts;
    ngx_str_t *found=NULL;
    ngx_uint_t i;
    size_t length=ngx_strlen(name);
    for(i=0;;i++) {
        if(i>=part->nelts) { if(part->next==NULL)break;part=part->next;headers=part->elts;i=0; }
        if(headers[i].key.len==length && ngx_strncasecmp(headers[i].key.data,(u_char *)name,length)==0) {
            if(found)return NULL;
            found=&headers[i].value;
        }
    }
    return found;
}

static int authorize(ngx_http_request_t *r,scdn_purge_main_t *main)
{
    ngx_table_elt_t *header=r->headers_in.authorization;
    size_t i;
    volatile u_char different=0;
    if(header==NULL || header->value.len!=main->token.len+7
       || ngx_strncasecmp(header->value.data,(u_char *)"Bearer ",7)!=0)return 0;
    for(i=0;i<main->token.len;i++)different|=header->value.data[i+7]^main->token.data[i];
    return different==0;
}

static void complete(ngx_event_t *event)
{
    scdn_purge_job_t *job=event->data;
    ngx_http_request_t *r=job->request;
    ngx_connection_t *connection=r->connection;
    r->main->blocked--;r->aio=0;
    if(r->main->terminated) { connection->write->handler(connection->write);return; }
    ngx_http_finalize_request(r,reply(r,job->status,job->error,job->sequence,job->count));
    ngx_http_run_posted_requests(connection);
}

static void body_ready(ngx_http_request_t *r)
{
    scdn_purge_main_t *main=ngx_http_get_module_main_conf(r,ngx_http_scdn_purge_module);
    ngx_str_t *mode=find_header(r,"X-SCDN-Purge-Mode"),*scope=find_header(r,"X-SCDN-Purge-Scope");
    ngx_thread_task_t *task;
    scdn_purge_job_t *job;
    ngx_chain_t *chain;
    u_char *bytes,*p,*end,*start;
    size_t length=0;
    u_char kind;
    if(mode==NULL)goto invalid;
    if(mode->len==5 && ngx_memcmp(mode->data,"exact",5)==0)kind='E';
    else if(mode->len==6 && ngx_memcmp(mode->data,"prefix",6)==0)kind='P';
    else if(mode->len==5 && ngx_memcmp(mode->data,"scope",5)==0)kind='S';
    else if(mode->len==3 && ngx_memcmp(mode->data,"all",3)==0)kind='A';
    else goto invalid;
    if(kind=='A' && !main->allow_all) {
        ngx_http_finalize_request(r,reply(r,403,"all_disabled",0,0));return;
    }
    if(kind!='A' && (scope==NULL || !valid_scope(scope)))goto invalid;
    if(r->request_body!=NULL && r->request_body->temp_file)goto invalid;
    for(chain=r->request_body!=NULL?r->request_body->bufs:NULL;chain;chain=chain->next) {
        if(ngx_buf_size(chain->buf)==0)continue;
        if(!ngx_buf_in_memory(chain->buf))goto invalid;
        length+=(size_t)(chain->buf->last-chain->buf->pos);
        if(length>SCDN_PURGE_BODY)goto invalid;
    }
    if((kind=='S' || kind=='A') && length!=0)goto invalid;
    if((kind=='E' || kind=='P') && length==0)goto invalid;
    task=ngx_thread_task_alloc(r->pool,sizeof(*job));if(task==NULL)goto failed;
    job=task->ctx;ngx_memzero(job,sizeof(*job));job->main=main;job->request=r;
    if(kind=='S' || kind=='A') {
        job->count=1;job->operations[0].mode=kind;
        if(kind=='S') { job->operations[0].scope=*scope; }
        else { ngx_str_set(&job->operations[0].scope,""); }
        ngx_str_set(&job->operations[0].key,"");
    } else {
        bytes=ngx_pnalloc(r->pool,length);if(bytes==NULL)goto failed;p=bytes;
        for(chain=r->request_body->bufs;chain;chain=chain->next) {
            if(chain->buf->last!=chain->buf->pos)
                p=ngx_cpymem(p,chain->buf->pos,(size_t)(chain->buf->last-chain->buf->pos));
        }
        p=bytes;end=bytes+length;
        while(p<end) {
            start=p;while(p<end && *p!='\n')p++;
            if(job->count==SCDN_PURGE_BATCH)goto invalid;
            job->operations[job->count].mode=kind;job->operations[job->count].scope=*scope;
            job->operations[job->count].key.data=start;
            job->operations[job->count].key.len=p-start;
            if(!valid_bytes(&job->operations[job->count].key,SCDN_PURGE_KEY))goto invalid;
            job->count++;if(p<end)p++;
        }
    }
    task->handler=scdn_purge_commit;task->event.handler=complete;
    task->event.data=job;task->event.log=r->connection->log;
    r->main->blocked++;r->aio=1;
    if(ngx_thread_task_post(main->threads,task)!=NGX_OK) {
        r->main->blocked--;r->aio=0;goto failed;
    }
    return;
invalid:
    ngx_http_finalize_request(r,reply(r,400,"invalid_purge_request",0,0));return;
failed:
    ngx_http_finalize_request(r,reply(r,503,"purge_queue_unavailable",0,0));
}

static ngx_int_t status(ngx_http_request_t *r,scdn_purge_main_t *main)
{
    ngx_buf_t *buffer=ngx_create_temp_buf(r->pool,1024);
    ngx_chain_t chain;
    ngx_uint_t nodes;
    uint64_t sequence,offset,batches,compacted;
    ngx_int_t rc;
    ngx_table_elt_t *header;
    if(buffer==NULL)return NGX_HTTP_INTERNAL_SERVER_ERROR;
    ngx_shmtx_lock(&main->slab->mutex);
    nodes=main->shared->nodes;sequence=(uint64_t)main->shared->sequence;
    offset=main->shared->journal_offset;batches=(uint64_t)main->shared->batches;compacted=(uint64_t)main->shared->compacted;
    ngx_shmtx_unlock(&main->slab->mutex);
    buffer->last=ngx_snprintf(buffer->last,1024,
        "{\"ok\":true,\"version\":\"" SCDN_PURGE_VERSION "\",\"sequence\":%uL,\"metadata_nodes\":%ui,\"journal_bytes\":%uL,"
        "\"batches\":%uL,\"checkpoints\":%uL,\"worker_pid\":%P,\"worker_lru_hits\":%uL,"
        "\"worker_lru_misses\":%uL,\"physical_deleted\":false}\n",
        sequence,nodes,offset,batches,compacted,ngx_pid,purge_hits,purge_misses);
    ngx_str_set(&r->headers_out.content_type,"application/json");r->headers_out.status=200;
    header=ngx_list_push(&r->headers_out.headers);if(header==NULL)return NGX_HTTP_INTERNAL_SERVER_ERROR;
    header->hash=1;ngx_str_set(&header->key,"Cache-Control");ngx_str_set(&header->value,"no-store");
    r->headers_out.content_length_n=buffer->last-buffer->pos;
    buffer->last_buf=r==r->main;buffer->last_in_chain=1;chain.buf=buffer;chain.next=NULL;
    rc=ngx_http_send_header(r);if(rc==NGX_ERROR || rc>NGX_OK || r->header_only)return rc;
    return ngx_http_output_filter(r,&chain);
}

static ngx_int_t purge_handler(ngx_http_request_t *r)
{
    scdn_purge_main_t *main=ngx_http_get_module_main_conf(r,ngx_http_scdn_purge_module);
    scdn_purge_location_t *location=ngx_http_get_module_loc_conf(r,ngx_http_scdn_purge_module);
    ngx_int_t rc;
    ngx_str_t *content_type;
    if(r!=r->main)return reply(r,400,"subrequest_not_allowed",0,0);
    if(!local_transport(r))return reply(r,403,"local_transport_required",0,0);
    if(!authorize(r,main))return reply(r,401,"purge_unauthorized",0,0);
    if(r->args.len)return reply(r,400,"query_not_allowed",0,0);
    if(location->api==2) {
        if(!(r->method&(NGX_HTTP_GET|NGX_HTTP_HEAD)))return reply(r,405,"method_not_allowed",0,0);
        if(r->headers_in.content_length_n>0 || r->headers_in.chunked)return reply(r,400,"body_not_allowed",0,0);
        return status(r,main);
    }
    if(r->method!=NGX_HTTP_POST)return reply(r,405,"method_not_allowed",0,0);
    content_type=find_header(r,"Content-Type");
    if(content_type==NULL || content_type->len<10
       || ngx_strncasecmp(content_type->data,(u_char *)"text/plain",10)!=0
       || (content_type->len>10 && content_type->data[10]!=';'))return reply(r,415,"content_type",0,0);
    if(r->headers_in.chunked || r->headers_in.content_length_n<0
       || r->headers_in.content_length_n>SCDN_PURGE_BODY)return reply(r,413,"body_size",0,0);
    r->request_body_in_single_buf=1;
    rc=ngx_http_read_client_request_body(r,body_ready);
    return rc>=NGX_HTTP_SPECIAL_RESPONSE?rc:NGX_DONE;
}
