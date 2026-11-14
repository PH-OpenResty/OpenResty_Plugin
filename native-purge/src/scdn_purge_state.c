#include "scdn_purge.h"
#include <openssl/rand.h>

static __thread scdn_purge_job_t *allocating_job;

/* The journal is private data. No key bytes are logged. All filesystem work
 * below happens at startup or in the dedicated purge thread pool. */
static void put32(u_char *p, uint32_t v)
{ p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }
static uint32_t get32(const u_char *p)
{ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static void put64(u_char *p, uint64_t v)
{ put32(p,(uint32_t)(v>>32)); put32(p+4,(uint32_t)v); }
static uint64_t get64(const u_char *p)
{ return ((uint64_t)get32(p)<<32)|get32(p+4); }

static int write_all(int fd, const void *data, size_t length)
{
    const u_char *p=data;
    ssize_t n;
    while(length) {
        n=write(fd,p,length);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) return 0;
        p+=n; length-=(size_t)n;
    }
    return 1;
}

static int read_all(int fd, void *data, size_t length)
{
    u_char *p=data;
    ssize_t n;
    while(length) {
        n=read(fd,p,length);
        if(n<0 && errno==EINTR) continue;
        if(n<=0) return 0;
        p+=n; length-=(size_t)n;
    }
    return 1;
}

uint32_t
scdn_purge_hash(u_char mode,const ngx_str_t *scope,const ngx_str_t *key)
{
    uint32_t hash;
    ngx_crc32_init(hash);
    ngx_crc32_update(&hash,&mode,1);
    ngx_crc32_update(&hash,scope->data,scope->len);
    mode=0;
    ngx_crc32_update(&hash,&mode,1);
    ngx_crc32_update(&hash,key->data,key->len);
    ngx_crc32_final(hash);
    return hash;
}

static scdn_purge_node_t *
lookup(scdn_purge_main_t *main,u_char mode,const ngx_str_t *scope,
    const ngx_str_t *key,int create)
{
    scdn_purge_node_t *node;
    uint32_t hash=scdn_purge_hash(mode,scope,key);
    size_t size;
    ngx_uint_t bucket=hash%SCDN_PURGE_BUCKETS;
    for(node=main->shared->buckets[bucket];node;node=node->next) {
        if(node->hash==hash && node->mode==mode
           && node->scope_length==scope->len && node->key_length==key->len
           && ngx_memcmp(node->bytes,scope->data,scope->len)==0
           && (key->len==0 || ngx_memcmp(node->bytes+scope->len,key->data,key->len)==0)) return node;
    }
    if(!create) return NULL;
    if(allocating_job && allocating_job->created_count>=SCDN_PURGE_BATCH*2)return NULL;
    size=sizeof(*node)+scope->len+key->len;
    node=ngx_slab_calloc_locked(main->slab,size);
    if(node==NULL) return NULL;
    node->hash=hash; node->mode=mode;
    node->scope_length=scope->len; node->key_length=key->len;
    ngx_memcpy(node->bytes,scope->data,scope->len);
    if(key->len) ngx_memcpy(node->bytes+scope->len,key->data,key->len);
    node->next=main->shared->buckets[bucket];
    main->shared->buckets[bucket]=node;
    main->shared->nodes++;
    if(allocating_job)allocating_job->created[allocating_job->created_count++]=node;
    return node;
}

static void rollback_reservations(scdn_purge_job_t *job)
{
    scdn_purge_main_t *main=job->main;
    scdn_purge_node_t *node,*scope,**cursor;
    ngx_str_t name,empty=ngx_string("");
    ngx_shmtx_lock(&main->slab->mutex);
    while(job->created_count) {
        node=job->created[--job->created_count];
        if(node->mode=='P') {
            name.data=node->bytes;name.len=node->scope_length;
            scope=lookup(main,'S',&name,&empty,0);
            if(scope!=NULL) {
                for(cursor=&scope->prefixes;*cursor;cursor=&(*cursor)->prefix_next) {
                    if(*cursor==node) { *cursor=node->prefix_next;scope->prefix_count--;break; }
                }
            }
        }
        for(cursor=&main->shared->buckets[node->hash%SCDN_PURGE_BUCKETS];*cursor;cursor=&(*cursor)->next) {
            if(*cursor==node) { *cursor=node->next;break; }
        }
        ngx_slab_free_locked(main->slab,node);main->shared->nodes--;
    }
    ngx_shmtx_unlock(&main->slab->mutex);
}

static int prepare(scdn_purge_main_t *main,scdn_purge_operation_t *op)
{
    ngx_str_t empty=ngx_string("");
    scdn_purge_node_t *scope,*existing;
    if(op->mode=='A') return 1;
    if(op->mode=='S') {
        op->node=lookup(main,'S',&op->scope,&empty,1);
        return op->node!=NULL;
    }
    if(op->mode=='P') {
        scope=lookup(main,'S',&op->scope,&empty,1);
        if(scope==NULL) return 0;
        existing=lookup(main,'P',&op->scope,&op->key,0);
        if(existing!=NULL) { op->node=existing; return 1; }
        if(scope->prefix_count>=SCDN_PURGE_PREFIXES) return 0;
        op->node=lookup(main,'P',&op->scope,&op->key,1);
        if(op->node==NULL) return 0;
        op->node->prefix_next=scope->prefixes;
        scope->prefixes=op->node; scope->prefix_count++;
        return 1;
    }
    op->node=lookup(main,'E',&op->scope,&op->key,1);
    return op->node!=NULL;
}

static void clear_nodes(scdn_purge_main_t *main)
{
    ngx_uint_t i;
    scdn_purge_node_t *node,*next;
    for(i=0;i<SCDN_PURGE_BUCKETS;i++) {
        for(node=main->shared->buckets[i];node;node=next) {
            next=node->next; ngx_slab_free_locked(main->slab,node);
        }
        main->shared->buckets[i]=NULL;
    }
    main->shared->nodes=0;
}

static void apply(scdn_purge_main_t *main,scdn_purge_operation_t *op,uint64_t seq)
{
    if(op->mode=='A') {
        if(seq>main->shared->all_epoch) {
            clear_nodes(main); main->shared->all_epoch=seq;
        }
    } else if(op->node->epoch<seq) op->node->epoch=seq;
}

static void reclaim_scope(scdn_purge_main_t *main,scdn_purge_operation_t *op,uint64_t seq)
{
    scdn_purge_node_t *node,**cursor,*scope=op->node,**prefix;
    ngx_uint_t bucket,steps;
    /* The durable scope epoch dominates the retired exact/prefix epochs.
     * Keep the scope node itself so no old cache namespace can reappear. */
    ngx_shmtx_lock(&main->slab->mutex);
    for(prefix=&scope->prefixes;*prefix;) {
        if((*prefix)->epoch<=seq) { *prefix=(*prefix)->prefix_next;scope->prefix_count--; }
        else prefix=&(*prefix)->prefix_next;
    }
    ngx_shmtx_unlock(&main->slab->mutex);
    for(bucket=0;bucket<SCDN_PURGE_BUCKETS;bucket++) {
        cursor=&main->shared->buckets[bucket];
        while(*cursor) {
            ngx_shmtx_lock(&main->slab->mutex);
            for(steps=0;steps<64 && *cursor;steps++) {
                node=*cursor;
                if(node->mode!='S' && node->epoch<=seq && node->scope_length==op->scope.len
                   && ngx_memcmp(node->bytes,op->scope.data,op->scope.len)==0) {
                    *cursor=node->next;ngx_slab_free_locked(main->slab,node);main->shared->nodes--;
                } else cursor=&node->next;
            }
            ngx_shmtx_unlock(&main->slab->mutex);
        }
    }
}

uint64_t
scdn_purge_epoch(scdn_purge_main_t *main,const ngx_str_t *scope,
    const ngx_str_t *key,uint64_t *sequence)
{
    scdn_purge_node_t *node,*prefix;
    ngx_str_t empty=ngx_string("");
    uint64_t epoch;
    ngx_shmtx_lock(&main->slab->mutex);
    epoch=main->shared->all_epoch;
    node=lookup(main,'S',scope,&empty,0);
    if(node!=NULL) {
        if(node->epoch>epoch) epoch=node->epoch;
        for(prefix=node->prefixes;prefix;prefix=prefix->prefix_next) {
            if(prefix->epoch>epoch && prefix->key_length<=key->len
               && ngx_memcmp(prefix->bytes+scope->len,key->data,prefix->key_length)==0) epoch=prefix->epoch;
        }
    }
    node=lookup(main,'E',scope,key,0);
    if(node!=NULL && node->epoch>epoch) epoch=node->epoch;
    *sequence=(uint64_t)main->shared->sequence;
    ngx_shmtx_unlock(&main->slab->mutex);
    return epoch;
}

static int header(int fd,u_char identity[16],int create)
{
    u_char bytes[32];
    struct stat st;
    uint32_t crc;
    if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || (st.st_mode&077)!=0) return 0;
    if(st.st_size==0 && create) {
        ngx_memzero(bytes,sizeof(bytes));
        ngx_memcpy(bytes,"SCDEPO1\n",8);
        if(RAND_bytes(bytes+8,16)!=1) return 0;
        crc=ngx_crc32_long(bytes,28);put32(bytes+28,crc);
        if(!write_all(fd,bytes,sizeof(bytes)) || fsync(fd)!=0) return 0;
    } else {
        if(lseek(fd,0,SEEK_SET)<0 || !read_all(fd,bytes,sizeof(bytes))) return 0;
        if(ngx_memcmp(bytes,"SCDEPO1\n",8)!=0
           || get32(bytes+28)!=ngx_crc32_long(bytes,28)) return 0;
    }
    ngx_memcpy(identity,bytes+8,16);
    return 1;
}

static int record(int fd,scdn_purge_operation_t *ops,ngx_uint_t count,uint64_t seq)
{
    u_char bytes[32],*body,*p;
    size_t length=0;
    ngx_uint_t i;
    uint32_t crc;
    for(i=0;i<count;i++) length+=5+ops[i].scope.len+ops[i].key.len;
    body=ngx_alloc(length,ngx_cycle->log);
    if(body==NULL) return 0;
    p=body;
    for(i=0;i<count;i++) {
        *p++=ops[i].mode;
        *p++=ops[i].scope.len>>8;*p++=ops[i].scope.len;
        *p++=ops[i].key.len>>8;*p++=ops[i].key.len;
        p=ngx_cpymem(p,ops[i].scope.data,ops[i].scope.len);
        p=ngx_cpymem(p,ops[i].key.data,ops[i].key.len);
    }
    ngx_memzero(bytes,sizeof(bytes));
    put32(bytes,0x53435031);put32(bytes+4,(uint32_t)length);
    put32(bytes+8,(uint32_t)count);put64(bytes+16,seq);
    ngx_crc32_init(crc);ngx_crc32_update(&crc,bytes,24);
    ngx_crc32_update(&crc,body,length);ngx_crc32_final(crc);put32(bytes+24,crc);
    i=write_all(fd,bytes,sizeof(bytes)) && write_all(fd,body,length);
    ngx_free(body);
    return i!=0;
}

static int recover(scdn_purge_main_t *main,int fd,int fresh)
{
    u_char bytes[32],identity[16],*body,*p,*end;
    struct stat st;
    off_t offset,start;
    size_t length;
    uint32_t crc;
    uint64_t seq,maximum=0,previous_sequence;
    ngx_uint_t count,i,j;
    scdn_purge_operation_t ops[SCDN_PURGE_BATCH];
    if(!header(fd,identity,1) || fstat(fd,&st)!=0) return 0;
    if(fresh) {
        ngx_memcpy(main->shared->identity,identity,16);
        ngx_hex_dump(main->shared->identity_hex,identity,16);
    } else if(ngx_memcmp(main->shared->identity,identity,16)!=0) return 0;
    start=main->shared->journal_inode==(uint64_t)st.st_ino
          ? (off_t)main->shared->journal_offset : 32;
    previous_sequence=(uint64_t)main->shared->sequence;
    if(start<32) start=32;
    if(st.st_size<start || st.st_size>SCDN_PURGE_JOURNAL*2) return 0;
    offset=start;
    while(offset<st.st_size) {
        if(st.st_size-offset<32) {
            if(ftruncate(fd,offset)!=0 || fsync(fd)!=0) return 0;
            break;
        }
        if(lseek(fd,offset,SEEK_SET)<0 || !read_all(fd,bytes,32)) return 0;
        length=get32(bytes+4);count=get32(bytes+8);seq=get64(bytes+16);
        if(seq>maximum)maximum=seq;
        if(get32(bytes)!=0x53435031 || length>SCDN_PURGE_BODY+SCDN_PURGE_BATCH*261
           || count==0 || count>SCDN_PURGE_BATCH || seq==0 || seq>INT64_MAX) return 0;
        if(st.st_size-offset-32<(off_t)length) {
            if(ftruncate(fd,offset)!=0 || fsync(fd)!=0) return 0;
            break;
        }
        body=ngx_alloc(length,ngx_cycle->log);if(body==NULL) return 0;
        if(!read_all(fd,body,length)) { ngx_free(body);return 0; }
        ngx_crc32_init(crc);ngx_crc32_update(&crc,bytes,24);
        ngx_crc32_update(&crc,body,length);ngx_crc32_final(crc);
        if(crc!=get32(bytes+24)) { ngx_free(body);return 0; }
        p=body;end=body+length;
        ngx_memzero(ops,sizeof(ops));
        for(i=0;i<count;i++) {
            if(end-p<5) break;
            ops[i].mode=*p++;
            ops[i].scope.len=((size_t)p[0]<<8)|p[1];p+=2;
            ops[i].key.len=((size_t)p[0]<<8)|p[1];p+=2;
            if(ops[i].scope.len>SCDN_PURGE_SCOPE || ops[i].key.len>SCDN_PURGE_KEY
               || (size_t)(end-p)<ops[i].scope.len+ops[i].key.len
               || strchr("EPSA",ops[i].mode)==NULL || ops[i].mode==0) break;
            ops[i].scope.data=p;p+=ops[i].scope.len;
            ops[i].key.data=p;p+=ops[i].key.len;
        }
        if(i!=count || p!=end) { ngx_free(body);return 0; }
        if((ops[0].mode=='A' || ops[0].mode=='S') && count!=1) { ngx_free(body);return 0; }
        for(i=1;i<count;i++)if(ops[i].mode!=ops[0].mode)break;
        if(i!=count) { ngx_free(body);return 0; }
        ngx_shmtx_lock(&main->slab->mutex);
        for(i=0;i<count;i++) {
            if(!prepare(main,&ops[i])) break;
            apply(main,&ops[i],seq);
        }
        if(i==count && (uint64_t)main->shared->sequence<seq) {
            ngx_memory_barrier();main->shared->sequence=(ngx_atomic_t)seq;
        }
        ngx_shmtx_unlock(&main->slab->mutex);
        if(i==count)for(j=0;j<count;j++)if(ops[j].mode=='S')reclaim_scope(main,&ops[j],seq);
        ngx_free(body);
        if(i!=count) return 0;
        offset+=32+(off_t)length;
    }
    if(!fresh && start==32 && maximum<previous_sequence) return 0;
    ngx_shmtx_lock(&main->slab->mutex);
    main->shared->journal_offset=offset;
    main->shared->journal_inode=(uint64_t)st.st_ino;
    ngx_shmtx_unlock(&main->slab->mutex);
    return 1;
}

static int lock_file(scdn_purge_main_t *main)
{
    char *path;
    int fd;
    struct stat st;
    path=ngx_alloc(main->journal.len+6,ngx_cycle->log);if(path==NULL) return -1;
    ngx_memcpy(path,main->journal.data,main->journal.len);
    ngx_memcpy(path+main->journal.len,".lock",6);
    fd=open(path,O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);ngx_free(path);
    if(fd<0) return -1;
    if(fstat(fd,&st)!=0 || !S_ISREG(st.st_mode) || (st.st_mode&077)!=0
       || flock(fd,LOCK_EX)!=0) { close(fd);return -1; }
    return fd;
}

static int compact(scdn_purge_main_t *main,int *fd)
{
    scdn_purge_operation_t *ops;
    scdn_purge_node_t *node;
    ngx_uint_t count=0,i,j;
    uint64_t *epochs,all;
    u_char bytes[32];
    char *path;
    int temporary,dir;
    struct stat st;
    size_t length;
    ngx_shmtx_lock(&main->slab->mutex);
    i=main->shared->nodes;
    ngx_shmtx_unlock(&main->slab->mutex);
    ops=ngx_alloc((i+1)*sizeof(*ops),ngx_cycle->log);
    epochs=ngx_alloc((i+1)*sizeof(*epochs),ngx_cycle->log);
    if(ops==NULL || epochs==NULL) { if(ops)ngx_free(ops);if(epochs)ngx_free(epochs);return 0; }
    ngx_shmtx_lock(&main->slab->mutex);
    all=main->shared->all_epoch;
    for(i=0;i<SCDN_PURGE_BUCKETS;i++) for(node=main->shared->buckets[i];node;node=node->next) {
        if(node->epoch<=all) continue;
        ops[count].mode=node->mode;
        ops[count].scope.data=node->bytes;ops[count].scope.len=node->scope_length;
        ops[count].key.data=node->bytes+node->scope_length;ops[count].key.len=node->key_length;
        epochs[count++]=node->epoch;
    }
    ngx_shmtx_unlock(&main->slab->mutex);
    path=ngx_alloc(main->journal.len+12,ngx_cycle->log);
    if(path==NULL) { ngx_free(ops);ngx_free(epochs);return 0; }
    ngx_memcpy(path,main->journal.data,main->journal.len);
    ngx_memcpy(path+main->journal.len,".checkpoint",12);
    /* The stable .lock file serializes writers, so any prior temporary file is
     * an abandoned checkpoint. Unlinking a symlink removes only the link. */
    if(unlink(path)!=0 && errno!=ENOENT) { ngx_free(path);ngx_free(ops);ngx_free(epochs);return 0; }
    temporary=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if(temporary<0) { ngx_free(path);ngx_free(ops);ngx_free(epochs);return 0; }
    ngx_memzero(bytes,32);ngx_memcpy(bytes,"SCDEPO1\n",8);
    ngx_memcpy(bytes+8,main->shared->identity,16);put32(bytes+28,ngx_crc32_long(bytes,28));
    j=write_all(temporary,bytes,32);
    if(all && j) {
        scdn_purge_operation_t global;
        ngx_memzero(&global,sizeof(global));global.mode='A';
        ngx_str_set(&global.scope,"");ngx_str_set(&global.key,"");
        j=record(temporary,&global,1,all);
    }
    for(i=0;i<count && j;i++) j=record(temporary,&ops[i],1,epochs[i]);
    if(!j || fsync(temporary)!=0) { close(temporary);unlink(path);ngx_free(path);ngx_free(ops);ngx_free(epochs);return 0; }
    close(temporary);
    if(rename(path,(char *)main->journal.data)!=0) { unlink(path);ngx_free(path);ngx_free(ops);ngx_free(epochs);return 0; }
    length=main->journal.len;
    while(length>0 && path[length-1]!='/') length--;
    path[length==1?1:length-1]=0;
    dir=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    j=dir>=0 && fsync(dir)==0;
    if(dir>=0) close(dir);
    ngx_free(path);ngx_free(ops);ngx_free(epochs);
    close(*fd);*fd=open((char *)main->journal.data,O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    if(!j || *fd<0 || fstat(*fd,&st)!=0) return 0;
    ngx_shmtx_lock(&main->slab->mutex);
    main->shared->journal_inode=(uint64_t)st.st_ino;
    main->shared->journal_offset=(uint64_t)st.st_size;
    main->shared->compacted++;
    ngx_shmtx_unlock(&main->slab->mutex);
    return 1;
}

ngx_int_t
scdn_purge_zone_init(ngx_shm_zone_t *zone,void *previous)
{
    scdn_purge_main_t *main=zone->data,*old=previous;
    int lock,fd,ok;
    main->slab=(ngx_slab_pool_t *)zone->shm.addr;
    if(old!=NULL) {
        if(old->journal.len!=main->journal.len
           || ngx_memcmp(old->journal.data,main->journal.data,main->journal.len)!=0) return NGX_ERROR;
        main->shared=old->shared;
        return main->shared->format==1?NGX_OK:NGX_ERROR;
    }
    main->shared=ngx_slab_calloc(main->slab,sizeof(*main->shared));
    if(main->shared==NULL) return NGX_ERROR;
    main->shared->format=1;
    lock=lock_file(main);if(lock<0) return NGX_ERROR;
    fd=open((char *)main->journal.data,O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
    ok=fd>=0 && recover(main,fd,1);
    if(fd>=0) close(fd);
    close(lock);
    if(!ok) ngx_log_error(NGX_LOG_EMERG,zone->shm.log,0,"scdn_purge journal validation failed");
    return ok?NGX_OK:NGX_ERROR;
}

void
scdn_purge_commit(void *data,ngx_log_t *log)
{
    scdn_purge_job_t *job=data;
    scdn_purge_main_t *main=job->main;
    int lock=-1,fd=-1;
    ngx_uint_t i;
    off_t start;
    struct stat st;
    scdn_purge_node_t **retired=NULL,*node,*next;
    ngx_uint_t bucket,freed;
    (void)log;
    job->status=503;job->error="journal_unavailable";
    lock=lock_file(main);if(lock<0) return;
    fd=open((char *)main->journal.data,O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0 || !recover(main,fd,0)) { job->error="journal_recovery_failed";goto done; }
    if(fstat(fd,&st)!=0) goto done;
    if(st.st_size>(off_t)main->checkpoint && !compact(main,&fd)) {
        job->error="checkpoint_failed";goto done;
    }
    ngx_shmtx_lock(&main->slab->mutex);
    allocating_job=job;
    for(i=0;i<job->count;i++) if(!prepare(main,&job->operations[i])) break;
    allocating_job=NULL;
    job->sequence=(uint64_t)main->shared->sequence+1;
    ngx_shmtx_unlock(&main->slab->mutex);
    if(i!=job->count || job->sequence>INT64_MAX) {
        job->status=507;job->error="metadata_capacity";goto done;
    }
    if(job->count==1 && job->operations[0].mode=='A') {
        retired=ngx_alloc(sizeof(*retired)*SCDN_PURGE_BUCKETS,log);
        if(retired==NULL) { job->error="purge_memory";goto done; }
    }
    start=lseek(fd,0,SEEK_END);
    if(start<0 || !record(fd,job->operations,job->count,job->sequence) || fsync(fd)!=0) {
        /* No success is acknowledged after an ambiguous durability failure. */
        job->error="journal_commit_failed";goto done;
    }
    ngx_shmtx_lock(&main->slab->mutex);
    if(retired!=NULL) {
        ngx_memcpy(retired,main->shared->buckets,sizeof(*retired)*SCDN_PURGE_BUCKETS);
        ngx_memzero(main->shared->buckets,sizeof(main->shared->buckets));
        main->shared->nodes=0;main->shared->all_epoch=job->sequence;
    } else {
        for(i=0;i<job->count;i++) apply(main,&job->operations[i],job->sequence);
    }
    main->shared->batches++;
    ngx_memory_barrier();
    main->shared->sequence=(ngx_atomic_t)job->sequence;
    ngx_shmtx_unlock(&main->slab->mutex);
    ngx_shmtx_lock(&main->slab->mutex);
    main->shared->journal_offset=(uint64_t)lseek(fd,0,SEEK_CUR);
    ngx_shmtx_unlock(&main->slab->mutex);
    if(job->count==1 && job->operations[0].mode=='S')reclaim_scope(main,&job->operations[0],job->sequence);
    /* Retired nodes are unreachable. Reclaim at most 64 under one lock hold;
     * business cache misses can proceed between these bounded batches. */
    if(retired!=NULL) {
        freed=0;
        for(bucket=0;bucket<SCDN_PURGE_BUCKETS;bucket++) {
            node=retired[bucket];
            while(node!=NULL) {
                ngx_shmtx_lock(&main->slab->mutex);
                for(i=0;i<64 && node!=NULL;i++) {
                    next=node->next;ngx_slab_free_locked(main->slab,node);node=next;
                }
                ngx_shmtx_unlock(&main->slab->mutex);
                if(++freed%16==0) sched_yield();
            }
        }
    }
    job->status=200;job->error=NULL;
done:
    if(job->status!=200 && job->created_count)rollback_reservations(job);
    if(retired!=NULL) ngx_free(retired);
    if(fd>=0) close(fd);
    if(lock>=0) close(lock);
}
