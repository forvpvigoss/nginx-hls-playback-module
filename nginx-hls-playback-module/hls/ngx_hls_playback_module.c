
/*
 * Copyright (C) Steven Su
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct ngx_hls_segment_s  ngx_hls_segment_t;

struct ngx_hls_segment_s{
    int                    id;
    ngx_str_t              name;
    int                    discont;
    double                 duration;

    ngx_hls_segment_t     *prev;
    ngx_hls_segment_t     *next;      
};

typedef struct {
    ngx_hls_segment_t      *head;
    ngx_hls_segment_t      *tail;
    int                     nsegs;    
} ngx_hls_playlist_t;

typedef struct {
    ngx_file_t              file;
    u_char                 *m3u8_path;
    ngx_hls_playlist_t     *playlist;
} ngx_hls_playback_t;

static char *ngx_hls_playback(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static int32_t ngx_hls_playback_sendfile(ngx_http_request_t *r, ngx_str_t path, size_t root, ngx_log_t *log);
static int32_t ngx_hls_parse_playlist(ngx_http_request_t *r, ngx_str_t path, ngx_hls_playlist_t *playlist, ngx_log_t *log);
static int32_t ngx_hls_send_delay_playlist(ngx_http_request_t *r, ngx_str_t path, double delay, ngx_log_t *log);

static ngx_command_t  ngx_hls_playback_commands[] = {

    { ngx_string("hls_playback"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_hls_playback,
      0,
      0,
      NULL },

      ngx_null_command
};

static ngx_http_module_t  ngx_hls_playback_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};


ngx_module_t  ngx_hls_playback_module = {
    NGX_MODULE_V1,
    &ngx_hls_playback_module_ctx,  /* module context */
    ngx_hls_playback_commands,     /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_hls_playback_handler(ngx_http_request_t *r)
{
    u_char                    *last;
    int                        delay;
    size_t                     root;
    ngx_int_t                  rc;
    ngx_str_t                  path, value;
    ngx_log_t                 *log;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    log = r->connection->log;
    log->action = "sending m3u8 to client";

    path.len = last - path.data;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http live streaming filename: \"%V\"", &path);

    delay = 0;
    if (r->args.len) {

        if (ngx_http_arg(r, (u_char *) "delay", 5, &value) == NGX_OK) {

            delay = ngx_atoof(value.data, value.len);
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                           "delay %d\r\n",delay);
            return ngx_hls_send_delay_playlist(r,path,delay,log);
        }
    }

    return ngx_hls_playback_sendfile(r,path,root,log);
}

static int32_t
ngx_hls_playback_sendfile(ngx_http_request_t *r, ngx_str_t path, size_t root, ngx_log_t *log)
{
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_uint_t                 level;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;
    
    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_http_set_disable_symlinks(r, clcf, &path, &of) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:
#if (NGX_HAVE_OPENAT)
        case NGX_EMLINK:
        case NGX_ELOOP:
#endif

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    r->root_tested = !r->error_page;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

#if !(NGX_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return NGX_HTTP_NOT_FOUND;
    }

#endif

    if (r->method == NGX_HTTP_POST) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }
    

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = of.size;
    r->headers_out.last_modified_time = of.mtime;

    if (ngx_http_set_etag(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r != r->main && of.size == 0) {
        return ngx_http_send_header(r);
    }

    r->allow_ranges = 1;

    /* we need to allocate all before the header would be sent */

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->file_pos = 0;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static int32_t    
ngx_hls_send_delay_playlist(ngx_http_request_t *r, ngx_str_t path, double delay, ngx_log_t *log)
{
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_hls_playlist_t        *playlist;

    playlist = ngx_pcalloc(r->pool,sizeof(ngx_hls_playlist_t));
    playlist->head = playlist->tail = NULL;
    playlist->nsegs = 0;
    rc = ngx_hls_parse_playlist(r, path, playlist, log);
    if (rc == NGX_ERROR || rc > NGX_OK) {
        return rc;
    }

    double duration = 0;
    int targetduration = 0;
    ngx_hls_segment_t* pseg;
    for(pseg = playlist->tail; pseg; )
    {
        if (targetduration < pseg->duration) {
            targetduration = pseg->duration;
        }
        
        duration += pseg->duration;
        if(duration - delay > 0.0000001)
        {
            break;
        }

        if(pseg->prev == NULL)
        {
            break;
        }
        pseg = pseg->prev;
    }

    b = ngx_create_temp_buf(r->pool,4096);
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    b->last = ngx_sprintf(b->last, "#EXTM3U\n"
                 "#EXT-X-VERSION:3\n"
                 "#EXT-X-MEDIA-SEQUENCE:%d\n"
                 "#EXT-X-TARGETDURATION:%d\n",
                 pseg->id,targetduration + 1);
    int i = 5;
    while(i-- && pseg)
    {
        b->last = ngx_sprintf(b->last, "#EXTINF:%.5f,\n"
                          "%V\n",pseg->duration,&pseg->name);
        pseg = pseg->next;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "m3u8 buffer \n%s\r\n",b->start);

    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = b->last - b->pos;
    ngx_str_set(&r->headers_out.content_type,"application/vnd.apple.mpegurl");

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }
    
    return ngx_http_output_filter(r,&out);
}

static int32_t
ngx_hls_parse_playlist(ngx_http_request_t *r, ngx_str_t path, ngx_hls_playlist_t *playlist, ngx_log_t *log)
{
    ngx_file_t                      file;
    ssize_t                         ret;
    off_t                           offset;
    ngx_int_t                       discont;
    u_char                         *p, *last, *end, *next, *pa;
    double                          duration;
    static u_char                   buffer[4096];
    
    file.fd = ngx_open_file(path.data,
                       NGX_FILE_RDONLY, 
                       NGX_FILE_OPEN,
                       0);
    
    if (file.fd == NGX_INVALID_FILE) {
        ngx_log_error(NGX_LOG_EMERG, log, ngx_errno,
                      ngx_open_file_n " \"%s\" failed", path);
        return NGX_ERROR;
    }

    file.log = log;
    file.name.data = path.data;

    offset = 0;
    duration = 0;
    discont = 0;

    for ( ;; ) {

        ret = ngx_read_file(&file, buffer, sizeof(buffer), offset);
        if (ret <= 0) {
            goto done;
        }

        p = buffer;
        end = buffer + ret;

        for ( ;; ) {
            last = ngx_strlchr(p, end, '\n');

            if (last == NULL) {
                break;
            }

            next = last + 1;
            offset += (next - p);

            if (p != last && last[-1] == '\r') {
                last--;
            }

#define NGX_HLS_EXTINF         "#EXTINF:"
#define NGX_HLS_EXTINF_LEN     (sizeof(NGX_HLS_EXTINF) - 1)

            if (ngx_memcmp(p, NGX_HLS_EXTINF, NGX_HLS_EXTINF_LEN) == 0) {

                duration = strtod((const char *) &p[NGX_HLS_EXTINF_LEN], NULL);
            }

#define NGX_HLS_DISCONT        "#EXT-X-DISCONTINUITY"
#define NGX_HLS_DISCONT_LEN    (sizeof(NGX_HLS_DISCONT) - 1)
            
            if (ngx_memcmp(p, NGX_HLS_DISCONT, NGX_HLS_DISCONT_LEN) == 0) {

                discont = 1;

                ngx_log_debug0(NGX_LOG_DEBUG, r->connection->log, 0,
                               "hls: discontinuity");
            }
            /* find '.ts\r' */

            if (p + 4 <= last &&
                last[-3] == '.' && last[-2] == 't' && last[-1] == 's')
            {
                ngx_hls_segment_t* seg = ngx_pcalloc(r->pool,sizeof(ngx_hls_segment_t));
                seg->duration = duration;
                seg->discont = discont;
                discont = 0;
                
                uint64_t mag = 1;
                for (pa = last - 4; pa >= p; pa--) {
                    if (*pa < '0' || *pa > '9') {
                        break;
                    }
                    seg->id += (*pa - '0') * mag;
                    mag *= 10;
                }
                seg->name.len = last - p;
                seg->name.data = ngx_pcalloc(r->pool, seg->name.len);
                ngx_memcpy(seg->name.data,p,seg->name.len);

                if(playlist->head == NULL)
                {
                    playlist->head = seg;
                    playlist->tail = seg;
                    seg->prev = NULL;
                    seg->next = NULL;
                }
                else
                {
                    seg->prev = playlist->tail;
                    playlist->tail->next = seg;
                    playlist->tail = seg;
                }

                playlist->nsegs++;
            }

            p = next;
        }
    }

done:    
    ngx_close_file(file.fd);
    return (playlist->tail == NULL);
}

static char *
ngx_hls_playback(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_hls_playback_handler;

    return NGX_CONF_OK;
}

