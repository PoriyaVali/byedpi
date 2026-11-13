#define _GNU_SOURCE

#include "desync.h"

#include <stdio.h>
#include <string.h>

#ifndef _WIN32
    #include <unistd.h>
    #include <time.h>
    #include <sys/time.h>
    #include <sys/socket.h>
    #include <sys/mman.h>
    #include <arpa/inet.h>
    #include <fcntl.h>
    
    #ifndef __linux__
    #include <netinet/tcp.h>
    #else
    #include <linux/tcp.h>
    #include <linux/filter.h>
    #endif
#else
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <mswsock.h>
#endif

#include "packets.h"
#include "error.h"

#define DEFAULT_TTL 8
#define ERR_WAIT -12


int setttl(int fd, int ttl)
{
    int ret6 = setsockopt(fd, IPPROTO_IPV6,
        IPV6_UNICAST_HOPS, (char *)&ttl, sizeof(ttl));
    int ret4 = setsockopt(fd, IPPROTO_IP, 
        IP_TTL, (char *)&ttl, sizeof(ttl));
    
    if (ret4 && ret6) {
        uniperror("setttl");
        return -1;
    }
    return 0;
}


#ifdef __linux__
static int drop_sack(int fd)
{
    struct sock_filter code[] = {
        { 0x30, 0, 0, 0x0000000c },
        { 0x74, 0, 0, 0x00000004 },
        { 0x35, 0, 3, 0x0000000b },
        { 0x30, 0, 0, 0x00000022 },
        { 0x15, 0, 1, 0x00000005 },
        { 0x6,  0, 0, 0x00000000 },
        { 0x6,  0, 0, 0x00040000 },
    };
    struct sock_fprog bpf = {
        .len = sizeof(code)/sizeof(*code),
        .filter = code
    };
    if (setsockopt(fd, SOL_SOCKET, 
            SO_ATTACH_FILTER, (char *)&bpf, sizeof(bpf)) == -1) {
        uniperror("setsockopt SO_ATTACH_FILTER");
        return -1;
    }
    return 0;
}


static bool sock_has_notsent(int sfd)
{
    struct tcp_info tcpi;
    socklen_t ts = sizeof(tcpi);
    
    if (getsockopt(sfd, IPPROTO_TCP,
            TCP_INFO, (char *)&tcpi, &ts) < 0) {
        perror("getsockopt TCP_INFO");
        return 0;
    }
    if (tcpi.tcpi_state != 1) {
        LOG(LOG_E, "state: %d\n", tcpi.tcpi_state);
        return 0;
    }
    if (ts <= offsetof(struct tcp_info, tcpi_notsent_bytes)) {
        LOG(LOG_E, "tcpi_notsent_bytes not provided\n");
        return 0;
    }
    return tcpi.tcpi_notsent_bytes != 0;
}


static char *alloc_pktd(size_t n)
{
    char *p = mmap(0, n, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    return p == MAP_FAILED ? 0 : p;
}
#else
#define sock_has_notsent(sfd) 0

#define alloc_pktd(n) malloc(n)
#endif


static struct packet get_tcp_fake(const char *buffer, ssize_t n,
        struct proto_info *info, const struct desync_params *opt)
{
    struct packet pkt = { 0 };
    if (opt->fake_data.data) {
        pkt = opt->fake_data;
    }
    else {
        if (!info->type) {
            if (is_tls_chello(buffer, n)) info->type = IS_HTTPS;
            else if (is_http(buffer, n)) info->type = IS_HTTP;
        }
        pkt = info->type == IS_HTTP ? fake_http : fake_tls;
    }
    ssize_t ps = n > pkt.size ? n : pkt.size;
    
    char *p = alloc_pktd(ps);
    if (!p) {
        uniperror("malloc/mmap");
        pkt.data = 0; return pkt;
    }
    const char *sni = 0;
    if (opt->fake_sni_count) {
        sni = opt->fake_sni_list[rand() % opt->fake_sni_count];
    }
    do {
        ssize_t f_size = opt->fake_tls_size;
        if (f_size < 0) {
            f_size = n + f_size;
        }
        if (f_size > n || f_size <= 0) {
            f_size = n;
        }
        if ((opt->fake_mod & FM_ORIG) && info->type == IS_HTTPS) {
            memcpy(p, buffer, n);
            
            if (!sni || !change_tls_sni(sni, p, n, f_size)) {
                break;
            }
            LOG(LOG_E, "change sni error\n");
        }
        memcpy(p, pkt.data, pkt.size);
        if (sni && change_tls_sni(sni, p, pkt.size, f_size) < 0) {
            break;
        }
    } while(0);
    
    if (opt->fake_mod & FM_RAND) {
        randomize_tls(p, ps);
    }
    pkt.data = p;
    pkt.size = ps;
    
    if (opt->fake_offset.m) {
        pkt.off = gen_offset(opt->fake_offset.pos, 
            opt->fake_offset.flag, buffer, n, 0, info);
        if (pkt.off > pkt.size || pkt.off < 0) {
            pkt.off = 0;
        }
    }
    return pkt;
}


#ifdef __linux__
static int set_md5sig(int sfd, unsigned short key_len)
{
    struct tcp_md5sig md5 = {
        .tcpm_keylen = key_len
    };
    socklen_t addr_size = sizeof(md5.tcpm_addr);
    
    if (getpeername(sfd, 
            (struct sockaddr *)&md5.tcpm_addr, &addr_size) < 0) {
        uniperror("getpeername");
        return -1;
    }
    if (setsockopt(sfd, IPPROTO_TCP,
            TCP_MD5SIG, (char *)&md5, sizeof(md5)) < 0) {
        uniperror("setsockopt TCP_MD5SIG");
        return -1;
    }
    return 0;
}


static ssize_t send_fake(struct eval *val, const char *buffer,
        long pos, const struct desync_params *opt, struct packet pkt)
{
    int fds[2];
    if (pipe(fds) < 0) {
        uniperror("pipe");
        return -1;
    }
    size_t ms = pos > pkt.size ? pos : pkt.size;
    ssize_t ret = -1;
    
    val->restore_orig = buffer;
    val->restore_orig_len = pos;
    
    while (1) {
        char *p = pkt.data + pkt.off;
        val->restore_fake = p;
        val->restore_fake_len = pkt.size;
        
        if (setttl(val->fd, opt->ttl ? opt->ttl : DEFAULT_TTL) < 0) {
            break;
        }
        val->restore_ttl = 1;
        if (opt->md5sig && set_md5sig(val->fd, 5)) {
            break;
        }
        val->restore_md5 = opt->md5sig;
        
        struct iovec vec = { .iov_base = p, .iov_len = pos };
        
        ssize_t len = vmsplice(fds[1], &vec, 1, SPLICE_F_GIFT);
        if (len < 0) {
            uniperror("vmsplice");
            break;
        }
        len = splice(fds[0], 0, val->fd, 0, len, 0);
        if (len < 0) {
            uniperror("splice");
            break;
        }
        ret = len;
        break;
    }
    close(fds[0]);
    close(fds[1]);
    return ret;
}
#endif

#ifdef _WIN32
#define MAX_TF 2

struct tf_s {
    HANDLE tfile;
    OVERLAPPED ov;
};

int tf_count = 0;
struct tf_s tf_exems[MAX_TF] = { 0 };


static struct tf_s *getTFE(void)
{
    struct tf_s *s = 0;
    if (tf_count < MAX_TF) 
        s = &tf_exems[tf_count];
    else {
        HANDLE events[MAX_TF];
        for (int i = 0; i < MAX_TF; i++) {
            events[i] = tf_exems[i].ov.hEvent;
        }
        DWORD ret = WaitForMultipleObjects(MAX_TF, events, FALSE, 0);
        
        if (ret >= WAIT_OBJECT_0 && ret < WAIT_OBJECT_0 + MAX_TF) {
            s = &tf_exems[ret - WAIT_OBJECT_0];
            CloseHandle(s->ov.hEvent);
            CloseHandle(s->tfile);
        }
    }
    if (s) memset(s, 0, sizeof(*s));
    return s;
}


static HANDLE openTempFile(void)
{
    char path[MAX_PATH], temp[MAX_PATH + 1];
    if (!GetTempPath(sizeof(temp), temp)) {
        uniperror("GetTempPath");
        return 0;
    }
    if (!GetTempFileName(temp, "t", 0, path)) {
        uniperror("GetTempFileName");
        return 0;
    }
    LOG(LOG_L, "temp file: %s\n", path);
    
    HANDLE hfile = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 
            FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hfile == INVALID_HANDLE_VALUE) {
        uniperror("CreateFileA");
        return 0;
    }
    return hfile;
}

    
static ssize_t send_fake(struct eval *val, const char *buffer,
        long pos, const struct desync_params *opt, struct packet pkt)
{
    struct tf_s *s = getTFE();
    if (!s) {
        return ERR_WAIT;
    }
    HANDLE hfile = openTempFile();
    if (!hfile) {
        return -1;
    }
    s->tfile = hfile;
    ssize_t len = -1, ps = pkt.size - pkt.off;
    
    while (1) {
        DWORD wrtcnt = 0;
        if (!WriteFile(hfile, pkt.data + pkt.off, ps < pos ? ps : pos, &wrtcnt, 0)) {
            uniperror("WriteFile");
            break;
        }
        if (ps < pos) {
            if (SetFilePointer(hfile, pos, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
                uniperror("SetFilePointer");
                break;
            }
            if (!SetEndOfFile(hfile)) {
                uniperror("SetFileEnd");
                break;
            }
        }
        if (SetFilePointer(hfile, 0, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
            uniperror("SetFilePointer");
            break;
        }
        if (setttl(val->fd, opt->ttl ? opt->ttl : DEFAULT_TTL) < 0) {
            break;
        }
        s->ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!s->ov.hEvent) {
            uniperror("CreateEvent");
            break;
        }
        if (!TransmitFile(val->fd, s->tfile, pos, pos, &s->ov, 
                NULL, TF_USE_KERNEL_APC | TF_WRITE_BEHIND)) {
            if ((GetLastError() != ERROR_IO_PENDING) 
                        && (WSAGetLastError() != WSA_IO_PENDING)) {
                uniperror("TransmitFile");
                break;
            }
        }
        if (SetFilePointer(hfile, 0, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
            uniperror("SetFilePointer");
            break;
        }
        if (!WriteFile(hfile, buffer, pos, &wrtcnt, 0)) {
            uniperror("WriteFile");
            break;
        }
        if (setttl(val->fd, params.def_ttl) < 0) {
            break;
        }
        len = pos;
        if (tf_count < MAX_TF) tf_count++;
        break;
    }
    if (len < 0) {
        CloseHandle(s->tfile);
        if (s->ov.hEvent) CloseHandle(s->ov.hEvent);
    }
    return len;
}
#endif

static void restore_state(struct eval *val)
{
    #ifdef __linux__
    if (val->restore_fake) {
        memcpy(val->restore_fake, 
            val->restore_orig, val->restore_orig_len);
        munmap(val->restore_fake, val->restore_fake_len);
        val->restore_fake = 0;
    }
    if (val->restore_md5) {
        set_md5sig(val->fd, 0);
        val->restore_md5 = 0;
    }
    #endif
    if (val->restore_ttl) {
        setttl(val->fd, params.def_ttl);
        val->restore_ttl = 0;
    }
}


static ssize_t send_oob(int sfd, char *buffer,
        ssize_t n, long pos, const char *c)
{
    if (n <= pos) {
        return -1;
    }
    char rchar = buffer[pos];
    buffer[pos] = c[1] ? c[0] : 'a';
    
    ssize_t len = send(sfd, buffer, pos + 1, MSG_OOB);
    buffer[pos] = rchar;
    
    if (len < 0) {
        uniperror("send");
        return -1;
    }
    
    len--;
    if (len != pos) {
        return len;
    }
    return len;
}


static void init_proto_info(
        const char *buffer, size_t n, struct proto_info *info)
{
    if (!info->init) {
        char *host = 0;
        
        if ((info->host_len = parse_tls(buffer, n, &host))) {
            info->type = IS_HTTPS;
        }
        else if ((info->host_len = parse_http(buffer, n, &host, 0))) {
            info->type = IS_HTTP;
        }
        info->host_pos = host ? host - buffer : 0;
        info->init = 1;
    }
}


static long gen_offset(long pos, int flag,
        const char *buffer, size_t n, long lp, struct proto_info *info)
{
    if (flag & (OFFSET_SNI | OFFSET_HOST)) {
        init_proto_info(buffer, n, info);
        
        if (!info->host_pos 
                || ((flag & OFFSET_SNI) && info->type != IS_HTTPS)) {
            return -1;
        }
        pos += info->host_pos;
        
        if (flag & OFFSET_END)
            pos += info->host_len;
        else if (flag & OFFSET_MID)
            pos += (info->host_len / 2);
        else if (flag & OFFSET_RAND)
            pos += (rand() % info->host_len);
    }
    else if (flag & OFFSET_RAND) {
        pos += lp + (rand() % (n - lp));
    }
    else if (flag & OFFSET_MID) {
        pos += (n / 2);
    }
    else if (pos < 0 || (flag & OFFSET_END)) {
        pos += n;
    }
    return pos;
}


static void tamp(char *buffer, size_t bfsize, ssize_t *n, 
        const struct desync_params *dp, struct proto_info *info)
{
    if (dp->mod_http && is_http(buffer, *n)) {
        LOG(LOG_S, "modify HTTP: n=%zd\n", *n);
        if (mod_http(buffer, *n, dp->mod_http)) {
            LOG(LOG_E, "mod http error\n");
        }
    }
    if (dp->tlsminor_set && is_tls_chello(buffer, *n)) {
        ((uint8_t *)buffer)[2] = dp->tlsminor;
    }
    if (dp->tlsrec_n && is_tls_chello(buffer, *n)) {
        long lp = 0;
        struct part part;
        int i = 0, r = 0, rc = 0;
        
        for (; r > 0 || i < dp->tlsrec_n; rc++, r--) {
            if (r <= 0) {
                part = dp->tlsrec[i];
                r = part.r; i++;
            }
            long pos = rc * 5;
            pos += gen_offset(part.pos, 
                part.flag, buffer, *n - pos, lp, info);
                
            if (part.pos < 0 || part.flag) {
                pos -= 5;
            }
            pos += (long )part.s * (part.r - r);
            if (pos < lp) {
                LOG(LOG_E, "tlsrec cancel: %ld < %ld\n", pos, lp);
                break;
            }
            if (!part_tls(buffer + lp, 
                    bfsize - lp, *n - lp, pos - lp)) {
                LOG(LOG_E, "tlsrec error: pos=%ld, n=%zd\n", pos, *n);
                break;
            }
            LOG(LOG_S, "tlsrec: pos=%ld, n=%zd\n", pos, *n);
            *n += 5;
            lp = pos + 5;
        }
    }
}



/*
 * Doctor Mobile: a ClientHello the client already cut into several TLS
 * records - Mirage, in our sing-box (common/tlsfragment) and mihomo
 * (component/mirage) - each record in its own write.
 *
 * Fills ends[] with where each complete handshake record ends and returns
 * how many there are, or 0 when buffer does not start with a ClientHello
 * split across more than one record. *whole is set when the records seen
 * hold the entire handshake message.
 */
static int chello_records(const char *buffer, ssize_t n,
        long *ends, int max, bool *whole)
{
    *whole = 0;
    if (!is_tls_chello(buffer, n) || n < 9) {
        return 0;
    }
    long need = 4 + (((uint8_t )buffer[6] << 16)
        | ((uint8_t )buffer[7] << 8) | (uint8_t )buffer[8]);
    if (ANTOHS(buffer, 3) >= need) {
        return 0;
    }
    long pos = 0, got = 0;
    int k = 0;
    while (k < max && pos + 5 <= n
            && buffer[pos] == 0x16 && buffer[pos + 1] == 0x03) {
        long len = ANTOHS(buffer, pos + 3);
        if (pos + 5 + len > n) {
            break;
        }
        pos += 5 + len;
        got += len;
        ends[k++] = pos;
        if (got >= need) {
            *whole = 1;
            break;
        }
    }
    return k > 1 ? k : 0;
}


/*
 * Joins the first k records into one, so that every SNI-relative position
 * and --tlsrec work on the ClientHello as if it had arrived whole. Only the
 * record framing changes; the handshake message is untouched.
 */
static ssize_t merge_chello(char *buffer, ssize_t n, const long *ends, int k)
{
    long total = ANTOHS(buffer, 3);
    long w = ends[0];
    for (int i = 1; i < k; i++) {
        long start = ends[i - 1] + 5;
        long len = ends[i] - start;
        memmove(buffer + w, buffer + start, len);
        w += len;
        total += len;
    }
    memmove(buffer + w, buffer + ends[k - 1], n - ends[k - 1]);
    SHTONA(buffer, 3, total);
    return n - 5 * (k - 1);
}

ssize_t desync(struct poolhd *pool, 
        struct eval *val, struct buffer *buff, ssize_t *np, bool *wait)
{
    struct desync_params dp = *val->pair->dp;
    struct proto_info info = { 0 };
    
    int sfd = val->fd;
    
    char *buffer = buff->data;
    size_t bfsize = buff->size;
    ssize_t offset = buff->offset;
    
    ssize_t skip = val->pair->round_sent;
    unsigned int part_skip = val->pair->part_sent;
    
    /*
     * A ClientHello that arrives already split into records (Mirage):
     *
     * - A group that changes the hello (split, disorder, oob, fake, tlsrec,
     *   tlsminor) gets it merged back into one record first. Its positions
     *   are relative to the SNI, which parse_tls only finds inside a single
     *   record: on the split hello every one of them resolved to nothing, so
     *   the group sent the records unchanged, in one write.
     * - A group that changes nothing forwards the records one write each, as
     *   the client wrote them. Sent in one write they are the form Hamrah-e
     *   Aval drops in silence (see mirage.go in the cores), which a plain
     *   pass-through produced whenever both records were read at once.
     *
     * Only when the merged record still fits a TLS record, and only for a
     * whole hello; a partial one is left as it is.
     */
    long rec_ends[8];
    bool rec_whole = 0;
    int recs = chello_records(buffer, *np, rec_ends, 8, &rec_whole);
    bool changes = dp.parts_n || dp.tlsrec_n || dp.tlsminor_set;
    struct part rec_parts[7];
    
    if (recs && changes) {
        if (!skip && rec_whole
                && rec_ends[recs - 1] - 5 * recs <= 16384) {
            *np = merge_chello(buffer, *np, rec_ends, recs);
            LOG(LOG_S, "merged %d TLS records\n", recs);
        }
    }
    else if (recs) {
        for (int k = 0; k < recs - 1; k++) {
            rec_parts[k] = (struct part ){ .m = DESYNC_SPLIT,
                .pos = rec_ends[k], .r = 1 };
        }
        dp.parts = rec_parts;
        dp.parts_n = recs - 1;
    }
    
    if (!skip && LOG_ENABLED) {
        init_proto_info(buffer, *np, &info);
        
        if (info.host_pos) {
            LOG(LOG_S, "host: %.*s (%d)\n",
                info.host_len, buffer + info.host_pos, info.host_pos);
        } else {
            INIT_HEX_STR(buffer, (*np > 16 ? 16 : *np));
            LOG(LOG_S, "bytes: %s (%zd)\n", HEX_STR, *np);
        }
    }
    if (!skip) {
        tamp(buffer, bfsize, np, &dp, &info);
    }
    ssize_t n = *np;
    
    long lp = offset;
    struct part part;
    
    int i = 0, r = 0;
    unsigned int curr_part = 0;
    
    for (; r > 0 || i < dp.parts_n; r--) {
        if (r <= 0) {
            part = dp.parts[i];
            r = part.r; i++;
        }
        curr_part++;
        
        long pos = gen_offset(part.pos, part.flag, buffer, n, lp, &info);
        pos += (long )part.s * (part.r - r);
        
        if (((skip && pos < skip) 
                || curr_part < part_skip) && !(part.flag & OFFSET_START)) {
            continue;
        }
        if (offset && pos < offset) {
            continue;
        }
        if (pos < 0 || pos < lp) {
            LOG(LOG_E, "split cancel: pos=%ld-%ld, n=%zd\n", lp, pos, n);
            break;
        }
        if (pos > n) {
            LOG(LOG_E, "pos reduced: %ld -> %ld\n", pos, n);
            pos = n;
        }
        ssize_t s = 0;
        
        if (curr_part == part_skip) {
            s = pos - lp;
        } else 
        {
        switch (part.m) {
            #ifdef FAKE_SUPPORT
            case DESYNC_FAKE:;
                struct packet pkt = get_tcp_fake(buffer, n, &info, &dp);
                if (!pkt.data) {
                    return -1;
                }
                if (pos != lp) s = send_fake(val, 
                    buffer + lp, pos - lp, &dp, pkt);
                #ifndef __linux
                free(pkt.data);
                #endif
                break;
            #endif
            case DESYNC_OOB:
                s = send_oob(sfd, 
                    buffer + lp, bfsize - lp, pos - lp, dp.oob_char);
                break;
                
            case DESYNC_DISORDER:
            case DESYNC_DISOOB:
                if (!((part.r - r) % 2)
                        && setttl(sfd, 1) < 0) {
                    s = -1;
                    break;
                }
                val->restore_ttl = 1;
                
                if (part.m == DESYNC_DISOOB) 
                    s = send_oob(sfd, 
                        buffer + lp, bfsize - lp, pos - lp, dp.oob_char);
                else 
                    s = send(sfd, buffer + lp, pos - lp, 0);
                
                if (s < 0) {
                    uniperror("send");
                }
                break;
            
            case DESYNC_SPLIT:
            case DESYNC_NONE:
            default:
                s = send(sfd, buffer + lp, pos - lp, 0);
                break;
        }
        LOG(LOG_S, "split: pos=%ld-%ld (%zd), m: %s\n", lp, pos, s, demode_str[part.m]);
        }
        val->pair->part_sent = curr_part;

        if (s == ERR_WAIT) {
            set_timer(pool, val, params.await_int);
            *wait = true;
            return lp - offset;
        }
        if (s < 0) {
            if (get_e() == EAGAIN) {
                return lp - offset;
            }
            return -1;
        }
        else if (s != (pos - lp)) {
            LOG(LOG_E, "%zd != %ld\n", s, pos - lp);
            return lp + s - offset;
        }
        
        if (sock_has_notsent(sfd) 
                || (params.wait_send 
                    && curr_part > part_skip)) {
            LOG(LOG_S, "sock_has_notsent\n");
            set_timer(pool, val, params.await_int);
            *wait = true;
            return pos - offset;
        }
        restore_state(val);
        
        lp = pos;
    }
    // send all/rest
    if (lp < n) {
        LOG((lp ? LOG_S : LOG_L), "send: pos=%ld-%zd\n", lp, n);
        if (send(sfd, buffer + lp, n - lp, 0) < 0) {
            if (get_e() == EAGAIN) {
                return lp - offset;
            }
            uniperror("send");
            return -1;
        }
    }
    return n - offset;
}


int pre_desync(int sfd, struct desync_params *dp)
{
    #ifdef __linux__
    if (dp->drop_sack && drop_sack(sfd)) {
        return -1;
    }
    #endif
    return 0;
}

int post_desync(int sfd, struct desync_params *dp)
{
    #ifdef __linux__
    int nop = 0;
    if (dp->drop_sack) {
        if (setsockopt(sfd, SOL_SOCKET, 
                SO_DETACH_FILTER, &nop, sizeof(nop)) == -1) {
            uniperror("setsockopt SO_DETACH_FILTER");
            return -1;
        }
    }
    #endif
    return 0;
}


ssize_t desync_udp(int sfd, char *buffer, 
        ssize_t n, const struct sockaddr *dst, struct desync_params *dp)
{
    if (LOG_ENABLED) {
        INIT_HEX_STR(buffer, (n > 16 ? 16 : n));
        LOG(LOG_S, "bytes: %s (%zd)\n", HEX_STR, n);
    }
    if (dp->udp_fake_count != 0) {
        struct packet pkt;
        if (dp->fake_data.data) {
            pkt = dp->fake_data;
        }
        else {
            pkt = fake_udp;
        }
        if (dp->fake_offset.m) {
            if (pkt.size > dp->fake_offset.pos) { 
                pkt.size -= dp->fake_offset.pos;
                pkt.data += dp->fake_offset.pos;
            }
            else pkt.size = 0;
        }
        int bttl = dp->ttl ? dp->ttl : DEFAULT_TTL;
        if (setttl(sfd, bttl) < 0) {
            return -1;
        }
        for (int i = 0; i < dp->udp_fake_count; i++) {
            ssize_t len = send(sfd, pkt.data, pkt.size, 0);
            if (len < 0) {
                uniperror("send");
                return -1;
            }
        }
        if (setttl(sfd, params.def_ttl) < 0) {
            return -1;
        }
    }
    return send(sfd, buffer, n, 0);
}
