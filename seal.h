#ifndef SEAL_H
#define SEAL_H
#include <stddef.h>

int seal_init(const char *pubkey_hex_file);        /* 0 ok, -1 error */
int seal_init_hex(const char *hex64);              /* baked-key path */
int seal_available(void);
int seal_blob(const unsigned char *msg, size_t mlen,
              unsigned char **out, size_t *outlen);

#endif
