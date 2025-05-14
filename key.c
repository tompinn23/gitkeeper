#include <sqlite3.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "log.h"

size_t base64_decode(const char *in, uint8_t *out, size_t max_out) {
    static const unsigned char d[] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, // 0–15
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, // 16–31
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, // 32–47
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64,  0, 64, 64, // 48–63
        64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 64–79
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64, // 80–95
        64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // 96–111
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51                      // 112–122
    };

    size_t i = 0, j = 0;
    uint32_t buf = 0;
    int bits = 0;

    while (in[i] && in[i] != '\n' && j < max_out) {
        unsigned char c = in[i++];
        if (c > 122) continue;
        unsigned char v = d[c];
        if (v == 64) continue;

        buf = (buf << 6) | v;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            out[j++] = (buf >> bits) & 0xFF;
        }
    }

    return j;
}

static int strdelimcpy(char *dest, const char *src, char delim, int max) {
    int i = 0;
    while(i < max - 1 && src[i] && src[i] != delim) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
    if(i >= max -1 || src[i] == '\0') {
        return -1;
    }
    return i;
}


bool mem_equals(const void *s1, size_t l1, const void *s2, size_t l2) {
    const uint8_t *p1 = (const uint8_t *)s1;
    const uint8_t *p2 = (const uint8_t *)s2;

    size_t len = l1 > l2 ? l1 : l2;
    uint8_t res = 0;

    for(size_t i = 0; i < len; i++) {
        res |= (i < l1 ? p1[i] : 0) ^ (i < l2 ? p2[i] : 0);
    }

    return res == 0;
}

struct key {
    char type[32];
    char bytes[4096];
    int bytesz;
    char comment[256];
};

struct key *key_decode(const char *keyline) {
    const char *s = keyline;
    int rc;
    char b64buf[4096];
    struct key *k;

    k = malloc(sizeof(*k));
    if((rc = strdelimcpy(k->type, s, ' ', sizeof(k->type))) < 0) {
        free(k);
        return NULL;
    }
    s += rc + 1;
    if((rc = strdelimcpy(b64buf, s, ' ', sizeof(b64buf))) < 0) {
        free(k);
        return NULL;
    }
    k->bytesz = base64_decode(b64buf, k->bytes, sizeof(k->bytes));
    s += rc + 1;
    strlcpy(k->comment, s, sizeof(k->comment));

    un_log(LOG_DEBUG, "key:\ntype: %s\nb64: %s\ncomment: %s", k->type, b64buf, k->comment);
    return k;
}

int verify_kdb(char *finger, char *kdb) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc = 0;
    const char *key, *user;
    struct key *entry;
    char incoming[4096];
    size_t incomingsz;


    if((incomingsz = base64_decode(finger, incoming, sizeof(incoming))) == 0) {
        un_log(LOG_ERR, "failed to decode key provided by ssh: %s", finger);
        return -1;
    }

    un_log(LOG_DEBUG, "opening: %s", kdb);
    rc = sqlite3_open_v2(kdb, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW, NULL);
    if(rc != SQLITE_OK) {
        un_log_sqlite(LOG_ERR, "failed to open kdb: %s", kdb);
        rc = -1;
        goto out;
    }

    if((rc = sqlite3_prepare_v2(db, "select KEY, UID from USER_KEYS", -1, &stmt, NULL)) != SQLITE_OK) {
        un_log_sqlite(LOG_ERR, "failed to prepare stmt: %s", sqlite3_errmsg(db));
        rc = -1;
        goto out;
    }

    while((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        key = sqlite3_column_text(stmt, 0);
        user = sqlite3_column_text(stmt, 1);
        un_log(LOG_INFO, "checking: uid='%s' key='%s'", user, key);
        entry = key_decode(key);
        if(entry == NULL) {
            un_log(LOG_WARN, "invalid key in db against uid: '%s'", user);
            continue;
        }
        if(mem_equals(incoming, incomingsz, entry->bytes, entry->bytesz)) {
            printf("command=\"gitkeeper -k %s shell \'%s\'\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding %s\n", kdb, user, key);
            break;
        }
    }

    rc = 0;
out:
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return rc;
}
