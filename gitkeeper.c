#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sqlite3.h>

#define STR2(x) #x
#define STR(x) STR2(x)

#define INCBIN(name, file) \
    __asm__(".section .rodata\n" \
            ".global " STR(name) "\n" \
            ".balign 16\n" \
            STR(name) ":\n" \
            ".incbin \"" file "\"\n" \
            \
            ".global " STR(name) "_end\n" \
            ".balign 1\n" \
            STR(name) "_end:\n" \
            ".byte 0\n" \
            ); \
            extern __attribute__((aligned(16))) const char name[]; \
            extern const char name##_end[]

INCBIN(schema_sql, "schema.sql");

enum un_log_mode {
    LOG_ERR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG,
    LOG_MODE_LAST
};

#ifdef __GNUC__
#define _UN_ATTRIB_PRINTF(start, end) __attribute__((format(printf, start, end)))
#else
#define _UN_ATTRIB_PRINTF(start, end)
#endif

void _un_log(enum un_log_mode mode, const char* fmt, ...) _UN_ATTRIB_PRINTF(2 ,3);
void _un_vlog(enum un_log_mode mode, const char* fmt, va_list args) _UN_ATTRIB_PRINTF(2, 0);

#ifdef UN_LOG_SRC_DIR
#define UN_FILENAME ((const char*)__FILE__ + sizeof(UN_LOG_SRC_DIR) - 1)
#else
#define UN_FILENAME __FILE__
#endif

bool un_log_enabled(enum un_log_mode mode);

#define log(mode, fmt, ...) _un_log(mode, "[%s:%d] " fmt, UN_FILENAME, __LINE__, ##__VA_ARGS__)
#define vlog(mode, fmt, args) _un_vlog("[%s:%d] " fmt, UN_FILENAME, __LINE__, args)
#define log_errno(mode, fmt, ...) _un_log(mode, "[%s:%d] " fmt ": %s", UN_FILENAME, __LINE__, ##__VA_ARGS__, strerror(errno))
#define log_err(mode, err, fmt, ...) _un_log(mode, "[%s:%d] " fmt ": %s", UN_FILENAME, __LINE__, ##__VA_ARGS__, strerror(err))
#define log_sqlite(mode, fmt, ...) _un_log(mode, "[%s:%d] " fmt ": %s", UN_FILENAME, __LINE__, ##__VA_ARGS__, sqlite3_errstr(rc))

#define S(x, n) (((((uint32_t)(x)&0xFFFFFFFFUL)>>(uint32_t)((n)&31))|((uint32_t)(x)<<(uint32_t)((32-((n)&31))&31)))&0xFFFFFFFFUL)
#define R(x, n) (((x)&0xFFFFFFFFUL)>>(n))
#define Gamma0(x) (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x) (S(x, 17) ^ S(x, 19) ^ R(x, 10))
#define RND(a,b,c,d,e,f,g,h,i) \
    t0 = h + (S(e, 6) ^ S(e, 11) ^ S(e, 25)) + (g ^ (e & (f ^ g))) + K[i] + W[i]; \
    t1 = (S(a, 2) ^ S(a, 13) ^ S(a, 22)) + (((a | b) & c) | (a & b)); \
    d += t0; \
    h  = t0 + t1;
#define STORE32H(x, y) \
    (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255); \
    (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255);
#define LOAD32H(x, y) \
    x = ((uint32_t)((y)[0]&255)<<24)|((uint32_t)((y)[1]&255)<<16)|((uint32_t)((y)[2]&255)<<8)|((uint32_t)((y)[3]&255));
#define STORE64H(x, y) \
    (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255); \
    (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255); \
    (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255); \
    (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255);
#define SHA256_COMPRESS(buff) \
    for (int i = 0; i < 8; i++) S[i] = sha256_state[i]; \
    for (int i = 0; i < 16; i++) LOAD32H(W[i], buff + (4*i)); \
    for (int i = 16; i < 64; i++) W[i] = Gamma1(W[i-2]) + W[i-7] + Gamma0(W[i-15]) + W[i-16]; \
    for (int i = 0; i < 64; i++) { \
        RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i); \
        t = S[7]; S[7] = S[6]; S[6] = S[5]; S[5] = S[4]; \
        S[4] = S[3]; S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t; \
    } \
    for (int i = 0; i < 8; i++) sha256_state[i] = sha256_state[i] + S[i];

int sha256(unsigned char out[32], const unsigned char* in, size_t len) {
    //writes the sha256 hash of the first "len" bytes in buffer "in" to buffer "out"
    //returns 0 on success, may return non-zero in future versions to indicate error
    const uint32_t K[64] = {
        0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
        0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
        0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
        0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
        0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
        0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
        0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
        0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
        0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
        0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
        0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
        0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
        0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
        0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
        0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
        0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
    };
    uint64_t sha256_length = 0;
    uint32_t sha256_state[8] = {
        0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
        0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
    }, S[8], W[64], t0, t1, t;
    unsigned char sha256_buf[64];
    //process input in 64 byte chunks
    while (len >= 64) {
       SHA256_COMPRESS(in);
       sha256_length += 64 * 8;
       in += 64;
       len -= 64;
    }
    //copy remaining bytes into sha256_buf
    memcpy(sha256_buf, in, len);
    //finish up (len now number of bytes in sha256_buf)
    sha256_length += len * 8;
    sha256_buf[len++] = 0x80;
    //pad then compress if length is above 56 bytes
    if (len > 56) {
        while (len < 64) sha256_buf[len++] = 0;
        SHA256_COMPRESS(sha256_buf);
        len = 0;
    }
    //pad up to 56 bytes
    while (len < 56) sha256_buf[len++] = 0;
    //store length and compress
    STORE64H(sha256_length, sha256_buf + 56);
    SHA256_COMPRESS(sha256_buf);
    //copy output
    for (int i = 0; i < 8; i++) {
        STORE32H(sha256_state[i], out + 4*i);
    }
    //return
    return 0;
}


/*
    LOG_ERR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG,
*/

static struct timespec start_time = {-1};

static const char *verbosity_colors[] = {
	[LOG_ERR] = "\x1B[1;31m",
    [LOG_WARN] = "\x1B[1;33m",
	[LOG_INFO] = "\x1B[1;34m",
	[LOG_DEBUG] = "\x1B[1;90m",
};

static const char *verbosity_headers[] = {
	[LOG_ERR] =   "[ERROR]",
    [LOG_WARN] =  "[WARN] ",
	[LOG_INFO] =  "[INFO] ",
	[LOG_DEBUG] = "[DEBUG]",
};

static void init_start_time() {
	if (start_time.tv_sec >= 0) {
		return;
	}
	clock_gettime(CLOCK_MONOTONIC, &start_time);
}

static const long NSEC_PER_SEC = 1000000000;

static void timespec_sub(struct timespec *r, const struct timespec *a,
		const struct timespec *b) {
	r->tv_sec = a->tv_sec - b->tv_sec;
	r->tv_nsec = a->tv_nsec - b->tv_nsec;
	if (r->tv_nsec < 0) {
		r->tv_sec--;
		r->tv_nsec += NSEC_PER_SEC;
	}
}

bool un_log_enabled(enum un_log_mode mode) {
    return true;
}

void _un_log(enum un_log_mode mode, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    _un_vlog(mode, fmt, args);
    va_end(args);
}
void _un_vlog(enum un_log_mode mode, const char* fmt, va_list args) {
        init_start_time();
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    timespec_sub(&ts, &ts, &start_time);
    fprintf(stderr, "%02d:%02d:%02d.%03ld ", (int)(ts.tv_sec / 60 / 60),
    (int)(ts.tv_sec / 60 % 60), (int)(ts.tv_sec % 60), ts.tv_nsec / 1000000);
    fprintf(stderr, "%s%s ", verbosity_colors[mode], verbosity_headers[mode]);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\x1B[0m\n");
}

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

// Encode to standard base64
void base64_encode(const uint8_t *in, size_t len, char *out) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, j;
    for (i = 0, j = 0; i + 2 < len; i += 3) {
        out[j++] = tbl[in[i] >> 2];
        out[j++] = tbl[((in[i] & 3) << 4) | (in[i+1] >> 4)];
        out[j++] = tbl[((in[i+1] & 15) << 2) | (in[i+2] >> 6)];
        out[j++] = tbl[in[i+2] & 63];
    }
    if (i < len) {
        out[j++] = tbl[in[i] >> 2];
        if (i + 1 < len) {
            out[j++] = tbl[((in[i] & 3) << 4) | (in[i+1] >> 4)];
            out[j++] = tbl[(in[i+1] & 15) << 2];
        } else {
            out[j++] = tbl[(in[i] & 3) << 4];
            out[j++] = '=';
        }
        out[j++] = '=';
    }
    out[j] = '\0';
}

size_t b64_decoded_size(const char *in) {
	size_t len;
	size_t ret;
	size_t i;

	if (in == NULL)
		return 0;

	len = strlen(in);
	ret = len / 4 * 3;

	for (i=len; i-->0; ) {
		if (in[i] == '=') {
			ret--;
		} else {
			break;
		}
	}

	return ret;
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


static inline char ct_tolower(char c) {
    // Branchless: if c is in 'A'..'Z', set bit 0x20 to convert to lowercase
    uint8_t is_upper = (uint8_t)((c - 'A') <= ('Z' - 'A'));
    return c | (is_upper * 0x20);
}

void str_lower(char *s, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        s[i] = ct_tolower(s[i]);
    }
}

bool str_iseq(const char *s1, const char *s2)
{
    int             m = 0;
    volatile size_t i = 0;
    volatile size_t j = 0;
    volatile size_t k = 0;

    if (s1 == NULL || s2 == NULL)
        return false;

    while (1) {
        m |= s1[i]^s2[j];

        if (s1[i] == '\0')
            break;
        i++;

        if (s2[j] != '\0')
            j++;
        if (s2[j] == '\0')
            k++;
    }

    return m == 0;
}

#define MODE_SSHD 1
#define MODE_STANDALONE 2

int add_ugroup(sqlite3 *db, char *grp, char *user) {
    const char *usql = "INSERT INTO GROUP_MEMBERSHIP (UID, GID) SELECT USERS.UID, USERGROUPS.GID FROM USERS, USERGROUPS WHERE USERS.USERNAME = ? AND USERGROUPS.NAME = ?";
    const char *check_usersql = "SELECT 1 FROM USERS WHERE USERNAME = ?";

    sqlite3_stmt *stmt, *check;
    int rc = 0;

    stmt = NULL;
    check = NULL;

    if((rc = sqlite3_prepare_v2(db, usql, -1, &stmt, NULL)) != SQLITE_OK) {
        log_sqlite(LOG_ERR, "prepare stmt: %s", usql);
        rc = -1;
        goto out;
    }
    if((rc = sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC)) != SQLITE_OK ||
       (rc = sqlite3_bind_text(stmt, 2, grp, -1, SQLITE_STATIC)) != SQLITE_OK) {
        log_sqlite(LOG_ERR, "binding user/group failed");
        rc = -1;
        goto out;
    }

    if((rc = sqlite3_step(stmt)) == SQLITE_CONSTRAINT) {
        log(LOG_WARN, "user '%s' already member of '%s'", user, grp);
    } else if(rc != SQLITE_DONE) {
        log_sqlite(LOG_ERR, "failed to execute stmt %s", usql);
        rc = -1;
        goto out;
    }

    if(sqlite3_changes(db) != 1) {
        if((rc = sqlite3_prepare_v2(db, check_usersql, -1, &check, NULL)) == SQLITE_OK &&
           (rc = sqlite3_bind_text(check, 1, user, -1, SQLITE_STATIC)) == SQLITE_OK &&
           (rc = sqlite3_step(check) != SQLITE_ROW)) {
            log(LOG_WARN, "user %s does not exist", user);
        }
    }

    rc = 0;
out:
    sqlite3_finalize(stmt);
    sqlite3_finalize(check);
    return rc;
}

int add_group(sqlite3 *db, char *group, char **users, int ulen) {
    sqlite3_stmt *grpstmt = NULL;
    sqlite3_stmt *ustmt = NULL, *check_ustmt = NULL;
    int rc = 0, rc2 = 0;


    const char *grpsql = "INSERT OR IGNORE INTO USERGROUPS (NAME) VALUES (?)";

    if(sqlite3_db_readonly(db, NULL)) {
        fprintf(stderr, "db is readonly");
        return -1;
    }

    log(LOG_DEBUG, "preparing stmt: %s", grpsql);
    if((rc = sqlite3_prepare_v2(db, grpsql, -1, &grpstmt, NULL)) != SQLITE_OK) {
        log_sqlite(LOG_ERR, "failed to prepare stmt");
        rc = -1;
        goto out;
    }

    if((rc = sqlite3_bind_text(grpstmt, 1, group, -1, SQLITE_STATIC)) != SQLITE_OK) {
        log_sqlite(LOG_ERR, "failed to bind stmt");
        rc = -1;
        goto out;
    }

    if((rc = sqlite3_step(grpstmt)) != SQLITE_DONE) {
        log_sqlite(LOG_ERR, "failed to exec sql");
        rc = -1;
        goto out;
    }

    if(ulen > 0) {
        if((rc = sqlite3_exec(db, "BEGIN", NULL, 0, 0)) != SQLITE_OK) {
            log_sqlite(LOG_ERR, "failed to being transaction");
            rc = -1;
            goto failed_transaction;
        }

        for(int i = 0; i < ulen; i++) {
            log(LOG_DEBUG, "adding user %s to %s", users[i], group);
            if(add_ugroup(db, group, users[i]) < 0) {
                goto failed_transaction;
            }
        }

        if((rc = sqlite3_exec(db, "COMMIT", NULL, 0, 0)) != SQLITE_OK) {
            log_sqlite(LOG_ERR, "failed to commit");
            rc = -1;
            goto failed_transaction;
        }
    }

    rc = 0;
    goto out;
failed_transaction:
    sqlite3_exec(db, "ROLLBACK", NULL, 0, 0);
out:
    sqlite3_finalize(grpstmt);
    sqlite3_finalize(ustmt);
    return rc;
}

int add_user(sqlite3 *db, char *user) {
    sqlite3_stmt *stmt = NULL;
    int rc;

    const char *sql = "INSERT INTO USERS (USERNAME) VALUES (?);";

    if(sqlite3_db_readonly(db, NULL)) {
        return -1;
    }

    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if(rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        fprintf(stderr, "error preparing stmt: %s\n", sqlite3_errstr(rc));
        return -1;
    }

    rc = sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
    if(rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        fprintf(stderr, "error binding to stmt: %s\n", sqlite3_errstr(rc));
        return -1;
    }

    rc = sqlite3_step(stmt);
    if(rc == SQLITE_CONSTRAINT) {
        fprintf(stderr, "failed to insert user (likely user already exists)\n");
    } else if(rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        fprintf(stderr, "insert user '%s' failed: %s\n",user, sqlite3_errstr(rc));
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
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

    printf("key:\ntype: %s\nb64: %s\ncomment: %s\n", k->type, b64buf, k->comment);
    return k;
}

static void verify_key(char *finger, char *fpath) {
    FILE *fp = NULL;
    char *line = NULL;
    char *s, *p;
    size_t linesz = 0;
    int rc;
    char b64buf[4096];
    struct key *k = NULL;

    int ex = EXIT_SUCCESS;

    fp = fopen(fpath, "r");
    if(!fp) {
        fprintf(stderr, "failed to open keyfile '%s': %s", fpath, strerror(errno));
        ex = EXIT_FAILURE;
        goto out;
    }

    rc = getline(&line, &linesz, fp);
    if(rc < 0) {
        perror("failed to read line");
        ex = EXIT_FAILURE;
        goto out;
    }
    k = key_decode(line);
    if(!k) {
        ex = EXIT_FAILURE;
        goto out;
    }

    unsigned char sha[32], encoded[64];
    sha256(sha, k->bytes, k->bytesz);
    base64_encode(sha, sizeof(sha), encoded);

    size_t len = strlen(encoded);
    while(len > 0 && encoded[len -1] == '=') encoded[--len] = '\0';

    char *out;
    asprintf(&out, "256 SHA256:%s", encoded);

    str_lower(finger, strlen(finger));
    str_lower(out, strlen(out));

    printf("fingerprint match: %s\n", str_iseq(out, finger) ? "yes": "no");
out:
    if(fp != NULL) {
        fclose(fp);
    }
    free(line);
    free(k);
    exit(ex);
}

static void verify_kdb(char *user, char *finger, char *kdb) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    int rc;
    rc = sqlite3_open_v2(kdb, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOFOLLOW, NULL);
    if(rc != SQLITE_OK) {
        fprintf(stderr, "failed to open kdb: %s\n", sqlite3_errstr(rc));
        exit(EXIT_FAILURE);
    }

    rc = sqlite3_prepare_v2(db, "SELECT (fingerprint, user) from user_keys;", sizeof("SELECT (fingerprint, user) from user_keys;"), &stmt, NULL);

}

static void usage() {
    puts("gitkeeper 1.0");
    puts("usage: gitkeeper [huf] [keyfile]");
    puts("usage: gitkeeper [huf] [database]");

    puts("options:");
    puts("\t--help,-h    shows this help message");
    puts("\t--user,-u    user id to auth as");
    puts("\t--mode,-m    mode to operate valid values [ssh, verify]");
    puts("\t--finger,-f  key fingerprint to check");

    exit(EXIT_SUCCESS);
}

void reset_getopt() {
#ifdef __GLIBC__
    optind = 0;
#elif defined(__OpenBSD__)
    optind = 1;
    optreset = 1;
#endif
}

int do_keys(char *user, int argc, char **argv) {
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"user", required_argument, NULL, 'u'},
        {"finger", required_argument, NULL, 'f'},
        {"standalone", required_argument, NULL, 's'},
        {NULL,0,NULL,0},
    };

    char *fingerprint = NULL;
    int standalone = 0;

    int ch;
    reset_getopt();
    while((ch = getopt_long(argc, argv, "hsu:f:", longopts, NULL)) != -1) {
        switch(ch) {
        case 'h':
            usage();
            break;
        case 'u':
            if(user != NULL) {
                free(user);
            }
            user = strdup(optarg);
            break;
        case 'f':
            fingerprint = strdup(optarg);
            break;
        case 's':
            standalone = 1;
            break;
        case '?':
            exit(EXIT_FAILURE);
        }
    }
    if(!user || !fingerprint) {
        fputs("require both fingerprint and user to be set\n", stderr);
    }
    char *file;

    if(optind < argc) {
        file = strdup(argv[optind]);
    } else {
        fputs("file required for verification\n", stderr);
    }

    if(standalone) {
        verify_key(fingerprint, file);
    } else {

    }
}

int open_sqlite_rw(char *file, sqlite3 **db) {
    int rc;
    char *errmsg;

    rc = sqlite3_open_v2(file, db, SQLITE_OPEN_READWRITE, NULL);
    if(rc == SQLITE_CANTOPEN) {
        rc = sqlite3_open_v2(file, db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
        if(rc != SQLITE_OK) {
            fprintf(stderr, "failed to create db: '%s'\n", file);
            rc = -1;
            goto out;
        }
        rc = sqlite3_exec(*db, schema_sql, NULL, NULL, &errmsg);
        if(rc != SQLITE_OK) {
            fprintf(stderr, "failed to initialize db: '%s'\n", errmsg);
            sqlite3_free(errmsg);
            rc = -1;
            goto out;
        }
    } else if(rc != SQLITE_OK) {
        fprintf(stderr, "failed to open db: '%s'\n", file);
        rc = -1;
        goto out;
    }
    return 1;
out:
    sqlite3_close(*db);
    return rc;
}

void do_addgroup(int argc, char **argv) {
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"kdb", required_argument, NULL, 'f'},
        {NULL, 0, NULL, 0},
    };
    sqlite3 *db = NULL;

    char *file = NULL;
    int ch, rc;

    reset_getopt();
    while((ch = getopt_long(argc, argv, "hf:", longopts, NULL)) != -1) {
        switch (ch) {
        case 'h':
            usage();
        case 'f':
            file = strdup(optarg);
            break;
        case '?':
            exit(EXIT_FAILURE);
        }
    }

    if(file == NULL) {
        file = "/etc/gitkeeper/kdb.db";
    }

    if(open_sqlite_rw(file, &db) < 0) {
        exit(EXIT_FAILURE);
    }

    if((argc - optind) >= 2) {
        rc = add_group(db, argv[optind], argv + optind + 1, (argc - optind - 1));
    } else if((argc - optind) == 1) {
        rc = add_group(db, argv[optind], NULL, 0);
    } else {
        fprintf(stderr, "addgroup requires either group [user...]\n");
        rc = 0;
    }

    if(rc < 0) {
        fprintf(stderr, "failed to add group\n");
    }

    if((rc = sqlite3_close(db)) != SQLITE_OK) {
        fprintf(stderr, "failed to close db: '%s'\n", sqlite3_errstr(rc));
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}

int do_adduser(int argc, char **argv) {
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"kdb", required_argument,NULL, 'f'},
        {NULL, 0, NULL, 0},
    };
    sqlite3 *db = NULL;
    char *file = NULL;
    int ch, rc;

    reset_getopt();
    while((ch = getopt_long(argc, argv, "hf:", longopts, NULL)) != -1) {
        switch (ch) {
        case 'h':
            usage();
        case 'f':
            file = strdup(optarg);
            break;
        case '?':
            exit(EXIT_FAILURE);
        }
    }

    if(file == NULL) {
        file = "/etc/gitkeeper/kdb.db";
    }

    if(optind >= argc) {
        fprintf(stderr, "adduser requires a [user] to add\n");
    }

    if(open_sqlite_rw(file, &db) < 0) {
        return -1;
    }

    ch = add_user(db, argv[optind]);
    if((rc = sqlite3_close(db)) != SQLITE_OK) {
        fprintf(stderr, "failed to close db: '%s'\n", sqlite3_errstr(rc));
        exit(EXIT_FAILURE);
    }
    exit(ch);
}

int main(int argc, char **argv) {

    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"user", required_argument, NULL, 'u'},
        { NULL, 0, NULL, 0}
    };

    char *user = NULL;
    char *subcommand;

    int ch;

    while ((ch = getopt_long(argc, argv, "+hu:", longopts, NULL)) != -1) {
        switch(ch) {
            case 'h':
                usage();
                break;
            case 'u':
                user = strdup(optarg);
                break;
            case '?':
                exit(EXIT_FAILURE);
                break;
        }
    }

    if(argc - optind < 1) {
        fputs("expected a subcommand", stderr);
        exit(EXIT_FAILURE);
    }
    subcommand = argv[optind];
    if(!strcmp(subcommand, "keys")) {
        do_keys(user, argc - optind, argv + optind);
    } else if(!strcmp(subcommand, "adduser")) {
        do_adduser(argc - optind, argv + optind);
    } else if(!strcmp(subcommand, "addgroup")) {
        do_addgroup(argc - optind, argv + optind);
    } else if(!strcmp(subcommand, "wrapper")) {

    }
}
