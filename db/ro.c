#include "ro.h"

#include "log.h"

#include <stdarg.h>
#include <string.h>
#include <sqlite3.h>
#include <ctype.h>
#include "util.h"


static int decode_key(const char *key, char *comment, size_t commentsz, char *data, size_t datasz) {
    const char *p, *b64;
    int ret = 0;

    if(key == NULL || data == NULL || datasz == 0) {
        return -1;
    }

    while(isspace(*key)) key++;

    p = key;
    while(*p && !isspace(*p)) p++;
    if(p == key) {
        return -1;
    }
    size_t clen = ((int)(p - key)) < commentsz ? ((int)(p - key)) : commentsz;
    memcpy(comment, key, clen);
    comment[clen - 1] = '\0';

    while(isspace(*p)) p++;

    b64 = p;
    if(!*b64) {
        return -1;
    }

    while(*p && !isspace(*p)) p++;
    ret = base64_decode(b64, (p - b64), data, datasz);
    if(ret == 0) {
        return -1;
    }

    return ret;
}

int open_sqlite_ro(const char *dbfile, sqlite3 **db) {
    int rc;
    char *errmsg;

    rc = sqlite3_open_v2(dbfile, db, SQLITE_OPEN_READONLY, NULL);
    if(rc != SQLITE_OK) {
        un_log(LOG_ERR, "failed to open db: '%s'\n", dbfile);
        rc = -1;
        goto out;
    }
    return 1;
out:
    sqlite3_close(*db);
    return rc;

}

int check_exists(sqlite3 *db, const char *sql, int cnt, ...) {
    sqlite3_stmt *stmt;
    int rc;
    int exists = 0;

    if((rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) != SQLITE_OK) {
        un_log(LOG_ERR, "failed to prepare stmt: %s", sqlite3_errmsg(db));
        return -1;
    }
    va_list va;
    va_start(va, cnt);
    for(int i = 0; i < cnt; i++) {
        const char *param = va_arg(va, char *);
        if(sqlite3_bind_text(stmt, 1, param, -1, SQLITE_STATIC) != SQLITE_OK) {
            un_log(LOG_ERR, "failed binding param %s", sqlite3_errmsg(db));
            sqlite3_finalize(stmt);
            return -1;
        }
    }
    if((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        exists = sqlite3_column_int(stmt, 0);
    } else if(rc == SQLITE_DONE) {
        exists = 0;
    } else {
        un_log(LOG_ERR, "failed to execute stmt: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return exists;
}

int check_user(sqlite3 *db, const char *user) {
    return check_exists(db, "SELECT EXISTS(SELECT UID FROM USERS WHERE USERNAME = ?)", 1, user);
}

int check_group(sqlite3 *db, const char *grp) {
    return check_exists(db, "SELECT EXISTS(SELECT GID FROM USERGROUPS WHERE NAME = ?)", 1, grp);
}

int check_key(sqlite3 *db, const char *key) {
    char data[4096];
    char comment[64];

    int x;

    x = strdelimcpy(comment, key, ' ', sizeof(comment));
    if(x == 0) {
        return -1;
    }
    x = strdelimcpy(data, key + x + 1, ' ', sizeof(data));
    if(x == 0) {
        return -1;
    }

    sqlite3_stmt *stmt = NULL;
    int rc = 0;

    if(sqlite3_prepare_v2(db, "SELECT EXISTS(SELECT FINGERPRINT FROM USER_KEYS WHERE TYPE = ? AND DATA = ?)", -1,&stmt, NULL) != SQLITE_OK) {
        un_log(LOG_ERR, "prepare stmt failed: %s", sqlite3_errmsg(db));
        rc = -1;
        goto out;
    }


    sqlite3_bind_text(stmt, 1, comment, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, data, -1, SQLITE_STATIC);

    if((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        rc = sqlite3_column_int(stmt, 0);
    } else if(rc == SQLITE_DONE) {
        rc  = 0;
    } else {
        un_log(LOG_ERR, "failed to execute stmt: %s", sqlite3_errmsg(db));
        sqlite3_finalize(stmt);
        return -1;
    }

out:
    sqlite3_finalize(stmt);
    return rc;
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

static char* lowerstr(char *s) {
    if(!s) return NULL;

    char *s1 = strdup(s);
    if(!s1) {
        return NULL;
    }

    char *save = s1;

    while(*s1) {
        unsigned char uc = (unsigned char)*s1;
        unsigned char is_upper = (uc - 'A') <= ('Z' - 'A');
        unsigned char mask = -(signed char)is_upper;
        *s1 = *s1 | (mask & 0x20);
        s1++;
    }
    return save;
}

int verify_key(sqlite3 *db,char *finger, char *key, char **out, long *user) {
    sqlite3_stmt *stmt = NULL;
    int rc = 0;

    char userkey[4096];
    size_t ukeysz;

    char dbkey[4096];
    size_t dbkeysz;

    *out = NULL;

    if((ukeysz = base64_decode(key, -1, userkey, sizeof(userkey))) == 0) {
        un_log(LOG_ERR, "failed to decode user key: %s", key);
        return -1;
    }

    if((rc = sqlite3_prepare_v2(db, "select UID, TYPE, DATA from USER_KEYS where FINGERPRINT = ?", -1, &stmt, NULL)) != SQLITE_OK) {
        un_log(LOG_ERR, "failed to prepare stmt: %s", sqlite3_errmsg(db));
        rc = -1;
        goto out;
    }

    sqlite3_bind_text(stmt, 1, finger, -1, SQLITE_STATIC);

    while((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        long uid = sqlite3_column_int(stmt, 0);
        const char *type = sqlite3_column_text(stmt, 1);
        const char *ent = sqlite3_column_blob(stmt, 2);
        dbkeysz = base64_decode(ent, -1, dbkey, sizeof(dbkey));

        if(mem_equals(userkey, ukeysz, dbkey, dbkeysz)) {
            asprintf(out, "%s %s", type, ent);
            *user = uid;
            rc = 0;
            goto out;
        }
    }

    rc = -1;
out:
    sqlite3_finalize(stmt);
    return rc;
}

char* repo_get_permissions(sqlite3 *db, const char *repo, long uid) {
    sqlite3_stmt *stmt;
    const char *sql =
        "SELECT "
        "  CASE "
        "    WHEN r.UID = ?1 THEN r.UPERM "
        "    WHEN EXISTS ("
        "      SELECT 1 FROM MEMBER_GROUPS mg "
        "      WHERE mg.UID = ?1 AND mg.GID = r.GID"
        "    ) THEN r.GPERM "
        "    ELSE NULL "
        "  END "
        "FROM REPOS r WHERE r.REPO = ?2;";

    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        un_log(LOG_ERR, "failed to prepare statement: %s", sqlite3_errmsg(db));
        return NULL;
    }

    sqlite3_bind_int(stmt, 1, uid);
    sqlite3_bind_text(stmt, 2, repo, -1, SQLITE_STATIC);

    char *result = NULL;
    if ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const unsigned char *perm = sqlite3_column_text(stmt, 0);
        if (perm) {
            result = strdup((const char *)perm);
        }
    } else if (rc != SQLITE_DONE) {
        un_log(LOG_ERR, "sqlite error: %s", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    return result;
}

