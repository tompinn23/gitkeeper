#include "rw.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "sqlite3.h"
#include "sha.h"
#include "util.h"

INCBIN(schema_sql, "schema.sql");

int open_sqlite_rw(char *file, sqlite3 **db) {
    int rc;
    char *errmsg;

    rc = sqlite3_open_v2(file, db, SQLITE_OPEN_READWRITE, NULL);
    if(rc == SQLITE_CANTOPEN) {
        rc = sqlite3_open_v2(file, db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
        if(rc != SQLITE_OK) {
            un_log(LOG_ERR, "failed to create db: '%s'\n", file);
            rc = -1;
            goto out;
        }
        rc = sqlite3_exec(*db, schema_sql, NULL, NULL, &errmsg);
        if(rc != SQLITE_OK) {
            un_log(LOG_ERR, "failed to initialize db: '%s'\n", errmsg);
            sqlite3_free(errmsg);
            rc = -1;
            goto out;
        }
    } else if(rc != SQLITE_OK) {
        un_log(LOG_ERR, "failed to open db: '%s'\n", file);
        rc = -1;
        goto out;
    }
    return 1;
out:
    sqlite3_close(*db);
    return rc;
}


static char *fingerprint(uint8_t *data, unsigned dlen) {
    char *ret = NULL;
    char decoded[4096];
    size_t decodedsz;

    decodedsz = base64_decode(data, dlen, decoded, sizeof(decoded));
    if(decodedsz == 0) {
        return NULL;
    }

    char chksum[32];
    sha256(chksum, decoded, decodedsz);

    char *b64 = base64_encode(chksum, sizeof(chksum));
    if(!b64) {
        return NULL;
    }
    for(size_t i = strlen(b64); i >= 0; i--) {
        if(b64[i] == '=' || b64[i] == '\0') {
            b64[i]= '\0';
        } else {
            break;
        }
    }


    asprintf(&ret, "SHA256:%s", b64);
    free(b64);

    return ret;
}


int add_user(sqlite3 *db, char *user, char *key) {
    sqlite3_stmt *stmt = NULL;
    int rc;

    const char *sql = "INSERT INTO USERS (USERNAME) VALUES (?)";

    if(check_user(db, user)) {
        if(key == NULL) { un_log(LOG_WARN, "user already exists"); }
    } else {
        if((rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) != SQLITE_OK) {
            un_log(LOG_ERR, "failed to prepare stmt: %s", sqlite3_errmsg(db));
            rc = -1;
            goto out;
        }
        sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);

        if(sqlite3_step(stmt) != SQLITE_DONE) {
            un_log(LOG_ERR, "failed adding user: %s", sqlite3_errmsg(db));
            rc = -1;
            goto out;
        }
    }

    if(key != NULL && !check_key(db, key)) {
        char type[64];
        int typelen = strdelimcpy(type, key, ' ', sizeof(type));
        char data[4096];
        int datalen = strdelimcpy(data, key + typelen + 1, ' ', sizeof(data));

        char *fngr = fingerprint(data, datalen);

        const char *ksql = "INSERT INTO USER_KEYS (FINGERPRINT, TYPE, DATA, UID) VALUES (?,?,?, (SELECT UID FROM USERS WHERE USERNAME = ?))";
        if(sqlite3_prepare_v2(db, ksql, -1, &stmt, NULL) != SQLITE_OK) {
            un_log(LOG_ERR, "failed prepare stmt: %s", sqlite3_errmsg(db));
            rc = -1;
            goto out;
        }

        sqlite3_bind_text(stmt, 1, fngr, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, type, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, data, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, user, -1, SQLITE_STATIC);

        if(sqlite3_step(stmt) != SQLITE_DONE) {
            un_log(LOG_ERR, "err executing stmt: %s", sqlite3_errmsg(db));
            rc = 0;
            goto out;
        }
    } else if(key != NULL) {
        un_log(LOG_ERR, "key is already in use");
        rc= -1;
    }
out:
    sqlite3_finalize(stmt);
    return rc;
}

int add_ugroup(sqlite3 *db, char *grp, char *user) {
    const char *usql = "INSERT INTO MEMBER_GROUPS (UID, GID) SELECT USERS.UID, USERGROUPS.GID FROM USERS, USERGROUPS WHERE USERS.USERNAME = ? AND USERGROUPS.NAME = ?";
    const char *check_usersql = "SELECT 1 FROM USERS WHERE USERNAME = ?";

    sqlite3_stmt *stmt, *check;
    int rc = 0;

    stmt = NULL;
    check = NULL;

    if((rc = sqlite3_prepare_v2(db, usql, -1, &stmt, NULL)) != SQLITE_OK) {
        un_log_sqlite(LOG_ERR, "prepare stmt: %s", usql);
        rc = -1;
        goto out;
    }
    if((rc = sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC)) != SQLITE_OK ||
       (rc = sqlite3_bind_text(stmt, 2, grp, -1, SQLITE_STATIC)) != SQLITE_OK) {
        un_log_sqlite(LOG_ERR, "binding user/group failed");
        rc = -1;
        goto out;
    }

    if((rc = sqlite3_step(stmt)) == SQLITE_CONSTRAINT) {
        un_log(LOG_WARN, "user '%s' already member of '%s'", user, grp);
    } else if(rc != SQLITE_DONE) {
        un_log_sqlite(LOG_ERR, "failed to execute stmt %s", usql);
        rc = -1;
        goto out;
    }

    if(sqlite3_changes(db) != 1) {
        if((rc = sqlite3_prepare_v2(db, check_usersql, -1, &check, NULL)) == SQLITE_OK &&
           (rc = sqlite3_bind_text(check, 1, user, -1, SQLITE_STATIC)) == SQLITE_OK &&
           (rc = sqlite3_step(check) != SQLITE_ROW)) {
            un_log(LOG_WARN, "user %s does not exist", user);
        }
    }

    rc = 0;
out:
    sqlite3_finalize(stmt);
    sqlite3_finalize(check);
    return rc;
}

int add_groups(sqlite3 *db, char *group, char **users, int ulen) {
    sqlite3_stmt *stmt = NULL;
    int rc = 0;

    if(sqlite3_db_readonly(db, NULL)) {
        un_log(LOG_ERR, "kdb is readonly");
        return -1;
    }

    if(sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO USERGROUPS (NAME) VALUES (?)", -1, &stmt, NULL) != SQLITE_OK) {
        un_log(LOG_ERR, "failed: prepare stmt: %s", sqlite3_errmsg(db));
        rc = -1;
        goto out;
    }

    sqlite3_bind_text(stmt, 1, group, -1, SQLITE_STATIC);

    if(sqlite3_step(stmt) != SQLITE_DONE) {
        un_log(LOG_ERR, "failed to add grp: %s", sqlite3_errmsg(db));
        rc = -1;
        goto out;
    }

    if(ulen > 0) {
        if(sqlite3_exec(db, "BEGIN", NULL, 0, 0) != SQLITE_OK) {
            un_log(LOG_ERR, "failed to begin transaction");
            rc = -1;
            goto out;
        }

        for(int i = 0; i < ulen; i++) {
            if(add_ugroup(db, group, users[i]) < 0) {
                goto failed;
            }
        }

        if(sqlite3_exec(db, "COMMIT", NULL, 0, 0) != SQLITE_OK) {
            un_log(LOG_ERR, "failed commit %s", sqlite3_errmsg(db));
            rc = -1;
            goto failed;
        }
    }

    rc = 0;
    goto out;
failed:
    sqlite3_exec(db, "ROLLBACK", NULL, 0, 0);
out:
    sqlite3_finalize(stmt);
    return rc;
}


int add_repo(sqlite3 *db, const char *repo, const char *user, const char *uprm, const char *grp, const char *gprm) {
    sqlite3_stmt *stmt = NULL;
    int rc;

    if (grp) {
        const char *sql =
            "INSERT INTO REPOS (REPO, UID, GID, UPERM, GPERM) "
            "VALUES (?, "
            "  (SELECT UID FROM USERS WHERE USERNAME = ?), "
            "  (SELECT GID FROM USERGROUPS WHERE NAME = ?), "
            "  ?, ?);";

        rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) return -1;

        sqlite3_bind_text(stmt, 1, repo, -1, SQLITE_STATIC);  // REPO
        sqlite3_bind_text(stmt, 2, user, -1, SQLITE_STATIC);  // USERNAME
        sqlite3_bind_text(stmt, 3, grp, -1, SQLITE_STATIC);   // GROUP NAME
        sqlite3_bind_text(stmt, 4, uprm, -1, SQLITE_STATIC);  // UPERM
        sqlite3_bind_text(stmt, 5, gprm ? gprm : "---", -1, SQLITE_STATIC); // GPERM
    } else {
        const char *sql =
            "INSERT INTO REPOS (REPO, UID, UPERM) "
            "VALUES (?, "
            "  (SELECT UID FROM USERS WHERE USERNAME = ?), "
            "  ?);";

        rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) return -1;

        sqlite3_bind_text(stmt, 1, repo, -1, SQLITE_STATIC);  // REPO
        sqlite3_bind_text(stmt, 2, user, -1, SQLITE_STATIC);  // USERNAME
        sqlite3_bind_text(stmt, 3, uprm, -1, SQLITE_STATIC);  // UPERM
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return rc == SQLITE_DONE ? 0 : -1;
}
