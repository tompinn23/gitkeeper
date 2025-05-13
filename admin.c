#include "admin.h"

#include <stdlib.h>
#include "log.h"

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

int add_ugroup(sqlite3 *db, char *grp, char *user) {
    const char *usql = "INSERT INTO GROUP_MEMBERSHIP (UID, GID) SELECT USERS.UID, USERGROUPS.GID FROM USERS, USERGROUPS WHERE USERS.USERNAME = ? AND USERGROUPS.NAME = ?";
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
    sqlite3_stmt *grpstmt = NULL;
    sqlite3_stmt *ustmt = NULL, *check_ustmt = NULL;
    int rc = 0, rc2 = 0;


    const char *grpsql = "INSERT OR IGNORE INTO USERGROUPS (NAME) VALUES (?)";

    if(sqlite3_db_readonly(db, NULL)) {
        un_log(LOG_ERR, "kdb is readonly");
        return -1;
    }

    un_log(LOG_DEBUG, "preparing stmt: %s", grpsql);
    if((rc = sqlite3_prepare_v2(db, grpsql, -1, &grpstmt, NULL)) != SQLITE_OK) {
        un_log_sqlite(LOG_ERR, "failed to prepare stmt");
        rc = -1;
        goto out;
    }

    if((rc = sqlite3_bind_text(grpstmt, 1, group, -1, SQLITE_STATIC)) != SQLITE_OK) {
        un_log_sqlite(LOG_ERR, "failed to bind stmt");
        rc = -1;
        goto out;
    }

    if((rc = sqlite3_step(grpstmt)) != SQLITE_DONE) {
        un_log_sqlite(LOG_ERR, "failed to exec sql");
        rc = -1;
        goto out;
    }

    if(ulen > 0) {
        if((rc = sqlite3_exec(db, "BEGIN", NULL, 0, 0)) != SQLITE_OK) {
            un_log_sqlite(LOG_ERR, "failed to being transaction");
            rc = -1;
            goto failed_transaction;
        }

        for(int i = 0; i < ulen; i++) {
            un_log(LOG_DEBUG, "adding user %s to %s", users[i], group);
            if(add_ugroup(db, group, users[i]) < 0) {
                goto failed_transaction;
            }
        }

        if((rc = sqlite3_exec(db, "COMMIT", NULL, 0, 0)) != SQLITE_OK) {
            un_log_sqlite(LOG_ERR, "failed to commit");
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
        un_log_sqlite(LOG_ERR, "error preparing stmt: %s\n", sql);
        return -1;
    }

    rc = sqlite3_bind_text(stmt, 1, user, -1, SQLITE_STATIC);
    if(rc != SQLITE_OK) {
        sqlite3_finalize(stmt);
        un_log_sqlite(LOG_ERR, "error binding stmt: %s\n", sql);
        return -1;
    }

    rc = sqlite3_step(stmt);
    if(rc == SQLITE_CONSTRAINT) {
        un_log(LOG_ERR, "failed to add user (user already exists)");
    } else if(rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        un_log_sqlite(LOG_ERR, "error inserting user: %s\n", user);
        return -1;
    }

    sqlite3_finalize(stmt);
    return 0;
}