#include "repos.h"

int open_sqlite_ro(char *dbfile, sqlite3 **db) {
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

int repos_check_permission(sqlite3 *db, const char *repo, int repolen, long uid) {
    const char *sql =
        "SELECT CASE "
        "    WHEN R.UID = ? THEN R.UPERM "
        "    WHEN EXISTS ( "
        "        SELECT 1 "
        "        FROM GROUP_MEMBERSHIP GM "
        "        WHERE GM.UID = ? AND GM.GID = R.GID "
        "    ) THEN R.GPERM "
        "    ELSE NULL "
        "END AS EFFECTIVE_PERMISSIONS "
        "FROM REPOS R "
        "WHERE R.REPO = ? "
        "LIMIT 1;";
    sqlite3_stmt *stmt = NULL;
    int rc = 0;
    const char *eff_perms;
    

    if((rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL)) != SQLITE_OK) {
        un_log(LOG_ERR, "failed to prepare stmt", sqlite3_errmsg(db));
        rc = -1;
        goto out;
    }

    sqlite3_bind_int(stmt, 1, uid);
    sqlite3_bind_int(stmt, 2, uid);
    sqlite3_bind_text(stmt, 3, repo, repolen, SQLITE_STATIC);

    if((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        eff_perms = sqlite3_column_text(stmt, 0);
        rc = 0;
        if(eff_perms == NULL) {
            goto out;
        }
        while(*eff_perms != '\0') {
            switch(*eff_perms) {
            case 'r':
                rc |= PERM_R;
                break;
            case 'w':
                rc |= PERM_W;
                break;
            case 'a':
                rc |= PERM_A;
                break;
            }
            eff_perms++;
        }
        goto out;
    } else if(rc == SQLITE_DONE) {
        un_log(LOG_WARN, "no result found for repo (default to no access)");
        rc = 0;
        goto out;
    } else {
        rc = -1;
        un_log(LOG_ERR, "sqlite: failed exec %s", sqlite3_errmsg(db));
    }
out:
    sqlite3_finalize(stmt);
    return rc;
}