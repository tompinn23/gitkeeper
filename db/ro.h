#pragma once

#include <sqlite3.h>
#include <stdarg.h>

int open_sqlite_ro(const char *, sqlite3 **);

int check_exists(sqlite3 *, const char *, int, ...);
int check_user(sqlite3 *, const char *);
int check_group(sqlite3 *, const char *);
int check_key(sqlite3 *, const char *);

int verify_key(sqlite3 *,char *, char *, char **, long *);
char *repo_get_permissions(sqlite3 *db, const char *repo, long uid);
