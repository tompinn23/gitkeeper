#pragma once

#include <sqlite3.h>

#define PERM_R (1<<0)
#define PERM_W (1<<1)
#define PERM_A (1<<2)

int open_sqlite_ro(char *, sqlite3 **);
int repos_check_permission(sqlite3 *db, const char *repo, int repolen, long uid);