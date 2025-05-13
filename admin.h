#pragma once

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


int open_sqlite_rw(char *file, sqlite3 **db);

int add_ugroup(sqlite3 *db, char *grp, char *user);
int add_groups(sqlite3 *db, char *group, char **users, int ulen);
int add_user(sqlite3 *db, char *user);