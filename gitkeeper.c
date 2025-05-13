#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sqlite3.h>

#include "log.h"
#include "sha.h"
#include "admin.h"

#include "key.h"



void reset_getopt() {
#if defined(__GLIBC__)
    optind = 0;
#elif defined(__OpenBSD__)
    optind = 1;
    optreset = 1;
#else
#error Must provide a reset mechanism for getopt
#endif
}

void do_checkdb(char *db, int argc, char **argv) {

    char *user, *key;
    if(argc != 2) {
        un_log(LOG_ERR, "require both user and key");
        exit(EXIT_FAILURE);
    }


    user = argv[0];
    key = argv[1];

    exit(verify_kdb(key, db));
}

void do_addgroup(char *dbfile, int argc, char **argv) {
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    sqlite3 *db = NULL;

    int ch, rc;

    reset_getopt();
    while((ch = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
        switch (ch) {
        case 'h':
            break;
        case '?':
            exit(EXIT_FAILURE);
        }
    }

    if(open_sqlite_rw(dbfile, &db) < 0) {
        exit(EXIT_FAILURE);
    }

    if((argc - optind) >= 2) {
        rc = add_groups(db, argv[optind], argv + optind + 1, (argc - optind - 1));
    } else if((argc - optind) == 1) {
        rc = add_groups(db, argv[optind], NULL, 0);
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

int do_adduser(char *dbfile, int argc, char **argv) {
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    sqlite3 *db = NULL;
    int ch, rc;

    reset_getopt();
    while((ch = getopt_long(argc, argv, "h", longopts, NULL)) != -1) {
        switch (ch) {
        case 'h':
            break;
        case '?':
            exit(EXIT_FAILURE);
        }
    }

    if(optind >= argc) {
        un_log(LOG_INFO, "adduser requires [user]");
        exit(EXIT_FAILURE);
    }

    if(open_sqlite_rw(dbfile, &db) < 0) {
        return -1;
    }

    ch = add_user(db, argv[optind]);
    if((rc = sqlite3_close(db)) != SQLITE_OK) {
        fprintf(stderr, "failed to close db: '%s'\n", sqlite3_errstr(rc));
        exit(EXIT_FAILURE);
    }
    exit(ch);
}

static void usage() {
    puts("gitkeeper 1.0\n");

    exit(EXIT_SUCCESS);
}

static void version() {
    puts("gitkeeper v1.0");
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {"debug", no_argument, NULL, 'd'},
        {"kdb", required_argument, NULL, 'k'},
        { NULL, 0, NULL, 0}
    };

    int debug = 0;
    char *subcommand, *db;
    int ch;

    while ((ch = getopt_long(argc, argv, "+hvdk:", longopts, NULL)) != -1) {
        switch(ch) {
            case 'h':
                usage();
                break;
            case 'v':
                version();
                break;
            case 'd':
                debug += 1;
                break;
            case 'k':
                db = strdup(optarg);
                break;
            case '?':
                exit(EXIT_FAILURE);
                break;
        }
    }

    if(db == NULL) {
        db = "/etc/gitkeeper/kdb.db";
    }

    if(argc - optind < 1) {
        un_log(LOG_ERR, "expected a command");
        exit(EXIT_FAILURE);
    }
    subcommand = argv[optind++];
    printf("subcommand: %s\n", subcommand);
    if(!strcmp(subcommand, "adduser")) {
        do_adduser(db, argc - optind, argv + optind);
    } else if(!strcmp(subcommand, "addgroup")) {
        do_addgroup(db, argc - optind, argv + optind);
    } else if(!strcmp(subcommand, "checkkdb")) {
        do_checkdb(db, argc - optind, argv + optind);
    }
}
