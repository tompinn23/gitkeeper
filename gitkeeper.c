#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <limits.h>

#include <sqlite3.h>


#include "log.h"
#include "sha.h"
#include "admin.h"
#include "repos.h"
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



void do_addgroup(char *dbfile, int argc, char **argv) {
    sqlite3 *db = NULL;

    int ch, rc;

    if(open_sqlite_rw(dbfile, &db) < 0) {
        exit(EXIT_FAILURE);
    }

    if(argc >= 2) {
        rc = add_groups(db, argv[0], argv + 1, argc - 1);
    } else if(argc == 1) {
        rc = add_groups(db, argv[0], NULL, 0);
    } else {
        fprintf(stderr, "addgroup requires group [user...]\n");
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
    sqlite3 *db = NULL;
    int rc;
    char *key = NULL;

    if(argc < 1) {
        un_log(LOG_INFO, "adduser requires user [key]");
        exit(EXIT_FAILURE);
    } 

    if(argc == 2) {
        struct key *k = NULL;
        FILE *fp;
        /** we think this param is a key */
        if(strncmp(argv[1], "ssh-", 4) == 0) {
            if((k = key_decode(argv[1]))) {
                free(k);
                key = argv[1];
            }
        } else if((fp = fopen(argv[1], "r"))) {
            getline(&key, NULL, fp);
        }
    }

    if(open_sqlite_rw(dbfile, &db) < 0) {
        return -1;
    }

    rc = add_user(db, argv[0], key);
    if(sqlite3_close(db) != SQLITE_OK) {
        un_log(LOG_ERR, "failed to close db properly");
        exit(EXIT_FAILURE);
    }
    exit(rc);
}

void do_shell(char *dbfile, char *uidstr) {
    char *endptr;
    long uid;
    const char *cmd;
    const char *repo;
    char *argv[4];
    int perms;
    sqlite3 *db;
    if(!dbfile || !uidstr) {
        die("required arg missing");
    }

    un_log(LOG_DEBUG, "original: %s uid: %s", getenv("SSH_ORIGINAL_COMMAND"), uidstr);

    uid = strtol(uidstr, &endptr, 10);
    if(errno == ERANGE && (uid == LONG_MAX || uid == LONG_MIN)) {
        die("failed to parse uid");
    }
    if((errno != 0 && uid == 0) ||
        endptr == uidstr ||
        *endptr != '\0') {
        die("failed to parse uid");
    }

    if(parse_command(getenv("SSH_ORIGINAL_COMMAND"), &cmd, &repo) < 0) {
        die("failed to parse cmdline");
    }
    
    if(open_sqlite_ro(dbfile, &db) < 0) {
        die("failed to open db");
    }

    perms = repos_check_permission(db, repo, -1, uid);
    if(perms < 0) {
        die("failed to obtain permissions");
    }
    if(perms == 0) {
        die("unauthorized");
    }
    un_log(LOG_DEBUG, "uid: %d has perms: %d on repo %s", uid, perms, repo);

    if(!strcmp("git-upload-pack", cmd) && (perms & PERM_R)) {
        argv[0] = "git";
        argv[1] = "upload-pack";
        argv[2] = repo;
        argv[3] = NULL;
        execvp(argv[0], argv);
        die("execvp failed: %s", strerror(errno));
    } else if(!strcmp("git-receive-pack", cmd) && (perms & PERM_W)) {
        argv[0] = "git";
        argv[1] = "receive-pack";
        argv[2] = repo;
        argv[3] = NULL;
        execvp(argv[0], argv);
        die("execvp failed: %s", strerror(errno));
    } else if(!strcmp("git-upload-archive", cmd) && (perms & PERM_R)) {
        argv[0] = "git";
        argv[1] = "upload-archive";
        argv[2] = repo;
        argv[3] = NULL;
        execvp(argv[0], argv);
        die("execvp failed: %s", strerror(errno));
    }

    exit(0);
}

void do_checkdb(char *db, int argc, char **argv) {
    char *user, *key;
    if(argc != 2) {
        un_log(LOG_ERR, "require both user and key");
        exit(EXIT_FAILURE);
    }

    user = argv[0];
    key = argv[1];

    if(strcmp(user, "git") != 0) {
        exit(1);
    }

    exit(verify_kdb(key, db));
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
    if(!strcmp(subcommand, "adduser")) {
        do_adduser(db, argc - optind, argv + optind);
    } else if(!strcmp(subcommand, "addgroup")) {
        do_addgroup(db, argc - optind, argv + optind);
    } else if(!strcmp(subcommand, "checkkdb")) {
        do_checkdb(db, argc - optind, argv + optind);
    } else if(!strcmp(subcommand, "shell")) {
        do_shell(db, argv[optind]);
    }
}
