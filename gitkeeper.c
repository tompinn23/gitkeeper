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
    sqlite3 *db = NULL;
    int ch, rc;

    if(argc < 1) {
        un_log(LOG_INFO, "adduser requires [user]");
        exit(EXIT_FAILURE);
    }

    if(open_sqlite_rw(dbfile, &db) < 0) {
        return -1;
    }

    ch = add_user(db, argv[0]);
    if((rc = sqlite3_close(db)) != SQLITE_OK) {
        fprintf(stderr, "failed to close db: '%s'\n", sqlite3_errstr(rc));
        exit(EXIT_FAILURE);
    }
    exit(ch);
}


int command_repo_range(const char *cmd, const char **start, size_t *len) {
    char quote = '\0';
    const char *repo, *end;

    if(!cmd || !start) return -1;

    const char *space = strchr(cmd, ' ');
    if(!space) return -1;

    const char *repo = space + 1;
    if(*repo == '\'' || *repo == '\"') {
        quote = *repo; /* save the quote */
        repo++;
    }

    const char *end = repo + strlen(repo);
    if(quote) {
        const char *q = end - 1;
        while(q > repo && *q != quote) q--;
        if(*q == quote) {
            end = q;
        } else {
            return -1;
        }
    }

    *start = repo;
    if(len) *len = (size_t)(end - repo);
    return 0;
}

#define PERM_R (1<<2)
#define PERM_W (1<<1)
#define PERM_X (1<<0) /* idk what this might even do. */

void do_shell(char *dbfile, char *uidstr) {
    char *endptr;
    long uid;
    char *cmd;
    const char *repo;
    size_t rlen;
    un_log(LOG_DEBUG, "original: %s uid: %s", getenv("SSH_ORIGINAL_COMMAND"), uidstr);

    uid = strtol(uidstr, &endptr, 10);
    if(errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) {
        exit(10);
    }
    if((errno != 0 && val == 0) ||
        endptr == input ||
        *endptr != '\0') {
        exit(10);
    }

    cmd = getenv("SSH_ORIGINAL_COMMAND");
    if(command_repo_range(cmd, &repo, &rlen) < 0) {
        //log(LOG_ERR, "parsing commandline failed")
        exit(12);
    }    
 

    exit(0);
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
    } else if(!strcmp(subcommand, "shell")) {
        do_shell(db, argv[optind]);
    }
}
