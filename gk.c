#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <string.h>

#include "log.h"

#include "db/rw.h"
#include "db/ro.h"

static char *argv0;

void cmd_adduser(char *dbfile, int argc, char **argv) {
    sqlite3 *db;

    if(argc < 1) {
        un_log(LOG_ERR, "gk adduser requires a user and optional key");
        exit(1);
    }

    if(open_sqlite_rw(dbfile, &db) < 0) {
        un_log(LOG_ERR, "failed to open kdb");
        exit(1);
    }

    if(argc == 2) {
        if(add_user(db, argv[0], argv[1]) < 0) {
            exit(1);
        }
    } else if(argc == 1) {
        if(add_user(db, argv[0], NULL) < 0) {
            exit(1);
        }
    }

    exit(0);
}

void cmd_addgrp(char *dbfile, int argc, char **argv) {
    sqlite3 *db;

    if(argc < 1) {
        un_log(LOG_ERR, "addgroup requires group");
        exit(1);
    }

    if(open_sqlite_rw(dbfile, &db) < 0) {
        un_log(LOG_ERR, "failed to open keydb");
        exit(1);
    }

    if(add_groups(db, argv[0], argc - 1 == 0 ? NULL : argv + 1, argc -1) < 0) {
        sqlite3_close(db);
        exit(1);
    }

    sqlite3_close(db);
    exit(0);
}

void cmd_keys(char *dbfile, int argc, char **argv) {
    if(*argv0 != '/') {
        un_log(LOG_ERR, "gk keys requires execution with a full path");
        exit(EXIT_FAILURE);
    }

    if(argc < 2) {
        un_log(LOG_ERR, "required arguments [finger] [key]");
        exit(EXIT_FAILURE);
    }

    char *key;
    long uid;
    sqlite3 *db;
    if(open_sqlite_ro(dbfile, &db) < 0) {
        un_log(LOG_ERR, "failed to open key db");
        exit(1);
    }


    if(verify_key(db, argv[0], argv[1], &key, &uid) < 0) {
        sqlite3_close(db);
        exit(1);
    }

    printf("command=\"%s -k %s shell \'%ld\'\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding %s\n",argv0, dbfile, uid, key);

    sqlite3_close(db);
    exit(0);
}

void cmd_addrepo(char *dbfile, int argc, char **argv) {
    sqlite3 *db;

    if(argc < 3) {
        un_log(LOG_ERR, "incorrect arguments");
        exit(1);
    }

    if(open_sqlite_rw(dbfile, &db) < 0) {
        un_log(LOG_ERR, "failed to open key db");
        exit(1);
    }

    if(argc == 3) {
        if(add_repo(db, argv[0], argv[1], argv[2], NULL, NULL) < 0) {
            sqlite3_close(db);
            exit(1);
        }
    } else if(argc == 5) {
        if(add_repo(db, argv[0], argv[1], argv[2], argv[3], argv[4]) < 0) {
            sqlite3_close(db);
            exit(1);
        }
    } else {
        un_log(LOG_ERR, "requires either repo and user / perm or repo user and group");
    }
    sqlite3_close(db);
    exit(0);
}

int parse_cmd(const char *input, char **cmd, char **arg) {
    *cmd = NULL;
    *arg = NULL;

    const char *cmd_start = input;
    while(*input && !isspace(*input)) input++;
    if(input == cmd_start) return -1;

    size_t cmdlen = input - cmd_start;
    *cmd = strndup(cmd_start, cmdlen);

    if(!*cmd) return -1;

    while(isspace(*input)) input++;
    if(*input == '\0') goto err;

    char quote = 0;
    if(*input == '\'' || *input == '"') {
        quote = *input++;
    }

    const char *arg_input = input;
    const char *arg_end = NULL;

    if(quote) {
        while(*input && *input != quote) input++;
        if(*input != quote) goto err;
        arg_end = input;
        input++;
    } else {
        while(*input &&!isspace(*input)) input++;
        arg_end = input;
    }

    *arg = strndup(arg_input, (arg_end - arg_input));

    return 0;
err:
    free(*cmd);
    free(*arg);
    *cmd = NULL;
    *arg = NULL;
    return -1;
}

int perm_contains(const char *p, char x) {
    return strchr(p, x) != NULL;
}

void cmd_shell(char *dbfile, int argc, char **argv) {
    long uid;
    char *endptr;
    sqlite3 *db;
    char *repo, *cmd;

    if(argc < 1) {
        un_log(LOG_ERR, "required uid");
        exit(1);
    }
    if(getenv("SSH_ORIGINAL_COMMAND") == NULL) {
        un_log(LOG_ERR, "ssh original command not found");
        exit(1);
    }
    uid = strtol(argv[0], &endptr, 10);
    if(uid == 0 && errno != 0 || *endptr != '\0') {
        un_log_errno(LOG_ERR, "failed to convert uid to a number");
        exit(1);
    }

    if(open_sqlite_ro(dbfile, &db) < 0) {
        un_log(LOG_ERR, "failed opening kdb");
        exit(1);
    }

    if(parse_cmd(getenv("SSH_ORIGINAL_COMMAND"), &cmd, &repo) < 0) {
        un_log(LOG_ERR, "failed parsing command");
        exit(1);
    }

    char *p = repo_get_permissions(db, repo, uid);
    if(p == NULL) { /* no permissions */
        un_log(LOG_ERR, "no permissions");
        exit(1);
    }

    sqlite3_close(db); /* close the db in preparation for exec */

    char *args[4];
    args[0] = "git";
    args[1] = "upload-pack";
    args[2] = repo;
    args[3] = NULL;

    if(!strcmp("git-upload-pack", cmd) && perm_contains(p, 'r')) {
        args[1] = "upload-pack";
    } else if(!strcmp("git-receive-pack", cmd) && perm_contains(p, 'w')) {
        args[1] = "receive-pack";
    } else if(!strcmp("git-upload-archive", cmd) && perm_contains(p, 'r')) {
        args[1] = "upload-pack";
    } else {
        exit(1); /* unsupported command */
    }

    execvp(args[0], args);
    exit(1);
}

struct cmd {
    const char *cmd, *desc;
    int internal;
    void (*func)(char *, int, char **);
} cmds[] = {
    {"adduser",  "Adds a user to the keydb",  0, cmd_adduser},
    {"addgroup", "Adds a group to keydb",     0, cmd_addgrp},
    {"addrepo",  "Adds a repo to the keydb",  0, cmd_addrepo},
    {"keys",     "(INTERNAL) verifies a key", 1, cmd_keys},
    {"shell",    "(INTERNAL) git shell",      1, cmd_shell},
    {NULL,       NULL,                        0, NULL},
};

int main(int argc, char **argv) {
    static struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"debug", no_argument, NULL, 'd'},
        {"kdb", required_argument, NULL, 'k'},
        {NULL, 0, NULL, 0}
    };

    int debug = 0;
    char *db = NULL;
    int ch;

    /* save argv0 for the keys command */
    argv0 = argv[0];

    while((ch = getopt_long(argc, argv, "+hdk:", longopts, NULL)) != -1) {
        switch(ch) {
        case 'd':
            debug = 1;
            break;
        case 'k':
            db = strdup(optarg);
            break;
        case '?':
            exit(EXIT_FAILURE);
        }
    }

    if(!db) {
        db = "/etc/gitkeeper/kdb.db";
    }

    if(argc - optind < 1) {
        un_log(LOG_ERR, "expected subcommand");
        exit(1);
    }

    char *subcmd = argv[optind++];
    struct cmd *c = cmds;

    while(c->cmd) {
        if(!strcasecmp(subcmd, c->cmd)) {
            c->func(db, argc - optind, argv + optind);
            break;
        }
        c++;
    }

    un_log(LOG_ERR, "%s is not a supported command", subcmd);
    exit(0);
}
