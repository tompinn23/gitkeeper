#include "log.h"

#include <stdio.h>
#include <time.h>

/*
    LOG_ERR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG,
*/

static struct timespec start_time = {-1};

static const char *verbosity_colors[] = {
	[LOG_ERR] = "\x1B[1;31m",
    [LOG_WARN] = "\x1B[1;33m",
	[LOG_INFO] = "\x1B[1;34m",
	[LOG_DEBUG] = "\x1B[1;90m",
};

static const char *verbosity_headers[] = {
	[LOG_ERR] =   "[ERROR]",
    [LOG_WARN] =  "[WARN] ",
	[LOG_INFO] =  "[INFO] ",
	[LOG_DEBUG] = "[DEBUG]",
};

static void init_start_time() {
	if (start_time.tv_sec >= 0) {
		return;
	}
	clock_gettime(CLOCK_MONOTONIC, &start_time);
}

static const long NSEC_PER_SEC = 1000000000;

static void timespec_sub(struct timespec *r, const struct timespec *a,
		const struct timespec *b) {
	r->tv_sec = a->tv_sec - b->tv_sec;
	r->tv_nsec = a->tv_nsec - b->tv_nsec;
	if (r->tv_nsec < 0) {
		r->tv_sec--;
		r->tv_nsec += NSEC_PER_SEC;
	}
}

bool un_log_enabled(enum un_log_mode mode) {
    return true;
}

void _un_log(enum un_log_mode mode, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    _un_vlog(mode, fmt, args);
    va_end(args);
}
void _un_vlog(enum un_log_mode mode, const char* fmt, va_list args) {
        init_start_time();
    struct timespec ts = {0};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    timespec_sub(&ts, &ts, &start_time);
    fprintf(stderr, "%02d:%02d:%02d.%03ld ", (int)(ts.tv_sec / 60 / 60),
    (int)(ts.tv_sec / 60 % 60), (int)(ts.tv_sec % 60), ts.tv_nsec / 1000000);
    fprintf(stderr, "%s%s ", verbosity_colors[mode], verbosity_headers[mode]);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\x1B[0m\n");
}