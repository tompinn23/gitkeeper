#include <stdarg.h>
#include <stdbool.h>

#include <stdio.h>

enum un_log_mode {
    LOG_ERR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG,
    LOG_MODE_LAST
};

#ifdef __GNUC__
#define _UN_ATTRIB_PRINTF(start, end) __attribute__((format(printf, start, end)))
#else
#define _UN_ATTRIB_PRINTF(start, end)
#endif

void _un_log(enum un_log_mode mode, const char* fmt, ...) _UN_ATTRIB_PRINTF(2 ,3);
void _un_vlog(enum un_log_mode mode, const char* fmt, va_list args) _UN_ATTRIB_PRINTF(2, 0);

#ifdef UN_LOG_SRC_DIR
#define UN_FILENAME ((const char*)__FILE__ + sizeof(UN_LOG_SRC_DIR) - 1)
#else
#define UN_FILENAME __FILE__
#endif

bool un_log_enabled(enum un_log_mode mode);

#define un_log(mode, fmt, ...) _un_log(mode, "[%s:%d] " fmt, UN_FILENAME, __LINE__, ##__VA_ARGS__)
#define un_vlog(mode, fmt, args) _un_vlog("[%s:%d] " fmt, UN_FILENAME, __LINE__, args)
#define un_log_errno(mode, fmt, ...) _un_log(mode, "[%s:%d] " fmt ": %s", UN_FILENAME, __LINE__, ##__VA_ARGS__, strerror(errno))
#define un_log_err(mode, err, fmt, ...) _un_log(mode, "[%s:%d] " fmt ": %s", UN_FILENAME, __LINE__, ##__VA_ARGS__, strerror(err))
#define un_log_sqlite(mode, fmt, ...) _un_log(mode, "[%s:%d] " fmt ": %s", UN_FILENAME, __LINE__, ##__VA_ARGS__, sqlite3_errmsg(db))

#define die(fmt, ...) _un_log(LOG_ERR, "[%s:%d] " fmt, UN_FILENAME, __LINE__, ##__VA_ARGS__); exit(EXIT_FAILURE)