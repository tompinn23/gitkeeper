#include "util.h"

#include <stdlib.h>

int strdelimcpy(char *dest, const char *src, char delim, int max) {
    int i = 0;
    while(i < max - 1 && src[i] && src[i] != delim) {
        dest[i] = src[i];
        i++;
    }
    dest[i] = '\0';
    if(i >= max -1 || src[i] == '\0') {
        return -1;
    }
    return i;
}

size_t base64_decode(const char *in, int n, uint8_t *out, size_t max_out) {
    static const unsigned char d[] = {
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, // 0–15
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, // 16–31
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, // 32–47
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64,  0, 64, 64, // 48–63
        64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 64–79
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64, // 80–95
        64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // 96–111
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51                      // 112–122
    };

    size_t i = 0, j = 0;
    uint32_t buf = 0;
    int bits = 0;

    while ((n == -1 || i < n) && in[i] && in[i] != '\n' && j < max_out) {
        unsigned char c = in[i++];
        if (c > 122) continue;
        unsigned char v = d[c];
        if (v == 64) continue;

        buf = (buf << 6) | v;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            out[j++] = (buf >> bits) & 0xFF;
        }
    }

    return j;
}


const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const unsigned char *in, size_t len) {
	char   *out;
	size_t  elen;
	size_t  i;
	size_t  j;
	size_t  v;

	if (in == NULL || len == 0)
		return NULL;

    elen = len;
    if(len % 3 != 0) {
        elen += 3 - (len % 3);
    }
    elen /= 3;
    elen *= 4;
	out  = malloc(elen+1);
	out[elen] = '\0';

	for (i=0, j=0; i<len; i+=3, j+=4) {
		v = in[i];
		v = i+1 < len ? v << 8 | in[i+1] : v << 8;
		v = i+2 < len ? v << 8 | in[i+2] : v << 8;

		out[j]   = b64chars[(v >> 18) & 0x3F];
		out[j+1] = b64chars[(v >> 12) & 0x3F];
		if (i+1 < len) {
			out[j+2] = b64chars[(v >> 6) & 0x3F];
		} else {
			out[j+2] = '=';
		}
		if (i+2 < len) {
			out[j+3] = b64chars[v & 0x3F];
		} else {
			out[j+3] = '=';
		}
	}

	return out;
}
