#pragma once

#include <stdint.h>
#include <stddef.h>

int strdelimcpy(char *, const char *, char, int);

char *base64_encode(const unsigned char *, size_t);
size_t base64_decode(const char *, int, uint8_t *, size_t);

