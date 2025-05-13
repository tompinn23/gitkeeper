#pragma once

#include <stddef.h>

int sha256(unsigned char out[32], const unsigned char* in, size_t len);