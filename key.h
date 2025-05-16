#pragma once

int verify_kdb(char *finger, char *kdb);
struct key *key_decode(const char *keyline);