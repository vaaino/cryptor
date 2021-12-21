/*    Copyright (c) 2021-2022, Vaino Kauppila
 *    All rights reserved
 *
 *    This file is part of the program "c-pass" and use in source and
 *    binary forms, with or without modification, are permitted exclusively
 *    under the terms of the GNU Public License v3.0. You should have received
 *    a copy of the license with this file. If not, please or visit:
 *    https://www.gnu.org/licenses/gpl-3.0.en.html
 */


#define CHUNK_SIZE 4096
#define SHRED_RNG_PASSES 4

int shred(const char *fname);

int encrypt_file(const char *in, const char *password, const char *out);

int decrypt_file(const char *in, const char *password, const char *out);

unsigned char *decrypt_mem(const char *in, const char *password);

int sodium_init();
