/*    Copyright (c) 2021-2022, Vaino Kauppila
 *    All rights reserved
 *
 *    This file is part of the program "c-pass" and use in source and
 *    binary forms, with or without modification, are permitted exclusively
 *    under the terms of the GNU Public License v3.0. You should have received
 *    a copy of the license with this file. If not, please or visit:
 *    https://www.gnu.org/licenses/gpl-3.0.en.html
 */


#if defined(__linux__)
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/random.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#endif

#include <sodium.h>

#include "enc.h"

// adapted from BusyBox coreutils
// 3 random passes, one zero pass. 
int shred(const char *f_in) {
    int rand_fd = rand_fd; /* for compiler */
    int zero_fd;
    unsigned num_iter = SHRED_RNG_PASSES;

    zero_fd = open("/dev/zero", O_RDONLY);
    rand_fd = open("/dev/urandom", O_RDONLY);

    struct stat sb;
    unsigned i;
    int fd;

    if (!f_in)
        return 1;
    fd = open(f_in, O_WRONLY);
    if (fd == -1)
        return 1;

    if (fstat(fd, &sb) == 0 && sb.st_size > 0) {
        off_t size = sb.st_size;

        for (i = 0; i < num_iter; i++) {
            sendfile(fd, rand_fd, 0, size);
            fdatasync(fd);
            lseek(fd, 0, SEEK_SET);
        }

        sendfile(fd, zero_fd, 0, size);
        fdatasync(fd);
        lseek(fd, 0, SEEK_SET);

    }
    truncate(f_in, 0);
    unlink(f_in);
    close(rand_fd);
    close(zero_fd);
    close(fd);

    return 0;
}

// encrypt file
int encrypt_file(const char *f_in, const char *password, const char *f_out) {
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];

    // we create a random salt to prepend in encrypted file
    randombytes_buf(salt, sizeof(salt));

    FILE *fp_in;
    fp_in = fopen(f_in, "rb");

    if (fp_in == NULL)
        return 1;

    if (crypto_pwhash(key, sizeof key, password, strlen(password), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        return 1;
    } else {
        printf("key generated from password\n");
    }


    unsigned char buffer_in[CHUNK_SIZE];
    unsigned char buffer_out[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE *fp_out;
    unsigned long long out_len;
    size_t read_len;
    int eof;
    unsigned char tag;


    fp_out = fopen(f_out, "wb");


    fwrite(salt, 1, sizeof salt, fp_out);

    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, fp_out);

    printf("header: %s\n", header);

    int i = 0;
    do {
        printf("%d\n", i);
        read_len = fread(buffer_in, 1, sizeof buffer_in, fp_in);
        eof = feof(fp_in);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buffer_out, &out_len, buffer_in, read_len, NULL, 0, tag);
        fwrite(buffer_out, 1, (size_t) out_len, fp_out);
        printf("%s\n", buffer_out);
        ++i;
    } while (!eof);

    fclose(fp_out);
    fclose(fp_in);

    sodium_memzero(key, sizeof(key));
    return 0;
}


// decrypt to file, for editing with external program
int decrypt_file(const char *f_in, const char *password, const char *f_out) {
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];

    // open encrypted file
    FILE *fp_in;
    fp_in = fopen(f_in, "rb");
    char c = 0;

    if (fp_in == NULL)
        return 1;

    // we need to cut the salt from first n bytes of encrypted file
    // iterate through file to get salt
    for (unsigned int i = 0; i <= crypto_pwhash_SALTBYTES && c != EOF; ++i) {
        c = fgetc(fp_in);
        strncat((char *) salt, &c, 1);
    }


    // cryptographic key generation from extracted salt and password
    if (crypto_pwhash(key, sizeof key, password, strlen(password), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        printf("key creation error\n");
        return 1;
    } else {
        printf("key generated from password\n");
    }


    unsigned char buffer_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char buffer_out[CHUNK_SIZE];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned long long out_len;
    size_t read_len;
    int eof;
    unsigned char tag;

    fseek(fp_in, crypto_pwhash_SALTBYTES, SEEK_SET);

    fread(header, 1, sizeof header, fp_in);

    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        printf("incomplete header\n");
        return 1;
    }

    FILE *fp_out;
    fp_out = fopen(f_out, "wb");


    do {
        read_len = fread(buffer_in, 1, sizeof buffer_in, fp_in);
        eof = feof(fp_in);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buffer_out, &out_len, &tag, buffer_in, read_len, NULL, 0) !=
            0) {
            printf("corrupted chunk encountered, incorrect password?\n");
            return 1;
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            printf("end of file to decrypt reached before the end of the stream\n");
            return 1;
        }
        // printf("%s\n", buffer_out);
        fwrite(buffer_out, 1, (size_t) out_len, fp_out);
    } while (!eof);


    fclose(fp_in);
    fclose(fp_out);

    return 0;

}


// decrypt file to memory
unsigned char *decrypt_mem(const char *f_in, const char *password) {
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];

    // open encrypted file
    FILE *fp_in;
    fp_in = fopen(f_in, "rb");
    char c = 0;

    if (fp_in == NULL)
        return NULL;

    // we need to cut the salt from first n bytes of encrypted file
    // iterate through file to get salt
    for (unsigned int i = 0; i <= crypto_pwhash_SALTBYTES && c != EOF; ++i) {
        c = fgetc(fp_in);
        strncat((char *) salt, &c, 1);
    }


    // cryptographic key generation from extracted salt and password
    if (crypto_pwhash(key, sizeof key, password, strlen(password), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        printf("key creation error\n");
        exit(1);
    } else {
        printf("key generated from password\n");
    }


    unsigned char buffer_in[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char buffer_out[CHUNK_SIZE];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned long long out_len;
    size_t read_len;
    int eof;
    unsigned char tag;

    fseek(fp_in, crypto_pwhash_SALTBYTES, SEEK_SET);

    fread(header, 1, sizeof header, fp_in);

    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        printf("incomplete header\n");
        return NULL;
    }

    // we have to progressively add to ret variable from buf... 
    FILE *fp_size;
    fp_size = fopen(f_in, "rb");
    fseek(fp_size, 0, SEEK_END);
    unsigned char *p_ret = malloc(sizeof(char) * (ftell(fp_size)));
    fclose(fp_size);


    // read and decrypt file stream 
    do {
        read_len = fread(buffer_in, 1, sizeof buffer_in, fp_in);
        eof = feof(fp_in);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buffer_out, &out_len, &tag, buffer_in, read_len, NULL, 0) !=
            0) {
            printf("corrupted chunk encountered, incorrect password?\n");
            return NULL;
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            printf("end of file to decrypt reached before the end of the stream\n");
            return NULL;
        }
        strncat((char *) p_ret, (char *) buffer_out, CHUNK_SIZE);
    } while (!eof);

    // close all files and remove key from memory
    fclose(fp_in);
    sodium_memzero(key, sizeof(key));

    // we return the constructed string
    return p_ret;
}

int init_sodium() {
#if defined(__linux__) && defined(RNDGETENTCNT)
    int fd;
    int c;

    if ((fd = open("/dev/random", O_RDONLY)) != -1) {
        if (ioctl(fd, RNDGETENTCNT, &c) == 0 && c < 160) {
            fputs("This system doesn't provide enough entropy to quickly generate high-quality random numbers.\n"
                  "Installing the rng-utils/rng-tools, jitterentropy or haveged packages may help.\n"
                  "On virtualized Linux environments, also consider using virtio-rng.\n"
                  "The service will not start until enough entropy has been collected.\n", stderr);
        }
        (void) close(fd);
    }
#endif

    if (sodium_init() < 0) {
        return 1;
    }

    return 0;
}