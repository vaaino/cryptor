#if defined(__linux__)
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/random.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#endif

#include <sodium.h>

#include "enc.h"

// adapted from BusyBox coreutils
// 3 random passes, one zero pass. 
int shred(const char *fname)
{
	int rand_fd = rand_fd; /* for compiler */
	int zero_fd;
	unsigned num_iter = SHRED_RNG_PASSES;

	zero_fd = open("/dev/zero", O_RDONLY);
	rand_fd = open("/dev/urandom", O_RDONLY);

    struct stat sb;
    unsigned i;
    int fd;

    if (!fname)
        return 1;
    fd = -1;
    fd = open(fname, O_WRONLY);
    if (fd == NULL)
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
    truncate(fd, 0);
    unlink(fname);
    close(rand_fd);
    close(zero_fd);
    close(fd);

	return 0;
}

// encrypt file
int encrypt_file(const char *filename, const char *password, const char *filename_out)
{
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    
    // we create a random salt to prepend in encrypted file
    randombytes_buf(salt, sizeof(salt));


    printf("salt: %s\n", salt);

    if (crypto_pwhash(key, sizeof key, password, strlen(password), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        printf("key creation error\n");
        return 1;
    } else {
        printf("key generated from password\n");
    }

    // TODO check for file


    unsigned char bufferi[CHUNK_SIZE];
    unsigned char buffero[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    FILE *out, *file;
    unsigned long long outputLen;
    size_t readLen;
    int eof;
    unsigned char tag;

    file = fopen(filename, "rb");
    out = fopen(filename_out, "wb");
   

    fwrite(salt, 1, sizeof salt, out);

    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, out);

    printf("header: %s\n", header);
    
    int i = 0;
    do {
        printf("%d\n", i);
        readLen = fread(bufferi, 1, sizeof bufferi, file);
        eof = feof(file);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buffero, &outputLen, bufferi, readLen, NULL, 0, tag);
        fwrite(buffero, 1, (size_t) outputLen, out);
        printf("%s\n", buffero);
        ++i;
    } while (!eof);


    fclose(out);
    fclose(file);
 
    shred(filename);
    
    sodium_memzero(key, sizeof(key));
    return 0;
}


// decrypt to file, for editing with external program
int decrypt_file(const char *filename_in, const char *password, const char *filename_out)
{
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    
    // open encrypted file
    FILE *p_file;
    p_file = fopen(filename_in, "rb");
    char c = 0; 

    // we need to cut the salt from first n bytes of encrypted file
    // iterate through file to get salt
    for (int i = 0; i <= crypto_pwhash_SALTBYTES && c != EOF; ++i) {
        c = fgetc(p_file);
        strncat(salt, &c, 1);
    }


    // cryptographic key generation from extracted salt and password
    if (crypto_pwhash(key, sizeof key, password, strlen(password), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        printf("key creation error\n");
        return 1;
    } else {
        printf("key generated from password\n");
    }

    // TODO check if file 

    unsigned char bufferi[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char buffero[CHUNK_SIZE];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned long long outputLen;
    size_t readLen;
    int eof;
    unsigned char tag;
    
    fseek(p_file, crypto_pwhash_SALTBYTES, SEEK_SET);

    fread(header, 1, sizeof header, p_file);

    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        printf("incomplete header\n");
        return 1;
    }

    FILE *p_file_out;
    p_file_out = fopen(filename_out, "wb");


    do {
        readLen = fread(bufferi, 1, sizeof bufferi, p_file);
        eof = feof(p_file);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buffero, &outputLen, &tag, bufferi, readLen, NULL, 0) != 0) {
            printf("corrupted chunk encountered, incorrect password?\n");
            return 1;
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            printf("end of file to decrypt reached before the end of the stream\n");
            return 1;
        }
        // printf("%s\n", buffero);
        fwrite(buffero, 1, (size_t) outputLen, p_file_out);
    } while (!eof);
    
    
    fclose(p_file);
    fclose(p_file_out);
    
    return 0;
 
}



// decrypt file to memory 
unsigned char * decrypt_mem(const char *filename, const char *password)
{
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];
    
    // open encrypted file
    FILE *file;
    file = fopen(filename, "rb");
    char c = 0; 

    // we need to cut the salt from first n bytes of encrypted file
    // iterate through file to get salt
    for (int i = 0; i <= crypto_pwhash_SALTBYTES && c != EOF; ++i) {
        c = fgetc(file);
        strncat(salt, &c, 1);
    }


    // cryptographic key generation from extracted salt and password
    if (crypto_pwhash(key, sizeof key, password, strlen(password), salt, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        printf("key creation error\n");
        exit(1);
    } else {
        printf("key generated from password\n");
    }

    // TODO check if file 

    unsigned char bufferi[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES];
    unsigned char buffero[CHUNK_SIZE];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    crypto_secretstream_xchacha20poly1305_state st;
    unsigned long long outputLen;
    size_t readLen;
    int eof;
    unsigned char tag;
    
    fseek(file, crypto_pwhash_SALTBYTES, SEEK_SET);

    fread(header, 1, sizeof header, file);

    if (crypto_secretstream_xchacha20poly1305_init_pull(&st, header, key) != 0) {
        printf("incomplete header\n");
        return NULL;
    }

    // we have to progressively add to ret variable from buf... 
    FILE *test;
    test = fopen(filename, "rb");
    fseek(test, 0, SEEK_END);
    unsigned char* ret = malloc(sizeof(char) * (ftell(test)));
    fclose(test);


    // read and decrypt file stream 
    do {
        readLen = fread(bufferi, 1, sizeof bufferi, file);
        eof = feof(file);
        if (crypto_secretstream_xchacha20poly1305_pull(&st, buffero, &outputLen, &tag, bufferi, readLen, NULL, 0) != 0) {
            printf("corrupted chunk encountered, incorrect password?\n");
            return NULL; 
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            printf("end of file to decrypt reached before the end of the stream\n");
            return NULL;
        }
        // TODO STRCAT!!! NOT SAFE!!!!
        strncat(ret, buffero, CHUNK_SIZE);
    } while (!eof);
    
    // close all files and remove key from memory
    fclose(file);
    sodium_memzero(key, sizeof(key));
    
    // we return the constructed string
    return ret;
}

int init_sodium()
{
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


