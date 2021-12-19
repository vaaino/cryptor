#if defined(__linux__)
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/random.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include <sodium.h>

#define CHUNK_SIZE 4096


// encrypt file
int encrypt(const char *filename, const char *password)
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
    FILE *temp, *file;
    unsigned long long outputLen;
    size_t readLen;
    int eof;
    unsigned char tag;

    file = fopen(filename, "rb");
    
    char *temp_fname;
    temp_fname = (char *) malloc(sizeof filename +4);
    strcpy(temp_fname, filename);
    strcat(temp_fname, ".tmp");

    temp = fopen(temp_fname, "wb");
   

    fwrite(salt, 1, sizeof salt, temp);

    crypto_secretstream_xchacha20poly1305_init_push(&st, header, key);
    fwrite(header, 1, sizeof header, temp);

    printf("header: %s\n", header);
    
    do {
        readLen = fread(bufferi, 1, sizeof bufferi, file);
        eof = feof(file);
        tag = eof ? crypto_secretstream_xchacha20poly1305_TAG_FINAL : 0;
        crypto_secretstream_xchacha20poly1305_push(&st, buffero, &outputLen, bufferi, readLen, NULL, 0, tag);
        fwrite(buffero, 1, (size_t) outputLen, temp);
    } while (!eof);

    fclose(temp);
    fclose(file);

    
    file = fopen(filename, "wb");
    temp = fopen(temp_fname, "rb");
    
    // shred old file (TODO maybe see if this is completely a secure method)
    // right now, this method overwrites with zeros
    printf("shred file\n");
    static const char zeros[4096];
    off_t size = lseek(file, 0, SEEK_END);
    lseek(file, 0, SEEK_SET);
    while (size>sizeof zeros)
        size -= write(file, zeros, sizeof zeros);
    while (size)
        size -= write(file, zeros, size);

    // write temp to old file
    char c;

    c = fgetc(temp);
    while (c != EOF)
    {
        fputc(c, file);
        c = fgetc(temp);
    }
    // remove temporary file
    remove(temp_fname);

    

    sodium_memzero(key, sizeof(key));

    return 0;

        
}



// decrypt file to memory 
unsigned char * decrypt(const char *filename, const char *password)
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
        exit(1);
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
            exit(1);
        }
        if (tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL && !eof) {
            printf("end of file to decrypt reached before the end of the stream\n");
            exit(1);
        }
        // TODO STRCAT!!! NOT SAFE!!!!
        strcat(ret, buffero);
    } while (!eof);
    
    // close all files and remove key from memory
    fclose(file);
    sodium_memzero(key, sizeof(key));
    
    // TODO we cannot just return the buffer. what if more than CHUNK_SIZE bytes? see above
    return ret;
}

int init_sodium()
{
    return 0;
}

int main(int argc, char **argv)
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
        printf("panic!\n");
    }
    printf("initialized libraries\n---\n");
    
    if (strcmp(argv[1], "e") == 0) {

        printf("encrypting file 'testencrypt'\n");
        encrypt("testencrypt", argv[2]);

    } else if (strcmp(argv[1], "d") == 0) {

        printf("decrypt the file 'testencrypt'\n");
        
        unsigned char *decrypted;
        decrypted = decrypt("testencrypt", argv[2]);
        
        printf("%s\n", decrypted);

    } else {
        printf("failure arguments\n");
    }

}
