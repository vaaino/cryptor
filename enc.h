#define CHUNK_SIZE 4096
#define SHRED_RNG_PASSES 4

int shred(const char *fname);

int encrypt_file(const char *filename, const char *password, const char *filename_out);

int decrypt_file(const char *filename_in, const char *password, const char *filename_out);

unsigned char * decrypt_mem(const char *filename, const char *password);

int sodium_init();
