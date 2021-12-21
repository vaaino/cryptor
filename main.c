/*    Copyright (c) 2021-2022, Vaino Kauppila
 *    All rights reserved
 *
 *    This file is part of the programme "c-pass" and use in source and
 *    binary forms, with or without modification, are permitted exclusively
 *    under the terms of the ######### license. You should have received
 *    a copy of the license with this file. If not, please or visit:
 *    ###############.com.
 */

#include <stdio.h>
#include <string.h>


#include "enc.h"

int main(int argc, char **argv)
{
    printf("%d\n", argc);

    if (argc != 3){
        printf("not enough arguments\n");
        return 1;
    }

    if (sodium_init() != 0){
        printf("error initializing libsodium\n");
    }

    char *opt = argv[1];
    

    if (!strcmp(opt, "e")) {

        printf("encrypting file 'testencrypt'\n");
        encrypt_file("testencrypt", argv[2], "testencrypt.o");

    } else if (!strcmp(opt, "d")) {

        printf("decrypt the file 'testencrypt'\n");
        
        char *decrypted;
        decrypted = decrypt_mem("testencrypt.o", argv[2]);
        
        printf("%s\n", decrypted);

    } else {
        printf("failure arguments\n");
    }

}
