LDFLAGS= -lsodium
CFLAGS=-Wall -Wextra 
CC=gcc

crypt.out: main.o
	$(CC) -o crypt.out main.o $(LDFLAGS) $(CFLAGS)

main.o: main.c
	$(CC) -c main.c $(CFLAGS)

run: main
	./crypt.out

clean:
	rm -rf *.o crypt.out
