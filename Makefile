LDFLAGS= -lsodium -g
CFLAGS=-Wall -Wextra -g
CC=gcc

crypt.out: main.o
	$(CC) -o crypt.out main.o $(LDFLAGS) $(CFLAGS)

main.o: main.c
	$(CC) -c main.c $(CFLAGS)

run: main
	./crypt.out

clean:
	rm -rf *.o crypt.out
