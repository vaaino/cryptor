LDFLAGS= -lsodium
CFLAGS=-Wall -g  
CC=gcc

main: main.o
	$(CC) -o main main.o $(LDFLAGS) $(CFLAGS)

main.o: main.c
	$(CC) -c main.c $(CFLAGS)

run: main
	./main

clean:
	rm -rf *.o main 
