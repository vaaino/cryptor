LDFLAGS= -lsodium -g
CFLAGS=-Wall -Wextra -g
CC=gcc
OBJFILES = enc.o main.o
TARGET = crypt.out

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJFILES) $(LDFLAGS)

run: main
	./$(TARGET)

clean:
	rm -rf $(OBJFILES) $(TARGET)
