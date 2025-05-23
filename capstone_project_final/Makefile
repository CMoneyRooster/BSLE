CC=gcc
CFLAGS=-Wall -Wextra -pthread -Iinclude
SRC=$(wildcard src/*.c)
OBJ=$(SRC:.c=.o)
BIN=bin/capstone

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f src/*.o $(BIN)
