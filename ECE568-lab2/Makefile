CC := gcc
CFLAGS := -Wall
LIBS := -lssl -lcrypto
LDFLAGS := $(LIBS)
RM := rm -f

sources := client.c server.c sslcomm.c
targets := client server

.PHONY: clean default all

default: all
all: $(targets)

client: client.o sslcomm.o
	$(CC) $(LDFLAGS) -o client client.o sslcomm.o

server: server.o sslcomm.o
	$(CC) $(LDFLAGS) -o server server.o sslcomm.o


client.o: client.c
	$(CC) $(CFLAGS) -c -o client.o client.c

server.o: server.c
	$(CC) $(CFLAGS) -c -o server.o  server.c

sslcomm.o: sslcomm.c
	$(CC) $(CFLAGS) -c -o sslcomm.o sslcomm.c

clean:
	$(RM) $(targets) $(sources:.c=.o) *~
