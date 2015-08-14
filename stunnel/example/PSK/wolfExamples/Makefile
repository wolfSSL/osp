CC=gcc
CFLAGS=-Wall
LIBS=-lwolfssl

all: client-tcp client-psk server-tcp server-psk 

client-tcp: client-tcp.o
	$(CC) -o $@ $^ $(CFLAGS)

client-psk: client-psk.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

server-tcp: server-tcp.o
	$(CC) -o $@ $^ $(CFLAGS)

server-psk: server-psk.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean all

clean:
	rm -f *.o client-tcp client-psk server-tcp server-psk
