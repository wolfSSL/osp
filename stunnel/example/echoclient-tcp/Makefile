CC=gcc
CFLAGS=-Wall -I ../include
DEPS = ../include/unp.h
OBJ = echoclient-tcp.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

echoclient-tcp: ../lib/*.c echoclient-tcp.c
	$(CC) -o echoclient-tcp ../lib/*.c echoclient-tcp.c -I ../include
	
.PHONY: clean

clean:
	rm -f *.o echoclient-tcp
