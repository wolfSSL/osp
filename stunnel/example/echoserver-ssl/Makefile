CC=gcc
CFLAGS=-Wall -I ../include -I/usr/local/include -lwolfssl
DEPS = ../include/echoserver.h 
OBJ = echoserver.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

echoserver-ssl: echoserver-ssl.c
	$(CC) -o echoserver-ssl echoserver-ssl.c -I ../include -I/usr/local/include -lwolfssl -L/usr/local/lib -lwolfssl
	
.PHONY: clean

clean:
	rm -f *.o echoserver-ssl
