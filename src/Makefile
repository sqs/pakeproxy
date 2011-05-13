PRODUCT=pakeproxy
SOURCES=pakeproxy.c cert.c conn.c
OBJS=$(SOURCES:.c=.o)

LIBS=-L/usr/local/lib -lgnutls -lgnutls-extra

CC=gcc
CFLAGS=-Wall -g

default: pakeproxy

$(OBJS): $(SOURCES)

pakeproxy: $(OBJS)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

clean:
	rm -f *.o $(PRODUCT)