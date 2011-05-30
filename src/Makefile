PRODUCT=pakeproxy
SOURCES=pakeproxy.c cert.c conn.c misc.c accounts.c daemon.c gnutls_support.c site.c
OBJS=$(SOURCES:.c=.o)

LIBS=-L/usr/local/lib -lgnutls -lgnutls-extra -lpthread
LIBS_STATIC = $(LIBS) -ltasn1 -lnettle -lz -ldl -lhogweed -lgmp

CC=gcc
CFLAGS=-Wall -g

default: pakeproxy

$(OBJS): $(SOURCES)

pakeproxy: $(OBJS)
	gcc -o $@ $^ $(CFLAGS) $(LIBS) $(LDFLAGS)

static: $(OBJS)
	gcc -o pakeproxy $^ $(CFLAGS) $(LIBS_STATIC) -static $(LDFLAGS)

clean:
	rm -f *.o $(PRODUCT)