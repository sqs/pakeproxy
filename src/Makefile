PRODUCT=pakeproxy
SOURCES=pakeproxy.c cert.c conn.c misc.c accounts.c daemon.c gnutls_support.c site.c
OBJS=$(SOURCES:.c=.o)

LIBS=-L/usr/local/lib -lgnutls -lgnutls-extra -lpthread
LIBS_STATIC = $(LIBS) -ltasn1 -lnettle -lz -ldl -lhogweed -lgmp
LIBS_STATIC_MACOSX = /opt/local/lib/libgnutls.a /opt/local/lib/libgnutls-extra.a /opt/local/lib/libtasn1.a /opt/local/lib/libgcrypt.a /opt/local/lib/libintl.a /opt/local/lib/libiconv.a /opt/local/lib/liblzo2.a /usr/local/lib/libgpg-error.a -lz -ldl /System/Library/Frameworks/CoreFoundation.framework/CoreFoundation

CC=gcc
CFLAGS+=-Wall -g

default: pakeproxy

$(OBJS): $(SOURCES)

pakeproxy: $(OBJS)
	gcc -o $@ $^ $(CFLAGS) $(LIBS) $(LDFLAGS)

static: $(OBJS)
	gcc -o pakeproxy $^ $(CFLAGS) $(LIBS_STATIC) -static $(LDFLAGS)

static-macosx: $(OBJS)
	gcc -o pakeproxy $^ $(CFLAGS) $(LIBS_STATIC_MACOSX) $(LDFLAGS)

clean:
	rm -f *.o $(PRODUCT)
