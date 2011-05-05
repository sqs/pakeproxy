PRODUCT=pakeproxy
SOURCES=pakeproxy.c
OBJS=$(SOURCES:.c=.o)

LIBS=-L/usr/local/lib -lgnutls -lgnutls-extra

CC=gcc
CFLAGS=-Wall -g

$(OBJS): $(SOURCES)

pakeproxy: $(OBJS)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

default: pakeproxy

clean:
	rm -f *.o $(PRODUCT)