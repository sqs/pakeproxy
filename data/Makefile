PRODUCTS=ca-key.pem ca-cert.pem
DEBUG=
CERTTOOL=/usr/bin/certtool

default: $(PRODUCTS)

clean:
	rm -f $(PRODUCTS)

ca-key.pem:
	echo generating CA key
	$(CERTTOOL) --generate-privkey --bits 2048 --outfile $@

ca-cert.pem:
	echo generating CA signing cert
	$(CERTTOOL) --load-privkey ca-key.pem --template ca-cert.cfg --generate-self-signed --outfile $@
