PRODUCTS=ca-key.pem ca-cert.pem
DEBUG=

default: $(PRODUCTS)

clean:
	rm -f $(PRODUCTS)

ca-key.pem:
	echo generating CA key
	certtool --generate-privkey --outfile $@

ca-cert.pem:
	echo generating CA signing cert
	certtool --load-privkey ca-key.pem --template ca-cert.cfg --generate-self-signed --outfile $@
