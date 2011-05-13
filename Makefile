.PHONY: src

default: src

certs:
	make -C data

src:
	make -C src

clean:
	make -C data clean
	make -C src clean