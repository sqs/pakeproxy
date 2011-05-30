.PHONY: src

default: src

certs:
	make -C data

src:
	make -C src

clean:
	make -C data clean
	make -C src clean

distpkg: xpi

xpi: certs
	rm pakeproxy.xpi
	make -C src clean
	make -C src static
	cd firefox && make && cd ..
	cd firefox && zip -r pakeproxy.xpi . && mv pakeproxy.xpi ../