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
	rm pakeproxy.xpi || echo
	make -C src clean
	make -C src static
	cd firefox && make && cd ..
	cd firefox && zip -r pakeproxy.xpi . && mv pakeproxy.xpi ../

install_ff_addon_dev:
	ln -s $PWD/firefox ~/.mozilla/firefox/*.default/extensions/pakeproxy@trustedhttp.org

remove_ff_addon_dev:
	rm ~/.mozilla/firefox/*.default/extensions/pakeproxy@trustedhttp.org
