certs:
	make -C data

default:
	make -C src

clean:
	make -C data clean
	make -C src clean