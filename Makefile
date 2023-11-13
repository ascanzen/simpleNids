CC=gcc
COPT=-Wall -g -O0

all: main.o nids.o output.o base64.o hash.o http_parser.o stream.o
	$(CC) $(COPT) -o simpleNids main.o nids.o output.o base64.o hash.o http_parser.o stream.o  -Wl -lnids -lpcap -lpthread -lcrypto -lz -ljson-c

nids.o: nids.c nids.h
	$(CC) $(COPT) -c nids.c

output.o: output.c output.h
	$(CC) $(COPT) -c output.c

base64.o: base64.c base64.h
	$(CC) $(COPT) -c base64.c

hash.o: hash.c hash.h
	$(CC) $(COPT) -c hash.c

http_parser.o: http_parser.c http_parser.h
	$(CC) $(COPT) -c http_parser.c

stream.o: stream.c stream.h
	$(CC) $(COPT) -c stream.c

main.o: main.c config.h
	$(CC) $(COPT) -c main.c

clean:
	rm -f *.o *~ simpleNids

start:
	SUDO_ASKPASS=./pw.sh sudo -A ./simpleNids -TUH  -i en0

libnet:
	tar xf libnet-1.3.tar.gz
	cd libnet-1.3/ && ./configure && make &&sudo make install

ljson:
	git clone https://github.com/json-c/json-c.git
	mkdir json-c-build
	cd json-c-build
	cmake ../json-c   # See CMake section below for custom arguments	
	make
	sudo make install

libnids:
	git clone https://github.com/MITRECND/libnids
	cd libnids
	make all
	make install

build_env:
	@make libnids
	@make libnet
	@make ljson