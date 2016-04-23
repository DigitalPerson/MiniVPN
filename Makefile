INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	gcc -w -I$(INC) -L$(LIB) minivpn.c -o minivpn -lssl -lcrypto -ldl -fpermissive
