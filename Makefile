INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	gcc -w -I$(INC) -L$(LIB) tunproxy.c -o tunproxy -lssl -lcrypto -ldl -fpermissive
