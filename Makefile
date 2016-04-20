INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	gcc -w -I$(INC) -L$(LIB) cli.c -o cli -pthread -lssl -lcrypto -ldl -fpermissive
	gcc -w -I$(INC) -L$(LIB) serv.c -o serv -pthread -lssl -lcrypto -ldl -fpermissive
#	gcc -w -I$(INC) -L$(LIB) tunproxy.c -o tunproxy -lcrypto -ldl

clean:
	rm -rf *~ cli serv
