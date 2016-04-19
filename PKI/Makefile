INC=/usr/local/ssl/include/
LIB=/usr/local/ssl/lib/

all:
	gcc -w -I$(INC) -L$(LIB) cli.c -o cli -lssl -lcrypto -ldl -fpermissive
	gcc -w -I$(INC) -L$(LIB) serv.c -o serv -lssl -lcrypto -ldl -fpermissive

clean:
	rm -rf *~ cli serv
