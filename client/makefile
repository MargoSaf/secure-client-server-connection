
LDFLAGS=-L/usr/local/ssl/lib -lssl -lcrypto -lrt

all : main.cpp 
	g++ -g -o main main.cpp    $(LDFLAGS)
clean :
	rm *.o main

.PHONY: all clean
