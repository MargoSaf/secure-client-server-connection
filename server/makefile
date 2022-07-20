OUT_DIR=out
LDFLAGS=-L/usr/local/ssl/lib -lssl -lcrypto -lrt

all : main.cpp $(OUT_DIR)/key_class.o $(OUT_DIR)/client_class.o src/client_class.h
	g++ -g -o main $(OUT_DIR)/key_class.o $(OUT_DIR)/client_class.o main.cpp   $(LDFLAGS)
	
$(OUT_DIR)/key_class.o: src/key_class.cpp src/key_class.h 
	g++ -g -c src/key_class.cpp -o $(OUT_DIR)/key_class.o $(LDFLAGS)
	
$(OUT_DIR)/client_class.o: src/client_class.cpp src/client_class.h src/key_class.h
	g++ -g -c src/client_class.cpp -o $(OUT_DIR)/client_class.o   $(LDFLAGS)
	
clean :
	rm *.o main

.PHONY: all clean

$(shell mkdir -p $(OUT_DIR))
