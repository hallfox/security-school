CC = g++
CFLAGS = -std=c++11 -g -Wall -Wextra -pedantic
LDFLAGS = -L/usr/local/opt/openssl/lib
LIBS = -lcrypto
SOURCES = fscrypt2.cc main.cc
INCLUDE = -I/usr/local/opt/openssl/include
TARGET = main
OBJECTS = $(SOURCES:.cc=.o)


all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ $(LIBS)

.cc.o:
	$(CC) $(INCLUDE) $(CFLAGS) -c $< -o $@

clean:
	rm $(TARGET) $(OBJECTS)

