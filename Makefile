CC = gcc
CFLAGS = -std=c23 -Os -s -flto -ffunction-sections -fdata-sections -Wl,--gc-sections -Wall -Wextra -Wno-unused-parameter
LIBS = -lcrypto -llzma
TARGET = sign-module
SOURCE = sign-module.c

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -D $(TARGET) $(DESTDIR)/usr/local/bin/$(TARGET)

example:
	@echo "Usage examples:"
	@echo "  ./$(TARGET) sha256 signing_key.pem signing_key.x509 nvidia.ko.xz"
	@echo "  ./$(TARGET) sha512 signing_key.pem signing_key.x509 my_module.ko"
