CC = gcc
CFLAGS = -std=c23 -Os -s -flto -ffunction-sections -fdata-sections -Wl,--gc-sections -Wall -Wextra -Wno-unused-parameter -Isrc/include
LIBS = -lcrypto -llzma
TARGET = sign-module
SOURCE = src/sign-module.c
DISTDIR = dist

.PHONY: all clean example

all: $(DISTDIR)/$(TARGET)

$(DISTDIR)/$(TARGET): $(SOURCE) | $(DISTDIR)
	$(CC) $(CFLAGS) $(SOURCE) -o $(DISTDIR)/$(TARGET) $(LIBS)

$(DISTDIR):
	mkdir -p $(DISTDIR)

clean:
	rm -rf $(DISTDIR)

example:
	@echo "Usage examples:"
	@echo "  ./$(DISTDIR)/$(TARGET) sha256 signing_key.pem signing_key.x509 nvidia.ko.xz"
	@echo "  ./$(DISTDIR)/$(TARGET) sha512 signing_key.pem signing_key.x509 my_module.ko"
