CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wshadow -Wpedantic -std=c11
AR      ?= ar
INSTALL ?= install

PREFIX    ?= /usr/local
LIBDIR    ?= $(PREFIX)/lib
INCLUDEDIR?= $(PREFIX)/include
PKGCONFIGDIR ?= $(LIBDIR)/pkgconfig

VERSION   = $(shell cat VERSION | tr -d '[:space:]')
DESCRIPTION = Standalone DER/PEM/Base64 codec for post-quantum key serialization

SRC     = src/pqc_asn1.c
HDR     = include/pqc_asn1.h
OBJ     = src/pqc_asn1.o
LIB     = libpqc_asn1.a
TEST_SRC = test/test_pqc_asn1.c
TEST_BIN = test/test_pqc_asn1

INCLUDES = -Iinclude

.PHONY: all clean test install uninstall

all: $(LIB)

$(OBJ): $(SRC) $(HDR)
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $@ $<

$(LIB): $(OBJ)
	$(AR) rcs $@ $^

$(TEST_BIN): $(TEST_SRC) $(LIB) $(HDR)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $(TEST_SRC) -L. -lpqc_asn1

test: $(TEST_BIN)
	./$(TEST_BIN)

install: $(LIB)
	$(INSTALL) -d $(DESTDIR)$(LIBDIR)
	$(INSTALL) -d $(DESTDIR)$(INCLUDEDIR)
	$(INSTALL) -d $(DESTDIR)$(PKGCONFIGDIR)
	$(INSTALL) -m 644 $(LIB) $(DESTDIR)$(LIBDIR)/
	$(INSTALL) -m 644 $(HDR) $(DESTDIR)$(INCLUDEDIR)/
	@echo 'prefix=$(PREFIX)' > $(DESTDIR)$(PKGCONFIGDIR)/pqc_asn1.pc
	@echo 'exec_prefix=$${prefix}' >> $(DESTDIR)$(PKGCONFIGDIR)/pqc_asn1.pc
	@echo 'libdir=$(LIBDIR)' >> $(DESTDIR)$(PKGCONFIGDIR)/pqc_asn1.pc
	@echo 'includedir=$(INCLUDEDIR)' >> $(DESTDIR)$(PKGCONFIGDIR)/pqc_asn1.pc
	@echo '' >> $(DESTDIR)$(PKGCONFIGDIR)/pqc_asn1.pc
	@echo 'Name: pqc_asn1' >> $(DESTDIR)$(PKGCONFIGDIR)/pqc_asn1.pc
	@echo 'Description: $(DESCRIPTION)' >> $(DESTDIR)$(PKGCONFIGDIR)/pqc_asn1.pc
	@echo 'Version: $(VERSION)' >> $(DESTDIR)$(PKGCONFIGDIR)/pqc_asn1.pc
	@echo 'Libs: -L$${libdir} -lpqc_asn1' >> $(DESTDIR)$(PKGCONFIGDIR)/pqc_asn1.pc
	@echo 'Cflags: -I$${includedir}' >> $(DESTDIR)$(PKGCONFIGDIR)/pqc_asn1.pc

uninstall:
	rm -f $(DESTDIR)$(LIBDIR)/$(LIB)
	rm -f $(DESTDIR)$(INCLUDEDIR)/pqc_asn1.h
	rm -f $(DESTDIR)$(PKGCONFIGDIR)/pqc_asn1.pc

clean:
	rm -f $(OBJ) $(LIB) $(TEST_BIN)
