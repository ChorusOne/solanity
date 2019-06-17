OS := $(shell uname)

all:
ifeq ($(OS),Darwin)
SO=dylib
else
SO=so
all: cuda_crypt
endif

MAKE_ARGS:=V=release

.PHONY:cuda_crypt
cuda_crypt:
	$(MAKE) $(MAKE_ARGS) -C src

DESTDIR ?= dist
install:
	mkdir -p $(DESTDIR)
ifneq ($(OS),Darwin)
	cp -f src/release/libcuda-crypt.a $(DESTDIR)
endif
	ls -lh $(DESTDIR)

.PHONY:clean
clean:
	$(MAKE) $(MAKE_ARGS) -C src clean
