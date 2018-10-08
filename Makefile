all: cpu_crypt cuda_crypt cuda_verify jerasure

.PHONY:cuda_verify
cuda_verify:
	$(MAKE) V=release -C src/cuda-ecc-ed25119

.PHONY:cuda_crypt
cuda_crypt:
	$(MAKE) V=release -C src/cuda-crypt

.PHONY:cpu_crypt
cpu_crypt:
	$(MAKE) V=release -C src/cpu-crypt


DESTDIR ?= dist
install:
	mkdir -p $(DESTDIR)
	cp -f \
    ./src/gf-complete/src/.libs/libgf_complete.so \
    ./src/jerasure/src/.libs/libJerasure.so \
    ./src/cuda-ecc-ed25119/release/libcuda_verify_ed25519.a \
    ./src/cuda-crypt/release/libcuda-crypt.so \
    ./src/cpu-crypt/release/libcpu-crypt.a \
    $(DESTDIR)
	ln -sfT libJerasure.so $(DESTDIR)/libJerasure.so.2
	ln -sfT libJerasure.so $(DESTDIR)/libJerasure.so.2.0.0
	ln -sfT libgf_complete.so $(DESTDIR)/libgf_complete.so.1.0.0
	ln -sfT libgf_complete.so $(DESTDIR)/libgf_complete.so.1
	ls -lh $(DESTDIR)

GFP_PATH=$(PWD)/src/gf-complete

.PHONY: jerasure gf_complete
jerasure: gf_complete
	cd src/jerasure && \
	autoreconf --force --install && \
	./configure LDFLAGS=-L$(GFP_PATH)/src/.libs/ CPPFLAGS=-I$(GFP_PATH)/include && \
	$(MAKE)

gf_complete:
	cd $(GFP_PATH) && \
	./autogen.sh && \
	./configure  && \
	$(MAKE) && export GFP_PATH=$(shell pwd)

