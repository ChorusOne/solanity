OS := $(shell uname)

ifeq ($(OS),Darwin)
SO=dylib
else
SO=so
all: cuda_crypt
endif
all: jerasure

MAKE_ARGS:=V=release

.PHONY:cuda_crypt
cuda_crypt:
	$(MAKE) $(MAKE_ARGS) -C src

DESTDIR ?= dist
install:
	mkdir -p $(DESTDIR)
	cp -f \
    src/gf-complete/src/.libs/libgf_complete.$(SO) \
    src/jerasure/src/.libs/libJerasure.$(SO) \
    $(DESTDIR)
ifneq ($(OS),Darwin)
	cp -f src/release/libcuda-crypt.a $(DESTDIR)
	ln -sfT libJerasure.so $(DESTDIR)/libJerasure.so.2
	ln -sfT libJerasure.so $(DESTDIR)/libJerasure.so.2.0.0
	ln -sfT libgf_complete.so $(DESTDIR)/libgf_complete.so.1.0.0
	ln -sfT libgf_complete.so $(DESTDIR)/libgf_complete.so.1
endif
	ls -lh $(DESTDIR)

GFP_PATH=$(PWD)/src/gf-complete
JERASURE_PATH=$(PWD)/src/jerasure

.PHONY: jerasure gf_complete
jerasure: gf_complete
	cd $(JERASURE_PATH) && \
	autoreconf --force --install && \
	./configure LDFLAGS=-L$(GFP_PATH)/src/.libs/ CPPFLAGS=-I$(GFP_PATH)/include && \
	$(MAKE)

gf_complete:
	cd $(GFP_PATH) && \
	./autogen.sh && \
	./configure  && \
	$(MAKE) && export GFP_PATH=$(shell pwd)

.PHONY:clean
clean:
	$(MAKE) $(MAKE_ARGS) -C src clean
	$(MAKE) -C $(JERASURE_PATH) clean
	$(MAKE) -C $(GFP_PATH) clean
