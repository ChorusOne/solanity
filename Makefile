all: cuda_verify jerasure

.PHONY:cuda_verify
cuda_verify:
	$(MAKE) -C src/cuda-ecc-ed25119

GFP_PATH=$(PWD)/src/gf-complete

.PHONY: jerasure gf_complete
jerasure: gf_complete
	cd src/jerasure && \
	./configure LDFLAGS=-L$(GFP_PATH)/src/.libs/ CPPFLAGS=-I$(GFP_PATH)/include && \
	$(MAKE)

gf_complete:
	cd $(GFP_PATH) && \
	./configure  && \
	$(MAKE) && export GFP_PATH=$(shell pwd)

