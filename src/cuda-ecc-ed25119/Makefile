
NVCC:=/usr/local/cuda-9.0/bin/nvcc
CFLAGS:=--ptxas-options=-v --gpu-architecture=compute_61 -O3 -g -Xcompiler "-Wall -Werror"
LIB:=cuda_verify_ed25519

all: cuda_ed25519_verify

verify.o:verify.cu seed.cu sha512.cu ge.cu sc.cu fe.cu sign.cu keypair.cu common.cu
	$(NVCC) -rdc=true $(CFLAGS) -c verify.cu -o verify.o

verify.o.ar:verify.o
	ar r lib$(LIB).a verify.o && touch verify.o.ar

verify.o.ranlib:verify.o.ar
	ranlib lib$(LIB).a && touch verify.o.ranlib

cuda_ed25519_verify:verify.o.ranlib main.cu lib$(LIB).a
	$(NVCC) $(CFLAGS) -L. -l$(LIB) main.cu -o cuda_ed25519_verify

.PHONY:clean
clean:
	rm -rf *.o
	rm -rf *.a
	rm -rf cuda_ed25519_verify
