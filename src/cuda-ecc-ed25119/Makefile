
NVCC:=nvcc
CFLAGS:=--ptxas-options=-v --gpu-architecture=compute_61 -O3 -g -Xcompiler "-Wall -Werror -fPIC"
LIB:=cuda_verify_ed25519

all: cuda_ed25519_verify

verify.o:verify.cu seed.cu sha512.cu ge.cu sc.cu fe.cu sign.cu keypair.cu common.cu
	$(NVCC) -rdc=true $(CFLAGS) -c verify.cu -o verify.o

verify.o.ar:verify.o
	ar r lib$(LIB).a verify.o && touch verify.o.ar

#verify.o.ranlib:verify.o.ar
#	ranlib lib$(LIB).a && touch verify.o.ranlib

verify-dlink.o:verify.o
	$(NVCC) -Xcompiler "-fPIC" --gpu-architecture=compute_61 --device-link verify.o --output-file verify-dlink.o

lib$(LIB).a:verify-dlink.o verify.o
	$(NVCC) -Xcompiler "-fPIC" --lib --output-file lib$(LIB).a verify-dlink.o verify.o

cuda_ed25519_verify:main.cu lib$(LIB).a
	$(NVCC) $(CFLAGS) -L. -l$(LIB) main.cu -o cuda_ed25519_verify

.PHONY:clean
clean:
	rm -rf *.o
	rm -rf *.a
	rm -rf cuda_ed25519_verify
