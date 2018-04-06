
NVCC:=nvcc
GPU_ARCH=compute_35
GPU_CFLAGS:=--gpu-code=sm_50,sm_61,$(GPU_ARCH) --gpu-architecture=$(GPU_ARCH)
CFLAGS:=--ptxas-options=-v $(GPU_CFLAGS) -O3 -g -Xcompiler "-Wall -Werror -fPIC -Wno-strict-aliasing"
LIB:=cuda_verify_ed25519

all: cuda_ed25519_verify

verify.o:verify.cu seed.cu sha512.cu ge.cu sc.cu fe.cu sign.cu keypair.cu common.cu ed25519.h
	$(NVCC) -rdc=true $(CFLAGS) -c verify.cu -o verify.o

verify.o.ar:verify.o
	ar r lib$(LIB).a verify.o && touch verify.o.ar

#verify.o.ranlib:verify.o.ar
#	ranlib lib$(LIB).a && touch verify.o.ranlib

verify-dlink.o:verify.o
	$(NVCC) -Xcompiler "-fPIC" --gpu-architecture=compute_61 --device-link verify.o --output-file verify-dlink.o

lib$(LIB).a:verify-dlink.o verify.o
	$(NVCC) -Xcompiler "-fPIC" --lib --output-file lib$(LIB).a verify-dlink.o verify.o

main.o:main.cu ed25519.h
	$(NVCC) -rdc=true $(CFLAGS) -c main.cu -o main.o

cuda_ed25519_verify:main.o lib$(LIB).a
	$(NVCC) $(CFLAGS) -L. -l$(LIB) main.o -o cuda_ed25519_verify

.PHONY:clean
clean:
	rm -rf *.o
	rm -rf *.a
	rm -rf cuda_ed25519_verify
