V=debug
include ../gpu-common.mk
LIB:=cuda_verify_ed25519

all: $V/cuda_ed25519_verify

$V/verify.o: verify.cu seed.cu sha512.cu ge.cu sc.cu fe.cu sign.cu keypair.cu common.cu ed25519.h
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

$V/verify.o.ar: $V/verify.o
	ar r lib$(LIB).a $< && touch $@

$V/verify-dlink.o: $V/verify.o
	$(NVCC) -Xcompiler "-fPIC" --gpu-architecture=compute_61 --device-link $< --output-file $@

$V/lib$(LIB).a: $V/verify-dlink.o $V/verify.o
	$(NVCC) -Xcompiler "-fPIC" --lib --output-file $@ $^

$V/main.o: main.cu ed25519.h
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

$V/cuda_ed25519_verify: $V/main.o $V/lib$(LIB).a
	$(NVCC) $(CFLAGS) -L$V -l$(LIB) $< -o $@

.PHONY:clean
clean:
	rm -rf $V
