V=debug
include ../gpu-common.mk

TEST_BIN=aes_test
LIB=cuda-crypt

all: $V/$(TEST_BIN)

$V/chacha_cbc.o: chacha_cbc.cu chacha.h common.cu
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

$V/aes_cbc.o: aes_cbc.cu aes_core.cu modes_lcl.h common.cu
	@mkdir -p $(@D)
	$(NVCC) -rdc=true $(CFLAGS) -c $< -o $@

$V/lib$(LIB).a: $V/aes_cbc.o $V/chacha_cbc.o
	$(NVCC) -Xcompiler "-fPIC" --lib --output-file $@ $^

$V/$(TEST_BIN): test.cu $V/lib$(LIB).a
	$(NVCC) $(CFLAGS) $^ -o $@

.PHONY:clean
clean:
	rm -rf $V
