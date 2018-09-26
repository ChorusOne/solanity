V:=debug

LIB:=cpu-crypt

CFLAGS_release:=-march=native -O3
CFLAGS_debug:=-g
CFLAGS:=$(CFLAGS_$V)

$V/cpu-crypt.o: chacha20_core.c chacha.h
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY:clean
clean:
	rm -rf $V
