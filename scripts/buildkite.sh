#!/bin/bash
export LD_LIBRARY_PATH=/usr/local/cuda/lib64
export PATH=$PATH:$HOME/.cargo/bin/:/usr/local/cuda/bin
make -j$(nproc)
cp src/cuda-ecc-ed25119/libcuda_verify_ed25519.a /tmp
cp src/jerasure/src/.libs/libJerasure.so* /tmp
cp src/gf-complete/src/.libs/libgf_complete.so* /tmp
