#!/bin/bash
export LD_LIBRARY_PATH=/usr/local/cuda/lib64
export PATH=$PATH:$HOME/.cargo/bin/:/usr/local/cuda/bin
make -C src/cuda-ecc-ed25119
cp src/cuda-ecc-ed25119/libcuda_verify_ed25519.a /tmp
