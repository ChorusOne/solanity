# wool
cuda + solana

## Building
After cloning this repo, first build the cuda
library and have nvcc in your path:

    export PATH=/usr/local/cuda/bin:$PATH
    make -j -C src/cuda-ecc-ed25119 V=release

This should generate libcuda\_verify\_ed25519.a

Copy that to the Solana repo:

    cp src/cuda-ecc-ed25519/release/libcuda_verify_ed25519.a $SOLANA_ROOT

Build Solana with the cuda feature enabled:

    cd $SOLANA_ROOT
    cargo build --release --features="cuda"
