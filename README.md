# wool
cuda + solana

## Building
After cloning this repo, first build the cuda
library and have nvcc in your path:

`export PATH=/usr/local/cuda/bin:$PATH`
`make -C src/cuda-ecc-ed25119`

This should generate libcuda\_verify\_ed25519.a

Copy that to the Solana repo:

`cp $WOOL_ROOT/src/cuda-ecc-ed25519/libcuda_verify_ed25519.a $SOLANA_ROOT`

Build Solana with the cuda feature enabled:

`cd $SOLANA ROOT`
`cargo build --release --features="cuda"`
