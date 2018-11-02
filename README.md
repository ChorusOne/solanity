[![Build status](https://badge.buildkite.com/dcc97a44f655a7473ff0f836a2cf154dff016a66db8e4f7405.svg?branch=master)](https://buildkite.com/solana-labs/wool)

# solana-perf-libs
cuda + solana

## Building
After cloning this repo use the makefile in the root to build the tree
with nvcc in your path:

    export PATH=/usr/local/cuda/bin:$PATH
    make -j

This should generate the libraries:
* libcuda-crypt.a - ed25519 verify (used by leaders) and chacha (used by validators) cuda implementations
* libcpu-crypt.a - CPU chacha encryption implementation, used by replicators (storage miners)
* libJerasure.so, libgf\_complete.so - CPU erasure code library used for coding blob send

Copy those to the Solana repo:

    cp src/release/libcuda-crypt.a $SOLANA_ROOT/target/perf-libs
    cp src/cpu-crypt/release/libcpu-crypt.a $SOLANA_ROOT/target/perf-libs
    cp src/gf-complete/src/.libs/libgf_complete.so $SOLANA_ROOT/target/perf-libs
    cp src/jerasure/src/.libs/libJerasure.so $SOLANA_ROOT/target/perf-libs

Build Solana with the cuda & chacha features enabled:

    cd $SOLANA_ROOT
    cargo build --release --features="cuda,chacha"
