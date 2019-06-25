[![Build status](https://badge.buildkite.com/dcc97a44f655a7473ff0f836a2cf154dff016a66db8e4f7405.svg?branch=master)](https://buildkite.com/solana-labs/wool)

# solana-perf-libs
CUDA, and more!

## Building
After cloning this repo use the makefile in the root to build the tree
with nvcc in your path:

```bash
$ export PATH=/usr/local/cuda/bin:$PATH
$ make -j$(nproc)
```

This should generate the libraries:
* libcuda-crypt.so - ed25519 verify (used by leaders) and chacha (used by validators) cuda implementations

Copy libraries to the main Solana repo:
```bash
$ make DESTDIR=${SOLANA_ROOT:?}/target/perf-libs install
```

Build Solana with the performance features enabled:
```bash
$ cd $SOLANA_ROOT
$ cargo build --release --features=cuda
```
