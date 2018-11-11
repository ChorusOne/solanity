#!/usr/bin/env bash -e

cd "$(dirname "$0")/.."

export LD_LIBRARY_PATH=/usr/local/cuda/lib64
export PATH=$PATH:$HOME/.cargo/bin/:/usr/local/cuda/bin

echo --- Build
(
  set -x
  make V=release -j$(nproc)
  make install

  ci/docker-run.sh solanalabs/sgxsdk ./src/sgx-ecc-ed25519/build.sh
  ci/docker-run.sh solanalabs/sgxsdk ./src/sgx/build.sh

  cd dist
  git rev-parse HEAD | tee solana-perf-HEAD.txt
  cp -f /usr/local/cuda/version.txt cuda-version.txt
  tar zcvf ../solana-perf.tgz *
)

BRANCH=$BUILDKITE_BRANCH
if [[ -n "$BUILDKITE_TAG" ]]; then
  BRANCH=$BUILDKITE_TAG
fi

if [[ -z "$BRANCH" || $BRANCH =~ pull/* ]]; then
  exit 0
fi

echo --- AWS S3 Store
set -x

TOOLCHAIN=x86_64-unknown-linux-gnu # TODO: Remove hard code

if [[ ! -r s3cmd-2.0.1/s3cmd ]]; then
  rm -rf s3cmd-2.0.1.tar.gz s3cmd-2.0.1
  wget https://github.com/s3tools/s3cmd/releases/download/v2.0.1/s3cmd-2.0.1.tar.gz
  tar zxf s3cmd-2.0.1.tar.gz
fi

python ./s3cmd-2.0.1/s3cmd --acl-public put solana-perf.tgz \
  s3://solana-perf/$BRANCH/$TOOLCHAIN/solana-perf.tgz

exit 0
