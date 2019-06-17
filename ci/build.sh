#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."

: "${CUDA_HOME:=/usr/local/cuda-10.1}"

if [[ ! -d $CUDA_HOME/lib64 ]]; then
  echo Invalid CUDA_HOME: $CUDA_HOME
  exit 1
fi

export LD_LIBRARY_PATH=$CUDA_HOME/lib64
export PATH=$PATH:$HOME/.cargo/bin/:$CUDA_HOME/bin

echo --- Build
(
  set -x
  make V=release -j$(nproc)
  make install

  ci/docker-run.sh solanalabs/sgxsdk ./src/sgx-ecc-ed25519/build.sh
  ci/docker-run.sh solanalabs/sgxsdk ./src/sgx/build.sh

  cd dist
  git rev-parse HEAD | tee solana-perf-HEAD.txt
  echo $CUDA_HOME | tee solana-perf-CUDA_HOME.txt
  cp -f $CUDA_HOME/version.txt cuda-version.txt
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

docker run \
  --rm \
  --env AWS_ACCESS_KEY_ID \
  --env AWS_SECRET_ACCESS_KEY \
  --volume "$PWD:/solana" \
  eremite/aws-cli:2018.12.18 \
  /usr/bin/s3cmd --acl-public put /solana/solana-perf.tgz \
  s3://solana-perf/$BRANCH/$TOOLCHAIN/solana-perf.tgz

exit 0
