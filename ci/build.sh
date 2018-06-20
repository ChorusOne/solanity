#!/bin/bash -e

cd "$(dirname "$0")/.."

export LD_LIBRARY_PATH=/usr/local/cuda/lib64
export PATH=$PATH:$HOME/.cargo/bin/:/usr/local/cuda/bin

echo --- Build
(
  set -x
  make V=release -j$(nproc)
  make install

  cd dist
  git rev-parse HEAD | tee solana-perf-HEAD.txt
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

#
# Legacy location.
# TODO: remove once main Solana README has been updated to reference new location
#

# this curl command was generated with the s3sign tool
curl -X PUT -T src/cuda-ecc-ed25119/release/libcuda_verify_ed25519.a \
  "https://solana-build-artifacts.s3.amazonaws.com/master/libcuda_verify_ed25519.a?AWSAccessKeyId=AKIAIWNK7Q7RADDL6RIA&Expires=1557293882&Signature=auwPpyaCcurrRxxXlhDJp873nkw%3D" -H "Content-Type: application/octet-stream" -H "x-amz-acl: public-read"

curl -X PUT -T src/jerasure/src/.libs/libJerasure.so.2.0.0 \
  "https://solana-build-artifacts.s3.amazonaws.com/master/libJerasure.so.2.0.0?AWSAccessKeyId=AKIAJBGAJEII7UKJATQQ&Expires=1558815750&Signature=C%2FLJC8yAyqs4ttOW94D8k4OV3pw%3D" -H "Content-Type: application/octet-stream" -H "x-amz-acl: public-read"

curl -X PUT -T src/gf-complete/src/.libs/libgf_complete.so.1.0.0 \
  "https://solana-build-artifacts.s3.amazonaws.com/master/libgf_complete.so.1.0.0?AWSAccessKeyId=AKIAJBGAJEII7UKJATQQ&Expires=1558815813&Signature=o%2BbwjXoPwjnf6nl%2F5YZ0Dje1dxQ%3D" -H "Content-Type: application/octet-stream" -H "x-amz-acl: public-read"

exit 0
