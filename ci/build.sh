#!/bin/bash -e

cd "$(dirname "$0")/.."

export LD_LIBRARY_PATH=/usr/local/cuda/lib64
export PATH=$PATH:$HOME/.cargo/bin/:/usr/local/cuda/bin

echo --- Make
(
  set -x
  make V=release -j$(nproc)
)

if [[ "$BUILDKITE_BRANCH" = "master" ]]; then
  echo --- AWS S3 Store
  (
    set -x

    cp src/cuda-ecc-ed25119/release/libcuda_verify_ed25519.a /tmp
    cp src/jerasure/src/.libs/libJerasure.so* /tmp
    cp src/gf-complete/src/.libs/libgf_complete.so* /tmp

    # this curl command was generated with the s3sign tool
    curl -X PUT -T src/cuda-ecc-ed25119/release/libcuda_verify_ed25519.a \
      "https://solana-build-artifacts.s3.amazonaws.com/master/libcuda_verify_ed25519.a?AWSAccessKeyId=AKIAIWNK7Q7RADDL6RIA&Expires=1557293882&Signature=auwPpyaCcurrRxxXlhDJp873nkw%3D" -H "Content-Type: application/octet-stream" -H "x-amz-acl: public-read"

    curl -X PUT -T src/jerasure/src/.libs/libJerasure.so.2.0.0 \
      "https://solana-build-artifacts.s3.amazonaws.com/master/libJerasure.so.2.0.0?AWSAccessKeyId=AKIAJBGAJEII7UKJATQQ&Expires=1558815750&Signature=C%2FLJC8yAyqs4ttOW94D8k4OV3pw%3D" -H "Content-Type: application/octet-stream" -H "x-amz-acl: public-read"

    curl -X PUT -T src/gf-complete/src/.libs/libgf_complete.so.1.0.0 \
      "https://solana-build-artifacts.s3.amazonaws.com/master/libgf_complete.so.1.0.0?AWSAccessKeyId=AKIAJBGAJEII7UKJATQQ&Expires=1558815813&Signature=o%2BbwjXoPwjnf6nl%2F5YZ0Dje1dxQ%3D" -H "Content-Type: application/octet-stream" -H "x-amz-acl: public-read"
  )
fi

echo done
