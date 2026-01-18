#!/bin/bash
echo "Building binary..."

mkdir -p build_amd64
cd build_amd64

cmake .. \
  -DCMAKE_SYSTEM_NAME=Linux \
  -DCMAKE_C_FLAGS="-Os -fPIC" \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DBUILD_SHARED_LIBS=OFF \
  -DCODEC2_BUILD_TESTS=OFF \
  -DCODEC2_BUILD_EXAMPLES=OFF

make -j8
