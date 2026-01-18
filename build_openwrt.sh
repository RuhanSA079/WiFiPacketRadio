#!/bin/bash
echo "Building binary..."

export SDK=$(pwd)/../../openwrt-sdk-24.10.4-ramips-mt76x8_gcc-13.3.0_musl.Linux-x86_64
export STAGING_DIR=$SDK/staging_dir
export PATH=$PATH:$STAGING_DIR/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin
CC=$STAGING_DIR/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin/mipsel-openwrt-linux-musl-gcc
CXX=$STAGING_DIR/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin/mipsel-openwrt-linux-musl-g++

mkdir -p build_openwrt
cd build_openwrt

cmake .. \
  -DCMAKE_SYSTEM_NAME=Linux \
  -DCMAKE_C_COMPILER=mipsel-openwrt-linux-musl-gcc \
  -DCMAKE_C_FLAGS="-Os -fPIC" \
  -DCMAKE_INSTALL_PREFIX=/usr \
  -DBUILD_SHARED_LIBS=OFF \
  -DCODEC2_BUILD_TESTS=OFF \
  -DCODEC2_BUILD_EXAMPLES=OFF

make -j8
