#!/bin/bash
echo "Building binary..."
mkdir -p bin/

set -e

export SDK=../openwrt-sdk-24.10.4-ramips-mt76x8_gcc-13.3.0_musl.Linux-x86_64/
export STAGING_DIR=$SDK/staging_dir
export PATH=$PATH:$STAGING_DIR/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin

# echo "Building wpr_mesh_test_mips..."
# mipsel-openwrt-linux-musl-gcc -Os -Wall -static -I "$STAGING_DIR/target-mipsel_24kc_musl/usr/include" -L "$STAGING_DIR/target-mipsel_24kc_musl/usr/lib" radiotap-library/radiotap.c wpr_mesh_test_mips.c -lpcap -o bin/wpr_mesh_test_mips

# echo "Building wpr_mesh_test_amd64..."
# gcc -Os -Wall radiotap-library/radiotap.c wpr_mesh_test_amd64.c -lpcap -o bin/wpr_mesh_test_amd64

echo "Building wpr_tx_rx_mips..."
mipsel-openwrt-linux-musl-gcc -Os -Wall -static -I codec2/src -I codec2/build_openwrt/src/codec2_native radiotap-library/radiotap.c wpr_tx_rx.c codec2/build_openwrt/src/libcodec2.a -I "$STAGING_DIR/target-mipsel_24kc_musl/usr/include" -L "$STAGING_DIR/target-mipsel_24kc_musl/usr/lib" -lpcap -o bin/wpr_tx_rx_mips

echo "Building wpr_tx_rx for amd64..."
gcc -Os -Wall radiotap-library/radiotap.c wpr_tx_rx.c -lcodec2 -lpcap -lm -o bin/wpr_tx_rx_amd64
