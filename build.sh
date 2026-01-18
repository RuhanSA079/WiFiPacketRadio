#!/bin/bash
echo "Building binary..."
mkdir -p bin/

export SDK=../openwrt-sdk-24.10.4-ramips-mt76x8_gcc-13.3.0_musl.Linux-x86_64/
export STAGING_DIR=$SDK/staging_dir
export PATH=$PATH:$STAGING_DIR/toolchain-mipsel_24kc_gcc-13.3.0_musl/bin

#echo "Building wifi-mon..."
#mipsel-openwrt-linux-musl-gcc -O2 -Wall -D_GNU_SOURCE wifi-mon.c -o wifi-mon

#echo "Building codec2_rx..."
#mipsel-openwrt-linux-musl-gcc -Os -Wall -static -I codec2/src -I codec2/build_openwrt/src/codec2_native codec2_rx.c codec2/build_openwrt/src/libcodec2.a -o codec2_rx

#echo "Building codec2_rx_2..."
#mipsel-openwrt-linux-musl-gcc -Os -Wall -static -I codec2/src -I codec2/build_openwrt/src/codec2_native codec2_rx_2.c codec2/build_openwrt/src/libcodec2.a -o codec2_rx_2

#echo "Building codec2_rx_3..."
#mipsel-openwrt-linux-musl-gcc -Os -Wall -static -I codec2/src -I codec2/build_openwrt/src/codec2_native radiotap-library/radiotap.c codec2_rx_3.c codec2/build_openwrt/src/libcodec2.a -o codec2_rx_3

echo "Building radiotap_decode_mips..."
mipsel-openwrt-linux-musl-gcc -Os -Wall -static radiotap-library/radiotap.c radiotap_decode_mips.c -o bin/radiotap_decode_mips

echo "Building radiotap_decode_amd64"
gcc -Os -Wall -static radiotap-library/radiotap.c radiotap_decode_amd64.c -o bin/radiotap_decode_amd64

echo "Building codec2_decode_mips..."
mipsel-openwrt-linux-musl-gcc -Os -Wall -static -I codec2/src -I codec2/build_openwrt/src/codec2_native radiotap-library/radiotap.c codec2_decode_mips.c codec2/build_openwrt/src/libcodec2.a -o bin/codec2_decode_mips

echo "Building codec2_decode_amd64..."
gcc -Os -Wall -static -I codec2/src -I codec2/build_amd64/src -I codec2/build_amd64/ radiotap-library/radiotap.c codec2_decode_amd64.c codec2/build_amd64/src/libcodec2.a -lm -o bin/codec2_decode_amd64

echo "Building codec2_transmit_mips..."
mipsel-openwrt-linux-musl-gcc -Os -Wall -static -I codec2/src -I codec2/build_openwrt/src/codec2_native radiotap-library/radiotap.c codec2_transmit_mips.c codec2/build_openwrt/src/libcodec2.a -o bin/codec2_transmit_mips

echo "Building codec2_transmit_amd64"
gcc -Os -Wall -static -I codec2/src -I codec2/build_amd64/src -I codec2/build_amd64/ radiotap-library/radiotap.c codec2_transmit_amd64.c codec2/build_amd64/src/libcodec2.a -lm -o bin/codec2_transmit_amd64

echo "Build done."
