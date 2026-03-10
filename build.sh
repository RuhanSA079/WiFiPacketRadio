#!/bin/bash
echo "Building binary..."
mkdir -p bin/

set -e

echo "Building wpr_tx_rx..."
gcc -O0 -fno-omit-frame-pointer -Wall -Wextra -g -Os -Wall radiotap-library/radiotap.c fec.c wpr_tx_rx.c -lcodec2 -lpcap -lm -lasound -o bin/wpr_tx_rx

#echo "Building wpr_tx_rx... (Raspberry Pi)"
#gcc -O0 -fno-omit-frame-pointer -Wall -Wextra -g -Os -Wall radiotap-library/radiotap.c fec.c wpr_tx_rx.c -lcodec2 -lpcap -lm -lasound -lgpiolib -o bin/wpr_tx_rx