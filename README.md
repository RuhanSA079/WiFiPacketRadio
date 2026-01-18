# WiFiPacketRadio
Crude method in transmitting compressed audio over WiFi packet injection and receiving it on monitor mode WiFi radios.  

Make sure that you have a WiFi radio/adapter that has Packet injection support, and another radio for monitor mode. (Most wireless radios support monitor mode)  

Decoder: AMD64 and MIPS.  
Encoder: AMD64 and MIPS.  
Radiotap: AMD64 and MIPS.  


My idea was, to build a complete system, that runs on a cheap WiFi radio module (OpenWRT, HLK7628 from Hi-Link) with a soundcard and GPIO pin for PTT and transmit/receive audio over the WiFi link, much like a walkie-talkie or HT (radio speak).  

This project is just a proof-of-concept that I can transmit compressed audio, receive it on another device and decode it, pipe the PCM samples through a socket for aplay stdin consumption on a remote computer.   

## Notice
Please make sure you are able to transmit such WiFi packets arbitrarily. Use this code on your own risk!  

I am not responsible if you transmit random packets on the 2.4Ghz or 5Ghz spectrum. You have been warned.  

## AI Notice
Has been vibe-coded heavily, and made some pure C developers turn in their graves with my patchy code, spewing memory leaks and violating coding rules.  

I also had modified a lot of code, since the AI can't really code, more of a theorist than a realist.  

## Notes
Uses [Codec2](https://github.com/drowe67/codec2) from drowe67, to compress PCM samples to transmit raw bytes over WiFi. Quite impressive. Thanks, mate!  
Uses [RadioTap](https://github.com/radiotap/radiotap-library) from the Radiotap org, but extended heavily on the debug logs and parser they had.  
Uses OpenWRT SDK for compiling to mt76x8 OpenWRT device, for receiving data and decoding.  

## Further notes
Seems like CPU usage spikes to about 90% on MIPS when transmitting, but about 70% when receiving.  
(Single core MIPS device, used top utility)  

There may be some audio glitches (timing related?) but YMMV. 

Current mt76 OpenWRT builds/releases crashes on packet injection.  
Manually patched mt76 driver [mt76-pktinject](https://github.com/RuhanSA079/mt76-pktinject)  

## Build (At your own risk)
Included build instructions and buildscripts used for compiling on AMD64 and ramips in notes.txt  
Please use at your own risk.  
