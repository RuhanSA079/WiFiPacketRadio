# WiFiPacketRadio
Crude method in transmitting compressed audio over WiFi packet injection and receiving it on monitor mode WiFi radios.  

Make sure that you have a WiFi radio/adapter that has Packet injection support, and another radio for monitor mode. (Most wireless radios support monitor mode)  

My idea is, to build a complete system, that runs on a cheap WiFi radio module (OpenWRT, HLK7628 from Hi-Link) with a soundcard and GPIO pin for PTT and transmit/receive audio over the WiFi link, much like a walkie-talkie or handheld transceiver 

This project is just a proof-of-concept that I can transmit compressed audio, receive it on another device and decode it, pipe the decompressed PCM samples through a socket for aplay stdin consumption on a remote computer.   

At this stage, due to the MIPS radio's inability to keep up with the sent packet rate and "stuttering", I was thinking of maybe doing the following:  

Port this to a Raspberry Pi Zero 2 W, with a RTL8812EU as wireless radio, and try again. Chances are, that it will give the same problem of "stuttering" audio, eventually.  

## TODO
- Implement a small RX audio buffer (consisting about 60ms) sampled audio, and send it to the audio layer. This is to avoid the "stuttering" of the packets arriving not on the same timeframe  
- Implement "meshing", where 3 or more radios can forward/receive the audio broadcasted from one radio. This will ensure that say, in a vehicle convoy of three cars on a long journey, that if one vehicle in the
front of the convoy transmits, the middle vehicle receives it, and relays it back to the last vehicle, because the third vehicle is be out of range of the first one, but still in the range of the 2nd vehicle.  


## Nice to have
- Build a "Pi powered" HT (handheld transceiver) unit, with a LCD, buttons and LiPo cell. (Will be expensive in small numbers) or a similar system.  
- Implement selective private comms by radio ID or MAC, say, between vehicle 1 and 3, without vehicle 2 hearing the conversation.  

## Very nice to do
- Port this code-base and driver code to something like Circle, running baremetal C++ code: https://github.com/rsta2/circle

## Notice
Please make sure you are able to transmit such WiFi packets arbitrarily. Use this code on your own risk!  

I am not responsible if you transmit random packets on the 2.4Ghz or 5Ghz spectrum. You have been warned.  

Please do not open a issue on why you cannot compile the code or anything like that. Go ask the AI to fix your compiler problems.  
You may use the code 

## AI Notice
Has been vibe-coded heavily, and made some pure C developers turn in their graves with my patchy code, spewing memory leaks and violating coding rules.  

I also had modified a lot of code, since the AI can't really code, more of a theorist than a realist.  

## Notes
Uses [Codec2](https://github.com/drowe67/codec2) from drowe67, to compress PCM samples to transmit raw bytes over WiFi. Quite impressive. Thanks, mate!  
Uses [RadioTap](https://github.com/radiotap/radiotap-library) from the Radiotap org, but extended heavily on the debug logs and parser they had.  
Have been heavily inspired by [WFB-ng](https://github.com/svpcom/wfb-ng) 
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
