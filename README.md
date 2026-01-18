# WiFiPacketRadio
Crude method in transmitting compressed audio over WiFi packet injection and receiving it on monitor mode WiFi radios.  

Make sure that you have a WiFi radio/adapter that has Packet injection support, and another radio for monitor mode. (Most wireless radios support monitor mode)  

Decoder: OpenWRT only, but can be modified to compile on Linux.  
Encoder: Linux only, but can be modified to compile on OpenWRT.  

My idea was, to build a complete system, that runs on a cheap WiFi radio module (OpenWRT, HLK7628 from Hi-Link) with a soundcard and GPIO pin for PTT and transmit/receive audio over the WiFi link, much like a walkie-talkie or HT (radio speak).  
This project is just a proof-of-concept that I can receive compressed audio and decode it on the device.  
At this stage, my OpenWRT device crashes on packet injection, so will have to build custom OpenWRT build with patched WiFi driver.  


## Notice
Please make sure you are able to transmit such WiFi packets arbitrarily. Use this code on your own risk!  

I am not responsible if you transmit random packets on the 2.4Ghz or 5Ghz spectrum. You have been warned.  

## AI Notice
Has been vibe-coded heavily, and made some pure C developers turn in their graves with my patchy code, spewing memory leaks and violating some coding rules.  
I also had modified a lot of code, since the AI can't really code, more of a theorist than a realist.  

## Notes
Uses [Codec2](https://github.com/drowe67/codec2) from drowe67, to compress PCM samples to transmit raw bytes over WiFi. Quite impressive. Thanks, mate!  
Uses [RadioTap](https://github.com/radiotap/radiotap-library) from the Radiotap org, but extended heavily on the debug logs and parser they had.  
Uses OpenWRT SDK for compiling to mt76x8 OpenWRT device, for receiving data and decoding.  

## Further notes
mt76 OpenWRT device crashes on packet injection. May have to manually patch driver and rebuild. [mt76-pktinject](https://github.com/RuhanSA079/mt76-pktinject)
