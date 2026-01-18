#define _GNU_SOURCE
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <signal.h>

//#include "codec2/codec2.h"
#include "codec2.h"
#include "radiotap-library/radiotap.h"

/* ---------------- user config ---------------- */

#define IFACE           "mon0"
#define CHANNEL_ID      0
#define TONE_FREQ       600.0
#define SAMPLE_RATE     8000
#define AMP             16000

#define CODEC_PKT_MAGIC 0xC2C2C2C2
#define CODEC_FRAME_BYTES 6

#define CODEC2_FRAMES_PER_PACKET 1 //Tunable: Do some maths to ensure payload is big enough!

/* --------------------------------------------- */

/* Minimal 802.11 data header */
struct ieee80211_hdr {
    uint16_t fc;
    uint16_t dur;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq;
} __attribute__((packed));

/* --- radiotap: Fasterer! --- */
struct rtapheader {
    struct ieee80211_radiotap_header rt;
    uint8_t rate;
} __attribute__((packed));

static volatile int running = 1;
static void sigint(int sig) { (void)sig; running = 0; }

int sock, codecSamplesPerFrame, codecBytesPerFrame, codecPayloadMinSize = 0;
struct CODEC2 *c2 = NULL;
struct sockaddr_ll sll;
struct rtapheader rtap;
struct ieee80211_hdr hdr;
static double phase = 0.0;
static FILE *wavFile = NULL;
uint16_t seq = 0;

static int cleanup(int exitCode){
    if (sock >= 0) close(sock);
    if (c2) codec2_destroy(c2);
    if (wavFile) fclose(wavFile);
    exit(exitCode);
}

/* Generate a smooth sine wave */
static void gen_tone(int16_t *pcm, int n)
{
    double step = 2.0 * M_PI * TONE_FREQ / SAMPLE_RATE;

    for (int i = 0; i < n; i++) {
        pcm[i] = (int16_t)(sin(phase) * AMP);
        phase += step;
        if (phase >= 2.0 * M_PI)
            phase -= 2.0 * M_PI;
    }
}

static int send_wav(const char *filename)
{
    wavFile = fopen(filename, "rb");
    if (!wavFile) {
        perror("Cannot open WAV file");
        return -1;
    }

    // Skip standard 44-byte WAV header (very simple – assumes canonical format)
    uint8_t header[44];
    if (fread(header, 1, 44, wavFile) != 44) {
        fprintf(stderr, "WAV file too short\n");
        fclose(wavFile);
        return -1;
    }

    // Very basic sanity check
    if (strncmp((char*)header, "RIFF", 4) != 0 ||
        strncmp((char*)(header+8), "WAVE", 4) != 0) {
        fprintf(stderr, "Not a valid WAV file\n");
        fclose(wavFile);
        return -1;
    }

    printf("Transmitting WAV file: %s  (mono 8kHz 16-bit PCM)\n", filename);

    int16_t pcm[codecSamplesPerFrame];
    uint8_t codec_bits[codecBytesPerFrame];

    int total_frames = 0;

    while (1) {
        size_t read_samples = fread(pcm, sizeof(int16_t), codecSamplesPerFrame, wavFile);
        if (read_samples == 0) break;  // EOF

        // Pad with silence if partial last frame
        if (read_samples < (size_t)codecSamplesPerFrame) {
            memset(pcm + read_samples, 0, (codecSamplesPerFrame - read_samples) * sizeof(int16_t));
        }

        codec2_encode(c2, codec_bits, pcm);

        // Build payload
        int payloadSize = 6 + codecPayloadMinSize;

        uint8_t payload[payloadSize];
        size_t poff = 0;
        uint32_t magic = htonl(CODEC_PKT_MAGIC);
        memcpy(payload + poff, &magic, 4); poff += 4;
        payload[poff++] = CHANNEL_ID;
        payload[poff++] = 1;  // PTT = on
        memcpy(payload + poff, codec_bits, codecBytesPerFrame);
        poff += codecBytesPerFrame;

        //Calculate exactly how big the frame must be.
        int frameSize = (sizeof(rtap) + sizeof(hdr) + poff);
        uint8_t frame[frameSize];
        size_t len = 0;

        memcpy(frame + len, &rtap, sizeof(rtap));
        len += sizeof(rtap);
        memcpy(frame + len, &hdr,  sizeof(hdr));
        len += sizeof(hdr);
        memcpy(frame + len, payload, poff);
        len += poff;

        if (sendto(sock, frame, len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("sendto during WAV");
            fclose(wavFile);
            return -1;
        }

        total_frames++;
        usleep(20000);  // 20 ms pacing – matches one frame
    }

    fclose(wavFile);
    printf("Finished transmitting WAV (%d frames sent)\n", total_frames);
    return 0;
}

static void setup_codec(void){
    c2 = codec2_create(CODEC2_MODE_2400);
    if (!c2) {
        fprintf(stderr, "codec2_create failed\n");
        cleanup(1);
    }

    //Setup the codec stuff
    codecSamplesPerFrame = codec2_samples_per_frame(c2);
    printf("codec2_samples_per_frame: %u\n", codecSamplesPerFrame);

    codecBytesPerFrame = codec2_bytes_per_frame(c2);
    printf("codec2_bytes_per_frame: %u\n", codecBytesPerFrame);

    codecPayloadMinSize = (codecBytesPerFrame * CODEC2_FRAMES_PER_PACKET);
    printf("Codec payload minimum size: %u\n", codecBytesPerFrame);
}

static void setup_radio_tx(void){
    /* --- socket --- */
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        cleanup(1);
    }

    //Interface stuff
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, IFACE, IFNAMSIZ - 1);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("SIOCGIFINDEX");
        cleanup(1);
    }

    //Botchy code, but as long as it works.
    struct sockaddr_ll sll_setup = {
        .sll_family   = AF_PACKET,
        .sll_ifindex  = ifr.ifr_ifindex,
        .sll_protocol = htons(ETH_P_ALL),
    };

    sll = sll_setup;
}

static void setup_mac_radiotap(void){
    //Setup rtap headers
    rtap.rt.it_version = 0;
    rtap.rt.it_len     = sizeof(rtap);
    rtap.rt.it_present = htole32(1 << IEEE80211_RADIOTAP_RATE);
    rtap.rate          = 48; //48 Mbps

    //Setup MAC headers
    hdr.fc = htole16(0x0008);   /* data frame */
    memset(hdr.addr1, 0xff, 6); /* broadcast */
    hdr.addr2[0] = 0x02;        /* locally administered */
    hdr.addr3[0] = 0x02;
}

static void sendTestTone(void){
    //Payload size calculate: MAGIC PACKET (4 bytes) + ChannelID (1 byte) + PTT mode (1 byte) + Codec2 encoded bytes
    int payloadSize = 6 + codecPayloadMinSize;

    uint8_t payload[payloadSize];
    size_t poff = 0;

    uint32_t magic = htonl(CODEC_PKT_MAGIC);
    memcpy(payload + poff, &magic, 4);
    poff += 4;

    payload[poff++] = CHANNEL_ID;
    payload[poff++] = 1; /* PTT on */

    //Encode the raw PCM data:
    for (int f = 0; f < CODEC2_FRAMES_PER_PACKET; f++) {
        int16_t pcm[codecSamplesPerFrame];
        uint8_t codec_bits[codecBytesPerFrame];

        gen_tone(pcm, codecSamplesPerFrame);

        codec2_encode(c2, codec_bits, pcm);

        memcpy(payload + poff, codec_bits, codecBytesPerFrame);
        poff += codecBytesPerFrame;
    }

    hdr.seq = htole16(seq++ << 4);

    //Calculate exactly how big the frame must be.
    int frameSize = (sizeof(rtap) + sizeof(hdr) + poff);
    uint8_t frame[frameSize];
    size_t len = 0;

    memcpy(frame + len, &rtap, sizeof(rtap));
    len += sizeof(rtap);

    memcpy(frame + len, &hdr, sizeof(hdr));
    len += sizeof(hdr);

    memcpy(frame + len, payload, poff);
    len += poff;

    if (sendto(sock, frame, len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("sendto");
        cleanup(1);
    }
}

static void sendCleanup(void){
    int payloadSize = 6;

    uint8_t payload[payloadSize];
    size_t poff = 0;

    uint32_t magic = htonl(CODEC_PKT_MAGIC);
    memcpy(payload + poff, &magic, 4);
    poff += 4;

    payload[poff++] = CHANNEL_ID;
    payload[poff++] = 0; /* PTT off */

    hdr.seq = htole16(seq++ << 4);

    //Calculate exactly how big the frame must be.
    int frameSize = (sizeof(rtap) + sizeof(hdr) + poff);
    uint8_t frame[frameSize];
    size_t len = 0;

    memcpy(frame + len, &rtap, sizeof(rtap));
    len += sizeof(rtap);

    memcpy(frame + len, &hdr, sizeof(hdr));
    len += sizeof(hdr);

    memcpy(frame + len, payload, poff);
    len += poff;

    if (sendto(sock, frame, len, 0, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("sendto");
        cleanup(1);
    }
}

int main(int argc, char *argv[])
{
    printf("Radiotap & Codec2 encode and TX tool\n");
    printf("Transmit audio via raw WiFi radio. (Test-tone of 600Hz OR 8khz, 16bit PCM audio file)\n");

	signal(SIGINT, sigint);
	signal(SIGTERM, sigint);

    printf("Setting up MAC & radiotap headers\n");
    setup_mac_radiotap();

    printf("Setting up radio interface\n");
    setup_radio_tx();
    
    printf("Setting up audio codec\n");
    setup_codec();


    if (argc >= 2) {
        // WAV file mode
        if (send_wav(argv[1]) != 0) {
            fprintf(stderr, "WAV transmission failed\n");
            cleanup(1);
        }
        sendCleanup();
        cleanup(0);
    }

    // No argument → test tone mode
    printf("No WAV file specified → running test tone (Ctrl+C to stop)\n");

    /* --- TX loop --- */
    printf("Sending test-tone...\n");
    while (running) {
        sendTestTone();
        usleep(20000); /* 20 ms pacing */
    }

    //Cleanup...
    if (!running){
        sendCleanup();
    }

    cleanup(0);
}
