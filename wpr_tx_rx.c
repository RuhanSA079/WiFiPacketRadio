#define _GNU_SOURCE

/* WiFiPacketRadio (WPR) is licensed under the GPLv2 license.
 The author takes no responsibility whatsoever for any damages caused, directly or indirectly, when using this program/source code.
 Please check with your country's radio licensing spectrum and power limits, as per regulatory domain.
 This program is developed as a proof-of-concept, as a experimental means to see how far 2.4 Ghz and 5Ghz radio packets being transmitted, can be received reliably.
 The author intends to use a higher power wireless radio (1 watt/30dBm) on 5Ghz, nothing more, to experiment with the range of radio packets TXed and RXed


 The mt76 target is considered deprecated, as the stringent "clocking" requirements are too strict, and "stutters" the audio, and driver overheads causing timing issues. (transmit)
 The author intends to test this WiFiPacketRadio experiment on a AMD64 laptop, and a Raspberry Pi Zero 2W or Raspberry Pi CM4 as client devices, with a patched RTL8812AU/EU driver.

 The experiment will determine the following:
 - Which frequency works best for the longest distance (2.4 GHz vs 5 GHz)
 - Which frequency is best used when doing Line-of-sight (LOS) or in "urban" areas or in the "field" (trees/foliage).
 - Are un-acked "WiFi" radio data being transmitted, better than analog systems in terms of audio clarity/quality/range, or best to stick to analog for communications.

 The code is expected to compile on a ARM64 and AMD64 system.
*/

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <poll.h>
#include <pcap/pcap.h>
#include "radiotap-library/radiotap.h"
#include "radiotap-library/radiotap_iter.h"
#include <math.h>
#include <inttypes.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <pthread.h>
#include <fcntl.h>
#include <codec2/codec2.h>
#include "fec.h"
#include "ringbuffer.h"

// on Raspberry-Pi
#if defined(__x86_64__) || defined(_M_X64)
#define RADIO_IFACE "wlan0"
#else
#define RADIO_IFACE "wlan1"
#endif

#define AUDIO_CHANNEL_ID 1
#define DATA_HDR_MAGIC 0xC2C2C2C2

#define TONE_FREQ 600.0
#define TONE_SAMPLE_RATE 8000
#define TONE_AMPLITUDE 16000

#define PCM_BUF_SAMPLE_COUNT 160

#define FRAME_SIZE 2048
#define BLOCK_SIZE (1 << 20)
#define BLOCK_NR 64
#define FC_TYPE(fc) (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc) (((fc) >> 4) & 0xF)
#define FC_TO_DS(fc) ((fc) & 0x0100)
#define FC_FROM_DS(fc) ((fc) & 0x0200)

// RadioTap message seems to work like this:
//  Radiotap_hdr -> header data defining the radio's settings, rates, enable/disable certain features, etc.
//  ieee80211_mac_hdr -> Header data that contains the data frame stuff, duration and then the three MAC addresses, as well as the frame sequence number.
//  Raw data -- My raw data that I send (c2c2c2c2 + channel data + audio data, etc.)

#define RADIO_DATA_NOOP 0x00
#define RADIO_DATA_AUDIO 0x01
#define RADIO_DATA_MESH 0x02
#define MCS_VALUES (IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW | IEEE80211_RADIOTAP_MCS_HAVE_GI | IEEE80211_RADIOTAP_MCS_HAVE_STBC | IEEE80211_RADIOTAP_MCS_HAVE_FEC)
#define IEEE80211_FTYPE_DATA 0x0008
// Stock standard radio struct:
//  Magic header
//  Data type
//  Data
//  FEC data

// Types of data:
// 1. Audio data
// 2. Mesh data (contains no audio data)

// Max data length that will be sent:
// 1. Audio data ->
//      channel ID -> 1 byte
//      ptt_mode -> 1 byte
//      Codec2 data -> 8 bytes
//      Total bytes: 10
// 2. Mesh data
//      Own radio MAC -> 6 bytes
//      Remote radio MAC -> 6 bytes
//      Mesh data -> 4 extra bytes

// FEC data
//      4 bytes or 6?

// From this, it derived that the maximum amount of "data" we can send, is 16 bytes, max.
// Can be adjusted later in the struct

struct wpr_data
{
    uint32_t magic_header;
    uint8_t data_type;
    uint8_t data[16];
    uint8_t fec[6];
} __attribute__((packed));

// Stock-standard 802.11 headers
struct ieee80211_mac_hdr
{
    uint16_t fc;
    uint16_t dur;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint16_t seq;
} __attribute__((packed));

struct radiotap_hdr_data
{
    uint8_t rt_flags;
    uint16_t tx_flags;
    uint8_t mcs_known;
    uint8_t mcs_flags;
    uint8_t mcs;
};

struct radiotap_hdr
{
    struct ieee80211_radiotap_header rt;
    struct radiotap_hdr_data rtd;
    struct ieee80211_mac_hdr mh;
    struct wpr_data wpr;
} __attribute__((packed));

struct audio_channel_state
{
    int active;
    uint64_t last_rx_ns;
};

/* ---------------- some variables ---------------- */

// Ringbuffer stuff for receiving packets via PACKET_RX_RING
static void *ring = NULL;
static size_t ring_size;
static unsigned int frame_nr;

// Codec2 stuff
struct CODEC2 *codec2 = NULL;

unsigned char *hwMAC;          // Hardware MAC address of the radio interface, used for filtering out our own transmitted packets.
unsigned char macBroadcast[6]; // Broadcast MAC address for filtering incoming packets (set to ff:ff:ff:ff:ff:ff).
int radio_fd, pcap_fd, audio_in_fd, audio_out_fd = 0;

bool debug = false;
bool debugRadioData = false;
volatile sig_atomic_t running = 1;
bool isRadioReceiving = false;
bool isRadioTransmitting = false;
bool useQDiscBypass = true;

static int tcp_listen = 0;
static double phase = 0.0;

uint64_t last_tx_test_tone = 0;
struct sockaddr_ll sll;
static FILE *wavFile = NULL;

pcap_t *pcap_handle = NULL;

uint16_t hdr_seq_tx = 0;

uint8_t mcs_flags = 0;

struct wpr_data wpr_data_rx;
struct wpr_data wpr_data_tx;
struct ieee80211_mac_hdr mac_hdr_tx;
struct radiotap_hdr_data rtap_hdr_data_tx;
struct radiotap_hdr rtap_tx;

static struct audio_channel_state channels[4];

#define PCM_BYTE_COUNT 160                             /* 20 ms of mono audio at 8 kHz */
#define PCM_100MS_BYTE_COUNT (PCM_BYTE_COUNT * 5)      // enough for 100 ms of audio, 160 bytes per 20 ms frame * 5 = 800 bytes
#define TEST_TONE_INTERVAL (PCM_100MS_BYTE_COUNT * 10) //

int16_t pcmToneBuffer[TEST_TONE_INTERVAL]; // about 1 second of tone at 8 kHz, 160 samples per 20 ms frame, so 160 * 5 = 800 bytes per 100 ms, so 800 * 10 = 8000 bytes for 1 second

RingBuffer audioBuf;

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void cleanup(void)
{
    running = 0;

    if (ring)
    {
        munmap(ring, ring_size);
    }

    if (radio_fd > 0)
    {
        close(radio_fd);
        radio_fd = 0;
    }

    if (pcap_fd > 0)
    {
        close(pcap_fd);
        pcap_fd = 0;
    }

    if (pcap_handle != NULL)
    {
        pcap_close(pcap_handle);
        pcap_handle = NULL;
    }

    if (audio_in_fd > 0)
    {
        close(audio_in_fd);
        audio_in_fd = 0;
    }

    if (audio_out_fd > 0)
    {
        close(audio_out_fd);
        audio_out_fd = 0;
    }
    if (wavFile)
        fclose(wavFile);

    if (codec2 != NULL)
    {
        codec2_destroy(codec2);
        codec2 = NULL;
    }

    exit(0);
}

static void sigint(int sig)
{
    (void)sig;
    running = 0;
    cleanup();
}

static void root_check(void)
{
    if (geteuid() != 0)
    {
        printf("Got root?\n");
        exit(1);
    }
}

static void run_cmd(const char *cmd)
{
    int ret = system(cmd);
    if (ret != 0)
    {
        fprintf(stderr, "Command failed: %s\n", cmd);
        cleanup();
    }
}

static void setup_radio_monitor(void)
{
    if (debug)
        printf("Setting up radio...\n");

    // Bring down monitor interface
    run_cmd("ip link set " RADIO_IFACE " down 2>/dev/null || true");

// reconfigure radio...
#if defined(__x86_64__) || defined(_M_X64)
    run_cmd("iw dev " RADIO_IFACE " set monitor otherbss");
    run_cmd("iwconfig " RADIO_IFACE " channel 36");
#else
    run_cmd("iw reg set BO");
    run_cmd("iw dev " RADIO_IFACE " set monitor otherbss");
    run_cmd("iwconfig " RADIO_IFACE " channel 36");
#endif

    // Leave txpower for now
    run_cmd("iw dev " RADIO_IFACE " set txpower fixed 300"); // powaaa
    // Do HT or VHT (high throughput or Very High Throughput), leave disabled for now
    // Radio is default on 20Mhz bw, which is fine.

    run_cmd("ip link set " RADIO_IFACE " up");
}

static void setup_mac_radiotap(void)
{
    if (debug)
    {
        printf("setup_mac_radiotap...\n");
    }

    memset(&rtap_tx, 0, sizeof(rtap_tx)); // Zero-out the radiotap header.

    // 20 Mhz, no GI, STBC 1, LDPC enabled
    mcs_flags |= IEEE80211_RADIOTAP_MCS_BW_20;
    mcs_flags |= (IEEE80211_RADIOTAP_MCS_STBC_1 << IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
    mcs_flags |= IEEE80211_RADIOTAP_MCS_FEC_LDPC;

    rtap_hdr_data_tx.tx_flags = IEEE80211_RADIOTAP_F_TX_NOACK;
    rtap_hdr_data_tx.mcs = 1;                // MCS 1
    rtap_hdr_data_tx.mcs_flags = mcs_flags;  // See above
    rtap_hdr_data_tx.mcs_known = MCS_VALUES; //

    // Set radiotap flags to disable FCS (for now, needs to enable it soon)
    rtap_hdr_data_tx.rt_flags = 0;

    rtap_tx.rt.it_version = 0;
    rtap_tx.rt.it_present = htole32(1u << IEEE80211_RADIOTAP_FLAGS | 1u << IEEE80211_RADIOTAP_TX_FLAGS | 1u << IEEE80211_RADIOTAP_MCS);
    rtap_tx.rt.it_len = htole16((sizeof(rtap_tx.rt) + sizeof(rtap_hdr_data_tx))); // Extremely important to define the whole radiotap header size and radiotap "data" that follows the header, before the 802.11 MAC stuff

    // Set the radiotap message data already to the whole "message" that needs to be sent...
    rtap_tx.rtd = rtap_hdr_data_tx;

    // Setup MAC headers for the WPR data stuff
    mac_hdr_tx.fc = htole16(IEEE80211_FTYPE_DATA); /* data frame */
    mac_hdr_tx.dur = 0x0000;                       /* duration */
    memset(mac_hdr_tx.addr1, 0xff, 6);             /* broadcast */
    memset(macBroadcast, 0xff, 6);

    memset(mac_hdr_tx.addr2, 0x00, 6);
    memset(mac_hdr_tx.addr3, 0x00, 6);

    // Set the "special flags" in addr2.
    mac_hdr_tx.addr2[0] = 0x57;
    mac_hdr_tx.addr2[1] = 0x42;
    mac_hdr_tx.addr2[5] = 0x01;

    // Set up the wpr_data struct
    wpr_data_tx.magic_header = DATA_HDR_MAGIC;
    wpr_data_tx.data_type = RADIO_DATA_NOOP;

    memset(wpr_data_tx.data, 0x00, sizeof(wpr_data_tx.data));

    wpr_data_tx.data[0] = AUDIO_CHANNEL_ID;
    wpr_data_tx.data[1] = 0; // PTT is OFF.

    memset(wpr_data_tx.fec, 0x00, sizeof(wpr_data_tx.fec));
}

static void codec2_timeout_check(void)
{
    uint64_t t = now_ns();

    for (int i = 0; i < 4; i++)
    {
        if (channels[i].active && (t - channels[i].last_rx_ns) > 300000000ULL)
        {
            printf("Channel %d: timeout\n", i);
            channels[i].active = 0;
        }
    }
}

static void setup_codec2(void)
{
    if (debug)
    {
        printf("Setting up Codec2 enc/dec on mode 3200...\n");
    }

    codec2 = codec2_create(CODEC2_MODE_3200);
    if (codec2 == NULL)
    {
        fprintf(stderr, "Failed to create Codec2 instance\n");
        cleanup();
    }
}

static void setup_radio(void)
{
    setup_radio_monitor();
    setup_mac_radiotap();

    if (debug)
    {
        printf("Opening radio socket...\n");
    }

    radio_fd = socket(PF_PACKET, SOCK_RAW, 0);
    if (radio_fd < 0)
    {
        perror("socket");
        cleanup();
    }

    if (useQDiscBypass)
    {
        if (debug)
        {
            printf("Setting up PACKET_QDISC_BYPASS...\n");
        }

        const int optval = 1;
        if (setsockopt(radio_fd, SOL_PACKET, PACKET_QDISC_BYPASS, (const void *)&optval, sizeof(optval)) != 0)
        {
            printf("Unable to bypass PACKET_QDISC_BYPASS");
            cleanup();
        }
    }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, RADIO_IFACE, IF_NAMESIZE - 1);

    if (ioctl(radio_fd, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("SIOCGIFINDEX");
        cleanup();
    }

    // Save if_index and get mac address
    int ifindex = ifr.ifr_ifindex;

    /* Get hardware (MAC) address */
    if (ioctl(radio_fd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("SIOCGIFHWADDR");
        cleanup();
    }

    hwMAC = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    if (debug)
    {
        printf("Radio MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n", hwMAC[0], hwMAC[1], hwMAC[2], hwMAC[3], hwMAC[4], hwMAC[5]);
    }

    // set the radio's MAC address in addr3
    memcpy(mac_hdr_tx.addr3, hwMAC, sizeof(mac_hdr_tx.addr3));

    struct sockaddr_ll sll_radio = {
        .sll_family = AF_PACKET,
        .sll_ifindex = ifindex,
        .sll_protocol = 0,
    };
    sll = sll_radio;

    if (debug)
    {
        printf("Binding to radio_fd...\n");
    }

    if (bind(radio_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
    {
        close(radio_fd);
        printf("Unable to bind to radio interface!");
        cleanup();
    }

    if (isRadioReceiving)
    {
        if (usePcapForRx)
        {
            printf("Setting up pcap...\n");
            char errbuf[PCAP_ERRBUF_SIZE];

            pcap_handle = pcap_create(RADIO_IFACE, errbuf);
            if (pcap_handle == NULL)
            {
                fprintf(stderr, "pcap_create failed: %s\n", errbuf);
                cleanup();
            }

            if (FRAME_SIZE > 0 && pcap_set_buffer_size(pcap_handle, FRAME_SIZE) != 0)
            {
                printf("set_buffer_size failed");
                cleanup();
            }
            if (pcap_set_snaplen(pcap_handle, 4096) != 0)
            {
                printf("set_snaplen failed");
                cleanup();
            }
            if (pcap_set_promisc(pcap_handle, 1) != 0)
            {
                printf("set_promisc failed");
                cleanup();
            }
            if (pcap_set_timeout(pcap_handle, -1) != 0)
            {
                printf("set_timeout failed");
                cleanup();
            }
            if (pcap_set_immediate_mode(pcap_handle, 1) != 0)
            {
                printf("pcap_set_immediate_mode failed: %s", pcap_geterr(pcap_handle));
                cleanup();
            }
            if (pcap_activate(pcap_handle) != 0)
            {
                printf("pcap_activate failed: %s", pcap_geterr(pcap_handle));
                cleanup();
            }
            if (pcap_setnonblock(pcap_handle, 1, errbuf) != 0)
            {
                printf("set_nonblock failed: %s", errbuf);
                cleanup();
            }

            int link_encap = pcap_datalink(pcap_handle);
            struct bpf_program bpfprogram;

            if (link_encap != DLT_IEEE802_11_RADIO)
            {
                printf("unknown encapsulation on %s", RADIO_IFACE);
                cleanup();
            }

            // const char *program = "ether[0x0a:2]==0x5742 && ether[0x0c:4] == 0x00000001";
            const char *program = "ether[0x0a:2]==0x5742"; // TODO filter out other packets. (using ff:ff:ff:ff:ff:ff as addr1 and our own MAC as addr3)

            if (pcap_compile(pcap_handle, &bpfprogram, program, 1, 0) == -1)
            {
                printf("Unable to compile %s: %s", program, pcap_geterr(pcap_handle));
                cleanup();
            }

            if (pcap_setfilter(pcap_handle, &bpfprogram) == -1)
            {
                printf("Unable to set filter %s: %s", program, pcap_geterr(pcap_handle));
                cleanup();
            }

            pcap_freecode(&bpfprogram);
            pcap_fd = pcap_get_selectable_fd(pcap_handle);

            if (pcap_fd < 0)
            {
                printf("Unable to obtain pcap FD...");
                cleanup();
            }
        }
        else
        {
            printf("Setting up ringbuffer and not using pcap\n");
            struct tpacket_req req = {
                .tp_block_size = BLOCK_SIZE,
                .tp_frame_size = FRAME_SIZE,
                .tp_block_nr = BLOCK_NR,
            };

            req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

            if (setsockopt(radio_fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0)
            {
                perror("PACKET_RX_RING");
                cleanup();
            }

            ring_size = req.tp_block_size * req.tp_block_nr;
            frame_nr = req.tp_frame_nr;

            ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, radio_fd, 0);

            if (ring == MAP_FAILED)
            {
                perror("mmap");
                cleanup();
            }
        }
    }
}

static uint64_t send_radio_data(struct wpr_data *pkt_data, size_t pkt_len)
{
    if (pkt_len == 0)
    {
        return 0;
    }

    // TODO: Maybe implement FEC stuff here?

    // Advance mac data header transmit sequence number
    mac_hdr_tx.seq = htole16(hdr_seq_tx++ << 4);

    uint8_t *frameDataTX = (uint8_t *)malloc(sizeof(rtap_tx));
    if (!frameDataTX)
    {
        fprintf(stderr, "send_radio_data: malloc frame failed\n");
        return (uint64_t)-1;
    }

    rtap_tx.mh = mac_hdr_tx;
    memcpy(&rtap_tx.wpr, pkt_data, sizeof(rtap_tx.wpr));

    size_t len = 0;
    memcpy(frameDataTX, &rtap_tx, sizeof(rtap_tx));
    len += sizeof(rtap_tx);

    struct iovec iov;
    iov.iov_base = (void *)frameDataTX;
    iov.iov_len = len;

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    if (radio_fd < 0)
    {
        printf(stderr, "send_radio_data: radio_fd not open, aborting send\n");
        free(frameDataTX);
        return (uint64_t)-1;
    }

    if (debugRadioData)
    {
        static int dbg_cnt = 0;
        if ((dbg_cnt++ & 0x3F) == 0)
        {
            fprintf(stderr, "send_radio_data: payload_len=%lu data:", len);
            for (size_t i = 0; i < len; ++i)
                fprintf(stderr, " %02x", frameDataTX[i]);
            fprintf(stderr, "\n");
        }
    }

    // ssize_t sret = sendto(radio_fd, frameDataTX, len, 0, (struct sockaddr *)&sll, sizeof(sll));
    ssize_t sret = sendmsg(radio_fd, &msg, 0);
    // ssize_t sret = write(radio_fd, frameDataTX, len);
    if (sret < 0)
    {
        fprintf(stderr, "send_radio_data: sendto returned %zd, aborting send\n", sret);
    }

    free(frameDataTX);
    return sret;
}

static void decode_codec2_voice_data(const uint8_t *voice, size_t voice_len)
{
    if (codec2 == NULL)
    {
        fprintf(stderr, "Codec2 invalid!\n");
        return;
    }

    ssize_t nsamples = codec2_samples_per_frame(codec2); // For CODEC2_MODE_3200, it is 160 samples.
    size_t pcm_bytes = (size_t)nsamples * sizeof(int16_t);

    if (voice_len == 0)
        return;

    // Prepare the PCM buffer...
    int16_t pcm_arr[nsamples];
    int16_t *pcm = pcm_arr;

    codec2_decode(codec2, pcm, voice);

    if (audio_out_fd > 0)
    {
        ssize_t w = write(audio_out_fd, pcm, pcm_bytes);
        if (w < 0)
            perror("write audio");
        else if ((size_t)w != pcm_bytes)
            fprintf(stderr, "Short audio write (%zd/%zu)\n", w, pcm_bytes);
    }
}

static void process_wpr_data_rx()
{
    uint8_t data_type = wpr_data_rx.data_type;

    // TODO: Implement FEC stuff

    switch (data_type)
    {
    case RADIO_DATA_NOOP:
        return;
        break;
    case RADIO_DATA_AUDIO:
        goto process_wpr_audio;
        break;
    case RADIO_DATA_MESH:
        printf("RADIO_DATA_MESH message not implemented yet.\n");
        return;
        break;
    default:
        return;
        break;
    }

process_wpr_audio:
    uint8_t channel = wpr_data_rx.data[0];
    uint8_t pttMode = wpr_data_rx.data[1];

    if (channel > 3)
    {
        printf("Unknown channel ID: %u", channel);
        return;
    }

    if (channel == AUDIO_CHANNEL_ID)
    {
        struct audio_channel_state *ch = &channels[channel];
        size_t audio_len = (size_t)codec2_bytes_per_frame(codec2);

        if (pttMode)
        {
            if (audio_len > (sizeof(wpr_data_rx.data) - 2))
            {
                printf("Audio data missing!\n");
                return;
            }

            if (!ch->active)
            {
                printf("Channel %u: PTT start\n", channel);
                ch->active = 1;
            }
            ch->last_rx_ns = now_ns();

            uint8_t *audio_ptr = (uint8_t *)malloc(audio_len);
            memcpy(audio_ptr, wpr_data_rx.data + 2, audio_len);
            decode_codec2_voice_data(audio_ptr, audio_len);
            free(audio_ptr);
        }
        else
        {
            if (ch->active)
            {
                printf("Channel %u: PTT end\n", channel);
                ch->active = 0;
            }
        }
    }
    else
    {
        printf("Ignoring channel ID: %u", channel);
        return;
    }
}

static void parse_radio_message(const uint8_t *pkt, size_t len, const struct pcap_pkthdr *pcaphdr)
{
    // TODO: Implement FCS data framing
    //  Start to decode the ieee80211_radiotap_header data
    struct ieee80211_radiotap_header *rt_hdr = (struct ieee80211_radiotap_header *)pkt;

    if (len < sizeof(*rt_hdr))
    {
        return;
    }

    uint16_t rt_hdr_len = le16toh(rt_hdr->it_len);
    if (rt_hdr_len > len)
    {
        return;
    }

    const uint8_t *mac_ptr = pkt + rt_hdr_len;
    size_t mac_len = len - rt_hdr_len;

    if (debugRadioData)
    {
        printf("Total packet len: %zu, Radiotap len: %u, MAC + data len: %zu\n", len, rt_hdr_len, mac_len);
        for (size_t i = 0; i < len; i++)
        {
            printf("%02x ", pkt[i]);
        }
        printf("\n");
    }

    // Not a radiotap message
    struct ieee80211_radiotap_iterator it;
    if (ieee80211_radiotap_iterator_init(&it, rt_hdr, rt_hdr_len, NULL) < 0)
    {
        // printf("ieee80211_radiotap_iterator_init(&it, rt_hdr, rt_hdr_len, NULL) < 0\n");
        // //print the data
        // fprintf(stderr, "TX: send_test_tone payload_len=%u data:", len);
        // for (size_t i = 0; i < (size_t)len; ++i)
        //     fprintf(stderr, " %02x", pkt[i]);
        // fprintf(stderr, "\n");
        return;
    }

    while (ieee80211_radiotap_iterator_next(&it) == 0)
    {
        if (!running)
            break;

        if (it.this_arg_index == IEEE80211_RADIOTAP_VENDOR_NAMESPACE)
        {
            if (debugRadioData)
            {
                printf("Vendor NS (%.2x-%.2x-%.2x:%d, %d bytes)\n",
                       it.this_arg[0], it.this_arg[1], it.this_arg[2], it.this_arg[3],
                       it.this_arg_size - 6);
                for (int i = 6; i < it.this_arg_size; i++)
                {
                    if (i % 8 == 6)
                        printf("\t\t");
                    else
                        printf(" ");
                    printf("%.2x", it.this_arg[i]);
                }
                printf("\n");
            }
        }
        else if (it.is_radiotap_ns)
        {
            switch (it.this_arg_index)
            {
            case IEEE80211_RADIOTAP_TSFT:
                if (debugRadioData)
                    printf("RT TSFT: %llu\n", (unsigned long long)le64toh(*(unsigned long long *)it.this_arg));
                break;
            case IEEE80211_RADIOTAP_FLAGS:
                if (debugRadioData)
                {
                    uint8_t f = *it.this_arg;
                    printf("RT flags: 0x%02x", f);
                    if (f & IEEE80211_RADIOTAP_F_CFP)
                        printf(" [CFP]");
                    if (f & IEEE80211_RADIOTAP_F_SHORTPRE)
                        printf(" [Short Preamble]");
                    if (f & IEEE80211_RADIOTAP_F_WEP)
                        printf(" [WEP]");
                    if (f & IEEE80211_RADIOTAP_F_FRAG)
                        printf(" [Fragment]");
                    if (f & IEEE80211_RADIOTAP_F_FCS)
                        printf(" [FCS included]");
                    if (f & IEEE80211_RADIOTAP_F_DATAPAD)
                        printf(" [Data pad]");
                    if (f & IEEE80211_RADIOTAP_F_BADFCS)
                        printf(" [Bad FCS]");
                    printf("\n");
                }
                break;
            case IEEE80211_RADIOTAP_RATE:
                if (debugRadioData)
                    printf("legacy datarate: %.1f Mbps\n", (*it.this_arg) * 0.5);
                break;
            case IEEE80211_RADIOTAP_CHANNEL:
                if (debugRadioData)
                {
                    uint16_t freq = le16toh(*(uint16_t *)it.this_arg);
                    uint16_t flags = le16toh(*(uint16_t *)(it.this_arg + 2));
                    printf("channel freq: %u MHz (flags: 0x%.4x)\n", freq, flags);
                }
                break;
            case IEEE80211_RADIOTAP_MCS:
                if (debugRadioData)
                {
                    uint8_t known = it.this_arg[0];
                    uint8_t flags = it.this_arg[1];
                    uint8_t mcs = it.this_arg[2];
                    printf("mcs_index=%u", mcs);
                    if (known & IEEE80211_RADIOTAP_MCS_HAVE_BW)
                    {
                        printf(", bw=%s", (flags & IEEE80211_RADIOTAP_MCS_BW_MASK) == IEEE80211_RADIOTAP_MCS_BW_20 ? "20MHz" : (flags & IEEE80211_RADIOTAP_MCS_BW_MASK) == IEEE80211_RADIOTAP_MCS_BW_40 ? "40MHz"
                                                                                                                           : (flags & IEEE80211_RADIOTAP_MCS_BW_MASK) == IEEE80211_RADIOTAP_MCS_BW_20L  ? "20MHz Lower"
                                                                                                                                                                                                        : "20MHz Upper");
                    }
                    printf("\n");
                }
                break;
            case IEEE80211_RADIOTAP_AMPDU_STATUS:
                if (debugRadioData)
                {
                    uint16_t reference = le16toh(*(uint16_t *)it.this_arg);
                    uint16_t flags = le16toh(*(uint16_t *)(it.this_arg + 2));
                    printf("A-MPDU: reference=%u, flags=0x%x\n", reference, flags);
                }
                break;
            case IEEE80211_RADIOTAP_TX_FLAGS:
                if (debugRadioData)
                {
                    uint16_t f = le16toh(*(uint16_t *)it.this_arg);
                    printf("TX flags: 0x%.4x\n", f);
                }
                break;
            case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
            case IEEE80211_RADIOTAP_DBM_ANTNOISE:
            case IEEE80211_RADIOTAP_ANTENNA:
            case IEEE80211_RADIOTAP_RX_FLAGS:
            default:
                break;
            }
        }
    }

    if (debugRadioData)
        printf("\n");

    // Start to decode the ieee80211_mac_hdr data
    if (mac_len <= 24)
    {
        // printf("MAC data header too small to process\n");
        return;
    }

    struct ieee80211_mac_hdr *mac_hdr = (struct ieee80211_mac_hdr *)mac_ptr;
    uint16_t fc = le16toh(mac_hdr->fc);
    uint8_t type = FC_TYPE(fc);
    uint8_t subtype = FC_SUBTYPE(fc);

    if (debugRadioData)
    {
        printf("MAC Header:\n");
        printf(" Frame Type: %u Subtype: %u\n", type, subtype);
        printf(" Addr1: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_hdr->addr1[0], mac_hdr->addr1[1], mac_hdr->addr1[2], mac_hdr->addr1[3], mac_hdr->addr1[4], mac_hdr->addr1[5]);
        printf(" Addr2: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_hdr->addr2[0], mac_hdr->addr2[1], mac_hdr->addr2[2], mac_hdr->addr2[3], mac_hdr->addr2[4], mac_hdr->addr2[5]);
        printf(" Addr3: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_hdr->addr3[0], mac_hdr->addr3[1], mac_hdr->addr3[2], mac_hdr->addr3[3], mac_hdr->addr3[4], mac_hdr->addr3[5]);
        printf(" Seq Ctrl: 0x%.4x\n", le16toh(mac_hdr->seq));
        printf("\n");
    }

    // Check if it is a broadcast message on addr1 on the mac_hdr level.
    if (memcmp(mac_hdr->addr1, macBroadcast, 6) != 0)
    {
        // printf("Not broadcast address...\n");
        return;
    }

    // Check if is "our" own packet, abort processing, otherwise continue.
    if (memcmp(mac_hdr->addr3, hwMAC, 6) == 0)
    {
        // printf("Own frame detected, aborting...\n");
        return;
    }

    size_t hdr_len = 24;
    if (FC_TO_DS(fc) && FC_FROM_DS(fc))
        hdr_len = 30;
    if (type == 2 && (subtype & 0x08))
        hdr_len += 2;
    // if (fc & IEEE80211_FCTL_ORDER) {
    //     if (mac_len >= hdr_len + 4) hdr_len += 4;
    // }

    // TODO -> split this to a seperate function.
    if (mac_len <= hdr_len)
    {
        // printf("mac_len <= hdr_len\n");
        return;
    }

    const uint8_t *body_start = mac_ptr + hdr_len;
    size_t body_len = (mac_len - hdr_len);

    if (body_len < sizeof(struct wpr_data))
    {
        // printf("body_len < sizeof(struct wpr_data)\n");
        return;
    }

    /* Check first 4 bytes */
    uint32_t magic;
    memcpy(&magic, body_start, sizeof(uint32_t));

    if (debugRadioData)
    {
        printf("magic value: %u\n", magic);
        printf("body_len: %lu\n", body_len);
        printf("Body (%zu bytes):\n", body_len);

        for (size_t i = 0; i < body_len; i++)
        {
            printf("%02x ", body_start[i]);

            if ((i + 1) % 16 == 0)
                printf("\n");
        }

        if (body_len % 16 != 0)
            printf("\n");
    }

    if (magic != DATA_HDR_MAGIC)
    {
        printf("magic value: %u", magic);
        printf("magic != DATA_HDR_MAGIC\n");
        return;
    }

    // if (body_len >= sizeof(struct wpr_data))
    // {
    //      if (debugRadioData)
    //      {
    //      printf("WARN: body_len >= sizeof(struct wpr_data)\n");
    //      }
    // }

    memcpy(&wpr_data_rx, body_start, sizeof(struct wpr_data));
    process_wpr_data_rx();
}

static void gen_tone(int16_t *pcm, int n)
{
    double step = 2.0 * M_PI * TONE_FREQ / TONE_SAMPLE_RATE;

    for (int i = 0; i < n; i++)
    {
        pcm[i] = (int16_t)(sin(phase) * TONE_AMPLITUDE);
        phase += step;
        if (phase >= 2.0 * M_PI)
            phase -= 2.0 * M_PI;
    }
}

static int send_wav(const char *filename)
{
    if (debug)
    {
        printf("Sending WAV file...\n");
    }

    if (codec2 == NULL)
    {
        fprintf(stderr, "Codec2 not initialized (send_wav)\n");
        return -1;
    }

    // Prepare the wpr_data_tx struct
    wpr_data_tx.data_type = RADIO_DATA_AUDIO;
    wpr_data_tx.data[1] = 1; // PTT is ON

    wavFile = fopen(filename, "rb");
    if (!wavFile)
    {
        perror("Cannot open WAV file");
        return -1;
    }

    // Skip standard 44-byte WAV header (very simple – assumes canonical format)
    uint8_t header[44];
    if (fread(header, 1, 44, wavFile) != 44)
    {
        fprintf(stderr, "WAV file too short\n");
        return -1;
    }

    // Very basic sanity check
    if (strncmp((char *)header, "RIFF", 4) != 0 || strncmp((char *)(header + 8), "WAVE", 4) != 0)
    {
        fprintf(stderr, "Not a valid WAV file\n");
        return -1;
    }

    printf("Transmitting WAV file: %s  (mono 8kHz 16-bit PCM)\n", filename);
    int codec2_encoded_bytecount = codec2_bytes_per_frame(codec2);   // 160 samples for MODE_2400, 160 samples for MODE_3200
    int codec2_decoded_bytecount = codec2_samples_per_frame(codec2); // 6 bytes for MODE_2400, 8 bytes for MODE_3200

    int16_t pcm_in[codec2_decoded_bytecount];
    uint8_t codec2_out[codec2_encoded_bytecount];

    int total_frames = 0;

    while (running)
    {
        size_t read_samples = fread(pcm_in, sizeof(int16_t), codec2_decoded_bytecount, wavFile);
        if (read_samples == 0)
            break; // EOF

        // Pad with silence if partial last frame
        if (read_samples < (size_t)codec2_decoded_bytecount)
        {
            memset(pcm_in + read_samples, 0, (codec2_decoded_bytecount - read_samples) * sizeof(int16_t));
        }

        codec2_encode(codec2, codec2_out, pcm_in);

        memcpy(wpr_data_tx.data + 2, codec2_out, (size_t)codec2_encoded_bytecount);

        if ((int64_t)send_radio_data(&wpr_data_tx, sizeof(wpr_data_tx)) < 0)
        {
            fprintf(stderr, "send_wav: radio send failed, stopping transmitter loop\n");
            cleanup();
            break;
        }

        total_frames++;
        usleep(20000);

        if (!running)
        {
            printf("Interrupted, stopping WAV transmission...\n");
            break;
        }
    }

    printf("Finished transmitting WAV (%d frames sent)\n", total_frames);
    return 0;
}

static void send_test_tone(void)
{
    if (debug)
    {
        printf("Sending test tone...\n");
    }

    if (codec2 == NULL)
    {
        fprintf(stderr, "Codec2 not initialized (send_wav)\n");
        cleanup();
    }

    // Prepare the wpr_data_tx struct
    wpr_data_tx.data_type = RADIO_DATA_AUDIO;
    wpr_data_tx.data[1] = 1; // PTT is ON

    // Generate PCM tone
    gen_tone(pcmToneBuffer, TEST_TONE_INTERVAL);

    int codec2_encoded_bytecount = codec2_bytes_per_frame(codec2);   // 160 samples for MODE_2400, 160 samples for MODE_3200
    int codec2_decoded_bytecount = codec2_samples_per_frame(codec2); // 6 bytes for MODE_2400, 8 bytes for MODE_3200

    int16_t pcm_in[codec2_decoded_bytecount];
    uint8_t codec2_out[codec2_encoded_bytecount];

    int toneIdx = 0;

    while (toneIdx < TEST_TONE_INTERVAL && running)
    {
        // Copy exactly samples_per_frame samples into pcm, wrapping around the circular tone buffer.
        for (int i = 0; i < codec2_decoded_bytecount; ++i)
        {
            pcm_in[i] = pcmToneBuffer[(toneIdx + i) % TEST_TONE_INTERVAL];
        }

        // Advance read index and wrap
        toneIdx = (toneIdx + codec2_decoded_bytecount) % TEST_TONE_INTERVAL;

        // Copy 160 bytes of PCM data, and encode to codec bits (6 or 8 bytes depending on mode) to send it.
        codec2_encode(codec2, codec2_out, pcm_in);

        /* copy exactly codec_bytes into payload */
        memcpy(wpr_data_tx.data + 2, codec2_out, (size_t)codec2_encoded_bytecount);

        if (debugRadioData)
        {
            static int dbg_cnt = 0;
            if ((dbg_cnt++ & 0x3F) == 0)
            {
                fprintf(stderr, "TX: send_test_tone payload_len=%u data:", codec2_encoded_bytecount);
                for (size_t i = 0; i < (size_t)codec2_encoded_bytecount; ++i)
                    fprintf(stderr, " %02x", codec2_out[i]);
                fprintf(stderr, "\n");
            }
        }

        if ((int64_t)send_radio_data(&wpr_data_tx, sizeof(wpr_data_tx)) < 0)
        {
            fprintf(stderr, "send_test_tone: radio send failed, stopping transmitter loop\n");
            cleanup();
            break;
        }

        // usleep 20ms here
        usleep(20000);

        if (!running)
        {
            printf("Interrupted, stopping test tone transmission...\n");
            break;
        }
    }
}

static int setup_audio_socket(void)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        perror("socket");
        cleanup();
    }

    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(3443),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        cleanup();
    }

    if (listen(s, 1) < 0)
    {
        perror("listen");
        cleanup();
    }

    return s;
}

static void detect_phy(const char *phy)
{
    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s", phy);

    if (access(path, F_OK) != 0)
    {
        printf("Error - PHY: %s interface not found", phy);
    }
}

static void printParameters(void)
{
    printf("Parameters: <programName> <rx/tx> <audiofilename-to-tx>\n");
}

static void do_main_loop(int argc, char *argv[])
{
    char *wav;

    if (argc == 0)
    {
        printf("No parameters specified. Aborting!\n");
        printParameters();
        cleanup();
    }

    if (argc >= 2)
    {
        if (argc == 2)
        {
            printf("argc == 2\n");

            if (strcmp(argv[1], "tx") == 0)
            {
                isRadioTransmitting = true;
            }
            else if (strcmp(argv[1], "rx") == 0)
            {
                isRadioReceiving = true;
            }
            else
            {
                printf("Unknown parameter, aborting.");
                cleanup();
            }
        }

        if (argc == 3)
        {

            printf("argc == 3\n");

            if (strcmp(argv[1], "rx") == 0)
            {
                printf("One cannot receive while transmitting audio, just yet.\n");
                cleanup();
            }
            else if (strcmp(argv[1], "tx") == 0)
            {
                isRadioTransmitting = true;
            }
            else
            {
                printf("Unknown parameter, aborting.\n");
                cleanup();
            }

            wav = argv[2];
        }
    }

    if (isRadioTransmitting && isRadioReceiving)
    {
        printf("One cannot transmit and receive just yet!");
        cleanup();
    }

    setup_radio();
    setup_codec2();

    if (isRadioTransmitting)
    {
        printf("Radio transmitting enabled.\n");
    }

    if (isRadioReceiving)
    {
        printf("Radio receiving enabled.\n");
        // //Setup audio ringbuffer
        // if (ringbuffer_init(&audioBuf, 1024, "audioBuff") != 0) {
        //     fprintf(stderr, "audiobuff init failed\n");
        //     cleanup();
        // }

        tcp_listen = setup_audio_socket();

        while (audio_out_fd <= 0 && running)
        {
            printf("Waiting for audio client to connect on port 3443...\n");
            audio_out_fd = accept(tcp_listen, NULL, NULL);
            if (audio_out_fd <= 0)
            {
                perror("accept");
                sleep(1);
                cleanup();
            }
        }

        if (audio_out_fd > 0 && running)
        {
            printf("Audio client connected...\n");
        }
    }

    unsigned int frame = 0;

    if (codec2 == NULL)
    {
        fprintf(stderr, "Codec2 not initialized (do_main_loop)\n");
        cleanup();
    }

    while (running)
    {
        if (isRadioTransmitting)
        {
            printf("Stage 2\n");
            if (wav != NULL)
            {
                printf("Stage 3\n");
                if (wav[0] != '\0')
                {
                    printf("Stage WAV\n");
                    send_wav(wav);
                    sleep(2);
                }
                else
                {
                    printf("Stage 4\n");
                    send_test_tone();
                }
            }
            else
            {
                printf("Stage Tone\n");
                send_test_tone();
            }
        }

        if (isRadioReceiving)
        {
            struct pcap_pkthdr hdr;
            const uint8_t *pkt;

            // Drain all available packets
            while ((pkt = pcap_next(pcap_handle, &hdr)) != NULL)
            {
                parse_radio_message(pkt, hdr.caplen, &hdr);
                codec2_timeout_check();
            }

            // else
            // {
            //     // Drain ring buffer aggressively to prevent overflow
            //     unsigned int processed = 0;
            //     unsigned int max_drain = 64; // Process up to 64 frames per iteration

            //     while (processed < max_drain)
            //     {
            //         struct tpacket_hdr *hdr = (struct tpacket_hdr *)((uint8_t *)ring + frame * FRAME_SIZE);

            //         if (!(hdr->tp_status & TP_STATUS_USER))
            //             break; // No more frames in buffer

            //         uint8_t *pkt = (uint8_t *)hdr + hdr->tp_mac;
            //         size_t pktlen = hdr->tp_snaplen;
            //         parse_radio_message(pkt, pktlen, (struct pcap_pkthdr *)hdr);
            //         codec2_timeout_check();

            //         hdr->tp_status = TP_STATUS_KERNEL;
            //         frame = (frame + 1) % frame_nr;
            //         processed++;
            //     }
            // }
        }

        usleep(10); // Allow other processes CPU time
    }
}

int main(int argc, char *argv[])
{
    printf("------------------------------------------\n");
    printf("-- WiFiPacketRadio -- DEV -- RuhanSA079 --\n");
    printf("------------------------------------------\n");

    root_check();
    detect_phy(RADIO_IFACE);

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, sigint);
    signal(SIGTERM, sigint);

    if (setpriority(PRIO_PROCESS, 0, -20) == -1)
    {
        perror("setpriority failed (are you root?)");
    }

    if (argc == 1)
    {
        do_main_loop(0, argv);
    }
    else
    {
        do_main_loop(argc, argv);
    }

    cleanup();
    return 0;
}