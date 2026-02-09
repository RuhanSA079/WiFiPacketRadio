#if defined(__x86_64__) || defined(_M_X64)
#define _GNU_SOURCE
#endif

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
#include "codec2/src/codec2.h"

/* ---------------- some constants ---------------- */
#if defined(__x86_64__) || defined(_M_X64)
#define RADIO_PHY "phy1" // TODO: Find this by looking for the phy that is not associated with the normal wifi interface (e.g. wlan0)
#else
#define RADIO_PHY "phy0" // TODO: Find this by looking for the phy that is not associated with the normal wifi interface (e.g. wlan0)
#endif

#define RADIO_IFACE "mon0"
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

struct radiotap_hdr
{
    struct ieee80211_radiotap_header rt; // 8 bytes (offset 0-7)
    uint8_t rate;                        // 1 byte (offset 8)
    uint8_t pad1;                        // 1 byte (offset 9) - align tx_flags to 2-byte boundary
    uint16_t tx_flags;                   // 2 bytes (offset 10-11) - IEEE80211_RADIOTAP_TX_FLAGS
    uint32_t pad2;                       // 4 bytes (offset 12-15) - align mcs fields to 4-byte boundary from start of rt
    uint8_t mcs_known;                   // 1 byte (offset 16) - which of the next fields are valid
    uint8_t mcs_flags;                   // 1 byte (offset 17) - BW, GI, FEC, STBC, ...
    uint8_t mcs_index;                   // 1 byte (offset 18) - MCS 0..76
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
unsigned char macBroadcast[6]; // Broadcast MAC address for filtering incoming packets (must be set to ff:ff:ff:ff:ff:ff).
int radio_fd, pcap_fd, audio_in_fd, audio_out_fd = 0;

bool debug = true;
bool debugRadioData = false;
volatile sig_atomic_t running = 1;
bool isRadioReceiving = false;
bool isRadioTransmitting = true;
bool usePcapForRx = false;

static int tcp_listen = 0;
static double phase = 0.0;
uint16_t tx_seq = 0;
uint64_t last_tx_test_tone = 0;
struct sockaddr_ll sll;
static FILE *wavFile = NULL;

pcap_t *pcap_handle = NULL;
uint16_t hdr_seq_tx = 0;
struct radiotap_hdr rtap_tx;
struct ieee80211_mac_hdr mac_hdr_tx;
static struct audio_channel_state channels[4];


#define PCM_BYTE_COUNT 160 /* 20 ms of audio at 8 kHz */
#define PCM_100MS_BYTE_COUNT (PCM_BYTE_COUNT * 5) // enough for 100 ms of audio, 160 bytes per 20 ms frame * 5 = 800 bytes
#define TEST_TONE_INTERVAL (PCM_100MS_BYTE_COUNT * 10) // 

int16_t pcmToneBuffer[TEST_TONE_INTERVAL]; //about 1 second of tone at 8 kHz, 160 samples per 20 ms frame, so 160 * 5 = 800 bytes per 100 ms, so 800 * 10 = 8000 bytes for 1 second

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

    if (codec2)
    {
        codec2_destroy(codec2);
        codec2 = NULL;
    }
}

static void sigint(int sig)
{
    (void)sig;
    running = 0;
    cleanup();
}

static void run_cmd(const char *cmd)
{
    int ret = system(cmd);
    if (ret != 0)
    {
        fprintf(stderr, "Command failed: %s\n", cmd);
        cleanup();
        exit(1);
    }
}

static void setup_radio_monitor(void)
{
    if (debug)
        printf("Setting up radio...\n");

    // Bring down monitor interface
    run_cmd("ip link set " RADIO_IFACE " down 2>/dev/null || true");
    run_cmd("iw dev " RADIO_IFACE " del 2>/dev/null || true");

    // Add and bringup monitor interface.
    run_cmd("iw phy " RADIO_PHY " interface add " RADIO_IFACE " type monitor");
    run_cmd("ip link set " RADIO_IFACE " up");
}

static void setup_mac_radiotap(void)
{
    memset(&rtap_tx, 0, sizeof(rtap_tx));

    rtap_tx.rt.it_version = 0;
    rtap_tx.rt.it_present = htole32(
        (1u << IEEE80211_RADIOTAP_RATE) |
        (1u << IEEE80211_RADIOTAP_TX_FLAGS) |
        (1u << IEEE80211_RADIOTAP_MCS));

    rtap_tx.rate = 12; /* 6 Mbps! */

    rtap_tx.tx_flags = htole16(IEEE80211_RADIOTAP_F_TX_NOACK);

    rtap_tx.mcs_known = IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW;

    rtap_tx.mcs_flags = IEEE80211_RADIOTAP_MCS_BW_20;
    rtap_tx.mcs_index = 1;

    rtap_tx.rt.it_len = htole16(sizeof(rtap_tx));

    // Setup MAC headers
    mac_hdr_tx.fc = htole16(0x0008);   /* data frame */
    memset(mac_hdr_tx.addr1, 0xff, 6); /* broadcast */
    memset(macBroadcast, 0xff, 6);

    memset(mac_hdr_tx.addr2, 0x00, 6);
    memset(mac_hdr_tx.addr3, 0x00, 6);

    // Set the "special flags" in addr2.
    mac_hdr_tx.addr2[0] = 0x57;
    mac_hdr_tx.addr2[1] = 0x42;
    mac_hdr_tx.addr2[5] = 0x01;
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
    codec2 = codec2_create(CODEC2_MODE_3200);
    if (!codec2)
    {
        fprintf(stderr, "Failed to create Codec2 instance\n");
        exit(1);
    }
}

static void setup_radio(void)
{
    setup_radio_monitor();
    setup_mac_radiotap();

    if (debug)
        printf("Opening radio socket...\n");

    radio_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (radio_fd < 0)
    {
        perror("socket");
        cleanup();
        exit(1);
    }

    // int f = fcntl(radio_fd, F_GETFL, 0);
    // if (f >= 0)
    // {
    //     fcntl(radio_fd, F_SETFL, f | O_NONBLOCK);
    // }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, RADIO_IFACE, IF_NAMESIZE - 1);

    if (ioctl(radio_fd, SIOCGIFINDEX, &ifr) < 0)
    {
        perror("SIOCGIFINDEX");
        cleanup();
        exit(1);
    }

    // Save if_index and get mac address
    int ifindex = ifr.ifr_ifindex;

    /* Get hardware (MAC) address */
    if (ioctl(radio_fd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("SIOCGIFHWADDR");
        cleanup();
        exit(1);
    }

    hwMAC = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    if (debug)
        printf("Radio MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n", hwMAC[0], hwMAC[1], hwMAC[2], hwMAC[3], hwMAC[4], hwMAC[5]);

    // set the radio's MAC address in addr3
    memcpy(mac_hdr_tx.addr3, hwMAC, sizeof(mac_hdr_tx.addr3));

    struct sockaddr_ll sll_radio = {
        .sll_family = AF_PACKET,
        .sll_ifindex = ifindex,
        .sll_protocol = htons(ETH_P_ALL),
    };
    sll = sll_radio;

    if (isRadioReceiving)
    {
        if (usePcapForRx)
        {
            if (debug)
                printf("[RADIO-DECODE] Setting up pcap...\n");

            char errbuf[PCAP_ERRBUF_SIZE];

            pcap_handle = pcap_create(RADIO_IFACE, errbuf);
            if (!pcap_handle)
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
            struct tpacket_req req = {
                .tp_block_size = BLOCK_SIZE,
                .tp_frame_size = FRAME_SIZE,
                .tp_block_nr = BLOCK_NR,
            };

            req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

            if (setsockopt(radio_fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0)
            {
                perror("PACKET_RX_RING");
                exit(1);
            }

            ring_size = req.tp_block_size * req.tp_block_nr;
            frame_nr = req.tp_frame_nr;

            ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, radio_fd, 0);

            if (ring == MAP_FAILED)
            {
                perror("mmap");
                exit(1);
            }
        }
    }
}

static uint64_t send_radio_data(const uint8_t *pkt_data, size_t pkt_len)
{

    if (pkt_len <= 0)
    {
        return 0;
    }

    uint8_t payload[pkt_len];

    size_t poff = 0;
    memcpy(payload + poff, pkt_data, pkt_len);
    poff += pkt_len;

    // Advance hdr sequence
    mac_hdr_tx.seq = htole16(hdr_seq_tx++ << 4);

    // Calculate exactly how big the frame must be.
    int frameSize = (sizeof(rtap_tx) + sizeof(mac_hdr_tx) + poff);
    uint8_t frame[frameSize];
    size_t len = 0;

    memcpy(frame + len, &rtap_tx, sizeof(rtap_tx));
    len += sizeof(rtap_tx);
    memcpy(frame + len, &mac_hdr_tx, sizeof(mac_hdr_tx));
    len += sizeof(mac_hdr_tx);
    memcpy(frame + len, payload, poff);
    len += poff;

    // static unsigned long tx_dbg_cnt = 0;
    // if ((tx_dbg_cnt++ & 0x3F) == 0) {
    //     fprintf(stderr, "TX frame_len=%zu payload_len=%zu body_first_bytes:", len, poff);
    //     size_t body_offset = sizeof(rtap_tx) + sizeof(mac_hdr_tx);
    //     size_t dump_n = poff < 12 ? poff : 12;
    //     for (size_t i = 0; i < dump_n; ++i) {
    //         fprintf(stderr, " %02x", frame[body_offset + i]);
    //     }
    //     fprintf(stderr, "\n");
    // }

    if (radio_fd < 0)
    {
        if (debug)
            fprintf(stderr, "send_radio_data: radio_fd not open, aborting send\n");
        return (uint64_t)-1;
    }

    ssize_t sret = sendto(radio_fd, frame, len, 0, (struct sockaddr *)&sll, sizeof(sll));
    if (sret < 0)
    {
        if (debug)
        {
            fprintf(stderr, "send_radio_data: sendto returned %zd, aborting send\n", sret);
        }
        return (uint64_t)-1;
    }

    return 0;
}

// TODO: Add "buffering" to handle latency jitter, e.g. store several frames and write them out at a steady rate.
static void decode_codec2_voice_data(const uint8_t *voice, size_t voice_len)
{
    if (!codec2)
    {
        fprintf(stderr, "Codec2 invalid!\n");
        return;
    }

    ssize_t expected = codec2_bytes_per_frame(codec2);   /* e.g. 6 or 8 */
    ssize_t nsamples = codec2_samples_per_frame(codec2); /* e.g. 160 */
    size_t pcm_bytes = (size_t)nsamples * sizeof(int16_t);

    /* Quick sanity: no payload */
    if (voice_len == 0)
        return;

    /* If payload exactly matches codec2 compressed size -> decode */
    if ((ssize_t)voice_len == expected)
    {
        int16_t pcm[nsamples];
        codec2_decode(codec2, pcm, voice);
        ssize_t w = write(audio_out_fd, pcm, pcm_bytes);
        (void)w;

        return;
    }

    /* If payload is larger than expected codec bytes but not full PCM:
       attempt to decode first `expected` bytes and log the rest for diagnosis. */
    if ((ssize_t)voice_len >= expected)
    {
        if (voice_len != (size_t)expected)
        {
            /* Log first bytes to help identify format (only first 16 bytes to avoid huge prints) */
            int dump_n = (voice_len < 16 ? (int)voice_len : 16);

            fprintf(stderr, "decode: payload len=%zu (expected %zd). first %d bytes:", voice_len, expected, dump_n);
            for (int i = 0; i < dump_n; ++i)
            {
                fprintf(stderr, " %02x", voice[i]);
            }
            fprintf(stderr, "\n");
        }

        /* Try to decode the first 'expected' bytes */
        int16_t pcm[nsamples];
        codec2_decode(codec2, pcm, voice); /* use first expected bytes */

        if (audio_out_fd > 0) {
            ssize_t w = write(audio_out_fd, pcm, nsamples * sizeof(int16_t));
            if (w < 0) {
                perror("write audio");
            } else if ((size_t)w != nsamples * sizeof(int16_t)) {
                printf("Short audio write (%zd/%zu)\n", w, nsamples * sizeof(int16_t));
            }
        }

        return;
    }

    /* If payload is shorter than expected compressed bytes -> log and ignore */
    fprintf(stderr, "decode: frame too small (%zu bytes, expected %zd). Dumping bytes:", voice_len, expected);
    int dump_n = (voice_len < 16 ? (int)voice_len : 16);
    for (int i = 0; i < dump_n; ++i)
    {
        fprintf(stderr, " %02x", voice[i]);
    }

    fprintf(stderr, "\n");
}

static void parse_radiotap_header(const uint8_t *pkt, size_t len, const struct pcap_pkthdr *pcaphdr)
{
    struct ieee80211_radiotap_header *rt_hdr = (struct ieee80211_radiotap_header *)pkt;

    bool rt_packet_self_injected = false;

    if (len < sizeof(*rt_hdr))
        return;

    uint16_t rt_hdr_len = le16toh(rt_hdr->it_len);
    if (rt_hdr_len > len)
        return;

    const uint8_t *mac_ptr = pkt + rt_hdr_len;
    size_t mac_len = len - rt_hdr_len;

    if (debugRadioData)
        printf("Total packet len: %zu, Radiotap len: %u, MAC len: %zu\n", len, rt_hdr_len, mac_len);

    struct ieee80211_radiotap_iterator it;
    if (ieee80211_radiotap_iterator_init(&it, rt_hdr, rt_hdr_len, NULL) < 0)
        return;

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
                rt_packet_self_injected = true;
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

    if (rt_packet_self_injected)
        return;

    if (mac_len <= 24)
        return;

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

    if (memcmp(mac_hdr->addr1, macBroadcast, 6) != 0)
        return;
    if (memcmp(mac_hdr->addr3, hwMAC, 6) == 0)
        return;

    size_t hdr_len = 24;
    if (FC_TO_DS(fc) && FC_FROM_DS(fc))
        hdr_len = 30;
    if (type == 2 && (subtype & 0x08))
        hdr_len += 2;
    // if (fc & IEEE80211_FCTL_ORDER) {
    //     if (mac_len >= hdr_len + 4) hdr_len += 4;
    // }

    if (mac_len <= hdr_len)
        return;
    const uint8_t *body_start = mac_ptr + hdr_len;
    size_t body_len = mac_len - hdr_len;

    // if (debug) fprintf(stderr, "MAC hdr_len=%zu body_len=%zu\n", hdr_len, body_len);
    if (body_len < 4)
        return;

    const uint8_t *found = NULL;
    uint32_t candidate_net;
    for (size_t i = 0; i + 4 <= body_len; ++i)
    {
        memcpy(&candidate_net, body_start + i, 4);
        if (ntohl(candidate_net) == DATA_HDR_MAGIC)
        {
            found = body_start + i;
            // if (debug) fprintf(stderr, "found DATA_HDR_MAGIC at body offset %zu (mac_len=%zu hdr_len=%zu)\n", i, mac_len, hdr_len);
            break;
        }
    }
    if (!found)
    {
        // if (debug) fprintf(stderr, "DATA_HDR_MAGIC not found in MAC body (mac_len=%zu hdr_len=%zu body_len=%zu)\n", mac_len, hdr_len, body_len);
        return;
    }

    const uint8_t *payload = found;
    size_t payload_len = body_len - (size_t)(found - body_start);
    if (payload_len < 6)
    {
        if (debug)
            fprintf(stderr, "payload_len (%zu) < 6, ignoring\n", payload_len);
        return;
    }

    const uint8_t *data_ptr = payload + 4;
    size_t data_len = payload_len - 4;
    uint8_t channel = data_ptr[0];
    uint8_t ptt = data_ptr[1];

    if (channel > 3)
    {
        // if (debug)
        //     fprintf(stderr, "invalid channel %u\n", channel);
        return;
    }

    struct audio_channel_state *ch = &channels[channel];

    const uint8_t *audio_ptr = data_ptr + 2;
    size_t audio_len = data_len >= 2 ? data_len - 2 : 0;

    size_t expected_audio_len = (size_t)codec2_bytes_per_frame(codec2);

    // if (debug) printf("Data packet: channel=%u ptt=%u audio_len=%zu (expected %zu)\n", channel, ptt, audio_len, expected_audio_len);

    if (channel != AUDIO_CHANNEL_ID)
    {
        // if (debug)
        //     printf("Ignoring packet for channel %u\n", channel);
        return;
    }

    if (ptt)
    {
        if (!ch->active)
        {
            printf("Channel %u: PTT start\n", channel);
            ch->active = 1;
        }
        ch->last_rx_ns = now_ns();

        if (audio_len < expected_audio_len)
        {
            // if (debug) fprintf(stderr, "audio_len %zu < expected %zu, dropping\n", audio_len, expected_audio_len);
            return;
        }

        /* decode only expected bytes; ignore any trailing bytes */
        decode_codec2_voice_data(audio_ptr, expected_audio_len);
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
    if (!codec2)
    {
        fprintf(stderr, "Codec2 not initialized\n");
        return -1;
    }

    // Payload size calculate: MAGIC PACKET (4 bytes) + ChannelID (1 byte) + PTT mode (1 byte) + Codec2 compressed data (6 or 8 bytes depending on mode)
    size_t codec_bytes = (size_t)codec2_bytes_per_frame(codec2);
    size_t payloadSize = 6 + codec_bytes; /* 6 bytes: magic(4) + channel(1) + ptt(1) */

    uint8_t payload[payloadSize];
    size_t poff = 0;

    uint32_t magic = htonl(DATA_HDR_MAGIC);
    memcpy(payload + poff, &magic, 4);
    poff += 4;

    payload[poff++] = AUDIO_CHANNEL_ID; // channel_ID
    payload[poff++] = 1;                // PTT mode (1=on, 0=off)

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

    int16_t pcm[codec2_samples_per_frame(codec2)];      // 160 samples for MODE_2400, 160 samples for MODE_3200
    uint8_t codec_bits[codec2_bytes_per_frame(codec2)]; // 6 bytes for MODE_2400, 8 bytes for MODE_3200

    int total_frames = 0;

    while (running)
    {
        size_t read_samples = fread(pcm, sizeof(int16_t), codec2_samples_per_frame(codec2), wavFile);
        if (read_samples == 0)
            break; // EOF

        // Pad with silence if partial last frame
        if (read_samples < (size_t)codec2_samples_per_frame(codec2))
        {
            memset(pcm + read_samples, 0, (codec2_samples_per_frame(codec2) - read_samples) * sizeof(int16_t));
        }

        size_t codec_bytes = (size_t)codec2_bytes_per_frame(codec2);
        codec2_encode(codec2, codec_bits, pcm);
        memcpy(payload + 6, codec_bits, codec_bytes);
        poff = 6 + codec_bytes; // 6 bytes header + codec compressed data (4 for magic, 1 byte for channel and one byte for ptt + 6/8 codec bytes)

        if ((int64_t)send_radio_data(payload, poff) < 0)
        {
            fprintf(stderr, "send_wav: radio send failed, stopping transmitter loop\n");
            break;
        }

        total_frames++;
        usleep(15000); // Since PCM is about 20ms per sample, make it so that we send a bit faster than real-time to account for processing delays and ensure smooth transmission.
                       // The receiver can handle some jitter, but we want to avoid large gaps that could cause timeouts or stuttering.

        if (!running)
        {
            printf("Interrupted, stopping WAV transmission...\n");
            break;
        }
    }

    printf("Finished transmitting WAV (%d frames sent)\n", total_frames);
    return 0;
}

static void sendTestTone(void)
{
    // TODO: Make it more efficient by "hardcoding the payload message" and only updating the codec bits in place, instead of reconstructing the whole payload every time for sending.
    // Put it in send_radio_data()

    /* Construct payload size in bytes (6 header + codec bits) */
    size_t codec_bytes = (size_t)codec2_bytes_per_frame(codec2);
    size_t payloadSize = 6 + codec_bytes; /* 6 bytes: magic(4) + channel(1) + ptt(1) */

    uint8_t payload[payloadSize];
    size_t poff = 0;

    uint32_t magic = htonl(DATA_HDR_MAGIC);
    memcpy(payload + poff, &magic, 4);
    poff += 4;

    payload[poff++] = AUDIO_CHANNEL_ID; /* channel_ID */
    payload[poff++] = 1;                /* PTT mode (1=on, 0=off) */

    // Generate PCM tone
    gen_tone(pcmToneBuffer, TEST_TONE_INTERVAL);

    int samples_per_frame = codec2_samples_per_frame(codec2);
    int16_t pcm[samples_per_frame];
    uint8_t codec_bits[codec_bytes];
    int toneIdx = 0;

    while (toneIdx < TEST_TONE_INTERVAL && running)
    {
        // Copy exactly samples_per_frame samples into pcm, wrapping around the circular tone buffer.
        for (int i = 0; i < samples_per_frame; ++i) {
            pcm[i] = pcmToneBuffer[(toneIdx + i) % TEST_TONE_INTERVAL];
        }

        // Advance read index and wrap
        toneIdx = (toneIdx + samples_per_frame) % TEST_TONE_INTERVAL;

        //Copy 160 bytes of PCM data, and encode to codec bits (6 or 8 bytes depending on mode) to send it.
        codec2_encode(codec2, codec_bits, pcm);

        /* copy exactly codec_bytes into payload */
        memcpy(payload + 6, codec_bits, codec_bytes);
        poff = 6 + codec_bytes;

        static int dbg_cnt = 0;
        if ((dbg_cnt++ & 0x3F) == 0)
        {
            fprintf(stderr, "TX: sendTestTone payload_len=%zu first_bytes:", poff);
            for (size_t i = 0; i < (codec_bytes < 8 ? codec_bytes : 8); ++i)
                fprintf(stderr, " %02x", codec_bits[i]);
            fprintf(stderr, "\n");
        }

        if ((int64_t)send_radio_data(payload, poff) < 0)
        {
            fprintf(stderr, "sendTestTone: radio send failed, stopping transmitter loop\n");
            break;
        }

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
        exit(1);
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

static void do_main_loop(const char *filename)
{
    unsigned int frame = 0;
    char *wav = filename;

    if (!codec2)
    {
        fprintf(stderr, "Codec2 not initialized\n");
        cleanup();
        exit(1);
    }

    while (running)
    {

        if (isRadioTransmitting)
        {
            if (wav && wav[0] != '\0')
            {
                send_wav(wav);
                sleep(2);
            }
            else
            {
                sendTestTone();
            }
        }

        if (isRadioReceiving)
        {

            if (usePcapForRx)
            {
                struct pcap_pkthdr hdr;
                const uint8_t *pkt;

                // Drain all available packets
                while ((pkt = pcap_next(pcap_handle, &hdr)) != NULL)
                {
                    parse_radiotap_header(pkt, hdr.caplen, &hdr);
                    codec2_timeout_check();
                }
            }
            else
            {
                // Drain ring buffer aggressively to prevent overflow
                unsigned int processed = 0;
                unsigned int max_drain = 64; // Process up to 64 frames per iteration

                while (processed < max_drain)
                {
                    struct tpacket_hdr *hdr = (struct tpacket_hdr *)((uint8_t *)ring + frame * FRAME_SIZE);

                    if (!(hdr->tp_status & TP_STATUS_USER))
                        break; // No more frames in buffer

                    uint8_t *pkt = (uint8_t *)hdr + hdr->tp_mac;
                    size_t pktlen = hdr->tp_snaplen;
                    parse_radiotap_header(pkt, pktlen, (struct pcap_pkthdr *)hdr);
                    codec2_timeout_check();

                    hdr->tp_status = TP_STATUS_KERNEL;
                    frame = (frame + 1) % frame_nr;
                    processed++;
                }
            }
        }

        usleep(100); // Allow other processes CPU time
    }
}

int main(int argc, char *argv[])
{
    printf("------------------------------------------\n");
    printf("-- WiFiPacketRadio -- DEV -- RuhanSA079 --\n");
    printf("------------------------------------------\n");

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, sigint);
    signal(SIGTERM, sigint);

    if (setpriority(PRIO_PROCESS, 0, -20) == -1)
    {
        perror("setpriority failed (are you root?)");
    }

    setup_radio();
    setup_codec2();

    if (isRadioReceiving)
        printf("Radio receiving enabled.\n");

    if (isRadioTransmitting)
        printf("Radio transmitting enabled.\n");

    if (isRadioReceiving)
    {
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

    if (argc >= 2)
    {
        do_main_loop(argv[1]);
    }
    else
    {
        do_main_loop("");
    }

    cleanup();
    return 0;
}