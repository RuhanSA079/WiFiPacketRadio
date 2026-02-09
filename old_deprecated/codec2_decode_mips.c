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
#include "codec2/src/codec2.h"
#include "radiotap-library/radiotap.h"
#include "radiotap-library/radiotap_iter.h"

#define PHY_NAME "phy0"
#define MON_IF   "mon0"

#define FRAME_SIZE 2048
#define BLOCK_SIZE (1 << 20)
#define BLOCK_NR   64

#define FC_TYPE(fc)   (((fc) >> 2) & 0x3)
#define FC_SUBTYPE(fc) (((fc) >> 4) & 0xF)
#define FC_TO_DS(fc)  ((fc) & 0x0100)
#define FC_FROM_DS(fc) ((fc) & 0x0200)

#define CODEC_PKT_MAGIC 0xC2C2C2C2
#define CODEC_HDR_LEN 6
#define CODEC_MAX_VOICE 160
#define CODEC_SOCKET_PORTNO 3443
#define CODEC_FRAME_BYTES 6

static void *ring = NULL;
static size_t ring_size;
static unsigned int frame_nr;
static int radio_fd, audio_fd = -1;
static int tcp_listen = 0;
struct CODEC2 *c2 = NULL;

static int running = 1;
static void sigint(int sig) { (void)sig; running = 0; }

/* Antenna info for multiple antennas */
struct antenna {
    int8_t dbm;           // Signal strength in dBm
    uint8_t antenna_num;  // Antenna number
};

/* Radio info for a single frame */
struct radioinfo {
    uint16_t channel_freq;  // MHz
    float data_rate;        // Mbps
    uint16_t bandwidth;     // MHz (20, 40, etc.)
    struct antenna *antennas; // Array of antennas
    int antenna_count;      // Number of antennas
};

struct ieee80211_mac_header {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
    // QoS: optional
};

struct audio_channel_state {
    int active;
    uint64_t last_rx_ns;
};
static struct audio_channel_state channels[4];

static void run_cmd(const char *cmd)
{
	int ret = system(cmd);
	if (ret != 0) {
		fprintf(stderr, "Command failed: %s\n", cmd);
		exit(1);
	}
}

static void setup_monitor(void)
{
    //Bring down mon0 interface
	run_cmd("ip link set " MON_IF " down 2>/dev/null || true");
	run_cmd("iw dev " MON_IF " del 2>/dev/null || true");

    //Add and bringup mon0 interface.
	run_cmd("iw phy " PHY_NAME " interface add " MON_IF " type monitor");
	run_cmd("ip link set " MON_IF " up");
}

static void create_socket(void)
{
	radio_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (radio_fd < 0) {
		perror("socket");
		exit(1);
	}

	struct ifreq ifr = {0};
	strncpy(ifr.ifr_name, MON_IF, IFNAMSIZ - 1);

	if (ioctl(radio_fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("SIOCGIFINDEX");
		exit(1);
	}

	struct sockaddr_ll sll = {
		.sll_family   = AF_PACKET,
		.sll_ifindex  = ifr.ifr_ifindex,
		.sll_protocol = htons(ETH_P_ALL),
	};

    if (bind(radio_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        exit(1); 
    }

	struct tpacket_req req = {
		.tp_block_size = BLOCK_SIZE,
		.tp_frame_size = FRAME_SIZE,
		.tp_block_nr   = BLOCK_NR,
	};

	req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

	if (setsockopt(radio_fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
		perror("PACKET_RX_RING");
		exit(1);
	}

	ring_size = req.tp_block_size * req.tp_block_nr;
	frame_nr  = req.tp_frame_nr;

	ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, radio_fd, 0);

	if (ring == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
}

static int setup_audio_socket(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { 
        perror("socket");
        exit(1);
    }

    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(CODEC_SOCKET_PORTNO),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        exit(1); 
    }

    if (listen(s, 1) < 0) {
        perror("listen");
        exit(1);
    }

    return s;
}

static int accept_audio_client(int listen_fd) {
    int c = accept(listen_fd, NULL, NULL);
    if (c < 0) {
        perror("accept");
        return -1;
    }

    printf("Audio client connected\n");
    return c;
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void codec2_timeout_check(void) {
    uint64_t t = now_ns();

    for (int i = 0; i < 4; i++) {
        if (channels[i].active && (t - channels[i].last_rx_ns) > 300000000ULL) {
            printf("Channel %d: timeout\n", i);
            channels[i].active = 0;
        }
    }
}

//Decode the raw codec2 data into PCM frames,and write to audio_socket.
// static void decode_codec2_voice_data(const uint8_t *voice, size_t voice_len){

//     if (!c2){
//         perror("Codec2 invalid! [decode_codec2_voice_data]");
//         exit(1);
//     }
//     ssize_t sampleSize = codec2_samples_per_frame(c2);
//     int16_t pcm[sampleSize];

//     codec2_decode(c2, pcm, voice);
    
//     if (audio_fd >= 0) {
//         ssize_t w = write(audio_fd, pcm, sizeof(pcm));
//         if (w <= 0) {
//             printf("Client disconnected, waiting for new client...\n");
//             close(audio_fd);
//             audio_fd = -1;
//         }
//     }
// }

static void decode_codec2_voice_data(const uint8_t *voice, size_t voice_len)
{
    if (!c2) {
        fprintf(stderr, "Codec2 invalid!\n");
        return;
    }

    ssize_t expected = codec2_bytes_per_frame(c2);  // 6

    if (voice_len != (size_t)expected) {
        fprintf(stderr, "decode: wrong size %zu, expected %zd bytes\n",
                voice_len, expected);
        return;
    }

    ssize_t nsamples = codec2_samples_per_frame(c2);  // should be 160

    int16_t pcm[nsamples];

    codec2_decode(c2, pcm, voice);

    if (audio_fd >= 0) {
        ssize_t w = write(audio_fd, pcm, nsamples * sizeof(int16_t));
        if (w < 0) {
            perror("write audio");
        } else if ((size_t)w != nsamples * sizeof(int16_t)) {
            printf("Short audio write (%zd/%zu)\n", w, nsamples * sizeof(int16_t));
        }
    }
}

// static void handle_codec2_frame(uint8_t channel, uint8_t ptt, const uint8_t *voice, size_t voice_len) {
//     if (channel > 3){
//         printf("Invalid channel! %u\n", channel);
//         return;
//     }

//     struct audio_channel_state *ch = &channels[channel];
//     uint64_t t = now_ns();

//     if (ptt == 1) {
//         if (!ch->active) {
//             printf("Channel %u: PTT start\n", channel);
//             ch->active = 1;
//         }

//         ch->last_rx_ns = t;

//         ssize_t codec2_frame_size = codec2_bytes_per_frame(c2);

//         if (voice_len >= codec2_frame_size) {
//             decode_codec2_voice_data(voice, voice_len);
//         }

//     }else {
//         if (ch->active) {
//             printf("Channel %u: PTT end\n", channel);
//             ch->active = 0;
//         }
//     }
// }

static void handle_codec2_frame(uint8_t channel, uint8_t ptt, const uint8_t *voice, size_t voice_len)
{
    if (channel > 3) {
        printf("Invalid channel! %u\n", channel);
        return;
    }

    struct audio_channel_state *ch = &channels[channel];
    uint64_t t = now_ns();

    ssize_t frame_bytes = codec2_bytes_per_frame(c2);   // 6 for MODE_2400

    if (ptt == 1) {
        if (!ch->active) {
            printf("Channel %u: PTT start\n", channel);
            ch->active = 1;
        }

        ch->last_rx_ns = t;

        // Process as many full frames as we have
        const uint8_t *ptr = voice;
        size_t remaining = voice_len;

        while (remaining >= (size_t)frame_bytes) {
            decode_codec2_voice_data(ptr, frame_bytes);   // now pass exactly one frame
            ptr       += frame_bytes;
            remaining -= frame_bytes;
        }

        if (remaining > 0) {
            // Optional: warn about partial/truncated frame at end
            printf("Channel %u: %zu trailing bytes after full frames (ignored)\n",
                   channel, remaining);
        }
    } else {
        if (ch->active) {
            printf("Channel %u: PTT end\n", channel);
            ch->active = 0;
        }
    }
}

static void decode_codec2_payload(const uint8_t *payload, size_t len)
{
    if (len < CODEC_HDR_LEN)
        return;

    uint32_t magic = ntohl(*(uint32_t *)payload);

    //If radiodata header magic is not set, continue.
    if (magic != CODEC_PKT_MAGIC)
        return;

    uint8_t channel = payload[4];
    uint8_t ptt     = payload[5];

    const uint8_t *voice = payload + CODEC_HDR_LEN;
    size_t voice_len = len - CODEC_HDR_LEN;

    if (voice_len > CODEC_MAX_VOICE)
        voice_len = CODEC_MAX_VOICE;

    //printf("Decoding audio frames...\n");
    // printf("Custom Frame (%zu bytes):\n", len);
    // for (size_t i = 0; i < len; i++) {
    //     if (i % 16 == 0) printf("\n  ");
    //     printf("%02x ", payload[i]);
    // }
    // printf("\n\n");
    handle_codec2_frame(channel, ptt, voice, voice_len);
}

static void parse_radiotap_codec(const uint8_t *pkt, size_t len, int debug)
{
	struct ieee80211_radiotap_header *rt = (struct ieee80211_radiotap_header *)pkt;

	if (len < sizeof(*rt))
		return;

	uint16_t rt_len = le16toh(rt->it_len);
	if (rt_len > len)
		return;

    const uint8_t *mac_ptr = pkt + rt_len;
    size_t mac_len = len - rt_len;
    
    if (debug){
        printf("Total packet len: %zu, Radiotap len: %u, MAC len: %zu\n", len, rt_len, mac_len);
    }
    

	struct ieee80211_radiotap_iterator it;
	if (ieee80211_radiotap_iterator_init(&it, rt, rt_len, NULL) < 0)
		return;

    //Create the radioinfo struct, to be later printed out:
    struct radioinfo info;
    memset(&info, 0, sizeof(info));
    info.antennas = calloc(8, sizeof(struct antenna));
    info.antenna_count = 0;

    
	if (debug)
        printf("Radiotap:\n");

	while (ieee80211_radiotap_iterator_next(&it) == 0) {

        if (it.this_arg_index == IEEE80211_RADIOTAP_VENDOR_NAMESPACE) {
            if (debug){
                printf("\tvendor NS (%.2x-%.2x-%.2x:%d, %d bytes)\n",
                    it.this_arg[0], it.this_arg[1],
                    it.this_arg[2], it.this_arg[3],
                    it.this_arg_size - 6);
                for (int i = 6; i < it.this_arg_size; i++) {
                    if (i % 8 == 6)
                        printf("\t\t");
                    else
                        printf(" ");
                    printf("%.2x", it.this_arg[i]);
                }
                printf("\n");
            }

		}
        else if (it.is_radiotap_ns){
            //Print out the radiotap stuff.		
            switch (it.this_arg_index) {

                case IEEE80211_RADIOTAP_TSFT:
                    if (debug)
                        printf("TSFT: %llu\n", (unsigned long long)le64toh(*(unsigned long long *)it.this_arg));
                    break;

                case IEEE80211_RADIOTAP_FLAGS: {
                    uint8_t f = *it.this_arg;
                    if (debug){
                        printf("flags: 0x%02x", f);
                        if (f & IEEE80211_RADIOTAP_F_CFP)       printf(" [CFP]");
                        if (f & IEEE80211_RADIOTAP_F_SHORTPRE)  printf(" [Short Preamble]");
                        if (f & IEEE80211_RADIOTAP_F_WEP)       printf(" [WEP]");
                        if (f & IEEE80211_RADIOTAP_F_FRAG)      printf(" [Fragment]");
                        if (f & IEEE80211_RADIOTAP_F_FCS)       printf(" [FCS included]");
                        if (f & IEEE80211_RADIOTAP_F_DATAPAD)   printf(" [Data pad]");
                        if (f & IEEE80211_RADIOTAP_F_BADFCS)    printf(" [Bad FCS]");
                        printf("\n");
                    }
                    break;
                }

                case IEEE80211_RADIOTAP_RATE:
                    info.data_rate = (*it.this_arg) * 0.5;
                    if (debug)
                        printf("rate: %.1f Mbps\n", (*it.this_arg) * 0.5);
                    break;

                case IEEE80211_RADIOTAP_CHANNEL: {
                    uint16_t freq = le16toh(*(uint16_t *)it.this_arg);
                    uint16_t flags = le16toh(*(uint16_t *)(it.this_arg + 2));
                    //radioinfo data
                    info.channel_freq = freq;
                    // if (flags & IEEE80211_CHAN_CCK) info.bandwidth = 20;
                    // else if (flags & IEEE80211_CHAN_OFDM) info.bandwidth = 20; // default
                    // if (flags & IEEE80211_CHAN_DYN) info.bandwidth = 20; // could extend

                    if (debug){
                        //Debug
                        printf("channel freq: %u MHz (flags: 0x%.4x", freq, flags);
                        if (flags & IEEE80211_CHAN_CCK)     printf(" CCK");
                        if (flags & IEEE80211_CHAN_OFDM)    printf(" OFDM");
                        if (flags & IEEE80211_CHAN_2GHZ)    printf(" 2GHz");
                        if (flags & IEEE80211_CHAN_5GHZ)    printf(" 5GHz");
                        if (flags & IEEE80211_CHAN_DYN)     printf(" Dynamic");
                        if (flags & IEEE80211_CHAN_HALF)    printf(" Half");
                        if (flags & IEEE80211_CHAN_QUARTER) printf(" Quarter");
                        printf(")\n");
                    }
                    break;
                }

                case IEEE80211_RADIOTAP_MCS: {
                    uint8_t known = it.this_arg[0];
                    uint8_t flags = it.this_arg[1];
                    uint8_t mcs   = it.this_arg[2];
                    
                    if (debug){
                        //debug
                        printf("MCS: index=%u", mcs);
                        if (known & IEEE80211_RADIOTAP_MCS_HAVE_BW) {
                            printf(", bw=%s", (flags & IEEE80211_RADIOTAP_MCS_BW_MASK) == IEEE80211_RADIOTAP_MCS_BW_20 ? "20MHz" :
                                            (flags & IEEE80211_RADIOTAP_MCS_BW_MASK) == IEEE80211_RADIOTAP_MCS_BW_40 ? "40MHz" :
                                            (flags & IEEE80211_RADIOTAP_MCS_BW_MASK) == IEEE80211_RADIOTAP_MCS_BW_20L ? "20MHz Lower" :
                                            "20MHz Upper");
                        }
                        if (flags & IEEE80211_RADIOTAP_MCS_SGI)    printf(", SGI");
                        if (flags & IEEE80211_RADIOTAP_MCS_FMT_GF) printf(", Greenfield");
                        if (flags & IEEE80211_RADIOTAP_MCS_FEC_LDPC) printf(", LDPC");
                        if ((flags & IEEE80211_RADIOTAP_MCS_STBC_MASK) >> IEEE80211_RADIOTAP_MCS_STBC_SHIFT)
                            printf(", STBC x%d", (flags & IEEE80211_RADIOTAP_MCS_STBC_MASK) >> IEEE80211_RADIOTAP_MCS_STBC_SHIFT);
                        printf("\n");
                    }
                    
                    //radioinfo data
                    if (known & IEEE80211_RADIOTAP_MCS_HAVE_BW) {
                        switch (flags & IEEE80211_RADIOTAP_MCS_BW_MASK) {
                            case IEEE80211_RADIOTAP_MCS_BW_20: info.bandwidth = 20; break;
                            case IEEE80211_RADIOTAP_MCS_BW_40: info.bandwidth = 40; break;
                            case IEEE80211_RADIOTAP_MCS_BW_20L: info.bandwidth = 20; break;
                            case IEEE80211_RADIOTAP_MCS_BW_20U: info.bandwidth = 20; break;
                        }
                    }
                    break;
                }

                case IEEE80211_RADIOTAP_AMPDU_STATUS: {
                    uint16_t reference = le16toh(*(uint16_t *)it.this_arg);
                    uint16_t flags     = le16toh(*(uint16_t *)(it.this_arg + 2));

                    if (debug){
                        printf("A-MPDU: reference=%u, flags=0x%x", reference, flags);
                        if (flags & IEEE80211_RADIOTAP_AMPDU_REPORT_ZEROLEN)  printf(" [Report ZeroLen]");
                        if (flags & IEEE80211_RADIOTAP_AMPDU_IS_ZEROLEN)      printf(" [Is ZeroLen]");
                        if (flags & IEEE80211_RADIOTAP_AMPDU_LAST_KNOWN)      printf(" [Last Known]");
                        if (flags & IEEE80211_RADIOTAP_AMPDU_IS_LAST)         printf(" [Is Last]");
                        if (flags & IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_ERR)   printf(" [Delimiter CRC Err]");
                        if (flags & IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_KNOWN) printf(" [Delimiter CRC Known]");
                        printf("\n");
                    }

                    break;
                }

                case IEEE80211_RADIOTAP_VHT: {
                    uint32_t known = le32toh(*(uint32_t *)it.this_arg);
                    uint8_t flags  = it.this_arg[4];
                    uint8_t bw    = it.this_arg[5];

                    //Do not assume from modulation schemes, just set the values as they are.
                    info.bandwidth = bw;

                    // uint8_t mcs_nss[4] = {0};
                    // for (int i = 0; i < 4 && (6+i) < it.this_arg_size; i++){
                    //     mcs_nss[i] = it.this_arg[6 + i];
                    // }
                    // if (it.this_arg_size > 10){
                    //     uint8_t coding = it.this_arg[10];
                    // }
                    

                    if (debug){
                        printf("VHT: known=0x%08x, flags=0x%02x bw=%u", known, flags, bw);
                        if (flags & IEEE80211_RADIOTAP_VHT_FLAG_STBC)                printf(" [STBC]");
                        if (flags & IEEE80211_RADIOTAP_VHT_FLAG_TXOP_PS_NA)          printf(" [TXOP PS Not Allowed]");
                        if (flags & IEEE80211_RADIOTAP_VHT_FLAG_SGI)                 printf(" [SGI]");
                        if (flags & IEEE80211_RADIOTAP_VHT_FLAG_SGI_NSYM_M10_9)      printf(" [SGI NSYM -10/9]");
                        if (flags & IEEE80211_RADIOTAP_VHT_FLAG_LDPC_EXTRA_OFDM_SYM) printf(" [LDPC extra OFDM]");
                        if (flags & IEEE80211_RADIOTAP_VHT_FLAG_BEAMFORMED)          printf(" [Beamformed]");
                        printf("\n");
                    }
                    break;
                }

                case IEEE80211_RADIOTAP_TX_FLAGS: {
                    uint16_t f = le16toh(*(uint16_t *)it.this_arg);
                    if (debug){
                        printf("TX flags: 0x%.4x", f);
                        if (f & IEEE80211_RADIOTAP_F_TX_FAIL)   printf(" [TX Fail]");
                        if (f & IEEE80211_RADIOTAP_F_TX_CTS)    printf(" [TX CTS]");
                        if (f & IEEE80211_RADIOTAP_F_TX_RTS)    printf(" [TX RTS]");
                        if (f & IEEE80211_RADIOTAP_F_TX_NOACK)  printf(" [TX NoAck]");
                        printf("\n");
                    }
                    break;
                }

                case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
                    //debug
                    if (debug)
                        printf("signal: %d dBm\n", *(int8_t *)it.this_arg);

                    //radioinfo data
                    if (info.antenna_count < 8) {
                        info.antennas[info.antenna_count].dbm = *(int8_t *)it.this_arg;
                    }
                    break;

                case IEEE80211_RADIOTAP_ANTENNA:
                    //debug
                    if (debug)
                        printf("antenna: %u\n", *it.this_arg);

                    //radioinfo data
                    if (info.antenna_count < 8) {
                        info.antennas[info.antenna_count].antenna_num = *it.this_arg;
                        info.antenna_count++;
                    }
                    break;
                
                case IEEE80211_RADIOTAP_RX_FLAGS: {
                    uint16_t f = le16toh(*(uint16_t *)it.this_arg);
                    if (debug){
                        printf("RX flags: 0x%.4x", f);
                        if (f & IEEE80211_RADIOTAP_F_RX_BADPLCP) printf(" [Bad PLCP]");
                        printf("\n");
                    }
                    break;
                }

                default:
                    /* ignore others for now */
                    break;
                }
            }
        }
    if (debug)
	    printf("\n");

    if (mac_len < 24){
        //printf("Frame does not contain MAC data\n");
        return;
        
    }else{

        if (debug){
            //Print out the radioinfo struct, when there is MAC address data.
            printf("Radio Info:\n");
            printf(" Channel freq: %u MHz\n", info.channel_freq);
            printf(" Data rate: %.1f Mbps\n", info.data_rate);
            printf(" Bandwidth: %u MHz\n", info.bandwidth);
            for (int i = 0; i < info.antenna_count; i++) {
                printf(" Antenna %u: %d dBm\n", info.antennas[i].antenna_num,
                                                info.antennas[i].dbm);
            }
            printf("\n");
        }
        

        free(info.antennas);

        struct ieee80211_mac_header *mac = (struct ieee80211_mac_header *)mac_ptr;
        uint16_t fc = le16toh(mac->frame_control);
        uint8_t type = FC_TYPE(fc);
        uint8_t subtype = FC_SUBTYPE(fc);

        if (debug){
            printf("MAC Header:\n");
            printf(" Frame Type: %u Subtype: %u\n", type, subtype);
            printf(" Addr1: %02x:%02x:%02x:%02x:%02x:%02x\n",
                mac->addr1[0], mac->addr1[1], mac->addr1[2],
                mac->addr1[3], mac->addr1[4], mac->addr1[5]);
            printf(" Addr2: %02x:%02x:%02x:%02x:%02x:%02x\n",
                mac->addr2[0], mac->addr2[1], mac->addr2[2],
                mac->addr2[3], mac->addr2[4], mac->addr2[5]);
            printf(" Addr3: %02x:%02x:%02x:%02x:%02x:%02x\n",
                mac->addr3[0], mac->addr3[1], mac->addr3[2],
                mac->addr3[3], mac->addr3[4], mac->addr3[5]);
            if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
                uint8_t *addr4 = mac_ptr + 24;
                printf(" Addr4: %02x:%02x:%02x:%02x:%02x:%02x\n",
                        addr4[0], addr4[1], addr4[2],
                        addr4[3], addr4[4], addr4[5]);
            }
            printf(" Seq Ctrl: 0x%.4x\n", le16toh(mac->seq_ctrl));
            printf("\n");
    
        }
        
        //Determine what the hdr_len is for payload data
        size_t hdr_len = 24;  // default
        
        if (FC_TO_DS(fc) && FC_FROM_DS(fc)) {
            hdr_len = 30; // Addr4 present
        }
        
        // Optional: QoS control field for QoS data frames (subtype 8, 12...)
        if (type == 2 && (subtype & 0x08)) {
            hdr_len += 2; // QoS Control
        }

        // /* HT Control (rare but valid) */
        // if (fc & IEEE80211_FCTL_ORDER)
        // hdr_len += 4;

        //payload stuff.
        if (mac_len > hdr_len){
            
            const uint8_t *payload = mac_ptr + hdr_len;
            size_t payload_len = mac_len - hdr_len;

            if (debug){
                //Decode the custom payload data now:
                printf("Custom Frame (%zu bytes):\n", payload_len);
                for (size_t i = 0; i < payload_len; i++) {
                    if (i % 16 == 0) printf("\n  ");
                    printf("%02x ", payload[i]);
                }
                printf("\n\n");
            }
            
            //Decode frames.
            decode_codec2_payload(payload, payload_len);

        }
    }

}

static void setup_decoder(void){
    c2 = codec2_create(CODEC2_MODE_2400);
    if (!c2) {
        fprintf(stderr, "codec2_create failed\n");
        exit(1);
    }
}

static void capture_loop(void)
{
	unsigned int frame = 0;

	while (running) {

		struct tpacket_hdr *hdr =
			(struct tpacket_hdr *)(
				(uint8_t *)ring +
				frame * FRAME_SIZE
			);

		if (!(hdr->tp_status & TP_STATUS_USER)) {
			usleep(10);
			continue;
		}

		uint8_t *pkt = (uint8_t *)hdr + hdr->tp_mac;
		size_t len = hdr->tp_snaplen;

		parse_radiotap_codec(pkt, len, 0);
        codec2_timeout_check();

		hdr->tp_status = TP_STATUS_KERNEL;
		frame = (frame + 1) % frame_nr;

        usleep(1);
	}
}

int main(void)
{
    printf("Radiotap & Codec2 RX and decode tool\n");
    printf("Receive codec2 encoded audio via raw WiFi, and pipe it into socket on port 3443.\n");
    printf("Open with 'nc device-ip 3443 | aplay -f S16_LE -r 8000 -c 1 --buffer-size=512 --period-size=64' on remote machine\n\n");
	signal(SIGINT, sigint);
	signal(SIGTERM, sigint);

    printf("Setting up monitor mode...\n");
	setup_monitor();

    printf("Setting up radiotap socket...\n");
	create_socket();

    printf("Setting up decoder...\n");
	setup_decoder();

    printf("Setting up audio-server socket...\n");
    tcp_listen = setup_audio_socket();

    printf("Waiting for audio client to connect on port %d ...\n", CODEC_SOCKET_PORTNO);
    audio_fd = accept(tcp_listen, NULL, NULL);
    if (audio_fd < 0) {
        perror("accept failed");
        goto cleanup;
    }
    printf("Audio client connected...\n");

	printf("Listening on %s (Ctrl-C to stop)\n", MON_IF);
	capture_loop();

cleanup:
    printf("Cleaning up...\n");
    if (ring) munmap(ring, ring_size);
    if (radio_fd >= 0) close(radio_fd);
    if (audio_fd >= 0) close(audio_fd);
    if (tcp_listen >= 0) close(tcp_listen);
    if (c2) codec2_destroy(c2);
    return 0;
}
