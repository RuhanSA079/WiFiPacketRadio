#define _GNU_SOURCE
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

static void *ring = NULL;
static size_t ring_size;
static unsigned int frame_nr;
static int fd = -1;

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
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd < 0) {
		perror("socket");
		exit(1);
	}

	struct ifreq ifr = {0};
	strncpy(ifr.ifr_name, MON_IF, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
		perror("SIOCGIFINDEX");
		exit(1);
	}

	struct sockaddr_ll sll = {
		.sll_family   = AF_PACKET,
		.sll_ifindex  = ifr.ifr_ifindex,
		.sll_protocol = htons(ETH_P_ALL),
	};

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        exit(1); 
    }

	struct tpacket_req req = {
		.tp_block_size = BLOCK_SIZE,
		.tp_frame_size = FRAME_SIZE,
		.tp_block_nr   = BLOCK_NR,
	};

	req.tp_frame_nr = (req.tp_block_size * req.tp_block_nr) / req.tp_frame_size;

	if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0) {
		perror("PACKET_RX_RING");
		exit(1);
	}

	ring_size = req.tp_block_size * req.tp_block_nr;
	frame_nr  = req.tp_frame_nr;

	ring = mmap(NULL, ring_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);

	if (ring == MAP_FAILED) {
		perror("mmap");
		exit(1);
	}
}

static void parse_radiotap(const uint8_t *pkt, size_t len, int debug)
{
	struct ieee80211_radiotap_header *rt = (struct ieee80211_radiotap_header *)pkt;

	if (len < sizeof(*rt))
		return;

	uint16_t rt_len = le16toh(rt->it_len);
	if (rt_len > len)
		return;

    const uint8_t *mac_ptr = pkt + rt_len;
    size_t mac_len = len - rt_len;
    
    printf("Total packet len: %zu, Radiotap len: %u, MAC len: %zu\n", len, rt_len, mac_len);

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
        free(info.antennas);

        struct ieee80211_mac_header *mac = (struct ieee80211_mac_header *)mac_ptr;
        uint16_t fc = le16toh(mac->frame_control);
        uint8_t type = FC_TYPE(fc);
        uint8_t subtype = FC_SUBTYPE(fc);

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

            //Decode the custom payload data now:
            printf("Custom Frame (%zu bytes):\n", payload_len);
            for (size_t i = 0; i < payload_len; i++) {
                if (i % 16 == 0) printf("\n  ");
                printf("%02x ", payload[i]);
            }
            printf("\n\n");
        }else{
            printf("Invalid data, skipping...\n");
        }
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
			usleep(1000);
			continue;
		}

		uint8_t *pkt = (uint8_t *)hdr + hdr->tp_mac;
		size_t len = hdr->tp_snaplen;

		parse_radiotap(pkt, len, 1);

		hdr->tp_status = TP_STATUS_KERNEL;
		frame = (frame + 1) % frame_nr;
	}
}




int main(void)
{
    printf("Radiotap decode tool by RuhanSA079\n");
	signal(SIGINT, sigint);
	signal(SIGTERM, sigint);

    printf("Setting up monitor mode...\n");
	setup_monitor();

    printf("Setting up radiotap socket...\n");

	create_socket();

	printf("Listening on %s (Ctrl-C to stop)\n", MON_IF);
	capture_loop();

    printf("CTRL-C pressed, cleaning up...\n");
	munmap(ring, ring_size);
	close(fd);
	return 0;
}
