#define _GNU_SOURCE

/* WiFiPacketRadio (WPR) is licensed under the GPLv2 license.
 The author takes no responsibility whatsoever for any damages caused, directly or indirectly, when using this program/source code.
 Please check with your country's radio licensing spectrum and power limits, as per regulatory domain.
 This program is developed as a proof-of-concept, as a experimental means to see how far 2.4 Ghz and 5Ghz radio packets being transmitted, can be received reliably.
 The author intends to use a higher power wireless radio (1 watt/30dBm) on 5Ghz, nothing more, to experiment with the range of radio packets TXed and RXed.
 This is all for science...

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
#include <linux/spi/spidev.h>
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
//#include "fec.h"
//#include "ringbuffer.h"
#include <alsa/asoundlib.h>
#include <linux/i2c-dev.h>
#include <sys/wait.h>
#include <pthread.h>

static pthread_mutex_t peer_mutex = PTHREAD_MUTEX_INITIALIZER;

#if defined(__x86_64__) || defined(_M_X64)
#define RADIO_IFACE "wlan0"
static int rfPower = 3000;
#else
#define RADIO_IFACE "wlan1"
#define SPI_DISPLAY_ENABLED true
#include <gpiolib.h>
#define USE_INA219_SENSOR
static int rfPower = 250;
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

#define SAMPLE_RATE 8000
#define CHANNELS 1
#define FORMAT SND_PCM_FORMAT_S16_LE
#define PERIOD_FRAMES 1024                  //Tunable
#define BUFFER_FRAMES (PERIOD_FRAMES * 4)   //Tunable??

#define ONE_MS_IN_US 1000
#define BUTTON_DEBOUNCE_US     20000ULL   // 20 ms
#define BUTTON_LONG_PRESS_US  800000ULL   // 800 ms

#ifdef SPI_DISPLAY_ENABLED
static const char *SPI_DEV = "/dev/spidev0.0";
static const uint32_t SPI_SPEED = 32000000; // 32 MHz
static const uint8_t SPI_MODE = SPI_MODE_0;
static const uint8_t BITS_PER_WORD = 8;
#endif

// RadioTap message seems to work like this:
//  Radiotap_hdr -> header data defining the radio's settings, rates, enable/disable certain features, etc.
//  ieee80211_mac_hdr -> Header data that contains the data frame stuff, duration and then the three MAC addresses, as well as the frame sequence number.
//  Raw data -- The raw data that I send (c2c2c2c2 + channel data + audio data, etc.)
#define WPR_TX_QUEUE_SZ 8
#define RADIO_DATA_NOOP 0x00
#define RADIO_DATA_AUDIO 0x01
#define RADIO_DATA_MESH 0x02
#define RADIO_DATA_MESH_MSG_DISCOVERY_PING 0xFA
#define RADIO_DATA_MESH_MSG_DISCOVERY_PONG 0xFB
#define RADIO_DATA_MESH_MSG_FORWARD_AUDIO 0xCA

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
//      Message type -> 1 byte
//      Destination MAC -> 6 bytes
//      Message contents -> 9 bytes long
//      
// FEC data
//      4 bytes or 6?

// From this, it derived that the maximum amount of "data" we can send, is 16 bytes, max.
// Can be adjusted later in the struct

struct peer_node
{
    uint8_t nodeID[6];      //MAC address of peer
    uint64_t lastSeen_us;   //Last time it was seen by us.
    int8_t rssiOne;
    int8_t rssiTwo;
    int8_t noiseOne;
    int8_t noiseTwo;
};

struct peer_nodes_remote
{
    uint8_t nodeID[6];      //MAC address of peer
    uint64_t lastSeen_us;   //Last time it was seen by us.
};

//Total byte count: 39 bytes!
struct wpr_mesh
{
    uint8_t msgtype; // Message type -> 1 byte
    uint8_t dst[6];  // Destination -> 6 bytes
    uint8_t msg[32];  // 32 bytes of message data
};

struct wpr_data
{
    uint32_t magic_header;
    uint8_t data_type;
    uint8_t data[40];
    uint8_t fec[6];
} __attribute__((packed));


struct wpr_queue {
    struct wpr_data items[WPR_TX_QUEUE_SZ];
    uint8_t head;   // index of oldest element
    uint8_t tail;   // index to place new element
    uint8_t len;    // Size of the wpr_queue
};

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
    uint64_t last_rx_us;
};

typedef enum {
    BUTTON_EVENT_NONE = 0,
    BUTTON_EVENT_SHORT,
    BUTTON_EVENT_LONG
} button_event_t;

typedef struct {
    int fd;
    uint8_t addr;
    float current_lsb_a;   // amps per bit
} ina219_t;

/* ---------------- some variables ---------------- */


// Codec2 stuff
struct CODEC2 *codec2 = NULL;

unsigned char *hwMAC;          // Hardware MAC address of the radio interface, used for filtering out our own transmitted packets.
unsigned char macBroadcast[6]; // Broadcast MAC address for filtering incoming packets (set to ff:ff:ff:ff:ff:ff).
int radio_fd, pcap_fd, audio_in_fd, spi_fd, i2c_fd = 0;

bool debug = false;
bool debugRadioData = false;
volatile sig_atomic_t running = 1;
bool isRadioReceiving = false;
bool isRadioTransmitting = false;
bool useQDiscBypass = true;
bool usingPcap = true;
bool usingDisplay = false;
static double phase = 0.0;

uint64_t last_tx_test_tone = 0;
struct sockaddr_ll sll;

pcap_t *pcap_handle = NULL;
uint16_t hdr_seq_tx = 0;
uint8_t mcs_flags = 0;

struct wpr_data wpr_data_rx;
struct wpr_data wpr_data_tx;
struct ieee80211_mac_hdr mac_hdr_tx;
struct radiotap_hdr_data rtap_hdr_data_tx;
struct radiotap_hdr rtap_tx;

static struct audio_channel_state channels[4];
static struct wpr_queue tx_queue;
#ifdef USE_INA219_SENSOR
static uint16_t ina219_bus_mv = 0;
static float ina219_current_ma = 0;
#endif
ina219_t ina;
int8_t ant1RSSI_dBm = -120;
int8_t ant2RSSI_dBm = -120;
int8_t ant1Noise_dBm = -120;
int8_t ant2Noise_dBm = -120;

#define PCM_BYTE_COUNT 160                             /* 20 ms of mono audio at 8 kHz */
#define PCM_100MS_BYTE_COUNT (PCM_BYTE_COUNT * 5)      // enough for 100 ms of audio, 160 bytes per 20 ms frame * 5 = 800 bytes
#define TEST_TONE_INTERVAL (PCM_100MS_BYTE_COUNT * 10) //

int16_t pcmToneBuffer[TEST_TONE_INTERVAL]; // about 1 second of tone at 8 kHz, 160 samples per 20 ms frame, so 160 * 5 = 800 bytes per 100 ms, so 800 * 10 = 8000 bytes for 1 second

//RingBuffer audioBuf;
snd_pcm_t *pcmDevice;
bool soundCardFound = false;
uint64_t discoveryFrameRX = 0;
uint64_t discoveryFrameTX = 0;

#define SPI_DISPLAY_RST 22
#define SPI_DISPLAY_CMD 24
#define SPI_DISPLAY_BKL 12
#define TFT_HEIGHT 160
#define TFT_WIDTH 128
uint16_t framebuffer[TFT_WIDTH * TFT_HEIGHT];

#define APP_VERSION "WPR dev-0.1.3"
#define FONT_SPACING 1           // extra spacing between chars
#define TOP_MARGIN 2
#define RIGHT_MARGIN 2
#define CENTER_MARGIN 0

// Sensor + button section
#define BUTTON_GPIO 21
#define INA219_SENSOR_ADDR   0x40
#define INA219_REG_CONFIG    0x00
#define INA219_REG_SHUNT     0x01
#define INA219_REG_BUS       0x02
#define INA219_REG_POWER     0x03
#define INA219_REG_CURRENT   0x04
#define INA219_REG_CALIB     0x05

#define INA219_CFG_BVOLT_32V        (1u << 13)
#define INA219_CFG_GAIN_320MV       (3u << 11)
#define INA219_CFG_BADC_12BIT       (3u << 7)
#define INA219_CFG_SADC_12BIT       (3u << 3)
#define INA219_CFG_MODE_CONT        7u

#define MAX_PEERS            32
#define PEER_TIMEOUT_US      200000ULL   // 200 ms

static struct peer_node local_peer_nodes[MAX_PEERS];
static bool local_peer_used[MAX_PEERS];

unsigned gpio_rst, gpio_cmd, gpio_bl = 0;

char *mac_to_string(const uint8_t mac[6])
{
    static char mac_str[18];
    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return mac_str;
}

static int peer_find_index(const uint8_t mac[6])
{
    for (int i = 0; i < MAX_PEERS; i++) {
        if (local_peer_used[i] &&
            memcmp(local_peer_nodes[i].nodeID, mac, 6) == 0) {
            return i;
        }
    }
    return -1;
}

static int peer_find_free_index(void)
{
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!local_peer_used[i]) {
            return i;
        }
    }
    return -1;
}

static void peer_update_from_pong(const uint8_t mac[6], int8_t ant1db, int8_t ant1nse, int8_t ant2db, int8_t ant2nse, uint64_t now)
{
    pthread_mutex_lock(&peer_mutex);
    int idx = peer_find_index(mac);

    if (idx < 0) {
        idx = peer_find_free_index();
        if (idx < 0) {
            // Table full, drop the oldest entry or just ignore
            printf("Local-peer table full!\n");
            return;
        }

        //printf("Creating new peer entry...\n");
        local_peer_used[idx] = true;
        memcpy(local_peer_nodes[idx].nodeID, mac, 6);
    }

    //printf("Updating peerID: %s, current_ts: %lu\n", mac_to_string(local_peer_nodes[idx].nodeID), now);
    local_peer_nodes[idx].lastSeen_us = now;
    local_peer_nodes[idx].rssiOne = ant1db;
    local_peer_nodes[idx].noiseOne = ant1nse;
    local_peer_nodes[idx].rssiTwo = ant2db;
    local_peer_nodes[idx].noiseTwo = ant2nse;

    pthread_mutex_unlock(&peer_mutex);
}

static int peer_count(void)
{
    pthread_mutex_lock(&peer_mutex);
    int count = 0;

    for (int i = 0; i < MAX_PEERS; i++) {
        if (local_peer_used[i]) {
            count++;
        }
    }
    pthread_mutex_unlock(&peer_mutex);

    return count;
}

static void peer_cleanup_old(uint64_t now, uint64_t cleanupTime)
{
    pthread_mutex_lock(&peer_mutex);
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!local_peer_used[i]) {
            continue;
        }

        uint64_t age = now - local_peer_nodes[i].lastSeen_us;

        if ((age) >= cleanupTime) {
            local_peer_used[i] = false;
            printf("Cleaning up node: %s, age: %lu\n", mac_to_string(local_peer_nodes[i].nodeID), age);
            memset(&local_peer_nodes[i], 0, sizeof(local_peer_nodes[i]));
        }
    }
    pthread_mutex_unlock(&peer_mutex);
}

static void init_tx_queue(void)
{
    tx_queue.head = 0;
    tx_queue.tail = 0;
    tx_queue.len  = 0;
}

static bool wpr_enqueue(const struct wpr_data *pkt)
{
    bool ok = false;
    if (pkt == NULL) return false;

    if (tx_queue.len < WPR_TX_QUEUE_SZ)
    {
        // copy packet into tail
        memcpy(&tx_queue.items[tx_queue.tail], pkt, sizeof(struct wpr_data));
        tx_queue.tail = (tx_queue.tail + 1) % WPR_TX_QUEUE_SZ;
        tx_queue.len++;
        ok = true;
    }

    return ok;
}

static bool wpr_dequeue(struct wpr_data *out_pkt)
{
    bool ok = false;
    if (out_pkt == NULL) return false;

    if (tx_queue.len > 0)
    {
        memcpy(out_pkt, &tx_queue.items[tx_queue.head], sizeof(struct wpr_data));
        tx_queue.head = (tx_queue.head + 1) % WPR_TX_QUEUE_SZ;
        tx_queue.len--;
        ok = true;
    }
    return ok;
}

static bool wpr_peek(struct wpr_data *out_pkt)
{
    bool ok = false;
    if (out_pkt == NULL) return false;

    if (tx_queue.len > 0)
    {
        memcpy(out_pkt, &tx_queue.items[tx_queue.head], sizeof(struct wpr_data));
        ok = true;
    }

    return ok;
}

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000000ULL) + (ts.tv_nsec / 1000ULL);
}

static void cleanup(void)
{
    running = 0;

    if (i2c_fd > 0)
    {
        close(i2c_fd);
        i2c_fd = 0;
    }

    if (spi_fd > 0)
    {
        close(spi_fd);
        spi_fd = 0;
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

    if (codec2 != NULL)
    {
        codec2_destroy(codec2);
        codec2 = NULL;
    }

    if (pcmDevice != NULL){
        snd_pcm_drain(pcmDevice);
        snd_pcm_close(pcmDevice);
        pcmDevice = NULL;
    }

    exit(0);
}

static void sigint(int sig)
{
    (void)sig;
    printf("\nApplication signal caught. Exiting.\n");
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

static int set_fd_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(F_GETFL)");
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(F_SETFL)");
        return -1;
    }
    return 0;
}

static void run_cmd(const char *cmd)
{
    int ret = system(cmd);

    if (ret == -1) {
        perror("system");
        return;
    }

    if (WIFEXITED(ret)) {
        int code = WEXITSTATUS(ret);
        if (code != 0) {
            fprintf(stderr, "Command failed (%d): %s\n", code, cmd);
            return;
        }
    } else {
        fprintf(stderr, "Command did not exit normally: %s\n", cmd);
        return;
    }
}

static void setRFPower(int power)
{
    printf("Setting rfpower to: %d\n", power);

    char cmd[100];
    snprintf(cmd, sizeof(cmd), "iw dev %s set txpower fixed %d", RADIO_IFACE, power);
    run_cmd(cmd);
}

#ifdef SPI_DISPLAY_ENABLED

#define X_OFFSET 2
#define Y_OFFSET 1

static bool init_gpio(void)
{

    if (gpiolib_init() < 0) {
        fprintf(stderr, "gpiolib_init failed\n");
        return false;
    }

    // Stage 2: map MMIO (requires privileges)
    if (gpiolib_mmap() != 0) {
        perror("gpiolib_mmap");
        return false;
    }

    // Ensure pin range initialised (recommended by the docs)
    unsigned first, last;
    gpio_get_pin_range(&first, &last);

    gpio_set_fsel(SPI_DISPLAY_BKL, GPIO_FSEL_GPIO);
    gpio_set_fsel(SPI_DISPLAY_CMD, GPIO_FSEL_GPIO);
    gpio_set_fsel(SPI_DISPLAY_RST, GPIO_FSEL_GPIO);
    gpio_set_fsel(BUTTON_GPIO, GPIO_FSEL_GPIO);

    gpio_set_dir(SPI_DISPLAY_BKL, DIR_OUTPUT);
    gpio_set_dir(SPI_DISPLAY_CMD, DIR_OUTPUT);
    gpio_set_dir(SPI_DISPLAY_RST, DIR_OUTPUT);
    gpio_set_dir(BUTTON_GPIO, DIR_INPUT);

    gpio_clear(SPI_DISPLAY_BKL);
    gpio_clear(SPI_DISPLAY_CMD);
    gpio_clear(SPI_DISPLAY_RST);

    gpio_set_pull(BUTTON_GPIO, PULL_UP);

    return true;
}

static bool readButton(void)
{
    int res = gpio_get_level(BUTTON_GPIO);

    if (res < 0) {
        return false;
    }

    return (res == 0);
}

int spi_write_bytes(const uint8_t *buf, size_t len) {
    struct spi_ioc_transfer tr = {0};
    tr.tx_buf = (unsigned long)buf;
    tr.rx_buf = 0;
    tr.len = len;
    tr.delay_usecs = 0;
    tr.speed_hz = SPI_SPEED;
    tr.bits_per_word = BITS_PER_WORD;
    if (ioctl(spi_fd, SPI_IOC_MESSAGE(1), &tr) < 1) { perror("spi_send"); return -1; }
    return 0;
}

int init_spi_bus(void) {
    spi_fd = open(SPI_DEV, O_RDWR);
    if (spi_fd < 0) { perror("open spi"); return -1; }
    if (ioctl(spi_fd, SPI_IOC_WR_MODE, &SPI_MODE) < 0) { perror("mode"); return -1; }
    if (ioctl(spi_fd, SPI_IOC_WR_BITS_PER_WORD, &BITS_PER_WORD) < 0) { perror("bits"); return -1; }
    if (ioctl(spi_fd, SPI_IOC_WR_MAX_SPEED_HZ, &SPI_SPEED) < 0) { perror("speed"); return -1; }
    return 0;
}

void send_command(uint8_t cmd) {
    gpio_clear(SPI_DISPLAY_CMD); //0
    spi_write_bytes(&cmd, 1);
}

void send_data(const uint8_t *data, size_t len) {
    gpio_set(SPI_DISPLAY_CMD); //1
    spi_write_bytes(data, len);
}

void st7735_init_sequence(void) {
    // Hardware reset
    gpio_clear(SPI_DISPLAY_RST); //0
    usleep(20000);
    gpio_set(SPI_DISPLAY_RST); //1
    usleep(20000);

    send_command(0x01); // Software reset
    usleep(15000);

    send_command(0x11); // Sleep out
    usleep(15000);

    // Frame rate / inversion / color mode / etc — depends on module
    send_command(0x3A); // COLMODE
    uint8_t col = 0x05; // 16-bit/pixel (RGB565) for many ST7735 modules
    send_data(&col, 1);

    send_command(0x29); // Display ON
    usleep(10000);
}

static bool init_spi_display(){
    if (!init_gpio()) return false;

    if (init_spi_bus() < 0) return false;
    st7735_init_sequence();

    //Switch on the backlight GPIO pin
    gpio_set(SPI_DISPLAY_BKL);
    return true;
}

/* 5x7 font (96 chars: ASCII 32..127)
   Each character is 5 bytes (columns), LSB top. Standard tiny font.
   Source: common 5x7 font table.
*/
static const uint8_t font5x7[96][5] = {
    // space (32)
    {0x00,0x00,0x00,0x00,0x00}, // ' '
    {0x00,0x00,0x5F,0x00,0x00}, // !
    {0x00,0x07,0x00,0x07,0x00}, // "
    {0x14,0x7F,0x14,0x7F,0x14}, // #
    {0x24,0x2A,0x7F,0x2A,0x12}, // $
    {0x23,0x13,0x08,0x64,0x62}, // %
    {0x36,0x49,0x55,0x22,0x50}, // &
    {0x00,0x05,0x03,0x00,0x00}, // '
    {0x00,0x1C,0x22,0x41,0x00}, // (
    {0x00,0x41,0x22,0x1C,0x00}, // )
    {0x14,0x08,0x3E,0x08,0x14}, // *
    {0x08,0x08,0x3E,0x08,0x08}, // +
    {0x00,0x50,0x30,0x00,0x00}, // ,
    {0x08,0x08,0x08,0x08,0x08}, // -
    {0x00,0x60,0x60,0x00,0x00}, // .
    {0x20,0x10,0x08,0x04,0x02}, // /
    {0x3E,0x51,0x49,0x45,0x3E}, // 0
    {0x00,0x42,0x7F,0x40,0x00}, // 1
    {0x72,0x49,0x49,0x49,0x46}, // 2
    {0x21,0x41,0x49,0x4D,0x33}, // 3
    {0x18,0x14,0x12,0x7F,0x10}, // 4
    {0x27,0x45,0x45,0x45,0x39}, // 5
    {0x3C,0x4A,0x49,0x49,0x30}, // 6
    {0x01,0x71,0x09,0x05,0x03}, // 7
    {0x36,0x49,0x49,0x49,0x36}, // 8
    {0x06,0x49,0x49,0x29,0x1E}, // 9
    {0x00,0x36,0x36,0x00,0x00}, // :
    {0x00,0x56,0x36,0x00,0x00}, // ;
    {0x08,0x14,0x22,0x41,0x00}, // <
    {0x14,0x14,0x14,0x14,0x14}, // =
    {0x00,0x41,0x22,0x14,0x08}, // >
    {0x02,0x01,0x59,0x09,0x06}, // ?
    {0x3E,0x41,0x5D,0x59,0x4E}, // @
    {0x7C,0x12,0x11,0x12,0x7C}, // A
    {0x7F,0x49,0x49,0x49,0x36}, // B
    {0x3E,0x41,0x41,0x41,0x22}, // C
    {0x7F,0x41,0x41,0x22,0x1C}, // D
    {0x7F,0x49,0x49,0x49,0x41}, // E
    {0x7F,0x09,0x09,0x09,0x01}, // F
    {0x3E,0x41,0x49,0x49,0x7A}, // G
    {0x7F,0x08,0x08,0x08,0x7F}, // H
    {0x00,0x41,0x7F,0x41,0x00}, // I
    {0x20,0x40,0x41,0x3F,0x01}, // J
    {0x7F,0x08,0x14,0x22,0x41}, // K
    {0x7F,0x40,0x40,0x40,0x40}, // L
    {0x7F,0x02,0x04,0x02,0x7F}, // M
    {0x7F,0x04,0x08,0x10,0x7F}, // N
    {0x3E,0x41,0x41,0x41,0x3E}, // O
    {0x7F,0x09,0x09,0x09,0x06}, // P
    {0x3E,0x41,0x51,0x21,0x5E}, // Q
    {0x7F,0x09,0x19,0x29,0x46}, // R
    {0x46,0x49,0x49,0x49,0x31}, // S
    {0x01,0x01,0x7F,0x01,0x01}, // T
    {0x3F,0x40,0x40,0x40,0x3F}, // U
    {0x1F,0x20,0x40,0x20,0x1F}, // V
    {0x3F,0x40,0x38,0x40,0x3F}, // W
    {0x63,0x14,0x08,0x14,0x63}, // X
    {0x07,0x08,0x70,0x08,0x07}, // Y
    {0x61,0x51,0x49,0x45,0x43}, // Z
    {0x00,0x7F,0x41,0x41,0x00}, // [
    {0x02,0x04,0x08,0x10,0x20}, // backslash
    {0x00,0x41,0x41,0x7F,0x00}, // ]
    {0x04,0x02,0x01,0x02,0x04}, // ^
    {0x40,0x40,0x40,0x40,0x40}, // _
    {0x00,0x01,0x02,0x04,0x00}, // `
    {0x20,0x54,0x54,0x54,0x78}, // a
    {0x7F,0x48,0x44,0x44,0x38}, // b
    {0x38,0x44,0x44,0x44,0x20}, // c
    {0x38,0x44,0x44,0x48,0x7F}, // d
    {0x38,0x54,0x54,0x54,0x18}, // e
    {0x08,0x7E,0x09,0x01,0x02}, // f
    {0x0C,0x52,0x52,0x52,0x3E}, // g
    {0x7F,0x08,0x04,0x04,0x78}, // h
    {0x00,0x44,0x7D,0x40,0x00}, // i
    {0x20,0x40,0x44,0x3D,0x00}, // j
    {0x7F,0x10,0x28,0x44,0x00}, // k
    {0x00,0x41,0x7F,0x40,0x00}, // l
    {0x7C,0x04,0x18,0x04,0x78}, // m
    {0x7C,0x08,0x04,0x04,0x78}, // n
    {0x38,0x44,0x44,0x44,0x38}, // o
    {0x7C,0x14,0x14,0x14,0x08}, // p
    {0x08,0x14,0x14,0x18,0x7C}, // q
    {0x7C,0x08,0x04,0x04,0x08}, // r
    {0x48,0x54,0x54,0x54,0x20}, // s
    {0x04,0x3F,0x44,0x40,0x20}, // t
    {0x3C,0x40,0x40,0x20,0x7C}, // u
    {0x1C,0x20,0x40,0x20,0x1C}, // v
    {0x3C,0x40,0x30,0x40,0x3C}, // w
    {0x44,0x28,0x10,0x28,0x44}, // x
    {0x0C,0x50,0x50,0x50,0x3C}, // y
    {0x44,0x64,0x54,0x4C,0x44}, // z
    {0x00,0x08,0x36,0x41,0x00}, // {
    {0x00,0x00,0x7F,0x00,0x00}, // |
    {0x00,0x41,0x36,0x08,0x00}, // }
    {0x10,0x08,0x08,0x10,0x08}, // ~
};

// Helper: convert 8-bit RGB to RGB565 
static inline uint16_t rgb565(uint8_t r, uint8_t g, uint8_t b)
{
    return (uint16_t)(((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)); 
}

// ST7735 helper: set address window (column/row)
static void set_address_window(uint8_t x0, uint8_t y0, uint8_t x1, uint8_t y1) 
{
    uint8_t data[4];
    send_command(0x2A);
    data[0] = 0x00;
    data[1] = x0 + X_OFFSET;
    data[2] = 0x00;
    data[3] = x1 + X_OFFSET;
    send_data(data, 4);

    send_command(0x2B);
    data[0] = 0x00;
    data[1] = y0 + Y_OFFSET;
    data[2] = 0x00;
    data[3] = y1 + Y_OFFSET;
    send_data(data, 4);
}

void fill_screen_black(void)
{
    memset(framebuffer, 0x00, sizeof(framebuffer));
}

void flush_framebuffer(void)
{
    set_address_window(0, 0, TFT_WIDTH - 1, TFT_HEIGHT - 1);
    send_command(0x2C);

    /*
     * Send in chunks, byte-swapped for ST7735 RGB565.
     * This is much better than sending one pixel at a time.
     */
    enum { PIXELS_PER_CHUNK = 256 };
    uint8_t out[PIXELS_PER_CHUNK * 2];

    size_t total_pixels = (size_t)TFT_WIDTH * TFT_HEIGHT;

    for (size_t i = 0; i < total_pixels; ) {
        size_t n = total_pixels - i;
        if (n > PIXELS_PER_CHUNK) n = PIXELS_PER_CHUNK;

        for (size_t j = 0; j < n; j++) {
            uint16_t px = framebuffer[i + j];
            out[j * 2 + 0] = (uint8_t)(px >> 8);
            out[j * 2 + 1] = (uint8_t)(px & 0xFF);
        }

        send_data(out, n * 2);
        i += n;
    }
}

static inline void fb_set_pixel(uint8_t x, uint8_t y, uint16_t color)
{
    if (x >= TFT_WIDTH || y >= TFT_HEIGHT) return;
    framebuffer[(size_t)y * TFT_WIDTH + x] = color;
}

static void fb_fill_rect(uint8_t x, uint8_t y, uint8_t w, uint8_t h, uint16_t color)
{
    if (x >= TFT_WIDTH || y >= TFT_HEIGHT) return;

    if ((uint16_t)x + w > TFT_WIDTH)  w = TFT_WIDTH - x;
    if ((uint16_t)y + h > TFT_HEIGHT) h = TFT_HEIGHT - y;

    for (uint8_t yy = 0; yy < h; yy++) {
        size_t row = (size_t)(y + yy) * TFT_WIDTH + x;
        for (uint8_t xx = 0; xx < w; xx++) {
            framebuffer[row + xx] = color;
        }
    }
}

static void fb_draw_char(uint8_t x, uint8_t y, char c, uint16_t fg, uint16_t bg)
{
    if (c < 32 || c > 127) c = '?';
    const uint8_t *ch = font5x7[c - 32];

    fb_fill_rect(x, y, 6, 8, bg);

    for (uint8_t col = 0; col < 5; col++) {
        uint8_t colbits = ch[col];
        for (uint8_t row = 0; row < 7; row++) {
            if (colbits & (1U << row)) {
                fb_set_pixel(x + col, y + row, fg);
            }
        }
    }
}

static void fb_draw_text(uint8_t x, uint8_t y, const char *s, uint16_t fg, uint16_t bg)
{
    while (*s) {
        fb_draw_char(x, y, *s, fg, bg);
        x += 6 + FONT_SPACING;
        s++;
    }
}

static void draw_bitmap_rgb565(uint8_t x, uint8_t y, const uint16_t *bmp, uint8_t w, uint8_t h, uint16_t bg)
{
    fb_fill_rect(x, y, w, h, bg);

    for (uint8_t row = 0; row < h; row++) {
        for (uint8_t col = 0; col < w; col++) {
            uint16_t p = bmp[row * w + col];
            if (p != 0x0000) {
                fb_set_pixel(x + col, y + row, p);
            }
        }
    }
}

// Example: format float voltage (V) into string buffer ("3.30V")
static void format_voltage_str(char *buf, size_t buf_len, float volts)
{
    // ensure one decimal or two decimals as desired
    // we'll print with 2 decimals
    snprintf(buf, buf_len, "%.2fV", volts);
}

static void format_current_str(char *buf, size_t buf_len, float curr)
{
    // ensure one decimal or two decimals as desired
    // we'll print with 2 decimals
    snprintf(buf, buf_len, "%.2fmA", curr);
}

// Clear entire screen to bg color
static void clear_screen(uint16_t bg_color)
{
    fb_fill_rect(0, 0, TFT_WIDTH, TFT_HEIGHT, bg_color);
}

// Compose and update the fields: battery, version, center counter, heart state
static void update_display()
{
    int peers_count = peer_count();
    // colors
    uint16_t black = rgb565(0,0,0);
    uint16_t white = rgb565(255,255,255);
    uint16_t red   = rgb565(255,0,0);

    // clear entire screen black (or do partial updates if you prefer)
    clear_screen(black);

    // top-right: battery voltage and version (stacked)
    char volt_buf[16];
    float batt_voltage = (ina219_bus_mv / 1000.00);
    format_voltage_str(volt_buf, sizeof(volt_buf), batt_voltage);

    char current_buf[16];
    format_current_str(current_buf, sizeof(current_buf), ina219_current_ma);

    //-------------------------------------
    //Show WPR version on top
    char wpr_version[64];
    snprintf(wpr_version, sizeof(wpr_version), "%s", APP_VERSION);
    int app_info_width = (int)strlen(wpr_version);
    int x_app = (TFT_WIDTH - app_info_width * (6 + FONT_SPACING)) / 2;
    int y_app = TOP_MARGIN + 5;
    fb_draw_text((uint8_t)x_app, (uint8_t)y_app, wpr_version, white, black);

    char batt_volt[32];
    snprintf(batt_volt, sizeof(batt_volt), "BATT: %s", volt_buf);
    int batt_info_width = (int)strlen(batt_volt);
    int x_batt = (TFT_WIDTH - batt_info_width * (6 + FONT_SPACING)) / 2;
    int y_batt = y_app + 12;
    fb_draw_text((uint8_t)x_batt, (uint8_t)y_batt, batt_volt, white, black);

    
    char batt_curr[32];
    snprintf(batt_curr, sizeof(batt_curr), "CURR: %s", current_buf);
    int batt_curr_width = (int)strlen(batt_curr);
    int x_curr = (TFT_WIDTH - batt_curr_width * (6 + FONT_SPACING)) / 2;
    int y_curr = y_batt + 12;
    fb_draw_text((uint8_t)x_curr, (uint8_t)y_curr, batt_curr, white, black);


    char rx_info[64];
    snprintf(rx_info, sizeof(rx_info), "DSC RX: %lu", discoveryFrameRX);
    int rx_info_len = strlen(rx_info);
    int cx = (TFT_WIDTH - rx_info_len * (6 + FONT_SPACING)) / 2;
    int cy = y_curr + 12;
    if (cx < 0) cx = 0;
    fb_draw_text((uint8_t)cx, (uint8_t)cy, rx_info, white, black);
    
    char tx_info[64];
    snprintf(tx_info, sizeof(tx_info), "DSC TX: %lu", discoveryFrameTX);
    int tx_info_len = strlen(tx_info);
    cx = (TFT_WIDTH - tx_info_len * (6 + FONT_SPACING)) / 2;
    int tx_y = cy + 12;
    if (cx < 0) cx = 0;
    fb_draw_text((uint8_t)cx, (uint8_t)tx_y, tx_info, white, black);

    char rf_buf[32];
    if (rfPower == 3000){
        snprintf(rf_buf, sizeof(rf_buf), "RFP: POWWAAA!");
    }else{
        snprintf(rf_buf, sizeof(rf_buf), "RFP: %d", rfPower);
    }

    int rf_len = strlen(rf_buf);
    int rfx = (TFT_WIDTH - rf_len * (6 + FONT_SPACING)) / 2;
    int rfy = tx_y + 12;

    if (rfx < 0) rfx = 0;

    if (rfPower == 3000)
    {
        fb_draw_text((uint8_t)rfx, (uint8_t)rfy, rf_buf, red, black);
    }
    else
    {
        fb_draw_text((uint8_t)rfx, (uint8_t)rfy, rf_buf, white, black);
    }

    char peer_count_buf[32];
    snprintf(peer_count_buf, sizeof(peer_count_buf), "Peers: %d", peers_count);
    int peer_len = strlen(peer_count_buf);
    int peerx = (TFT_WIDTH - peer_len * (6 + FONT_SPACING)) / 2;
    int peery = rfy + 12;
    if (peerx < 0) peerx = 0;
    fb_draw_text((uint8_t)peerx, (uint8_t)peery, peer_count_buf, white, black);

    char rssi_buf[64];
    snprintf(rssi_buf, sizeof(rssi_buf), "RSSI: %d, %d", ant1RSSI_dBm, ant2RSSI_dBm);
    int rssi_len = strlen(rssi_buf);
    int rssix = (TFT_WIDTH - rssi_len * (6 + FONT_SPACING)) / 2;
    int rssiy = peery + 12;
    if (rssix < 0) rssix = 0;
    fb_draw_text((uint8_t)rssix, (uint8_t)rssiy, rssi_buf, white, black);

    char noise_buf[64];
    snprintf(noise_buf, sizeof(noise_buf), "Noise: %d, %d", ant1Noise_dBm, ant2Noise_dBm);
    int noise_len = strlen(noise_buf);
    int noisex = (TFT_WIDTH - noise_len * (6 + FONT_SPACING)) / 2;
    int noisey = rssiy + 12;
    if (noisex < 0) noisex = 0;
    fb_draw_text((uint8_t)noisex, (uint8_t)noisey, noise_buf, white, black);

    flush_framebuffer();
}

#endif

#ifdef USE_INA219_SENSOR

static int ina219_write_u16(int fd, uint8_t reg, uint16_t value)
{
    uint8_t buf[3];
    buf[0] = reg;
    buf[1] = (uint8_t)(value >> 8);   // MSB first
    buf[2] = (uint8_t)(value & 0xFF);

    return (write(fd, buf, 3) == 3) ? 0 : -1;
}

static int ina219_read_u16(int fd, uint8_t reg, uint16_t *value)
{
    uint8_t r = reg;
    uint8_t buf[2];

    if (write(fd, &r, 1) != 1) {
        return -1;
    }

    if (read(fd, buf, 2) != 2) {
        return -1;
    }

    *value = ((uint16_t)buf[0] << 8) | buf[1];
    return 0;
}

static int ina219_init(ina219_t *dev, int fd, uint8_t addr, float shunt_ohms, float max_expected_current_a)
{
    if (ioctl(fd, I2C_SLAVE, addr) < 0) {
        printf("INA219 fault detected \n");
        dev->fd = -1;
        close(i2c_fd);
        return -1;
    }

    dev->fd = fd;
    dev->addr = addr;

    /*
     * Pick current_LSB based on the max expected current.
     * Example: 3.2A max -> about 97.7uA per bit.
     */
    dev->current_lsb_a = max_expected_current_a / 32768.0f;

    /*
     * Calibration formula from INA219 datasheet:
     * Cal = 0.04096 / (Current_LSB * Rshunt)
     */
    uint16_t cal = (uint16_t)(0.04096f / (dev->current_lsb_a * shunt_ohms));
    if (cal == 0) {
        return -1;
    }

    if (ina219_write_u16(fd, INA219_REG_CALIB, cal) < 0) {
        return -1;
    }

    /*
     * Continuous shunt and bus voltage conversion.
     * 32V range, 320mV shunt gain, 12-bit conversions.
     */
    uint16_t config =
        INA219_CFG_BVOLT_32V |
        INA219_CFG_GAIN_320MV |
        INA219_CFG_BADC_12BIT |
        INA219_CFG_SADC_12BIT |
        INA219_CFG_MODE_CONT;

    if (ina219_write_u16(fd, INA219_REG_CONFIG, config) < 0) {
        return -1;
    }

    return 0;
}

static int ina219_read_bus_voltage_mv(ina219_t *dev, uint16_t *mv)
{
    uint16_t raw;

    if (ina219_read_u16(dev->fd, INA219_REG_BUS, &raw) < 0) {
        return -1;
    }

    /*
     * Bus voltage register:
     * bits [15:3] contain value, LSB = 4mV
     */
    raw >>= 3;
    *mv = (uint16_t)(raw * 4);

    return 0;
}

static int ina219_read_current_ma(ina219_t *dev, float *current_ma)
{
    uint16_t raw_u16;
    int16_t raw_s16;

    if (ina219_read_u16(dev->fd, INA219_REG_CURRENT, &raw_u16) < 0) {
        return -1;
    }

    raw_s16 = (int16_t)raw_u16;

    /*
     * Current register = signed value * current_lsb
     */
    *current_ma = (float)raw_s16 * dev->current_lsb_a * 1000.0f;

    return 0;
}

static void setup_ina219(void)
{
    printf("Setting up i2c-bus...\n");

    i2c_fd = open("/dev/i2c-1", O_RDWR);
    if (i2c_fd < 0) {
        perror("Failed to open I2C bus");
    }

    if (ina219_init(&ina, i2c_fd, 0x40, 0.1f, 3.2f) < 0) {
        printf("Unable to init INA219 sensor...");
    }
}

static void read_ina219(void)
{
    if (ina.fd <= 0){
        return;
    }

    if (!(ina219_read_bus_voltage_mv(&ina, &ina219_bus_mv) == 0 && ina219_read_current_ma(&ina, &ina219_current_ma) == 0))
    {
        ina219_bus_mv = 0;
        ina219_current_ma = 0;
    }
}

#endif

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

    //Default rfPower on app start
    setRFPower(rfPower);

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

static void fatal(const char *msg, int err) {
    if (err)
        fprintf(stderr, "%s: %s\n", msg, snd_strerror(err));
    else
        fprintf(stderr, "%s\n", msg);
    cleanup();
}

static snd_pcm_t *try_open_pcm_device(const char *device) {
    snd_pcm_t *pcm = NULL;
    int err = snd_pcm_open(&pcm, device, SND_PCM_STREAM_PLAYBACK, 0);
    if (err < 0) {
        return NULL;
    }
    return pcm;
}

static snd_pcm_t *open_pcm_sndcard(void) {
    snd_pcm_t *pcm = NULL;
    int err;

    pcm = try_open_pcm_device("default");
    if (pcm) return pcm;

    int card = -1;
    if ((err = snd_card_next(&card)) < 0) {
        fprintf(stderr, "snd_card_next error: %s\n", snd_strerror(err));
        return NULL;
    }

    while (card >= 0) {
        char dev[64];

        // try plughw:card,0 first (allows automatic conversion)
        snprintf(dev, sizeof(dev), "plughw:%d,0", card);
        pcm = try_open_pcm_device(dev);
        if (pcm) return pcm;

        // try hw:card,0
        snprintf(dev, sizeof(dev), "hw:%d,0", card);
        pcm = try_open_pcm_device(dev);
        if (pcm) return pcm;

        // next card
        if ((err = snd_card_next(&card)) < 0) {
            fprintf(stderr, "snd_card_next error: %s\n", snd_strerror(err));
            break;
        }
    }

    // nothing found
    return NULL;
}

static void set_hw_params(snd_pcm_t *pcm, unsigned int sample_rate, int channels, snd_pcm_format_t format) {
    snd_pcm_hw_params_t *hw;
    int err;

    snd_pcm_hw_params_malloc(&hw);
    snd_pcm_hw_params_any(pcm, hw);

    err = snd_pcm_hw_params_set_access(pcm, hw, SND_PCM_ACCESS_RW_INTERLEAVED);
    if (err < 0) fatal("Failed to set access", err);

    err = snd_pcm_hw_params_set_format(pcm, hw, format);
    if (err < 0) fatal("Failed to set format", err);

    err = snd_pcm_hw_params_set_channels(pcm, hw, channels);
    if (err < 0) fatal("Failed to set channels", err);

    unsigned int rate = sample_rate;
    err = snd_pcm_hw_params_set_rate_near(pcm, hw, &rate, 0);
    if (err < 0) fatal("Failed to set rate", err);
    if (rate != sample_rate) {
        fprintf(stderr, "Requested sample rate %u, got %u\n", sample_rate, rate);
    }

    snd_pcm_uframes_t period = PERIOD_FRAMES;
    snd_pcm_uframes_t buffer = BUFFER_FRAMES;
    err = snd_pcm_hw_params_set_period_size_near(pcm, hw, &period, 0);
    if (err < 0) fatal("Failed to set period size", err);

    err = snd_pcm_hw_params_set_buffer_size_near(pcm, hw, &buffer);
    if (err < 0) fatal("Failed to set buffer size", err);

    err = snd_pcm_hw_params(pcm, hw);
    if (err < 0) fatal("Failed to apply HW params", err);

    snd_pcm_hw_params_free(hw);
}

static void audio_channel_timeout_check(void)
{
    uint64_t t = now_us();

    for (int i = 0; i < 4; i++)
    {
        if (channels[i].active && (t - channels[i].last_rx_us) > (ONE_MS_IN_US * 100))
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
        printf("Setting radio_fd nonblock...\n");
    }

    if (set_fd_nonblocking(radio_fd) != 0) {
        close(radio_fd);
        cleanup();
    }

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
}

static bool add_to_tx_queue(struct wpr_data *pkt)
{
    if (!wpr_enqueue(pkt))
    {
        printf("Buffer full, dropping oldest packet...\n");
        // queue full -- handle overflow (drop, log, or backoff)
        // pop oldest
        tx_queue.head = (tx_queue.head + 1) % WPR_TX_QUEUE_SZ;
        tx_queue.len--;
        // push new
        memcpy(&tx_queue.items[tx_queue.tail], &pkt, sizeof(struct wpr_data));
        tx_queue.tail = (tx_queue.tail + 1) % WPR_TX_QUEUE_SZ;
        tx_queue.len++;
    }
    return true;
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
        fprintf(stderr, "send_radio_data: radio_fd not open, aborting send\n");
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

static void send_radio_tx_queue(void)
{
    struct wpr_data pkt;
    // Dequeue and send until empty or until you hit a sending quota (not imposed here)
    while (wpr_dequeue(&pkt))
    {
        // send_radio_data copies the data as you described (user-supplied)
        // Note: send_radio_data may block or take time — consider doing this outside critical sections.
        if ((uint64_t)send_radio_data(&pkt, sizeof(pkt)) < 0)
        {
            fprintf(stderr, "send_radio_tx_queue: radio send failed.\n");
        }
    }
}

static void decode_codec2_voice_data(const uint8_t *voice, size_t voice_len)
{
    if (codec2 == NULL)
    {
        fprintf(stderr, "Codec2 invalid!\n");
        return;
    }

    ssize_t nsamples = codec2_samples_per_frame(codec2); // For CODEC2_MODE_3200, it is 160 samples.
    //size_t pcm_bytes = (size_t)nsamples * sizeof(int16_t);

    if (voice_len == 0)
        return;

    // Prepare the PCM buffer...
    int16_t pcm_arr[nsamples];
    int16_t *pcm = pcm_arr;

    codec2_decode(codec2, pcm, voice);

    if (soundCardFound)
    {
        if (pcmDevice) {
            snd_pcm_sframes_t frames = nsamples; /* nsamples is frames for mono interleaved int16 */
            snd_pcm_sframes_t written = snd_pcm_writei(pcmDevice, pcm, frames);

            if (written == -EPIPE) {
                /* underrun */
                fprintf(stderr, "ALSA underrun: preparing device\n");
                int err = snd_pcm_prepare(pcmDevice);
                if (err < 0) {
                    fprintf(stderr, "snd_pcm_prepare failed: %s\n", snd_strerror(err));
                    /* optionally fall back to socket or return */
                } else {
                    /* try writing again once */
                    written = snd_pcm_writei(pcmDevice, pcm, frames);
                }
            } 
            else if (written == -ESTRPIPE)
            {
                /* suspended; try resume */
                while ((written = snd_pcm_resume(pcmDevice)) == -EAGAIN) sleep(1);
                if (written < 0) {
                    int err = snd_pcm_prepare(pcmDevice);
                    if (err < 0) {
                        fprintf(stderr, "snd_pcm_prepare after resume failed: %s\n", snd_strerror(err));
                    } else {
                        written = snd_pcm_writei(pcmDevice, pcm, frames);
                    }
                } else {
                    /* resumed: try writing */
                    written = snd_pcm_writei(pcmDevice, pcm, frames);
                }
            }

            if (written < 0) {
                int err = snd_pcm_recover(pcmDevice, written, 1);
                if (err < 0) {
                    fprintf(stderr, "ALSA write failed and recover failed: %s\n", snd_strerror(err));
                }
            } 
            else if (written != frames) 
            {
                fprintf(stderr, "ALSA short write: wrote %ld of %ld frames\n", (long)written, (long)frames);
                /* partial write handling: advance buffer and write remaining frames (rare with proper buffering) */
                snd_pcm_sframes_t remaining = frames - written;
                int16_t *ptr = pcm + written;
                while (remaining > 0) {
                    snd_pcm_sframes_t w2 = snd_pcm_writei(pcmDevice, ptr, remaining);
                    if (w2 < 0) {
                        int err = snd_pcm_recover(pcmDevice, w2, 1);
                        if (err < 0) {
                            fprintf(stderr, "ALSA write/recover failed during remainder: %s\n", snd_strerror(err));
                            break;
                        }
                        continue;
                    }
                    remaining -= w2;
                    ptr += w2;
                }
            }
        }else{
            fprintf(stderr, "No PCM audio device found!");
            return;
        }
    }
}

static void send_discovery_ping(){
    //TODO: Make sure it does not roll over and let app crash.
    discoveryFrameTX++;

    struct wpr_mesh mesh_tx;
    memset(mesh_tx.dst, 0xFF, 6);
    mesh_tx.msgtype = RADIO_DATA_MESH_MSG_DISCOVERY_PING;
    uint64_t t = now_us();
    memcpy(mesh_tx.msg, &t, sizeof(t));

    //Construct and send this message...
    struct wpr_data wpr_send_ping;

    wpr_send_ping.data_type = RADIO_DATA_MESH;
    wpr_send_ping.magic_header = DATA_HDR_MAGIC;
    memcpy(wpr_send_ping.data, &mesh_tx, sizeof(mesh_tx));
    
    if (!add_to_tx_queue(&wpr_send_ping))
    {
        fprintf(stderr, "send_discovery_ping: radio tx message enqueue failed.\n");
    }
}

static void send_discovery_pong(uint8_t addr[6]){
    //Construct the discovery ping message to send..
    struct wpr_mesh mesh_tx_pong;
    memcpy(mesh_tx_pong.dst, &addr, 6);
    mesh_tx_pong.msgtype = RADIO_DATA_MESH_MSG_DISCOVERY_PONG;
    uint64_t t = now_us();
    memcpy(mesh_tx_pong.msg, &t, sizeof(t));

    //Construct and send this message...
    struct wpr_data wpr_send_pong;

    wpr_send_pong.data_type = RADIO_DATA_MESH;
    wpr_send_pong.magic_header = DATA_HDR_MAGIC;
    memcpy(wpr_send_pong.data, &mesh_tx_pong, sizeof(mesh_tx_pong));
    
    if (!add_to_tx_queue(&wpr_send_pong))
    {
        fprintf(stderr, "send_discovery_pong: radio tx message enqueue failed.\n");
    }
}

static void process_wpr_data_rx(uint8_t srcAddr[6], int8_t ant1rssi, int8_t ant2rssi, int8_t ant1nois, int8_t ant2nois)
{
    uint8_t data_type = wpr_data_rx.data_type;
    ant1RSSI_dBm = ant1rssi;
    ant2RSSI_dBm = ant2rssi;
    ant1Noise_dBm = ant1nois;
    ant2Noise_dBm = ant2nois;
    
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
            goto process_wpr_mesh;
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
            ch->last_rx_us = now_us();

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

process_wpr_mesh:
    struct wpr_mesh mesh_data;

    memcpy(&mesh_data, wpr_data_rx.data, sizeof(struct wpr_mesh));

    uint8_t mesh_command = mesh_data.msgtype;

    switch (mesh_command)
    {
        //We got a discovery ping message, send a pong message.
    case RADIO_DATA_MESH_MSG_DISCOVERY_PING:
        //TODO, make sure it does not roll over and crash and burn.
        discoveryFrameRX++;

        //printf("Ping message from: %s, Ant1-> RSSI: %d dBm, Noise: %d, Ant2 -> RSSI: %d dBm, Noise: %d\n", mac_to_string(srcAddr), ant1rssi, ant1nois, ant2rssi, ant2nois);
        send_discovery_pong(srcAddr);
        break;
    case RADIO_DATA_MESH_MSG_DISCOVERY_PONG:

        peer_update_from_pong(srcAddr, ant1rssi, ant1nois, ant2rssi, ant2nois, now_us());
        //printf("Pong message from: %s, Ant1-> RSSI: %d dBm, Noise: %d, Ant2 -> RSSI: %d dBm, Noise: %d\n", mac_to_string(srcAddr), ant1rssi, ant1nois, ant2rssi, ant2nois);

        break;
    case RADIO_DATA_MESH_MSG_FORWARD_AUDIO:
        printf("Feature not available yet.\n");
        return;
    default:
        printf("Unknown mesh radio command: %u\n", mesh_command);
        return;
    }
}

static void parse_radio_message(const uint8_t *pkt, size_t len)
{
    uint8_t antIndex = 0;
    int8_t ant1dBm = 0;
    int8_t ant2dBm = 0;
    int8_t ant1noise = 0;
    int8_t ant2noise = 0;

    // TODO: Implement FCS data framing
    // Start to decode the ieee80211_radiotap_header data
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
                {
                    if (antIndex == 0){
                        ant1dBm = *(int8_t *)it.this_arg;
                    }else{
                        ant2dBm = *(int8_t *)it.this_arg;
                    }
                }
                break;
            case IEEE80211_RADIOTAP_DBM_ANTNOISE:
                {
                    if (antIndex == 0){
                        ant1noise = *(int8_t *)it.this_arg;
                    }else{
                        ant2noise = *(int8_t *)it.this_arg;
                    }
                }
                break;
            case IEEE80211_RADIOTAP_ANTENNA:
                {
                    antIndex++;
                }
                break;
            //case IEEE80211_RADIOTAP_RX_FLAGS:
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
    process_wpr_data_rx(mac_hdr->addr3, ant1dBm, ant2dBm, ant1noise, ant2noise);
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

static void send_test_tone(void)
{
    if (debug)
    {
        printf("Sending test tone...\n");
    }

    if (codec2 == NULL)
    {
        fprintf(stderr, "Codec2 not initialized (send_test_tone)\n");
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
        if (toneIdx == 0){
            break;
        }

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

#ifdef SPI_DISPLAY_ENABLED
static button_event_t button_update(void)
{
    static bool last_raw = false;
    static bool stable_state = false;
    static uint64_t last_change_us = 0;
    static uint64_t press_start_us = 0;

    uint64_t now = now_us();
    bool raw = readButton();

    if (raw != last_raw) {
        last_raw = raw;
        last_change_us = now;
    }

    if ((now - last_change_us) < BUTTON_DEBOUNCE_US) {
        return BUTTON_EVENT_NONE;
    }

    if (stable_state != raw) {
        stable_state = raw;

        if (stable_state) {
            press_start_us = now;
        } else {
            uint64_t held_us = now - press_start_us;

            if (held_us >= BUTTON_LONG_PRESS_US) {
                return BUTTON_EVENT_LONG;
            } else {
                return BUTTON_EVENT_SHORT;
            }
        }
    }

    return BUTTON_EVENT_NONE;
}

static void doButtonStuff(void)
{
    button_event_t ev = button_update();

    switch (ev) {
        case BUTTON_EVENT_SHORT:
            rfPower += 250;
            if (rfPower > 3000) {
                rfPower = 250;
            }
            setRFPower(rfPower);
            break;

        case BUTTON_EVENT_LONG:
            printf("Shutting down...\n");
            run_cmd("poweroff");
            break;

        default:
            break;
    }
}
#endif

static void do_main_loop(int argc, char *argv[])
{
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
            else if (strcmp(argv[1], "rxtx") == 0 || strcmp(argv[1], "txrx") == 0)
            {
                isRadioReceiving = true;
                isRadioTransmitting = true;
            }
            else
            {
                printf("Unknown parameter, aborting.");
                cleanup();
            }
        }
        else
        {
            printf("Unknown count of parameters, aborting\n");
            cleanup();
        }
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

        //Not using a PCM sound card device for now, just want to TX/RX mesh data for testing purposes.
        // pcmDevice = open_pcm_sndcard();
        // if (pcmDevice != NULL){
        //     printf("Found PCM device, configuring...\n");
        //     set_hw_params(pcmDevice, SAMPLE_RATE, CHANNELS, FORMAT);

        //     int bytes_per_frame = snd_pcm_format_width(FORMAT) / 8 * CHANNELS;
        //     if (bytes_per_frame <= 0) fatal("Invalid format width", 0);

        //     printf("PCM audio out device configured...\n");
        //     soundCardFound = true;
        // }else{
        //     printf("Unable to find a soundcard device...\n");
        //     soundCardFound = false;
        // }
    }

    uint64_t now_in_us = 0;
    uint64_t peerNodeListCleanup = 0;
    uint64_t loggerTS = 0;
#ifdef SPI_DISPLAY_ENABLED
    uint64_t refreshDisplayTime = 0;
#endif
    uint64_t discoverySend = 0;
    

    if (codec2 == NULL)
    {
        fprintf(stderr, "Codec2 not initialized (do_main_loop)\n");
        cleanup();
    }

    printf("Starting application loop...\n");

    while (running)
    {
        now_in_us = now_us();

        if (now_in_us - loggerTS > (ONE_MS_IN_US * 2000))
        {
            loggerTS = now_in_us;
            printf("Health message -> RFPower %d, Peer count: %d, Mesh ping TX: %lu, Mesh ping RX: %lu\nRSSI: %d, %d dBm, Noise: %d, %d dBm\n", 
                rfPower, 
                peer_count(), 
                discoveryFrameTX, 
                discoveryFrameRX, 
                ant1RSSI_dBm, 
                ant2RSSI_dBm, 
                ant1Noise_dBm, 
                ant2Noise_dBm
            );
        }

#ifdef SPI_DISPLAY_ENABLED
        doButtonStuff();

        if (usingDisplay){
            if (now_in_us - refreshDisplayTime > (ONE_MS_IN_US * 100))
            {
#ifdef USE_INA219_SENSOR
                read_ina219();
#endif
                refreshDisplayTime = now_in_us;
                //Refresh the display here
                update_display();
            }
        }
#endif

        if (now_in_us - peerNodeListCleanup > (ONE_MS_IN_US * 500))
        {
            peerNodeListCleanup = now_in_us;
            peer_cleanup_old(now_in_us, (ONE_MS_IN_US * 500));
        }

        if (isRadioTransmitting)
        {
            if (now_in_us - discoverySend > (ONE_MS_IN_US * 100))
            {
                discoverySend = now_in_us;
                //printf("Sending discovery message...\n");
                send_discovery_ping();
                send_radio_tx_queue();
            }
        }

        if (isRadioReceiving)
        {
            if (usingPcap)
            {
                struct pcap_pkthdr *hdr_ptr;
                const u_char *pkt_ptr;
                int res;

                // In non-blocking mode pcap_next_ex returns:
                //  1 -> got a packet (hdr_ptr and pkt_ptr set)
                //  0 -> timeout expired / no packet (non-blocking gives 0 immediately)
                // -1 -> error
                // -2 -> EOF (dead capture)
                while ((res = pcap_next_ex(pcap_handle, &hdr_ptr, &pkt_ptr)) != -1) {
                    if (res == 0) {
                        // no packet available right now (non-blocking)
                        break; // drain loop
                    }
                    // res == 1 : have packet
                    parse_radio_message(pkt_ptr, hdr_ptr->caplen);

                    //After radio message parsed, try to send here?
                    send_radio_tx_queue();
                }

                if (res == -1) {
                    fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(pcap_handle));
                    cleanup();
                    //TODO: implement error counter and abort if errors gets a handful.
                }
            }
        }

        audio_channel_timeout_check();

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

    init_tx_queue();

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, sigint);
    signal(SIGTERM, sigint);

    if (setpriority(PRIO_PROCESS, 0, -20) == -1)
    {
        perror("setpriority failed (are you root?)");
    }

#ifdef SPI_DISPLAY_ENABLED
    printf("Enabling SPI display...\n");
    usingDisplay = init_spi_display();
    if (!usingDisplay){
        printf("A SPI fault has been detected...\n");
    }
    else
    {
        fill_screen_black();
    }
#ifdef USE_INA219_SENSOR
    setup_ina219();
#endif
#endif

    do_main_loop(argc, argv);

    cleanup();
    return 0;
}