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
#include "fec.h"
#include "ringbuffer.h"
#include <alsa/asoundlib.h>


#if defined(__x86_64__) || defined(_M_X64)
#define RADIO_IFACE "wlan0"
#else
#define RADIO_IFACE "wlan1"
#define SPI_DISPLAY_ENABLED true
#include <gpiolib.h>
#define USE_INA219_SENSOR
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

static const char *SPI_DEV = "/dev/spidev0.0";
static const uint32_t SPI_SPEED = 32000000; // 32 MHz
static const uint8_t SPI_MODE = SPI_MODE_0;
static const uint8_t BITS_PER_WORD = 8;

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

struct peer_nodes
{
    uint8_t nodeID[6];      //MAC address of peer
    uint64_t lastSeen_us;   //Last time it was seen by us.
};

//One more byte available to send
struct wpr_mesh
{
    uint8_t msgtype; // Message type -> 1 byte
    uint8_t dst[6];  // Destination -> 6 bytes
    uint8_t msg[8];  // 9 bytes of message. (audio or time in 8 bytes)
};

struct wpr_data
{
    uint32_t magic_header;
    uint8_t data_type;
    uint8_t data[16];
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

#define PCM_BYTE_COUNT 160                             /* 20 ms of mono audio at 8 kHz */
#define PCM_100MS_BYTE_COUNT (PCM_BYTE_COUNT * 5)      // enough for 100 ms of audio, 160 bytes per 20 ms frame * 5 = 800 bytes
#define TEST_TONE_INTERVAL (PCM_100MS_BYTE_COUNT * 10) //

int16_t pcmToneBuffer[TEST_TONE_INTERVAL]; // about 1 second of tone at 8 kHz, 160 samples per 20 ms frame, so 160 * 5 = 800 bytes per 100 ms, so 800 * 10 = 8000 bytes for 1 second

//RingBuffer audioBuf;
snd_pcm_t *pcmDevice;
bool soundCardFound = false;
uint16_t discoveryFrameCounter = 0;
uint16_t discoveryFrameCounterOnLCD = 0;

#define SPI_DISPLAY_RST 22
#define SPI_DISPLAY_CMD 24
#define SPI_DISPLAY_BKL 12
#define TFT_HEIGHT 160
#define TFT_WIDTH 128

#define APP_VERSION "WPR dev-0.1.1"
#define HEART_BLINK_INTERVAL_S 1 // heartbeat every second
#define FONT_SPACING 1           // extra spacing between chars
#define TOP_MARGIN 2
#define RIGHT_MARGIN 2
#define CENTER_MARGIN 0

// Sensor section
#define INA219_SENSOR_ADDR 0x40
#define INA219_SENSOR_X 0


unsigned gpio_rst, gpio_cmd, gpio_bl = 0;

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

char *mac_to_string(const uint8_t mac[6])
{
    static char mac_str[18];
    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return mac_str;
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

#ifdef SPI_DISPLAY_ENABLED

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

    gpio_set_dir(SPI_DISPLAY_BKL, DIR_OUTPUT);
    gpio_set_dir(SPI_DISPLAY_CMD, DIR_OUTPUT);
    gpio_set_dir(SPI_DISPLAY_RST, DIR_OUTPUT);

    gpio_clear(SPI_DISPLAY_BKL);
    gpio_clear(SPI_DISPLAY_CMD);
    gpio_clear(SPI_DISPLAY_RST);

    return true;
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

void fill_screen_black(void) {

    // Column address: CASET (0x2A) -> start col high, start col low, end col high, end col low
    send_command(0x2A);
    uint8_t coldata[4] = { 0x00, 0x00, 0x00, 0x7F }; // 0..127
    send_data(coldata, 4);

    // Row address: RASET (0x2B)
    send_command(0x2B);
    uint8_t rowdata[4] = { 0x00, 0x00, 0x00, 0x9F }; // 0..159
    send_data(rowdata, 4);

    // Memory write
    send_command(0x2C);

    // Stream pixel data in chunks to avoid huge allocations.
    // Each pixel is 2 bytes for RGB565. For black: 0x00, 0x00.
    const size_t PIXELS = TFT_WIDTH * TFT_HEIGHT;
    const size_t BYTES_TOTAL = PIXELS * 2;
    const size_t CHUNK_BYTES = 4096; // choose a chunk size (must be even)
    uint8_t chunk[CHUNK_BYTES];
    // fill chunk with zeros (black)
    memset(chunk, 0x00, CHUNK_BYTES);

    size_t remaining = BYTES_TOTAL;
    while (remaining) {
        size_t to_send = remaining > CHUNK_BYTES ? CHUNK_BYTES : remaining;
        // ensure to_send is even (2 bytes per pixel)
        if (to_send & 1) to_send--;
        if (to_send == 0) break;
        send_data(chunk, to_send);
        remaining -= to_send;
    }
}

// Helper: convert 8-bit RGB to RGB565
static inline uint16_t rgb565(uint8_t r, uint8_t g, uint8_t b) 
{
    return (uint16_t)(((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3));
}

// ST7735 helper: set address window (column/row)
static void set_address_window(uint8_t x0, uint8_t y0, uint8_t x1, uint8_t y1) 
{
    uint8_t data[4];
    // CASET
    send_command(0x2A);
    data[0] = 0x00; data[1] = x0; data[2] = 0x00; data[3] = x1;
    send_data(data, 4);
    // RASET
    send_command(0x2B);
    data[0] = 0x00; data[1] = y0; data[2] = 0x00; data[3] = y1;
    send_data(data, 4);
    // MEMWR will be issued by caller
}
// push repeated color pixels (count pixels, color is RGB565)
static void push_color_repeat(uint16_t color, size_t count) {
    // send_data expects bytes; create a small chunk buffer of pairs
    const size_t CHUNK_PIXELS = 512; // 512 pixels => 1024 bytes (adjust if memory constrained)
    uint8_t chunk[CHUNK_PIXELS * 2];
    // fill chunk with color in big-endian (MSB first for ST7735)
    chunk[0] = (uint8_t)(color >> 8);
    chunk[1] = (uint8_t)(color & 0xFF);
    for (size_t i = 1; i < CHUNK_PIXELS; ++i) {
        chunk[i*2 + 0] = chunk[0];
        chunk[i*2 + 1] = chunk[1];
    }

    send_command(0x2C); // memory write
    size_t remaining = count;
    while (remaining) {
        size_t to_pixels = remaining > CHUNK_PIXELS ? CHUNK_PIXELS : remaining;
        send_data(chunk, to_pixels * 2);
        remaining -= to_pixels;
    }
}

// draw filled rectangle with color
static void fill_rect(uint8_t x, uint8_t y, uint8_t w, uint8_t h, uint16_t color) {
    if ((x >= TFT_WIDTH) || (y >= TFT_HEIGHT)) return;
    if (x + w - 1 >= TFT_WIDTH) w = TFT_WIDTH - x;
    if (y + h - 1 >= TFT_HEIGHT) h = TFT_HEIGHT - y;
    set_address_window(x, y, x + w - 1, y + h - 1);
    push_color_repeat(color, (size_t)w * h);
}

// draw single pixel
static void draw_pixel(uint8_t x, uint8_t y, uint16_t color) {
    set_address_window(x, y, x, y);
    uint8_t b[2] = { (uint8_t)(color >> 8), (uint8_t)(color & 0xFF) };
    send_command(0x2C);
    send_data(b, 2);
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

// draw a character (foreground color on background color)
static void draw_char(uint8_t x, uint8_t y, char c, uint16_t fg, uint16_t bg) {
    if (c < 32 || c > 127) c = '?';
    const uint8_t *ch = font5x7[c - 32];
    // each char is 5x7, we'll add 1 column spacing
    // draw background rectangle for char (6x8)
    fill_rect(x, y, 6, 8, bg);

    for (uint8_t col = 0; col < 5; ++col) {
        uint8_t colbits = ch[col];
        for (uint8_t row = 0; row < 7; ++row) {
            if (colbits & (1 << row)) {
                draw_pixel(x + col, y + row, fg);
            }
        }
    }
}

// draw a text string (left-to-right)
static void draw_text(uint8_t x, uint8_t y, const char *s, uint16_t fg, uint16_t bg) {
    while (*s) {
        draw_char(x, y, *s, fg, bg);
        x += 6 + FONT_SPACING;
        ++s;
    }
}

// small heart bitmap (12x12) precomputed in RGB565 (MSB,LSB pairs).
// This is a 12x12 red heart shape; transparent pixels encoded as 0x0000 (black).
static const uint16_t heart12[12*12] = {
    // row-major 12x12; 0xF800 for red, 0x0000 for transparent
    // handcrafted pattern
    0x0000,0x0000,0x0000,0xF800,0xF800,0xF800,0xF800,0xF800,0x0000,0x0000,0x0000,0x0000,
    0x0000,0x0000,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0x0000,0x0000,0x0000,
    0x0000,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0x0000,0x0000,
    0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0x0000,
    0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,
    0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,
    0x0000,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0x0000,0x0000,
    0x0000,0x0000,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0xF800,0x0000,0x0000,0x0000,
    0x0000,0x0000,0x0000,0xF800,0xF800,0xF800,0xF800,0xF800,0x0000,0x0000,0x0000,0x0000,
    0x0000,0x0000,0x0000,0x0000,0xF800,0xF800,0xF800,0x0000,0x0000,0x0000,0x0000,0x0000,
    0x0000,0x0000,0x0000,0x0000,0x0000,0xF800,0x0000,0x0000,0x0000,0x0000,0x0000,0x0000,
    0x0000,0x0000,0x0000,0x0000,0x0000,0x0000,0x0000,0x0000,0x0000,0x0000,0x0000,0x0000
};

// draw a small bitmap (16-bit per pixel array)
static void draw_bitmap_rgb565(uint8_t x, uint8_t y, const uint16_t *bmp, uint8_t w, uint8_t h, uint16_t bg)
{
    // fill background rect first
    fill_rect(x, y, w, h, bg);
    // then draw pixels
    for (uint8_t row = 0; row < h; ++row) {
        for (uint8_t col = 0; col < w; ++col) {
            uint16_t p = bmp[row * w + col];
            if (p != 0x0000) { // treat 0x0000 as transparent/skip (if you want black use other pattern)
                draw_pixel(x + col, y + row, p);
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

// Clear entire screen to bg color
static void clear_screen(uint16_t bg_color)
{
    fill_rect(0, 0, TFT_WIDTH, TFT_HEIGHT, bg_color);
}

// Compose and update the fields: battery, version, center counter, heart state
static void update_display(uint16_t discovery_count, float batt_voltage)
{
    // colors
    uint16_t black = rgb565(0,0,0);
    uint16_t white = rgb565(255,255,255);
    uint16_t red   = rgb565(255,0,0);

    // clear entire screen black (or do partial updates if you prefer)
    clear_screen(black);

    // top-right: battery voltage and version (stacked)
    char volt_buf[16];
    format_voltage_str(volt_buf, sizeof(volt_buf), batt_voltage);

    // Decide where to place strings so they are right-justified
    // text width = (6 + FONT_SPACING)*chars - FONT_SPACING -> simpler compute per char 6
    size_t volt_len = strlen(volt_buf);
    //size_t ver_len  = strlen(APP_VERSION);
    int volt_w = (int)volt_len * (6 + FONT_SPACING);
    //int ver_w  = (int)ver_len  * (6 + FONT_SPACING);

    int x_volt = TFT_WIDTH - volt_w - RIGHT_MARGIN;
    //int x_ver  = TFT_WIDTH - ver_w - RIGHT_MARGIN;
    int y_volt = TOP_MARGIN;
    //int y_ver  = TOP_MARGIN + 8 + 2; // below voltage (8 px high font + small gap)

    draw_text((uint8_t)x_volt, (uint8_t)y_volt, volt_buf, white, black);
    //draw_text((uint8_t)x_ver,  (uint8_t)y_ver,  APP_VERSION, white, black);

    // center: "Discovery: N"
    char center_buf[32];
    snprintf(center_buf, sizeof(center_buf), "Discovery:%u", discovery_count);
    int center_len = strlen(center_buf);
    int cx = (TFT_WIDTH - center_len * (6 + FONT_SPACING)) / 2;
    int cy = (TFT_HEIGHT - 8) / 2 - 8; // a little above center
    if (cx < 0) cx = 0;
    draw_text((uint8_t)cx, (uint8_t)cy, center_buf, white, black);
}

#endif

#ifdef USE_INA219_SENSOR
static bool setup_i2c_bus(void)
{
    //Setup the i2c bus and return true if OK.
    return true;
}

// TODO: Implement INA219 sensor stuff here.

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

static void process_wpr_data_rx(uint8_t srcAddr[6], uint8_t ant1, uint8_t ant2)
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
        if (discoveryFrameCounter == 65534)
        {
            discoveryFrameCounter = 0;
        }
        else
        {
            discoveryFrameCounter++;
        }

        printf("Ping message from: %s, Ant-1: %d dBm, Ant-2: %d dBm\n", mac_to_string(srcAddr), ant1, ant2);
        send_discovery_pong(srcAddr);
        break;
    case RADIO_DATA_MESH_MSG_DISCOVERY_PONG:
        //We got a response from the other side, use the time.
        printf("Pong message from: %s, Ant-1: %d dBm, Ant-2: %d dBm\n", mac_to_string(srcAddr), ant1, ant2);
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
//static void parse_radio_message(const uint8_t *pkt, size_t len, const struct pcap_pkthdr *pcaphdr)
{
    uint8_t antIndex = 0;
    uint8_t ant1dBm = 0;
    uint8_t ant2dBm = 0;

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
            case IEEE80211_RADIOTAP_ANTENNA:
                {
                    antIndex++;
                }
                break;
            //case IEEE80211_RADIOTAP_RX_FLAGS:
            //case IEEE80211_RADIOTAP_DBM_ANTNOISE:
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
    process_wpr_data_rx(mac_hdr->addr3, ant1dBm, ant2dBm);
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

    unsigned int frame = 0;
    
    uint64_t now_in_us = 0;
    uint64_t refreshDisplayTime = 0;
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

#ifdef SPI_DISPLAY_ENABLED
        if (usingDisplay){
            if (now_in_us - refreshDisplayTime > (ONE_MS_IN_US * 100))
            {
                refreshDisplayTime = now_in_us;
                //Refresh the display here
                //Do not refresh the display unless we got a new discovery message
                if (discoveryFrameCounterOnLCD != discoveryFrameCounter)
                {
                    discoveryFrameCounterOnLCD = discoveryFrameCounter;
                    update_display(discoveryFrameCounter, 4.2);
                }

                //Refresh the voltage of the INA219 sensor
            }
        }
#endif

        if (isRadioTransmitting)
        {
            if (now_in_us - discoverySend > (ONE_MS_IN_US * 1000))
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
            // else
            // {
            //     struct tpacket_hdr *hdr = (struct tpacket_hdr *)((uint8_t *)ring + frame * FRAME_SIZE);

            //     if (!(hdr->tp_status & TP_STATUS_USER))
            //         break; // No more frames in buffer

            //     uint8_t *pkt = (uint8_t *)hdr + hdr->tp_mac;
            //     size_t pktlen = hdr->tp_snaplen;
            //     parse_radio_message(pkt, pktlen);

            //     hdr->tp_status = TP_STATUS_KERNEL;
            //     frame = (frame + 1) % frame_nr;
            // }
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
#endif

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