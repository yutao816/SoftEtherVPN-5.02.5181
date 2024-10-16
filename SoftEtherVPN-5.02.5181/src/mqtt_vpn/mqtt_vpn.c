/**************************************************************************
 * mqtt_vpn.c                                                             *
 *                                                                        *
 * A simple IPv4 tunnelling program using tun interfaces and MQTT.        * 
 *                                                                        *
 * Based on work from Davide Brini                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * Uses the Paho MQTT C Client Library                                    *
 * https://www.eclipse.org/paho/files/mqttdoc/MQTTClient/html/index.html  *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#else
#include <net/if.h>
#endif

   
#include "MQTTClient.h"
#ifdef USE_SODIUM
#include "sodium.h"
#endif
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

/* MQTT related defs */
#define CLIENTID_PRE "MQTT_VPN_"
#define TOPIC_PRE "mqttip"
#define QOS 0
#define TIMEOUT 10000L

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28

#define HOST "fec2::22"

#ifdef _WIN32
#define IFNAMSIZ 256
#endif

#ifndef IFF_TUN
#define IFF_TUN 0x0001
#endif

#ifndef IFF_NO_PI
#define IFF_NO_PI 0x1000
#endif

struct in6_ifreq
{
  struct in6_addr ifr6_addr;
  ULONG ifr6_prefixlen;
  unsigned int ifr6_ifindex;
};

MQTTClient client;
MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
char *receive_topic, *broadcast_topic;
#define N_ADDR_MAX 10
uint8_t n_addr=0;
char *addr_topic[N_ADDR_MAX];
u_char key[32];  // Assuming crypto_secretbox_KEYBYTES is 32
unsigned char key_set = 0;

char *if_addr = NULL;
char *broker = NULL;
char *cl_id = NULL;

int debug;
char *progname;
HANDLE tap_fd;
int net2tap = 0;

int tun_alloc(char *dev, int flags) {
    // 这里需要实现Windows下的TUN/TAP设备创建逻辑
    // 可能需要使用 TAP-Windows 驱动程序
    // 返回设备句柄
    return 0; // 临时返回值，需要实际实现
}

int cread(HANDLE fd, unsigned char *buf, int n) {
    DWORD bytesRead;
    if (!ReadFile(fd, buf, n, &bytesRead, NULL)) {
        // 处理错误
        return -1;
    }
    return bytesRead;
}

int cwrite(HANDLE fd, unsigned char *buf, int n) {
    DWORD bytesWritten;
    if (!WriteFile(fd, buf, n, &bytesWritten, NULL)) {
        // 处理错误
        return -1;
    }
    return bytesWritten;
}

int read_n(HANDLE fd, unsigned char *buf, int n)
{
  int nread, left = n;

  while (left > 0)
  {
    if ((nread = cread(fd, buf, left)) == 0)
    {
      return 0;
    }
    else
    {
      left -= nread;
      buf += nread;
    }
  }
  return n;
}

void do_debug(char *msg, ...)
{
  va_list argp;
  if (debug)
  {
    va_start(argp, msg);
    vfprintf(stderr, msg, argp);
    va_end(argp);
  }
}

void my_err(char *msg, ...)
{
  va_list argp;
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

void usage(void)
{
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <if_name> -a <ip> -b <broker> [-m <netmask>] [-n <clientid>] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <if_name>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-a <ip>: IP address of interface to use (mandatory)\n");
  fprintf(stderr, "-b <broker>: Address of MQTT broker (like: tcp://broker.io:1883) (mandatory)\n");
  fprintf(stderr, "-u <username>: user of the MQTT broker\n");
  fprintf(stderr, "-p <password>: password of the MQTT broker user\n");
  fprintf(stderr, "-k <password>: preshared key for all clients of this VPN\n");
  fprintf(stderr, "-m <netmask>: Netmask of interface to use (default 255.255.255.0)\n");
  fprintf(stderr, "-6 <ip6>: IPv6 address of interface to use\n");
  fprintf(stderr, "-x <prefix>: prefix length of the IPv6 address (default 64)\n");
  fprintf(stderr, "-n <clientid>: ID of MQTT client (%s<random>)\n", CLIENTID_PRE);
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-t <ip>: IP address of a target to NAT\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

void delivered(void *context, MQTTClient_deliveryToken dt)
{
  fprintf(stderr, "Message with token value %d delivery confirmed\n", dt);
}

int msgarrvd(void *context, char *topicName, int topicLen, MQTTClient_message *message)
{
  int nwrite;
  unsigned int packet_len;
  unsigned char *packet_start;
  int packet_ok = 1;
  do_debug("Message arrived %d bytes on topic: %s\n", message->payloadlen, topicName);
  uint8_t i=0;
  while (i<n_addr && !(strncmp(topicName, addr_topic[i], topicLen) == 0))
  {
    ++i;
  }
  if (i<n_addr)
  {
    net2tap++;
    packet_start = message->payload;
    packet_len = message->payloadlen;
    unsigned char *m = malloc(packet_len);
    if (key_set)
    {
      if ((packet_len <= 24 + 32) ||
         (crypto_secretbox_open(m, packet_start + 24, packet_len - 24, packet_start, key) == -1))
      {
        do_debug("NET2TAP %lu: Decrypt Error\r\n", net2tap);
        packet_ok = 0;
      } else {
        packet_start = m + 32;
        packet_len = packet_len - 24 - 32;
      }
    }
    if (packet_ok)
    {
      if (packet_len <= 1500)
      {
        nwrite = cwrite(tap_fd, (unsigned char *)packet_start, packet_len);
        do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
      }
      else
      {
        do_debug("NET2TAP %lu: %d bytes too long to write the tap interface\n", net2tap, message->payloadlen);
      }
    }
    free(m);
  }
  MQTTClient_freeMessage(&message);
  MQTTClient_free(topicName);

  return 1;
}

void mqtt_if_add_reading_topic(const char* addr)
{
  if (n_addr<N_ADDR_MAX)
  {
    addr_topic[n_addr] = malloc(sizeof(TOPIC_PRE) + strlen(addr) + 2);
    sprintf(addr_topic[n_addr], "%s/%s", TOPIC_PRE, addr);
    printf("Added topic: %s\n", addr_topic[n_addr]);
    n_addr++;
  }
}

void mqtt_if_subscribe()
{
  for (uint8_t i=0; i<n_addr; ++i)
  {
    do_debug("Subscribing to topic %s\n", addr_topic[i]);
    MQTTClient_subscribe(client, addr_topic[i], QOS);
  }
}

void mqttconnect()
{
  int rc;
  if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS)
  {
    fprintf(stderr, "Failed to connect, return code %d\n", rc);
    exit(-1);
  }
  do_debug("Successfully connected client %s to the MQTT broker %s\n", cl_id, broker);
  mqtt_if_add_reading_topic(if_addr);
  mqtt_if_add_reading_topic("255.255.255.255");
  mqtt_if_subscribe();
  fprintf(stderr, "MQTT VPN client %s on broker %s for ip address %s started\n", cl_id, broker, if_addr);
}

void connlost(void *context, char *cause)
{
  fprintf(stderr, "\nConnection lost\n");
  fprintf(stderr, "     cause: %s\n", cause);
  fprintf(stderr, "\nReconnecting...\n");
  mqttconnect();
}

int main(int argc, char *argv[])
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return 1;
    }

    int option;
    int flags = IFF_TUN;
    char if_name[IFNAMSIZ] = "";
    char if_mask[20] = "255.255.255.0";
    char *if_addr6 = NULL;
    int pre6 = 64;
    int maxfd;
    uint16_t nread;
    unsigned char buffer[BUFSIZE];
    unsigned char *plain_buf = malloc(BUFSIZE + 32);
    unsigned char *cypher_buf = malloc(BUFSIZE + 24 + 32);
    SOCKET ip_fd, ip6_fd;
    unsigned long int tap2net = 0;
    unsigned char h[64];  // Assuming crypto_hash_BYTES is 64

    MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token;

    progname = argv[0];
    srand(time(NULL));

    /* Check command line options */
    while ((option = getopt(argc, argv, "i:a:m:k:6:x:b:u:p:n:t:hd")) > 0)
    {
        switch (option)
        {
            case 'd':
                debug = 1;
                break;
            case 'h':
                usage();
                break;
            case 'i':
                #ifdef _WIN32
                if (strlen(optarg) < IFNAMSIZ) {
                    strcpy(if_name, optarg);
                } else {
                    strncpy(if_name, optarg, IFNAMSIZ - 1);
                    if_name[IFNAMSIZ - 1] = '\0';  // 确保字符串以 null 结尾
                }
                #else
                strncpy(if_name, optarg, IFNAMSIZ - 1);
                #endif
                break;
            case 'a':
                if_addr = optarg;
                break;
            case 'k':
                crypto_hash(h, (unsigned char *)optarg, strlen(optarg));
                memcpy(key, h, 32);
                key_set = 1;
                break;
            case '6':
                if_addr6 = optarg;
                break;
            case 'x':
                pre6 = atoi(optarg);
                break;
            case 'b':
                broker = optarg;
                break;
            case 'u':
                conn_opts.username = optarg;
                break;
            case 'p':
                conn_opts.password = optarg;
                break;
            case 'n':
                cl_id = optarg;
                break;
            case 'm':
                strncpy(if_mask, optarg, sizeof(if_mask));
                if_addr[sizeof(if_mask) - 1] = '\0';
                break;
            case 't':
                mqtt_if_add_reading_topic(optarg);
                break;
            default:
                my_err("Unknown option %c\n", option);
                usage();
        }
    }

    argv += optind;
    argc -= optind;

    if (argc > 0)
    {
        my_err("Too many options!\n");
        usage();
    }

    if (*if_name == '\0')
    {
        my_err("Must specify interface name!\n");
        usage();
    }

    if (if_addr == NULL)
    {
        my_err("Must specify interface address!\n");
        usage();
    }

    if (broker == NULL)
    {
        my_err("Must specify broker address!\n");
        usage();
    }

    if (cl_id == NULL)
    {
        cl_id = malloc(sizeof(CLIENTID_PRE) + 20);
        sprintf(cl_id, "%s%u", CLIENTID_PRE, rand());
    }

    /* Initialize tun/tap interface */
    if ((tap_fd = (HANDLE)tun_alloc(if_name, flags | IFF_NO_PI)) == INVALID_HANDLE_VALUE)
    {
        my_err("Error connecting to tun/tap interface %s!\n", if_name);
        exit(1);
    }

    do_debug("Successfully connected to interface %s\n", if_name);

    /* The rest of the main function remains largely the same,
       but you'll need to adapt the socket and ioctl calls to their Windows equivalents */

    MQTTClient_create(&client, broker, cl_id,
                      MQTTCLIENT_PERSISTENCE_NONE, NULL);
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;
    MQTTClient_setCallbacks(client, NULL, connlost, msgarrvd, delivered);
    ssl_opts.verify = 0;
    ssl_opts.enableServerCertAuth = 0;
    conn_opts.ssl = &ssl_opts;

    mqttconnect();

    maxfd = (int)tap_fd;

    while (1)
    {
        int ret;
        fd_set rd_set;

        FD_ZERO(&rd_set);
        FD_SET(tap_fd, &rd_set);

        ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

        if (ret < 0 && WSAGetLastError() != WSAEINTR)
        {
            perror("select()");
            exit(1);
        }

        if (FD_ISSET(tap_fd, &rd_set))
        {
            /* data from tun/tap: just read it and write it to the network */
            char send_topic[sizeof(TOPIC_PRE) + 20];

            nread = cread(tap_fd, buffer, BUFSIZE);

            tap2net++;
            do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

            sprintf(send_topic, "%s/%u.%u.%u.%u", TOPIC_PRE, buffer[16], buffer[17], buffer[18], buffer[19]);
            pubmsg.qos = QOS;
            pubmsg.retained = 0;

            if (key_set)
            {
                do_debug("TAP2NET %lu: crypto_secretbox_NONCEBYTES: %d crypto_secretbox_ZEROBYTES: %d\n", tap2net, 24, 32);
                for (int i = 0; i < 24; i++)
                {
                    cypher_buf[i] = rand();
                }
                memset(plain_buf, 0, 32);
                memcpy(plain_buf + 32, buffer, nread);
                crypto_secretbox(cypher_buf + 24, plain_buf, nread + 32, cypher_buf, key);
                pubmsg.payload = cypher_buf;
                pubmsg.payloadlen = nread + 24 + 32;
            }
            else
            {
                pubmsg.payload = buffer;
                pubmsg.payloadlen = nread;
            }

            MQTTClient_publishMessage(client, send_topic, &pubmsg, &token);

            do_debug("TAP2NET %lu: Written %d bytes to topic %s\n", tap2net, pubmsg.payloadlen, send_topic);
        }
    }

    free(plain_buf);
    free(cypher_buf);
    WSACleanup();
    return 0;
}
