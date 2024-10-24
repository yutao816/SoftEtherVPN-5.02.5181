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
#include <time.h>
#include "mqtt_vpn.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "MQTTClient.h"
#include <sodium.h>  // 确保 sodium.h 在正确的路径中
#include "Cedar/Connection.h"
#include "Cedar/Cedar.h"
#include "Cedar/Session.h"
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "paho-mqtt3c.lib")
#pragma comment(lib, "libsodium.lib")

#define CLIENTID_PRE "MQTT_VPN_"
#define TOPIC_PRE "mqttip"
#define QOS 0
#define TIMEOUT 10000L
#define BUFSIZE 2000
#define CLIENT 0
#define SERVER 1
#define PORT 55555
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28
#define HOST "fec2::22"
#define IFNAMSIZ 16

#define IFF_TAP 0x0002
#define IFF_NO_PI 0x1000

unsigned char key[crypto_secretbox_KEYBYTES];
unsigned char key_set = 0;

char if_name[IFNAMSIZ];
char *if_addr = NULL;
char *broker = NULL;
char *cl_id = NULL;
char netmask[16] = "255.255.255.0";
int if_index = 0;

int debug;
char *progname;
HANDLE tap_fd;
int net2tap = 0;

int optind = 1;
char *optarg = NULL;

// //mqtt函数调用
// void run_mqtt_vpn(int use_mqtt, const char *if_name, const char *if_addr, const char *broker) {
//     // 初始化和设置代码
//     // ...

//     if (use_mqtt) {
//         handle_mqtt(); // 调用 MQTT 处理函数
//     } else {
//         handle_udp(); // 调用 UDP 处理函数
//     }

//     // 清理资源
//     // ...
// }

int getopt(int argc, char *const argv[], const char *optstring)
{
    static int optpos = 1;
    const char *arg;
    (void)argc;

    if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0') {
        return -1;
    }
    arg = argv[optind] + optpos;
    if (arg[0] == '\0') {
        optind++;
        optpos = 1;
        return getopt(argc, argv, optstring);
    }
    for (const char *opt = optstring; *opt; opt++) {
        if (*opt == ':') {
            continue;
        }
        if (arg[0] == *opt) {
            if (opt[1] == ':') {
                if (arg[1] == '\0') {
                    if (optind + 1 >= argc) {
                        return '?';
                    }
                    optarg = argv[++optind];
                } else {
                    optarg = (char *)(arg + 1);
                }
                optind++;
                optpos = 1;
                return *opt;
            }
            if (arg[1] == '\0') {
                optind++;
                optpos = 1;
            } else {
                optpos++;
            }
            return *opt;
        }
    }
    return '?';
}

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
HANDLE tun_alloc(char *dev, int flags) {
    HANDLE handle;
    char device_path[256];
    snprintf(device_path, sizeof(device_path), "\\\\.\\Global\\%s.tap", dev);

    handle = CreateFile(
        device_path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
        0
    );

    if (handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error opening TAP device: %lu\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    return handle;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(HANDLE fd, unsigned char *buf, int n)
{
    DWORD bytesRead;
    if (!ReadFile(fd, buf, n, &bytesRead, NULL)) {
        // 处理错误
        return -1;
    }
    return bytesRead;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(HANDLE fd, unsigned char *buf, int n)
{
    DWORD bytesWritten;
    if (!WriteFile(fd, buf, n, &bytesWritten, NULL)) {
        // 处理错误
        return -1;
    }
    return bytesWritten;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
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

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
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

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...)
{
  va_list argp;
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
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

// MQTT client handle
MQTTClient mqtt_client;

// MQTT connection options
MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;

// MQTT message arrived callback
int messageArrived(void *context, char *topicName, int topicLen, MQTTClient_message *message) {
    // Handle received MQTT message
    // ... implement message handling logic ...
    MQTTClient_freeMessage(&message);
    MQTTClient_free(topicName);
    return 1;
}

// Initialize MQTT connection
int init_mqtt(const char *broker, const char *clientid) {
    int rc;
    MQTTClient_create(&mqtt_client, broker, clientid, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;

    MQTTClient_setCallbacks(mqtt_client, NULL, NULL, messageArrived, NULL);

    if ((rc = MQTTClient_connect(mqtt_client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
        fprintf(stderr, "Failed to connect to MQTT broker, return code %d\n");
        return 0;
    }
    return 1;
}

// Send MQTT message
int send_mqtt_message(const char *topic, const void *payload, int payload_len) {
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    pubmsg.payload = (void*)payload;
    pubmsg.payloadlen = payload_len;
    pubmsg.qos = 0;
    pubmsg.retained = 0;
    return MQTTClient_publishMessage(mqtt_client, topic, &pubmsg, NULL);
}

// MQTT VPN main loop
void run_mqtt_vpn(CONNECTION *c) {
    char clientid[50];
    snprintf(clientid, sizeof(clientid), "MQTT_VPN_%d", rand());
    
    if (!init_mqtt(c->ServerName, clientid)) {
        return;
    }

    while (!c->Halt) {
        MQTTClient_yield();

        BLOCK *b;
        while ((b = GetNextBlock(c->SendBlocks)) != NULL) {
            MQTTClient_publish(c->MqttClient, c->MqttTopic, b->Size, b->Buf, c->MqttQoS, 0, NULL);
            FreeBlock(b);
        }

        SleepThread(100);
    }

    MQTTClient_disconnect(c->MqttClient, 10000);
    MQTTClient_destroy(&c->MqttClient);
}
typedef struct {
    BLOCK **blocks;
    int capacity;
    int size;
    int front;
    int rear;
} SimpleQueue;

SimpleQueue* NewSimpleQueue(int capacity) {
    SimpleQueue* queue = (SimpleQueue*)malloc(sizeof(SimpleQueue));
    if (queue == NULL) return NULL;
    queue->blocks = (BLOCK**)malloc(sizeof(BLOCK*) * capacity);
    if (queue->blocks == NULL) {
        free(queue);
        return NULL;
    }
    queue->capacity = capacity;
    queue->size = 0;
    queue->front = 0;
    queue->rear = -1;
    return queue;
}
// 主函数
int main(int argc, char *argv[])
{
    char *if_name = NULL;
    char *if_addr = NULL;
    char *broker = NULL;
    bool use_mqtt = true;  // 或者根据命令行参数设置

    // 解析命令行参数，设置 if_name, if_addr 和 broker
    // ... 在这里添加参数解析代码 ...

    if (use_mqtt)
{
    CONNECTION *c = NewServerConnection(NULL, NULL, NULL);
    if (c == NULL)
    {
        fprintf(stderr, "Failed to create new connection\n");
        return 1;
    }
    
    // 设置必要的 CONNECTION 字段
    strncpy(c->ServerName, broker, sizeof(c->ServerName) - 1);
    c->ServerName[sizeof(c->ServerName) - 1] = '\0';
    c->Halt = false;
    c->ServerPort = 1883;  // MQTT 默认端口
    
    // 初始化 MQTT 相关字段
    c->UseMqtt = true;
    c->MqttTopic = strdup("your/mqtt/topic");
    if (c->MqttTopic == NULL) {
        fprintf(stderr, "Failed to allocate memory for MqttTopic\n");
        ReleaseConnection(c);
        return 1;
    }
    c->MqttQoS = 0;
    
    // 初始化 SendBlocks 队列
    c->SendBlocks = (QUEUE*)NewSimpleQueue(100);
    if (c->SendBlocks == NULL) {
        fprintf(stderr, "Failed to create SendBlocks queue\n");
        free(c->MqttTopic);
        ReleaseConnection(c);
        return 1;
    }
    
    // 运行 MQTT VPN
    run_mqtt_vpn(c);
    
    // 清理资源
    ReleaseConnection(c);
}

    return 0;
}
