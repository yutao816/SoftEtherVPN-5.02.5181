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
int main(int argc, char *argv[]) {
    // ... 其他代码保持不变

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return 1;
    }

    // 初始化 OpenSSL
    SSL_library_init();
    SSL_load_error_strings();

    // 创建 TAP 设备
    tap_fd = tun_alloc(if_name, IFF_TAP | IFF_NO_PI);
    if (tap_fd == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error creating TAP device.\n");
        WSACleanup();
        return 1;
    }

    // 设置 IP 地址和子网掩码
    ULONG NTEContext = 0;
    ULONG NTEInstance = 0;
    DWORD dwRetVal;

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    if (InetPton(AF_INET, if_addr, &sin.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP address format.\n");
        return 1;
    }

    ULONG netmask_addr;
    if (InetPton(AF_INET, netmask, &netmask_addr) != 1) {
        fprintf(stderr, "Invalid netmask format.\n");
        return 1;
    }

    dwRetVal = AddIPAddress(sin.sin_addr.s_addr, netmask_addr, if_index, &NTEContext, &NTEInstance);
    if (dwRetVal != NO_ERROR) {
        fprintf(stderr, "AddIPAddress failed with error: %lu\n", dwRetVal);
        CloseHandle(tap_fd);
        WSACleanup();
        return 1;
    }

    // ... 其他代码保持不变

    while (1) {
        DWORD waitResult = WaitForSingleObject(tap_fd, INFINITE);

        switch (waitResult) {
            case WAIT_OBJECT_0:
                // tap_fd is ready for reading
                // 处理 TAP 设备数据
                // ... 处理数据的代码保持不变
                break;

            case WAIT_FAILED:
                fprintf(stderr, "WaitForSingleObject failed with error: %lu\n", GetLastError());
                break;

            default:
                // 处理其他情况
                break;
        }

        // 处理 MQTT 消息
        MQTTClient_yield();
    }

    // 清理资源
    DeleteIPAddress(NTEContext);
    CloseHandle(tap_fd);
    WSACleanup();
    return 0;
}
