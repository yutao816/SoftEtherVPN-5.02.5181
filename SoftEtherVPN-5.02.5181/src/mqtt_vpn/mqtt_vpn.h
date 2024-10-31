// mqtt_vpn.h

#ifndef MQTT_VPN_H
#define MQTT_VPN_H

#include <windows.h>
#include <stdbool.h>
#include "../Cedar/Cedar.h"
#include "../Cedar/Connection.h"

// TAP 设备相关标志
#define IFF_TUN     0x0001
#define IFF_TAP     0x0002
#define IFF_NO_PI   0x1000

// TUN_HANDLE 结构定义
typedef struct {
    HANDLE vh_handle;    // VH 结构句柄
    SOCKET tap_socket;   // TAP 设备 socket
    CEDAR *cedar;        // Cedar 实例指针
} TUN_HANDLE;

// 函数声明
//TUN_HANDLE* tun_alloc(const char *if_name, int flags);
void cleanup_tun(TUN_HANDLE* handle);
bool init_softether(void);
void cleanup_softether(void);
int mqtt_vpn_start(int argc, char *argv[]);
void usage(void);
void cleanup_tun(TUN_HANDLE* handle);

bool InitMqttConnection(CONNECTION *connection);
void CleanupMqttConnection(CONNECTION *connection);
void run_mqtt_vpn(CONNECTION *connection);
int mqtt_vpn_init(void);
void SendDataWithMQTT(CONNECTION *c);
void ProcessMqttMessages(CONNECTION *c);
#endif // MQTT_VPN_H
