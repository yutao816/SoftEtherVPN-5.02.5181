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

// MQTT 配置结构
typedef struct {
    char broker[256];
    char topic[128];
    int qos;
    char client_id[50];
} MQTT_CONFIG;

// TUN_HANDLE 结构定义
typedef struct {
    HANDLE vh_handle;    // VH 结构句柄
    SOCKET tap_socket;   // TAP 设备 socket
    CEDAR *cedar;        // Cedar 实例指针
    MQTT_CONFIG mqtt;    // MQTT 配置
} TUN_HANDLE;

// 函数声明
bool InitializeMqttConnection(CONNECTION *c, const char *broker, const char *topic);
void CleanupMqttConnection(CONNECTION *c);
void ProcessMqttMessages(CONNECTION *c);
// 修改函数声明
void SendDataWithMQTT(CONNECTION *c);  // 移除 BLOCK *b 参数
// TAP 设备和配置相关函数
TUN_HANDLE* CreateTunDevice(const char *if_name, const char *ip_addr);
void CleanupTunDevice(TUN_HANDLE* handle);
bool GetMqttConfig(MQTT_CONFIG *config);  // 获取用户配置

#endif // MQTT_VPN_H