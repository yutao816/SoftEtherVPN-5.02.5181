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
// MQTT 相关错误码
#define ERR_MQTT_INIT_FAILED          200   // MQTT 初始化失败

typedef struct MQTT_CONFIG
{
    char broker[MAX_PATH];     // MQTT broker 地址
    char topic[MAX_PATH];      // MQTT topic
    char client_id[64];        // MQTT client ID
    UINT port;                // MQTT broker 端口
    char username[64];        // MQTT 用户名
    char password[64];        // MQTT 密码
    bool use_tls;            // 是否使用 TLS
    UINT qos;                // MQTT QoS level
} MQTT_CONFIG;
// TUN_HANDLE 结构定义
typedef struct {
    HANDLE vh_handle;    // VH 结构句柄
    SOCKET tap_socket;   // TAP 设备 socket
    CEDAR *cedar;        // Cedar 实例指针
    MQTT_CONFIG mqtt;    // MQTT 配置
} TUN_HANDLE;



// 函数声明
bool GetMqttUserConfig(void);
bool InitializeMqttConnection(CONNECTION *c, char *broker, char *topic);
void CleanupMqttConnection(CONNECTION *c);
void ProcessMqttMessages(CONNECTION *c);
// 修改函数声明
const MQTT_CONFIG* GetCurrentMqttConfig();
void SendDataWithMQTT(CONNECTION *c);  // 移除 BLOCK *b 参数
// TAP 设备和配置相关函数
TUN_HANDLE* CreateTunDevice(const char *if_name, const char *ip_addr);
void CleanupTunDevice(TUN_HANDLE* handle);
bool GetMqttConfig(MQTT_CONFIG *config);  // 获取用户配置

#endif // MQTT_VPN_H