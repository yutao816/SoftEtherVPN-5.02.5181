#ifndef MQTT_VPN_H
#define MQTT_VPN_H

#include <windows.h>
#include <stdbool.h>
#include "../Cedar/Cedar.h"
#include "../Cedar/Connection.h"
#include "../Cedar/CedarType.h"
#include "MQTTClient.h"
// MQTT相关常量定义

#define TOPIC_PRE "vpn"  // 更简单的主题前缀
#define QOS 1  // 提高QoS级别以确保消息可靠性
#define TIMEOUT 30000L  // 增加超时时间
#define MQTT_QOS        0       // MQTT服务质量
#define MQTT_TIMEOUT    10000L  // MQTT超时时间（毫秒）
#define MQTT_TOPIC_MAX  256     // MQTT主题最大长度
#define MQTT_CLIENT_PREFIX "MQTT_VPN_"  // MQTT客户端ID前缀
#define TOPIC_PRE "mqttip"     // Topic前缀
#define MTU_FOR_MQTT 1400  // MQTT 传输的 MTU 值
// IP包相关定义
#define IP_HDR_LEN      20      // IPv4头部长度
#define IP_VER_MASK     0xf0    // IP版本掩码
#define IP_VER_IPV4     0x40    // IPv4版本号

// MQTT 相关错误码
#define ERR_MQTT_INIT_FAILED          200   // MQTT 初始化失败
// MQTT配置
#define MQTT_BROKER_URL "tcp://localhost:1883"  // MQTT broker地址
#define MQTT_TOPIC "vpn/data"                   // MQTT主题
#define MQTT_QOS 1                              // QoS级别
#define MQTT_USERNAME ""                        // MQTT用户名（如果需要）
#define MQTT_PASSWORD ""                       

// MQTT配置结构
typedef struct MQTT_CONFIG
{
    char broker[MAX_PATH];     // MQTT broker 地址
    char client_id[64];        // MQTT client ID
    int qos;                   // MQTT QoS level
} MQTT_CONFIG;

// 函数声明
void connectionLost(void *context, char *cause);
const MQTT_CONFIG* GetCurrentMqttConfig();
bool ConnectMqttClient(CONNECTION* c);
void ProcessMqttLoop(CONNECTION *c);
void GenerateMqttTopic(char* topic, UINT size, UINT ip_uint);
void SendDataWithMQTT(CONNECTION *c);
void ProcessMqttMessages(CONNECTION *c);
void CleanupMqttConnection(CONNECTION *c);
void GenerateRandomString(char *str, UINT size);
bool InitMqttVpn();
void FreeMqttVpn();
bool ConfigureVirtualAdapter(CONNECTION *c);
bool GetMqttUserInput(char* broker, UINT broker_size);
bool SubscribeMqttTopic(CONNECTION* c, const char* topic);
bool UnsubscribeMqttTopic(CONNECTION* c, const char* topic);
bool IsMqttConnected(CONNECTION* c);
bool ReconnectMqtt(CONNECTION* c);
bool SetMqttConfig(const char* broker);
#endif // MQTT_VPN_H