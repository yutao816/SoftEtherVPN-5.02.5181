#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include "mqtt_vpn.h"
#include <stdbool.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "MQTTClient.h"
#include <sodium.h>
#include "../Mayaqua/Mayaqua.h"
#include "../Cedar/Connection.h"
#include "../Cedar/Cedar.h"
#include "../Cedar/Session.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Str.h"
#include "../Mayaqua/Object.h"
#include "../Cedar/Virtual.h"
#include "../Cedar/VLan.h"
#include "../Cedar/Client.h"
#include "../Cedar/CedarType.h"
#include "../Cedar/Nat.h"

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
#define FILE_DEVICE_UNKNOWN 0x00000022
#define METHOD_BUFFERED 0
#define FILE_ANY_ACCESS 0

#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))

#define TAP_CONTROL_CODE(request, method) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, request, method, FILE_ANY_ACCESS)

#define TAP_IOCTL_SET_MEDIA_STATUS \
    TAP_CONTROL_CODE(6, METHOD_BUFFERED)

#define IFF_TUN     0x0001
#define IFF_TAP     0x0002
#define IFF_NO_PI   0x1000

// 全局配置
static MQTT_CONFIG g_mqtt_config = {0};

// MQTT 消息到达回调函数
int messageArrived(void *context, char *topicName, int topicLen, MQTTClient_message *message) {
    CONNECTION *c = (CONNECTION *)context;
    if (c && message) {
        BLOCK *block = NewBlock(message->payload, message->payloadlen, 0);
        if (block) {
            InsertReceivedBlockToQueue(c, block, false);
        }
    }
    MQTTClient_freeMessage(&message);
    MQTTClient_free(topicName);
    return 1;
}

// 初始化 MQTT 连接
bool InitializeMqttConnection(CONNECTION *c, const char *broker, const char *topic)
{
    if (c == NULL || broker == NULL || topic == NULL) {
        return false;
    }

    // 保存配置
    StrCpy(g_mqtt_config.broker, sizeof(g_mqtt_config.broker), broker);
    StrCpy(g_mqtt_config.topic, sizeof(g_mqtt_config.topic), topic);
    g_mqtt_config.qos = QOS;
    snprintf(g_mqtt_config.client_id, sizeof(g_mqtt_config.client_id), 
        "%s%d", CLIENTID_PRE, rand());

    // 创建 MQTT 客户端
    int rc = MQTTClient_create((MQTTClient*)&c->MQTTClient, broker, 
        g_mqtt_config.client_id, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    if (rc != MQTTCLIENT_SUCCESS) {
        Debug("MQTT: Failed to create client, return code %d\n", rc);
        return false;
    }

    // 设置连接选项
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;

    // 设置回调
    rc = MQTTClient_setCallbacks((MQTTClient)c->MQTTClient, c, NULL, messageArrived, NULL);
    if (rc != MQTTCLIENT_SUCCESS) {
        Debug("MQTT: Failed to set callbacks, return code %d\n", rc);
        return false;
    }

    // 连接到 MQTT 服务器
    rc = MQTTClient_connect((MQTTClient)c->MQTTClient, &conn_opts);
    if (rc != MQTTCLIENT_SUCCESS) {
        Debug("MQTT: Connection failed, return code %d\n", rc);
        return false;
    }

    // 保存连接参数
    StrCpy(c->ServerName, sizeof(c->ServerName), broker);
    StrCpy(c->MqttTopic, sizeof(c->MqttTopic), topic);
    c->MqttQoS = QOS;

    Debug("MQTT: Connection successful\n");
    return true;
}

// 处理 MQTT 消息
void ProcessMqttMessages(CONNECTION *c) 
{
    if (c->MQTTClient != NULL) 
    {
        MQTTClient_yield();
    }
}

// 发送数据
void SendDataWithMQTT(CONNECTION *c) 
{
    if (c == NULL) return;

    BLOCK *b;
    while ((b = GetNext(c->SendBlocks)) != NULL) 
    {
        if (c->MQTTClient && MQTTClient_isConnected((MQTTClient)c->MQTTClient)) 
        {
            MQTTClient_message pubmsg = MQTTClient_message_initializer;
            pubmsg.payload = b->Buf;
            pubmsg.payloadlen = b->Size;
            pubmsg.qos = c->MqttQoS;
            pubmsg.retained = 0;

            MQTTClient_deliveryToken token;
            int rc = MQTTClient_publishMessage((MQTTClient)c->MQTTClient, 
                c->MqttTopic, &pubmsg, &token);
            if (rc != MQTTCLIENT_SUCCESS) {
                Debug("MQTT: Failed to publish message, return code %d\n", rc);
            }
        }
        FreeBlock(b);
    }
}

// 清理 MQTT 连接
void CleanupMqttConnection(CONNECTION *c)
{
    if (c != NULL && c->MQTTClient)
    {
        MQTTClient_disconnect((MQTTClient)c->MQTTClient, TIMEOUT);
        MQTTClient_destroy((MQTTClient*)&c->MQTTClient);
        c->MQTTClient = NULL;
    }
}

// 创建 TAP 设备
HANDLE CreateTapDevice(char *device_name)
{
    HANDLE handle;
    char device_path[256];
    
    // 构造设备路径
    snprintf(device_path, sizeof(device_path), 
        "\\\\.\\Global\\%s.tap", device_name);

    // 打开 TAP 设备
    handle = CreateFileA(device_path, GENERIC_READ | GENERIC_WRITE,
        0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);

    if (handle == INVALID_HANDLE_VALUE)
    {
        Debug("TAP: Failed to open device %s\n", device_path);
        return INVALID_HANDLE_VALUE;
    }

    // 设置 TAP 设备为启用状态
    DWORD len;
    ULONG status = 1;
    if (!DeviceIoControl(handle, TAP_IOCTL_SET_MEDIA_STATUS,
        &status, sizeof(status), &status, sizeof(status), &len, NULL))
    {
        Debug("TAP: Failed to set media status\n");
        CloseHandle(handle);
        return INVALID_HANDLE_VALUE;
    }

    Debug("TAP: Device %s opened successfully\n", device_path);
    return handle;
}

// 配置 TAP 设备 IP 地址
bool ConfigureTapDevice(const char *device_name, const char *ip_address)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), 
        "netsh interface ip set address \"%s\" static %s 255.255.255.0",
        device_name, ip_address);
    
    return (system(cmd) == 0);
}

// 获取用户输入的 MQTT 配置
bool GetMqttUserConfig()
{
    char buffer[256];
    
    printf("Enter MQTT broker address (e.g., tcp://localhost:1883): ");
    if (!fgets(buffer, sizeof(buffer), stdin)) return false;
    buffer[strcspn(buffer, "\n")] = 0;
    StrCpy(g_mqtt_config.broker, sizeof(g_mqtt_config.broker), buffer);

    printf("Enter MQTT topic (default: mqttip): ");
    if (!fgets(buffer, sizeof(buffer), stdin)) return false;
    buffer[strcspn(buffer, "\n")] = 0;
    if (strlen(buffer) > 0) {
        StrCpy(g_mqtt_config.topic, sizeof(g_mqtt_config.topic), buffer);
    } else {
        StrCpy(g_mqtt_config.topic, sizeof(g_mqtt_config.topic), TOPIC_PRE);
    }

    printf("Enter MQTT QoS (0-2, default: 0): ");
    if (!fgets(buffer, sizeof(buffer), stdin)) return false;
    g_mqtt_config.qos = atoi(buffer);
    if (g_mqtt_config.qos < 0 || g_mqtt_config.qos > 2) {
        g_mqtt_config.qos = QOS;
    }

    return true;
}

// 获取当前 MQTT 配置
const MQTT_CONFIG* GetCurrentMqttConfig()
{
    return &g_mqtt_config;
}