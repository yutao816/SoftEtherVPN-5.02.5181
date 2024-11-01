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
#include "../Mayaqua/Memory.h"
#include "../Mayaqua/Str.h"
#include "../Mayaqua/Object.h"
#include "../Mayaqua/Internat.h"
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

// 简化的 MQTT 配置
static MQTT_CONFIG g_mqtt_config = {0};
static bool g_mqtt_enabled = false;

// MQTT 消息到达回调函数
int messageArrived(void *context, char *topicName, int topicLen, MQTTClient_message *message) {
    CONNECTION *c = (CONNECTION *)context;
    if (c && message) {
        BLOCK *block = NewBlock(message->payload, message->payloadlen, 0);
        if (block) {
            InsertReceivedBlockToQueue(c, block, false);
            Debug("MQTT: Received message on topic %s, size: %d", topicName, message->payloadlen);
        }
    }
    MQTTClient_freeMessage(&message);
    MQTTClient_free(topicName);
    return 1;
}

// 初始化 MQTT 连接
bool InitializeMqttConnection(CONNECTION *c, char *broker, char *topic)
{
    if (c == NULL || broker == NULL || topic == NULL) {
        Debug("MQTT: Invalid parameters for initialization");
        return false;
    }

    // 创建 MQTT 客户端
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;
    conn_opts.reliable = 1;
    
    int rc = MQTTClient_create((MQTTClient*)&c->MQTTClient, broker, 
        g_mqtt_config.client_id, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    if (rc != MQTTCLIENT_SUCCESS) {
        Debug("MQTT: Failed to create client, return code %d", rc);
        return false;
    }

    // 设置回调
    rc = MQTTClient_setCallbacks((MQTTClient)c->MQTTClient, c, 
        NULL, messageArrived, NULL);
    if (rc != MQTTCLIENT_SUCCESS) {
        Debug("MQTT: Failed to set callbacks, return code %d", rc);
        return false;
    }

    // 连接到 MQTT 服务器
    rc = MQTTClient_connect((MQTTClient)c->MQTTClient, &conn_opts);
    if (rc != MQTTCLIENT_SUCCESS) {
        Debug("MQTT: Connection failed, return code %d", rc);
        return false;
    }

    // 订阅主题
    rc = MQTTClient_subscribe((MQTTClient)c->MQTTClient, topic, g_mqtt_config.qos);
    if (rc != MQTTCLIENT_SUCCESS) {
        Debug("MQTT: Subscribe failed, return code %d", rc);
        return false;
    }

    // 保存连接参数
    StrCpy(c->ServerName, sizeof(c->ServerName), broker);
    StrCpy(c->MqttTopic, sizeof(c->MqttTopic), topic);
    c->MqttQoS = g_mqtt_config.qos;

    Debug("MQTT: Connection successful to %s on topic %s", broker, topic);
    return true;
}

// 发送数据
void SendDataWithMQTT(CONNECTION *c) 
{
    if (c == NULL || c->MQTTClient == NULL) return;

    BLOCK *b;
    while ((b = GetNext(c->SendBlocks)) != NULL) 
    {
        if (MQTTClient_isConnected((MQTTClient)c->MQTTClient)) 
        {
            MQTTClient_message pubmsg = MQTTClient_message_initializer;
            pubmsg.payload = b->Buf;
            pubmsg.payloadlen = b->Size;
            pubmsg.qos = c->MqttQoS;
            pubmsg.retained = 0;

            MQTTClient_deliveryToken token;
            int rc = MQTTClient_publishMessage((MQTTClient)c->MQTTClient, 
                c->MqttTopic, &pubmsg, &token);
            
            if (rc != MQTTCLIENT_SUCCESS) 
            {
                Debug("MQTT: Failed to publish message, return code %d", rc);
                // 尝试重新连接
                if (!MQTTClient_isConnected((MQTTClient)c->MQTTClient)) 
                {
                    Debug("MQTT: Connection lost, attempting to reconnect...");
                    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
                    conn_opts.keepAliveInterval = 20;
                    conn_opts.cleansession = 1;
                    rc = MQTTClient_connect((MQTTClient)c->MQTTClient, &conn_opts);
                    if (rc == MQTTCLIENT_SUCCESS) 
                    {
                        Debug("MQTT: Reconnection successful");
                        // 重新订阅主题
                        MQTTClient_subscribe((MQTTClient)c->MQTTClient, 
                            c->MqttTopic, c->MqttQoS);
                    }
                }
            }
            else 
            {
                // 等待消息发送完成
                rc = MQTTClient_waitForCompletion((MQTTClient)c->MQTTClient, 
                    token, TIMEOUT);
                if (rc != MQTTCLIENT_SUCCESS) 
                {
                    Debug("MQTT: Message delivery failed, return code %d", rc);
                }
            }
        }
        FreeBlock(b);
    }
}

// 处理 MQTT 消息
void ProcessMqttMessages(CONNECTION *c) 
{
    if (c && c->MQTTClient) 
    {
        // 处理接收到的消息
        MQTTClient_yield();
        
        // 检查连接状态
        if (!MQTTClient_isConnected((MQTTClient)c->MQTTClient)) 
        {
            Debug("MQTT: Connection lost during processing, attempting to reconnect...");
            MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
            conn_opts.keepAliveInterval = 20;
            conn_opts.cleansession = 1;
            
            int rc = MQTTClient_connect((MQTTClient)c->MQTTClient, &conn_opts);
            if (rc == MQTTCLIENT_SUCCESS) 
            {
                Debug("MQTT: Reconnection successful");
                // 重新订阅主题
                MQTTClient_subscribe((MQTTClient)c->MQTTClient, 
                    c->MqttTopic, c->MqttQoS);
            }
            else 
            {
                Debug("MQTT: Reconnection failed, return code %d", rc);
            }
        }
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

// 从用户获取 MQTT 配置信息
bool GetMqttUserInput()
{
    char input[MAX_PATH];
    bool ret = true;

    Print("MQTT VPN Configuration\n");
    Print("--------------------\n");

    // 获取 Broker 地址
    Print("Enter MQTT Broker address (default: tcp://localhost:1883): ");
    if (GetLine(input, sizeof(input)) == false || IsEmptyStr(input))
    {
        StrCpy(g_mqtt_config.broker, sizeof(g_mqtt_config.broker), "tcp://localhost:1883");
    }
    else
    {
        StrCpy(g_mqtt_config.broker, sizeof(g_mqtt_config.broker), input);
    }

    // 获取 Topic
    Print("Enter MQTT Topic (default: mqttip): ");
    if (GetLine(input, sizeof(input)) == false || IsEmptyStr(input))
    {
        StrCpy(g_mqtt_config.topic, sizeof(g_mqtt_config.topic), TOPIC_PRE);
    }
    else
    {
        StrCpy(g_mqtt_config.topic, sizeof(g_mqtt_config.topic), input);
    }

    // 获取 QoS
    Print("Enter MQTT QoS (0-2, default: 0): ");
    if (GetLine(input, sizeof(input)) == false || IsEmptyStr(input))
    {
        g_mqtt_config.qos = QOS;
    }
    else
    {
        g_mqtt_config.qos = ToInt(input);
        if (g_mqtt_config.qos > 2)
        {
            g_mqtt_config.qos = QOS;
        }
    }

    // 生成随机的客户端 ID
    snprintf(g_mqtt_config.client_id, sizeof(g_mqtt_config.client_id), 
        "%s%d", CLIENTID_PRE, rand());

    // 显示配置信息
    Print("\nMQTT Configuration Summary:\n");
    Print("  Broker: %s\n", g_mqtt_config.broker);
    Print("  Topic: %s\n", g_mqtt_config.topic);
    Print("  QoS: %d\n", g_mqtt_config.qos);
    Print("  Client ID: %s\n", g_mqtt_config.client_id);
    Print("\nPress Enter to continue or Ctrl+C to cancel...");
    GetLine(input, sizeof(input));

    g_mqtt_enabled = true;
    return true;  // 直接返回 true
}

// 获取当前 MQTT 配置
const MQTT_CONFIG* GetCurrentMqttConfig()
{
    return &g_mqtt_config;
}

// 获取 MQTT 配置
bool GetMqttUserConfig()
{
    UINT argc;
    wchar_t **argv;
    bool broker_specified = false;

    // 使用 GetCommandLineW 和 CommandLineToArgvW 获取命令行参数
    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == NULL)
    {
        Debug("Failed to get command line arguments\n");
        return false;
    }

    // 解析命令行参数
    for (UINT i = 1; i < argc; i++)
    {
        if (_wcsicmp(argv[i], L"-b") == 0)
        {
            if (i + 1 < argc)
            {
                char broker[MAX_PATH];
                UniToStr(broker, sizeof(broker), argv[i + 1]);
                StrCpy(g_mqtt_config.broker, sizeof(g_mqtt_config.broker), broker);
                broker_specified = true;
                i++;
            }
        }
    }

    // 释放参数数组
    LocalFree(argv);

    // 如果没有在命令行指定 broker，则通过交互方式获取配置
    if (!broker_specified)
    {
        return GetMqttUserInput();
    }

    // 设置其他默认值
    StrCpy(g_mqtt_config.topic, sizeof(g_mqtt_config.topic), TOPIC_PRE);
    g_mqtt_config.qos = QOS;
    snprintf(g_mqtt_config.client_id, sizeof(g_mqtt_config.client_id), 
        "%s%d", CLIENTID_PRE, rand());

    Debug("MQTT Configuration:");
    Debug("  Broker: %s", g_mqtt_config.broker);
    Debug("  Topic: %s", g_mqtt_config.topic);
    Debug("  QoS: %d", g_mqtt_config.qos);
    Debug("  Client ID: %s", g_mqtt_config.client_id);

    g_mqtt_enabled = true;
    return true;
}