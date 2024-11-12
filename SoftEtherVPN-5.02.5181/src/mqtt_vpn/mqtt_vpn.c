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
#include "../Mayaqua/Network.h"  // 包含IP相关函数的头文件

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

// MQTT配置管理
static MQTT_CONFIG g_mqtt_config = {0};
static bool g_mqtt_enabled = false;

// MQTT模块初始化
bool InitMqttVpn()
{
    Debug("MQTT VPN: Initializing...");

    // 初始化MQTT配置
    Zero(&g_mqtt_config, sizeof(MQTT_CONFIG));
    g_mqtt_enabled = false;

    // 设置默认QoS
    g_mqtt_config.qos = QOS;

    // 生成默认的客户端ID前缀
    char rand_str[32];
    GenerateRandomString(rand_str, sizeof(rand_str));
    Format(g_mqtt_config.client_id, sizeof(g_mqtt_config.client_id), 
        CLIENTID_PRE "%s", rand_str);

    Debug("MQTT VPN: Initialized with default client ID: %s", g_mqtt_config.client_id);

    // 设置默认broker（可以通过配置文件或命令行参数修改）
    StrCpy(g_mqtt_config.broker, sizeof(g_mqtt_config.broker), "tcp://localhost:1883");
    g_mqtt_enabled = true;

    Debug("MQTT VPN: Configuration completed. Default Broker: %s", g_mqtt_config.broker);
    return true;
}

// MQTT模块清理
void FreeMqttVpn()
{
    Debug("MQTT VPN: Cleaning up...");
    g_mqtt_enabled = false;
    Zero(&g_mqtt_config, sizeof(MQTT_CONFIG));
}

// 从用户获取MQTT配置
bool GetMqttUserInput(char* broker, UINT broker_size)
{
    char tmp[MAX_SIZE];
    
    Print("\nMQTT VPN Configuration\n");
    Print("--------------------\n");
    
    // 获取 Broker 地址
    Print("Enter MQTT Broker address\n");
    Print("Example: tcp://localhost:1883\n");
    Print("Broker: ");
    
    if (GetLine(tmp, sizeof(tmp)) == false || IsEmptyStr(tmp))
    {
        // 使用默认值
        StrCpy(broker, broker_size, "tcp://localhost:1883");
        Print("Using default broker: %s\n", broker);
    }
    else
    {
        StrCpy(broker, broker_size, tmp);
    }

    Print("\nConfiguration Summary:\n");
    Print("Broker: %s\n", broker);
    Print("QoS: %d\n", QOS);
    Print("Client ID will be generated automatically\n");
    Print("\nPress Enter to continue or Ctrl+C to cancel...");
    GetLine(tmp, sizeof(tmp));

    return true;
}

// 订阅MQTT主题
bool SubscribeMqttTopic(CONNECTION* c, const char* topic)
{
    if (c == NULL || c->MQTTClient == NULL || topic == NULL)
    {
        return false;
    }

    int rc = MQTTClient_subscribe((MQTTClient)c->MQTTClient, topic, c->MqttQoS);
    if (rc != MQTTCLIENT_SUCCESS)
    {
        Debug("MQTT: Failed to subscribe to topic %s, return code %d", topic, rc);
        return false;
    }

    Debug("MQTT: Successfully subscribed to topic: %s", topic);
    return true;
}

// 取消订阅MQTT主题
bool UnsubscribeMqttTopic(CONNECTION* c, const char* topic)
{
    if (c == NULL || c->MQTTClient == NULL || topic == NULL)
    {
        return false;
    }

    int rc = MQTTClient_unsubscribe((MQTTClient)c->MQTTClient, topic);
    if (rc != MQTTCLIENT_SUCCESS)
    {
        Debug("MQTT: Failed to unsubscribe from topic %s, return code %d", topic, rc);
        return false;
    }

    Debug("MQTT: Successfully unsubscribed from topic: %s", topic);
    return true;
}

// MQTT 消息到达回调函数
int messageArrived(void *context, char *topicName, int topicLen, MQTTClient_message *message)
{
    CONNECTION *c = (CONNECTION *)context;
    if (c == NULL || c->Session == NULL || c->Session->Virtual == NULL)
    {
        return 1;
    }

    if (message->payloadlen > 0)
    {
        VH *v = (VH *)c->Session->Virtual;
        if (v != NULL)
        {
            // 标记为接收方向
            c->IsInPacket = true;
            
            // 创建数据包副本并写入虚拟网卡
            void *data = Clone(message->payload, message->payloadlen);
            if (data != NULL)
            {
                VirtualPutPacket(v, data, message->payloadlen);
                Debug("MQTT: Received and forwarded packet, size: %d", message->payloadlen);
            }
            
            c->IsInPacket = false;
        }
    }

    MQTTClient_freeMessage(&message);
    MQTTClient_free(topicName);
    return 1;
}

// 设置MQTT配置
bool SetMqttConfig(const char* broker)
{
    if (broker == NULL)
    {
        return false;
    }

    // 保存配置
    StrCpy(g_mqtt_config.broker, sizeof(g_mqtt_config.broker), broker);
    g_mqtt_config.qos = QOS;  // 使用默认QoS值
    Debug("MQTT VPN: Broker configured: %s, QoS: %d", broker, g_mqtt_config.qos);
    return true;
}

// 获取当前MQTT配置
const MQTT_CONFIG* GetCurrentMqttConfig()
{
    return g_mqtt_enabled ? &g_mqtt_config : NULL;
}

// 生成MQTT Topic
void GenerateMqttTopic(char* topic, UINT size, UINT ip_uint)
{
    UCHAR ip_bytes[4];
    UINTToIP(ip_bytes, ip_uint);
    Format(topic, size, "%s/%u.%u.%u.%u", TOPIC_PRE, 
        ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
}

// MQTT连接处理
bool ConnectMqttClient(CONNECTION* c)
{
    if (c == NULL || !g_mqtt_enabled)
    {
        Debug("MQTT: Connection failed - invalid parameters or MQTT not enabled");
        return false;
    }

    // 确保broker地址格式正确
    char broker[MAX_SIZE];
    if (StartWith(g_mqtt_config.broker, "tcp://") == false)
    {
        Format(broker, sizeof(broker), "tcp://%s", g_mqtt_config.broker);
    }
    else
    {
        StrCpy(broker, sizeof(broker), g_mqtt_config.broker);
    }
    
    Debug("MQTT: Attempting to connect to broker %s", broker);

    // 初始化发送队列
    c->SendBlocks = NewQueue();
    c->MqttQoS = g_mqtt_config.qos;
    
    // 设置MQTT连接选项
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    conn_opts.keepAliveInterval = 60;
    conn_opts.cleansession = 1;
    conn_opts.reliable = 1;
    conn_opts.connectTimeout = 30;  // 30秒连接超时
    
    Debug("MQTT: Creating client with ID %s", g_mqtt_config.client_id);

    // 创建MQTT客户端
    int rc = MQTTClient_create((MQTTClient*)&c->MQTTClient, 
        broker, g_mqtt_config.client_id,
        MQTTCLIENT_PERSISTENCE_NONE, NULL);
    if (rc != MQTTCLIENT_SUCCESS)
    {
        Debug("MQTT: Client creation failed with code %d", rc);
        return false;
    }

    // 设置回调函数
    rc = MQTTClient_setCallbacks((MQTTClient)c->MQTTClient, c, 
        connectionLost, messageArrived, NULL);
    if (rc != MQTTCLIENT_SUCCESS)
    {
        Debug("MQTT: Setting callbacks failed with code %d", rc);
        MQTTClient_destroy((MQTTClient*)&c->MQTTClient);
        return false;
    }

    // // 连接到MQTT broker
    // rc = MQTTClient_connect((MQTTClient)c->MQTTClient, &conn_opts);
    // if (rc != MQTTCLIENT_SUCCESS)
    // {
    //     char* error_msg;
    //     switch(rc)
    //     {
    //         case 1: error_msg = "Connection refused: Unacceptable protocol version"; break;
    //         case 2: error_msg = "Connection refused: Identifier rejected"; break;
    //         case 3: error_msg = "Connection refused: Server unavailable"; break;
    //         case 4: error_msg = "Connection refused: Bad username or password"; break;
    //         case 5: error_msg = "Connection refused: Not authorized"; break;
    //         default: error_msg = "Connection failed with unknown error"; break;
    //     }
    //     Debug("MQTT: %s (code %d)", error_msg, rc);
    //     MQTTClient_destroy((MQTTClient*)&c->MQTTClient);
    //     return false;
    // }

    // Debug("MQTT: Connection established successfully");
    // return true;
    // 尝试连接到MQTT broker
    Debug("MQTT: Attempting to connect...");
    rc = MQTTClient_connect((MQTTClient)c->MQTTClient, &conn_opts);
    
    // 详细的错误处理
    if (rc != MQTTCLIENT_SUCCESS)
    {
        char* error_msg;
        switch(rc)
        {
            case 1: 
                error_msg = "Connection refused: Unacceptable protocol version";
                Debug("MQTT: Broker doesn't support MQTT v3.1.1");
                break;
            case 2: 
                error_msg = "Connection refused: Identifier rejected";
                Debug("MQTT: Client ID was rejected by broker");
                break;
            case 3: 
                error_msg = "Connection refused: Server unavailable";
                Debug("MQTT: Broker is not accepting connections or unreachable");
                break;
            case 4: 
                error_msg = "Connection refused: Bad username or password";
                Debug("MQTT: Authentication failed");
                break;
            case 5: 
                error_msg = "Connection refused: Not authorized";
                Debug("MQTT: Client is not authorized to connect");
                break;
            case -1: 
                error_msg = "Connection failed: Network error";
                Debug("MQTT: Network connection failed - check broker address and port");
                break;
            default: 
                error_msg = "Connection failed with unknown error";
                Debug("MQTT: Unknown error occurred (code %d)", rc);
                break;
        }
        Debug("MQTT: Connection error - %s (code %d)", error_msg, rc);
        
        // 尝试获取更多网络信息
        Debug("MQTT: Checking network connectivity to %s", broker);
        // TODO: 添加网络连接测试代码
        
        MQTTClient_destroy((MQTTClient*)&c->MQTTClient);
        return false;
    }

    Debug("MQTT: Connection established successfully");
    return true;
}

// 发送VPN数据包通过MQTT
void SendDataWithMQTT(CONNECTION *c)
{
    if (c == NULL || c->MQTTClient == NULL || !c->SendBlocks)
    {
        return;
    }

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
            if (MQTTClient_publishMessage((MQTTClient)c->MQTTClient, 
                c->MqttTopic, &pubmsg, &token) == MQTTCLIENT_SUCCESS)
            {
                MQTTClient_waitForCompletion((MQTTClient)c->MQTTClient, 
                    token, TIMEOUT);
                Debug("MQTT: Sent packet, size: %d", b->Size);
            }
        }
        FreeBlock(b);
    }
}
// 添加 MQTT 主循环处理函数
void ProcessMqttLoop(CONNECTION *c)
{
    if (c == NULL || !c->MQTTClient)
    {
        return;
    }

    // 处理接收消息
    MQTTClient_yield();

    // 检查连接状态并在需要时重连
    if (!MQTTClient_isConnected((MQTTClient)c->MQTTClient))
    {
        Debug("MQTT: Connection lost, attempting to reconnect...");
        if (ReconnectMqtt(c))
        {
            // 重新订阅主题
            SubscribeMqttTopic(c, c->MqttTopic);
        }
    }

    // 处理发送队列
    SendDataWithMQTT(c);
}
// 配置虚拟网卡
bool ConfigureVirtualAdapter(CONNECTION *c)
{
    if (c == NULL || c->Session == NULL)
    {
        return false;
    }

    SESSION *s = c->Session;
    if (s->Virtual == NULL)
    {
        Debug("Virtual Adapter: No virtual interface available");
        return false;
    }

    // 配置虚拟网卡
    if (s->ClientOption != NULL)
    {
        // 设置虚拟网卡参数
        if (s->ClientModeAndUseVLan)
        {
            VH *v = s->Virtual;
            if (v != NULL)
            {
                IP ip;
                if (StrToIP(&ip, s->ClientIP))
                {
                    // 设置虚拟主机的IP地址
                    v->HostIP = IPToUINT(&ip);
                    
                    // 设置子网掩码 (默认使用 255.255.255.0)
                    v->HostMask = 0xFFFFFF00;

                    // 设置MTU
                    v->Mtu = MTU_FOR_MQTT;

                    Debug("Virtual Adapter: Configured with IP %s", s->ClientIP);
                    return true;
                }
            }
        }
    }

    Debug("Virtual Adapter: Configuration failed");
    return false;
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

// 辅助函数：生成随机字符串
void GenerateRandomString(char *str, UINT size)
{
    UCHAR rand_data[16];
    Rand(rand_data, sizeof(rand_data));
    BinToStr(str, size, rand_data, sizeof(rand_data));
}

// 检查MQTT连接状态
bool IsMqttConnected(CONNECTION* c)
{
    if (c == NULL || c->MQTTClient == NULL)
    {
        return false;
    }
    return MQTTClient_isConnected((MQTTClient)c->MQTTClient);
}

// 重新连接MQTT
bool ReconnectMqtt(CONNECTION* c)
{
    if (c == NULL || c->MQTTClient == NULL)
    {
        return false;
    }

    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;
    conn_opts.reliable = 1;

    int rc = MQTTClient_connect((MQTTClient)c->MQTTClient, &conn_opts);
    if (rc != MQTTCLIENT_SUCCESS)
    {
        Debug("MQTT: Reconnection failed, return code %d", rc);
        return false;
    }

    Debug("MQTT: Reconnection successful");
    return true;
}

// 添加连接断开回调
void connectionLost(void *context, char *cause)
{
    Debug("MQTT: Connection lost. Cause: %s", cause ? cause : "Unknown");
}
