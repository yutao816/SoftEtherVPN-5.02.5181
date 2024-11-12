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

static bool g_mqtt_connected = false;
static CONNECTION *g_mqtt_current_connection = NULL;
// 在现有的 #define 部分添加
#define MAX_PACKET_SIZE 1500  // 标准以太网MTU

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
// MQTT全局状态
static struct {
    bool initialized;     // 初始化标志
    bool connected;       // 连接标志
    CONNECTION *current;  // 当前连接
    MQTT_CONFIG config;   // MQTT配置
} g_mqtt_state = {0};

// 检查MQTT状态
bool IsMqttConnected(void)
{
    return g_mqtt_state.connected && g_mqtt_state.current != NULL;
}

// 设置MQTT连接状态
void SetMqttConnected(CONNECTION *c, bool connected)
{
    if (connected && c != NULL)
    {
        g_mqtt_state.connected = true;
        g_mqtt_state.current = c;
        Debug("MQTT: Connection established");
    }
    else
    {
        g_mqtt_state.connected = false;
        g_mqtt_state.current = NULL;
        Debug("MQTT: Connection closed");
    }
}

// 初始化MQTT
bool InitMqttVpn()
{
    if (g_mqtt_state.initialized)
    {
        return true;
    }

    Debug("MQTT VPN: Initializing...");
    Zero(&g_mqtt_state.config, sizeof(MQTT_CONFIG));
    
    // 设置默认QoS
    g_mqtt_state.config.qos = QOS;

    // 设置TLS默认值
    g_mqtt_state.config.use_tls = false;
    g_mqtt_state.config.verify_cert = true;
    ClearStr(g_mqtt_state.config.ca_cert, sizeof(g_mqtt_state.config.ca_cert));
    ClearStr(g_mqtt_state.config.client_cert, sizeof(g_mqtt_state.config.client_cert));
    ClearStr(g_mqtt_state.config.client_key, sizeof(g_mqtt_state.config.client_key));

    // 生成默认的客户端ID前缀
    char rand_str[32];
    GenerateRandomString(rand_str, sizeof(rand_str));
    Format(g_mqtt_state.config.client_id, sizeof(g_mqtt_state.config.client_id), 
        CLIENTID_PRE "%s", rand_str);

    Debug("MQTT VPN: Initialized with default client ID: %s", g_mqtt_state.config.client_id);

    // 设置默认broker
    StrCpy(g_mqtt_state.config.broker, sizeof(g_mqtt_state.config.broker), "tcp://localhost:1883");

    g_mqtt_state.initialized = true;
    Debug("MQTT VPN: Initialization completed");
    return true;
}

// 清理MQTT资源
void FreeMqttVpn()
{
    if (g_mqtt_state.current != NULL)
    {
        DisconnectMqttClient(g_mqtt_state.current);
    }
    Zero(&g_mqtt_state, sizeof(g_mqtt_state));
    Debug("MQTT VPN: Cleaned up");
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

// 生成MQTT主题
bool GenerateMqttTopic(CONNECTION *c)
{
    if (c == NULL)
    {
        return false;
    }

    // 生成6位随机字符串作为主题后缀
    char suffix[7];  // 6位随机字符 + 1位结束符
    UCHAR rand_data[3];  // 需要3字节来生成6位十六进制字符串
    
    Rand(rand_data, sizeof(rand_data));
    BinToStr(suffix, sizeof(suffix), rand_data, sizeof(rand_data));
    
    // 格式化主题: vpn/XXXXXX
    Format(c->MqttTopic, sizeof(c->MqttTopic), "%s/%s", TOPIC_PRE, suffix);
    
    Debug("MQTT: Generated topic: %s", c->MqttTopic);
    return true;
}

// 订阅MQTT主题
bool SubscribeMqttTopic(CONNECTION* c, const char* topic)
{
    if (c == NULL || c->MQTTClient == NULL || topic == NULL)
    {
        Debug("MQTT: Invalid parameters for topic subscription");
        return false;
    }

    // 生成并设置主题（如果未指定）
    if (IsEmptyStr(topic))
    {
        if (!GenerateMqttTopic(c))
        {
            Debug("MQTT: Failed to generate topic");
            return false;
        }
        topic = c->MqttTopic;
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
    if (c == NULL || message == NULL)
    {
        return 1;
    }

    // 处理收到的数据包
    if (message->payloadlen > 0 && message->payloadlen <= MAX_PACKET_SIZE)
    {
        ProcessMqttPacket(c, message->payload, message->payloadlen);
    }
    else
    {
        Debug("MQTT: Invalid packet size: %d", message->payloadlen);
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
    StrCpy(g_mqtt_state.config.broker, sizeof(g_mqtt_state.config.broker), broker);
    g_mqtt_state.config.qos = QOS;  // 使用默认QoS值
    Debug("MQTT VPN: Broker configured: %s, QoS: %d", broker, g_mqtt_state.config.qos);
    return true;
}

// 获取当前MQTT配置
const MQTT_CONFIG* GetCurrentMqttConfig()
{
    return g_mqtt_state.initialized ? &g_mqtt_state.config : NULL;
}

// 生成MQTT Topic
// void GenerateMqttTopic(char* topic, UINT size, UINT ip_uint)
// {
//     UCHAR ip_bytes[4];
//     UINTToIP(ip_bytes, ip_uint);
//     Format(topic, size, "%s/%u.%u.%u.%u", TOPIC_PRE, 
//         ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
// }

// MQTT连接处理
bool ConnectMqttClient(CONNECTION* c)
{
    if (c == NULL || !g_mqtt_state.initialized)
    {
        Debug("MQTT: Connection failed - invalid parameters or MQTT not enabled");
        return false;
    }

    // 确保broker地址格式正确
    char broker[MAX_SIZE];
    if (StartWith(g_mqtt_state.config.broker, "tcp://") == false)
    {
        Format(broker, sizeof(broker), "tcp://%s", g_mqtt_state.config.broker);
    }
    else
    {
        StrCpy(broker, sizeof(broker), g_mqtt_state.config.broker);
    }
    
    Debug("MQTT: Connecting to broker %s", broker);

    // 初始化发送队列
    c->SendBlocks = NewQueue();
    c->MqttQoS = g_mqtt_state.config.qos;
    
    // 设置MQTT连接选项
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    conn_opts.keepAliveInterval = 60;
    conn_opts.cleansession = 1;
    conn_opts.reliable = 1;
    conn_opts.connectTimeout = 30;  // 30秒连接超时

    // 创建MQTT客户端
    int rc = MQTTClient_create((MQTTClient*)&c->MQTTClient, 
        broker, g_mqtt_state.config.client_id,
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

    // 尝试连接到MQTT broker
    rc = MQTTClient_connect((MQTTClient)c->MQTTClient, &conn_opts);
    
    // 错误处理
    if (rc != MQTTCLIENT_SUCCESS)
    {
        char* error_msg;
        switch(rc)
        {
            case 1: error_msg = "Unacceptable protocol version"; break;
            case 2: error_msg = "Identifier rejected"; break;
            case 3: error_msg = "Server unavailable"; break;
            case 4: error_msg = "Bad username or password"; break;
            case 5: error_msg = "Not authorized"; break;
            case -1: error_msg = "Network error"; break;
            default: error_msg = "Unknown error"; break;
        }
        Debug("MQTT: Connection failed - %s (code %d)", error_msg, rc);
        
        MQTTClient_destroy((MQTTClient*)&c->MQTTClient);
        return false;
    }

    Debug("MQTT: Connected successfully");
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
        // 添加大小检查
        if (b->Size > MAX_PACKET_SIZE)
        {
            Debug("MQTT: Packet too large: %d", b->Size);
            FreeBlock(b);
            continue;
        }

        if (MQTTClient_isConnected((MQTTClient)c->MQTTClient))
        {
            // ... 其余代码保持不变 ...
        }
        FreeBlock(b);
    }
}
void ProcessMqttPacket(CONNECTION *c, void *data, UINT size)
{
    if (c == NULL || c->Session == NULL || 
        c->Session->Virtual == NULL || data == NULL || size == 0)
    {
        Debug("MQTT: Invalid parameters for packet processing");
        return;
    }

    VH *v = (VH *)c->Session->Virtual;
    
    // 获取虚拟主机的数据包适配器
    PACKET_ADAPTER *pa = VirtualGetPacketAdapter(v);
    if (pa != NULL)
    {
        void *packet_data = Clone(data, size);
        if (packet_data != NULL)
        {
            // 使用虚拟主机的 PutPacket 函数
            if (pa->PutPacket(pa, packet_data, size))
            {
                Debug("MQTT: Forwarded packet to virtual adapter, size: %d", size);
            }
            else
            {
                Debug("MQTT: Failed to forward packet");
                Free(packet_data);
            }
        }
    }
    else
    {
        Debug("MQTT: Virtual adapter not available");
    }
}
// 添加 MQTT 主循环处理函数
void ProcessMqttLoop(CONNECTION *c)
{
    if (c == NULL || !c->MQTTClient)
    {
        return;
    }

    // 设置处理标志
    c->IsInPacket = false;

    // 检查连接状态
    if (!MQTTClient_isConnected((MQTTClient)c->MQTTClient))
    {
        UINT retry_count = 0;
        const UINT max_retries = 3;
        
        while (retry_count < max_retries)
        {
            Debug("MQTT: Connection lost, attempting to reconnect... (attempt %u/%u)", 
                retry_count + 1, max_retries);
            
            if (ReconnectMqtt(c))
            {
                // 重新订阅主题
                if (SubscribeMqttTopic(c, c->MqttTopic))
                {
                    Debug("MQTT: Successfully reconnected and resubscribed");
                    break;
                }
            }
            
            retry_count++;
            if (retry_count < max_retries)
            {
                // 等待一段时间再重试
                SleepThread(1000);
            }
        }
        
        if (retry_count >= max_retries)
        {
            Debug("MQTT: Failed to reconnect after %u attempts", max_retries);
            return;
        }
    }

    // 处理发送队列中的数据
    if (c->SendBlocks != NULL && GetQueueNum(c->SendBlocks) > 0)
    {
        Debug("MQTT: Processing send queue, %u packets pending", 
            GetQueueNum(c->SendBlocks));
        SendDataWithMQTT(c);
    }

    // 处理接收消息
    c->IsInPacket = true;
    MQTTClient_yield();
    
    // 检查接收状态
    if (c->Session != NULL && c->Session->Virtual != NULL)
    {
        VH *v = (VH *)c->Session->Virtual;
        if (v->LastRecvTime + (UINT64)TIMEOUT < v->Now)
        {
            Debug("MQTT: No data received for %u ms", TIMEOUT);
        }
    }

    // 重置处理标志
    c->IsInPacket = false;
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
bool DisconnectMqttClient(CONNECTION *c)
{
    // 参数检查
    if (c == NULL || c->MQTTClient == NULL)
    {
        Debug("MQTT: Invalid parameters for disconnect");
        return false;
    }

    Debug("MQTT: Disconnecting client %s", c->MqttTopic);

    // 取消订阅主题
    if (c->MqttTopic[0] != '\0')
    {
        int rc = MQTTClient_unsubscribe((MQTTClient)c->MQTTClient, c->MqttTopic);
        if (rc != MQTTCLIENT_SUCCESS)
        {
            Debug("MQTT: Failed to unsubscribe from topic %s, rc=%d", c->MqttTopic, rc);
        }
        else
        {
            Debug("MQTT: Unsubscribed from topic %s", c->MqttTopic);
        }
    }

    // 断开连接
    int rc = MQTTClient_disconnect((MQTTClient)c->MQTTClient, TIMEOUT);
    if (rc != MQTTCLIENT_SUCCESS)
    {
        Debug("MQTT: Disconnect failed with error code %d", rc);
    }

    // 清理MQTT客户端
    MQTTClient_destroy((MQTTClient*)&c->MQTTClient);
    c->MQTTClient = NULL;

    // 清理发送队列
    if (c->SendBlocks != NULL)
    {
        LockQueue(c->SendBlocks);
        {
            BLOCK *b;
            while ((b = GetNext(c->SendBlocks)) != NULL)
            {
                FreeBlock(b);
            }
        }
        UnlockQueue(c->SendBlocks);
    }

    // 清空主题
    Zero(c->MqttTopic, sizeof(c->MqttTopic));
    SetMqttConnected(c, false);

    Debug("MQTT: Client disconnected successfully");
    return true;
}