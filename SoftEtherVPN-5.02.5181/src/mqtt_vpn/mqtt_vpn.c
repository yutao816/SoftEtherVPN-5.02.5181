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

// MQTT 连接选项
MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;

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
int init_mqtt(CONNECTION *c, const char *clientid) {
    int rc;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;

    // 创建 MQTT 客户端
    rc = MQTTClient_create((MQTTClient*)&c->MQTTClient, c->ServerName, clientid, MQTTCLIENT_PERSISTENCE_NONE, NULL);
    if (rc != MQTTCLIENT_SUCCESS) {
        fprintf(stderr, "Failed to create MQTT client, return code %d\n", rc);
        return 0;
    }

    // 设置连接选项
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;

    // 设置回调
    rc = MQTTClient_setCallbacks((MQTTClient)c->MQTTClient, c, NULL, messageArrived, NULL);
    if (rc != MQTTCLIENT_SUCCESS) {
        fprintf(stderr, "Failed to set callbacks, return code %d\n", rc);
        return 0;
    }

    // 连接到 MQTT 服务器
    rc = MQTTClient_connect((MQTTClient)c->MQTTClient, &conn_opts);
    if (rc != MQTTCLIENT_SUCCESS) {
        fprintf(stderr, "Connection to MQTT server failed, return code %d\n", rc);
        return 0;
    }

    printf("MQTT connection successful\n");
    return 1;
}

void ProcessMqttMessages(CONNECTION *c) {
    if (c->MQTTClient == NULL || !MQTTClient_isConnected((MQTTClient)c->MQTTClient)) {
        char clientid[50];
        snprintf(clientid, sizeof(clientid), "%s%d", CLIENTID_PRE, rand());
        if (!init_mqtt(c, clientid)) {
            return;
        }
    }

     MQTTClient_yield();
}



void SendDataWithMQTT(CONNECTION *c) {
    BLOCK *b;
    while ((b = GetNext(c->SendBlocks)) != NULL) {
        if (c->MQTTClient && MQTTClient_isConnected((MQTTClient)c->MQTTClient)) {
            MQTTClient_message pubmsg = MQTTClient_message_initializer;
            pubmsg.payload = b->Buf;
            pubmsg.payloadlen = b->Size;
            pubmsg.qos = c->MqttQoS;
            pubmsg.retained = 0;

            MQTTClient_deliveryToken token;
            int rc = MQTTClient_publishMessage((MQTTClient)c->MQTTClient, c->MqttTopic, &pubmsg, &token);
            if (rc != MQTTCLIENT_SUCCESS) {
                fprintf(stderr, "发布消息失败，返回代码 %d\n", rc);
            }
        }
        FreeBlock(b);
    }
}

bool InitMqttConnection(CONNECTION *c)
{
    char clientid[50];
    snprintf(clientid, sizeof(clientid), "%s%d", CLIENTID_PRE, rand());
    
    return init_mqtt(c, clientid);
}

void CleanupMqttConnection(CONNECTION *c)
{
    if (c != NULL)
    {
        if (c->MQTTClient)
        {
            MQTTClient_disconnect((MQTTClient)c->MQTTClient, 10000);
            MQTTClient_destroy((MQTTClient*)&c->MQTTClient);
            c->MQTTClient = NULL;
        }

        // 释放引用计数
        if (c->ref != NULL)
        {
            Release(c->ref);  // 使用 Release 而不是 ReleaseRef
            c->ref = NULL;
        }
    }
}

void run_mqtt_vpn(CONNECTION *c) {
    if (!InitMqttConnection(c)) {
        return;
    }

    while (!c->Halt) {
        ProcessMqttMessages(c);
        SendDataWithMQTT(c);
        SleepThread(100);
    }

    CleanupMqttConnection(c);
}
void usage(void) {
    fprintf(stderr, "Usage: mqtt_vpn -i <if_name> -b <mqtt_broker> [-n <client_id>] [-d]\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i <if_name>        Name of interface to use (mandatory)\n");
    fprintf(stderr, "  -a <ip>             IP address of interface to use (mandatory)\n");
    fprintf(stderr, "  -b <mqtt_broker>    MQTT broker address (e.g., tcp://localhost:1883)\n");
    fprintf(stderr, "  -n <client_id>      MQTT client ID (optional)\n");
    fprintf(stderr, "  -d                  Enable debug mode\n");
    //exit(1);
}
// 添加一个函数来获取用户输入
int get_mqtt_params(char **if_addr, char **ip_addr, char **broker, char **cl_id) {
    char buffer[1024];  // 增大缓冲区以容纳完整命令行
    char *token;
    
    // 显示 usage 信息
    fprintf(stderr, "Usage: mqtt_vpn -i <tap_interface> -b <mqtt_broker> [-n <client_id>] [-d]\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -i <tap_interface>  TAP interface name/address\n");
    fprintf(stderr, "  -a <ip>             IP address of interface to use (mandatory)\n");
    fprintf(stderr, "  -b <mqtt_broker>    MQTT broker address (e.g., tcp://localhost:1883)\n");
    fprintf(stderr, "  -n <client_id>      MQTT client ID (optional)\n");
    fprintf(stderr, "  -d                  Enable debug mode\n\n");
    
    printf("Enter command (e.g., -i mq0 -a 192.168.1.100 -b tcp://my_broker.org:1883 -d): ");
    if (!fgets(buffer, sizeof(buffer), stdin)) {
        return -1;
    }
    buffer[strcspn(buffer, "\n")] = 0;  // 移除换行符
    
    // 解析命令行参数
    token = strtok(buffer, " ");
    while (token) {
        if (strcmp(token, "-i") == 0) {
            token = strtok(NULL, " ");
            if (token) {
                *if_addr = _strdup(token);
            }
        } else if (strcmp(token, "-a") == 0) {
            token = strtok(NULL, " ");
            if (token) {
                *ip_addr = _strdup(token);
            }
        } else if (strcmp(token, "-b") == 0) {
            token = strtok(NULL, " ");
            if (token) {
                *broker = _strdup(token);
            }
        } else if (strcmp(token, "-n") == 0) {
            token = strtok(NULL, " ");
            if (token) {
                *cl_id = _strdup(token);
            }
        }
        token = strtok(NULL, " ");
    }
    
    // 验证必要参数
    if ((!*if_addr && !*ip_addr) || !*broker) {
        fprintf(stderr, "Error: Either TAP interface or IP address, and MQTT broker address are required.\n");
        return -1;
    }
    
    return 0;
}
// 修改 mqtt_vpn_init 函数
int mqtt_vpn_init(void) {
    char *if_addr = NULL;
    char *ip_addr = NULL;  // 新增 IP 地址参数
    char *broker = NULL;
    char *cl_id = NULL;
    
    // 获取用户输入的参数
    if (get_mqtt_params(&if_addr, &ip_addr, &broker, &cl_id) != 0) {  // 修改函数签名
        fprintf(stderr, "Failed to get MQTT parameters from user input\n");
        return -1;
    }
    
    // 构建参数数组
    char *argv[9];  // 最多9个参数：程序名 + 8个选项 (-i, -a, -b, -n)
    int argc = 0;
    
    argv[argc++] = "mqtt_vpn";
    
    // 添加接口名称参数
    if (if_addr) {
        argv[argc++] = "-i";
        argv[argc++] = if_addr;
    }
    
    // 添加 IP 地址参数
    if (ip_addr) {
        argv[argc++] = "-a";
        argv[argc++] = ip_addr;
    }
    
    // 添加 broker 参数
    argv[argc++] = "-b";
    argv[argc++] = broker;
    
    // 添加可选的客户端 ID
    if (cl_id) {
        argv[argc++] = "-n";
        argv[argc++] = cl_id;
    }
    
    // 调用 mqtt_vpn_start
    int result = mqtt_vpn_start(argc, argv);
    
    // 清理分配的内存
    free(if_addr);
    free(ip_addr);  // 释放新增的内存
    free(broker);
    free(cl_id);
    
    return result;
}

HANDLE tun_alloc(const char *if_name, int flags, CEDAR *cedar) {
    VH *v;
    VH_OPTION vh_option;
    CLIENT_OPTION client_option;
    CLIENT_AUTH client_auth;
    
    // 不需要在这里创建 Cedar 实例，使用传入的参数
    if (cedar == NULL) {
        fprintf(stderr, "Error: Cedar instance is NULL\n");
        return INVALID_HANDLE_VALUE;
    }
    
    // 初始化选项
    Zero(&vh_option, sizeof(vh_option));
    Zero(&client_option, sizeof(client_option));
    Zero(&client_auth, sizeof(client_auth));

    // 设置虚拟主机选项
    StrCpy(vh_option.HubName, sizeof(vh_option.HubName), if_name);
    vh_option.UseNat = true;
    
    // 创建虚拟主机
    v = NewVirtualHost(cedar, &client_option, &client_auth, &vh_option);
    if (v == NULL) {
        fprintf(stderr, "Error: Could not create virtual host\n");
        return INVALID_HANDLE_VALUE;
    }

    // 初始化虚拟接口
    if (!VirtualInit(v)) {
        fprintf(stderr, "Error: Could not initialize virtual interface\n");
        ReleaseVirtual(v);
        return INVALID_HANDLE_VALUE;
    }

    printf("Successfully created virtual interface\n");
    return (HANDLE)v;
}


int mqtt_vpn_start(int argc, char *argv[]) {
    char *if_addr = NULL;
    char *ip_addr = NULL;
    char *broker = NULL;
    char *cl_id = NULL;
    int debug = 0;
    TUN_HANDLE *tun = NULL;
    ULONG NTEContext;
    MQTTClient client;
    CONNECTION *connection = NULL;
    CEDAR *cedar = NULL;

    // 初始化 Cedar
    cedar = NewCedar(NULL, NULL);
    if (cedar == NULL) {
        fprintf(stderr, "Error: Could not create Cedar instance\n");
        goto cleanup;
    }

    // 初始化 Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    // 初始化 OpenSSL
    SSL_library_init();
    SSL_load_error_strings();

    // 解析命令行参数
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            if_addr = argv[++i];
        }
        else if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            ip_addr = argv[++i];
        }
        else if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            broker = argv[++i];
        }
        else if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            cl_id = argv[++i];
        }
        else if (strcmp(argv[i], "-d") == 0) {
            debug = 1;
        }
    }

    // 验证必要参数
    if ((!if_addr && !ip_addr) || !broker) {
        usage();
        goto cleanup;
    }

    // 打印调试信息
    if (debug) {
        fprintf(stderr, "Interface: %s\n", if_addr ? if_addr : "not set");
        fprintf(stderr, "IP Address: %s\n", ip_addr ? ip_addr : "not set");
        fprintf(stderr, "Broker: %s\n", broker);
        fprintf(stderr, "Client ID: %s\n", cl_id ? cl_id : "not set");
    }

    // 创建 TAP 设备并使用指定的接口名称
    tun = tun_alloc(if_addr, IFF_TAP | IFF_NO_PI, cedar);
    if (tun == NULL) {
        fprintf(stderr, "Error: Failed to create TAP interface '%s'\n", if_addr);
        ReleaseCedar(cedar);  // 记得释放 Cedar
        WSACleanup();
        return 1;
    }
    printf("TAP interface '%s' created successfully\n", if_addr);

    // 修正连接获取方式
    LIST *connection_list = cedar->ConnectionList;
    
    // 获取新连接
    if (connection_list != NULL)
    {
    connection = NewServerConnection(cedar, NULL, TCP_BOTH);
    if (connection == NULL) {
        fprintf(stderr, "Failed to create server connection\n");
        goto cleanup;
    }
    
    // 初始化引用计数
    connection->ref = NewRef();  // 添加这行
    if (connection->ref == NULL) {
        fprintf(stderr, "Failed to create reference counter\n");
        ReleaseConnection(connection);
        goto cleanup;
    }
    
    // 添加到连接列表
    Add(connection_list, connection);
    
    // 初始化连接参数
    StrCpy(connection->ServerName, sizeof(connection->ServerName), broker);
    connection->MqttQoS = QOS;
    StrCpy(connection->MqttTopic, sizeof(connection->MqttTopic), TOPIC_PRE);
    connection->Socket = tun->tap_socket;
    connection->Protocol = CONNECTION_TCP;
    connection->Type = CONNECTION_TYPE_MQTT;
    }
    else
    {
        fprintf(stderr, "Connection list is NULL\n");
        goto cleanup;
    }

    // 初始化 MQTT 连接
    if (!InitMqttConnection(connection)) {
        fprintf(stderr, "Failed to initialize MQTT connection\n");
        goto cleanup;
    }

    // 运行主循环
    run_mqtt_vpn(connection);

cleanup:
    // 清理资源
    if (connection) {
        CleanupMqttConnection(connection);
        ReleaseConnection(connection);
    }
    if (tun) {
        cleanup_tun(tun);
    }
    if (cedar) {
        ReleaseCedar(cedar);  // 在清理时释放 Cedar
    }
    WSACleanup();
    ERR_free_strings();

    return 0;
}
// 添加 cleanup_tun 函数的实现
void cleanup_tun(TUN_HANDLE* handle)
{
    if (handle != NULL)
    {
        // 关闭 TAP 设备 socket
        if (handle->tap_socket != INVALID_SOCKET)
        {
            closesocket(handle->tap_socket);
            handle->tap_socket = INVALID_SOCKET;
        }

        // 释放 VH 句柄
        if (handle->vh_handle != INVALID_HANDLE_VALUE)
        {
            VH *v = (VH *)handle->vh_handle;
            // 停止虚拟主机
            StopVirtualHost(v);
            // 释放虚拟主机
            ReleaseVirtual(v);
            handle->vh_handle = INVALID_HANDLE_VALUE;
        }

        // 释放 Cedar 实例
        if (handle->cedar != NULL)
        {
            ReleaseCedar(handle->cedar);
            handle->cedar = NULL;
        }

        // 释放 TUN_HANDLE 结构体
        Free(handle);
    }
}