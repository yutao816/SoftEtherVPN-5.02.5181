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
    if (c->MQTTClient)
    {
        MQTTClient_disconnect((MQTTClient)c->MQTTClient, 10000);
        MQTTClient_destroy((MQTTClient*)&c->MQTTClient);
        c->MQTTClient = NULL;
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