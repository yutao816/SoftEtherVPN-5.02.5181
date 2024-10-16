#ifndef MQTT_VPN_H
#define MQTT_VPN_H

#include <MQTTClient.h>

typedef struct MQTT_SOCK
{
    MQTTClient client;
    char *broker;
    char *username;
    char *password;
    char *client_id;
    // 可以根据需要添加其他字段
} MQTT_SOCK;

// 函数声明
void InitMQTT(MQTT_SOCK *mqtt_sock);
void CleanupMQTT(MQTT_SOCK *mqtt_sock);
int SendToMQTT(MQTT_SOCK *mqtt_sock, void *data, int size);
int RecvFromMQTT(MQTT_SOCK *mqtt_sock, void *data, int size);

#endif // MQTT_VPN_H
