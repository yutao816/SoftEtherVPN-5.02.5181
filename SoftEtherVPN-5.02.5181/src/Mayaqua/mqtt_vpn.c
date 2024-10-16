#include "mqtt_vpn.h"
#include <string.h>
#include <stdio.h>

void InitMQTT(MQTT_SOCK *mqtt_sock)
{
    MQTTClient_create(&mqtt_sock->client, mqtt_sock->broker, mqtt_sock->client_id,
                      MQTTCLIENT_PERSISTENCE_NONE, NULL);
    
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;
    conn_opts.username = mqtt_sock->username;
    conn_opts.password = mqtt_sock->password;

    MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;
    ssl_opts.verify = 0;
    ssl_opts.enableServerCertAuth = 0;
    conn_opts.ssl = &ssl_opts;

    int rc;
    if ((rc = MQTTClient_connect(mqtt_sock->client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
        printf("Failed to connect to MQTT broker, return code %d\n", rc);
    }
}

void CleanupMQTT(MQTT_SOCK *mqtt_sock)
{
    MQTTClient_disconnect(mqtt_sock->client, 10000);
    MQTTClient_destroy(&mqtt_sock->client);
}

int SendToMQTT(MQTT_SOCK *mqtt_sock, void *data, int size)
{
    char topic[256];
    sprintf(topic, "mqttip/%u.%u.%u.%u", ((unsigned char*)data)[16], ((unsigned char*)data)[17], ((unsigned char*)data)[18], ((unsigned char*)data)[19]);
    
    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    pubmsg.payload = data;
    pubmsg.payloadlen = size;
    pubmsg.qos = 0;
    pubmsg.retained = 0;

    MQTTClient_deliveryToken token;
    return MQTTClient_publishMessage(mqtt_sock->client, topic, &pubmsg, &token);
}

int RecvFromMQTT(MQTT_SOCK *mqtt_sock, void *data, int size)
{
    // This function should be implemented as a callback
    // For now, we'll just return 0 to indicate no data received
    return 0;
}