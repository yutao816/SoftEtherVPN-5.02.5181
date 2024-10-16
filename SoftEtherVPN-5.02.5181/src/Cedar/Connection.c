// SoftEther VPN Source Code - Developer Edition Master Branch
// Cedar Communication Module

#include "Connection.h"

#include "BridgeUnix.h"
#include "BridgeWin32.h"
#include "Hub.h"
#include "Layer3.h"
#include "Link.h"
#include "Listener.h"
#include "Nat.h"
#include "Protocol.h"
#include "Server.h"
#include "SecureNAT.h"
#include "Session.h"
#include "UdpAccel.h"
#include "Virtual.h"

#include "Mayaqua/DNS.h"
#include "Mayaqua/Kernel.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Object.h"
#include "Mayaqua/Pack.h"
#include "Mayaqua/Str.h"
#include "Mayaqua/Table.h"
#include "Mayaqua/Tick64.h"

#include <stdlib.h>

#include "../Mayaqua/mqtt_vpn.h"

// MQTT 相关函数

// 创建 MQTT 连接
MQTT_SOCK *CreateMQTTSock(char *broker_url, char *username, char *password, char *client_id)
{
    MQTT_SOCK *mqtt = ZeroMalloc(sizeof(MQTT_SOCK));
    
    // 初始化 MQTT 连接参数
    mqtt->broker = CopyStr(broker_url);
    mqtt->username = CopyStr(username);
    mqtt->password = CopyStr(password);
    mqtt->client_id = CopyStr(client_id);
    
    // 初始化 MQTT 连接
    InitMQTT(mqtt);
    
    return mqtt;
}

// 通过 MQTT 发送数据
UINT SendToMQTT(MQTT_SOCK *mqtt, void *data, UINT size)
{
    int rc = SendToMQTT(mqtt, data, (int)size);
    if (rc != MQTTCLIENT_SUCCESS)
    {
        Debug("MQTT send failed with error code %d\n", rc);
        return 0;
    }
    return size;
}

// 从 MQTT 接收数据
UINT ReceiveFromMQTT(MQTT_SOCK *mqtt, void *data, UINT size)
{
    return (UINT)RecvFromMQTT(mqtt, data, (int)size);
}

// 关闭 MQTT 连接
void CloseMQTTSock(MQTT_SOCK *mqtt)
{
    if (mqtt != NULL)
    {
        CleanupMQTT(mqtt);
        Free(mqtt->broker);
        Free(mqtt->username);
        Free(mqtt->password);
        Free(mqtt->client_id);
        Free(mqtt);
    }
}

// Creating a Client Connection
CONNECTION *NewClientConnection(SESSION *s)
{
    CONNECTION *c = NewClientConnectionEx(s, NULL, 0, 0);
    c->MqttSock = NULL;
    
    // 检查是否应该使用 MQTT
    c->UseMqtt = false;  // 默认不使用 MQTT
    
    // 这里可以添加一些逻辑来决定是否使用 MQTT
    // 例如，检查配置文件或其他条件
    if (s->ClientOption != NULL && s->ClientOption->UseMqtt)
    {
        c->UseMqtt = true;
    }
    
    if (c->UseMqtt)
    {
        c->MqttSock = CreateMQTTSock("mqtt://broker.example.com:1883", "username", "password", "client_id");
    }
    return c;
}

CONNECTION *NewClientConnectionEx(SESSION *s, char *client_str, UINT client_ver, UINT client_build)
{
	CONNECTION *c;

	// Initialization of CONNECTION object
	c = ZeroMalloc(sizeof(CONNECTION));
	c->ConnectedTick = Tick64();
	c->lock = NewLock();
	c->ref = NewRef();
	c->Cedar = s->Cedar;
	AddRef(c->Cedar->ref);
	c->Protocol = CONNECTION_TCP;
	c->Tcp = ZeroMalloc(sizeof(TCP));
	c->Tcp->TcpSockList = NewList(NULL);
	c->ServerMode = false;
	c->Status = CONNECTION_STATUS_CONNECTING;
	c->Name = CopyStr("CLIENT_CONNECTION");
	c->Session = s;
	c->CurrentNumConnection = NewCounter();
	c->LastCounterResetTick = Tick64();
	Inc(c->CurrentNumConnection);

	c->ConnectingThreads = NewList(NULL);
	c->ConnectingSocks = NewList(NULL);

	if (client_str == NULL)
	{
		c->ClientVer = s->Cedar->Version;
		c->ClientBuild = s->Cedar->Build;

		if (c->Session->VirtualHost == false)
		{
			if (c->Session->LinkModeClient == false)
			{
				StrCpy(c->ClientStr, sizeof(c->ClientStr), CEDAR_CLIENT_STR);
			}
			else
			{
				StrCpy(c->ClientStr, sizeof(c->ClientStr), CEDAR_SERVER_LINK_STR);
			}
		}
		else
		{
			StrCpy(c->ClientStr, sizeof(c->ClientStr), CEDAR_ROUTER_STR);
		}
	}
	else
	{
		c->ClientVer = client_ver;
		c->ClientBuild = client_build;
		StrCpy(c->ClientStr, sizeof(c->ClientStr), client_str);
	}

	// Server name and port number
	StrCpy(c->ServerName, sizeof(c->ServerName), s->ClientOption->Hostname);
	c->ServerPort = s->ClientOption->Port;

	// Create queues
	c->ReceivedBlocks = NewQueue();
	c->SendBlocks = NewQueue();
	c->SendBlocks2 = NewQueue();

	return c;
}
