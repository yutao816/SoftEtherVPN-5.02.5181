// ��������һ����ִ���ļ�
#define VPN_EXE

// ������Ҫ��ͷ�ļ�
#include "Cedar/Client.h"
#include "Cedar/CM.h"
#include "Cedar/Command.h"
#include "Cedar/Server.h"
#include "Cedar/SM.h"
#include "Mayaqua/Internat.h"
#include "Mayaqua/Mayaqua.h"
#include "Mayaqua/Memory.h"
#include "Mayaqua/Microsoft.h"
#include "Mayaqua/Str.h"

// ���Կͻ��˹���
void client_test(UINT num, char **arg)
{
    Print("VPN Client Test. Press Enter key to stop the VPN Client .\n");
    CtStartClient();      // �����ͻ���
    GetLine(NULL, 0);     // �ȴ��û����룬�˴�Ϊ�ȴ��س���
    CtStopClient();       // ֹͣ�ͻ���
}

// ���Է���������
void server_test(UINT num, char **arg)
{
    Print("VPN Server Test. Press Enter key to stop the VPN Server .\n");
    StInit();             // ��ʼ��������
    StStartServer(false); // ������ͨ������ģʽ
    GetLine(NULL, 0);     // �ȴ��û����룬�˴�Ϊ�ȴ��س���
    StStopServer();       // ֹͣ������
    StFree();             // �ͷŷ�������Դ
}

// �����Žӹ���
void bridge_test(UINT num, char **arg)
{
    Print("VPN Bridge Test. Press Enter key to stop the VPN Bridge .\n");
    StInit();             // ��ʼ��������
    StStartServer(true);  // �����Ž�ģʽ
    GetLine(NULL, 0);     // �ȴ��û����룬�˴�Ϊ�ȴ��س���
    StStopServer();       // ֹͣ������
    StFree();             // �ͷŷ�������Դ
}

// ����Windowsƽ̨�϶���
#ifdef OS_WIN32
// ���Է������������
void server_manager_test(UINT num, char **arg)
{
    SMExec();             // ִ�з������������
}

// ���Կͻ��˹������
void client_manager_test(UINT num, char **arg)
{
    CMExec();             // ִ�пͻ��˹������
}

// ����SetupAPI�ӿ�
void setup_test(UINT num, char **arg)
{
    char name[MAX_SIZE];  // ����ӿڿ�������
    Print("SetupAPI test. Please enter the name of the NIC I should retrieve the status of.\n");
    GetLine(name, sizeof(name)); // ��ȡ�û������NIC����
    Print("Status: %s\n", MsIsVLanEnabledWithoutLock(name) ? "enabled" : "disabled"); // ���NIC��״̬
}
#endif

// �����ڴ�й©
void memory_leak_test(UINT num, char **arg)
{
    char *a = Malloc(1);  // ����1�ֽ��ڴ棬���Ҳ����ͷ�
    Print("Hello, I am the great dictator of this kingdom!\n");
    Print("Just now I called Malloc(1) and never free! Ha ha ha !!\n");
}

// ������Ժ�������
typedef void (TEST_PROC)(UINT num, char **arg);

// ���Ժ����б�
typedef struct TEST_LIST
{
    char *command_str;  // �����ַ���
    TEST_PROC *proc;    // ���Ժ���ָ��
    char *help;         // ������Ϣ
} TEST_LIST;

// ���Ժ����б�����
TEST_LIST test_list[] =
{
    {"c", client_test, "VPN Client in Test Mode, enter key to graceful stop."},
    {"s", server_test, "VPN Server in Test Mode, enter key to graceful stop."},
    {"b", bridge_test, "VPN Bridge in Test Mode, enter key to graceful stop."},
#ifdef OS_WIN32
    {"sm", server_manager_test, "VPN Server Manager UI in Test Mode."},
    {"cm", client_manager_test, "VPN Client Manager UI in Test Mode."},
    {"setupapi", setup_test, "SetupAPI test: tries to retrieve the specified NIC's status."},
#endif
    {"memory_leak", memory_leak_test, "Memory leak test: Try to leak one byte by malloc()."},
};

// �����Ժ���
int TestMain(char *cmd)
{
    char tmp[MAX_SIZE];
    bool first = true;
    bool exit_now = false;
    int status = 0;

    // �����ӭ��Ϣ
    Print("SoftEther VPN Project\n");
    Print("vpntest: VPN Server / VPN Client / VPN Bridge test program\n");
    Print("Usage: vpntest [/memcheck] [command]\n\n");
    Print("Enter '?' or 'help' to show the command list.\n");
    Print("Enter 'q' or 'exit' to exit the process.\n\n");
    Print("   - In Jurassic Park: \"It's a UNIX system! I know this!\"\n\n");

    // ��Windowsƽ̨������MiniDump
#ifdef OS_WIN32
    MsSetEnableMinidump(true);
#endif

    // ��ѭ��
    while (true)
    {
        Print("TEST>");
        if (first && StrLen(cmd) != 0 && g_memcheck == false)
        {
            first = false;
            StrCpy(tmp, sizeof(tmp), cmd);
            exit_now = true;
            Print("%s\n", cmd);
        }
        else
        {
            GetLine(tmp, sizeof(tmp));
        }
        Trim(tmp); // ȥ����β�ո�
        if (StrLen(tmp) != 0)
        {
            // ���������в���
            UINT i, num;
            bool b = false;
            TOKEN_LIST *token = ParseCmdLine(tmp);
            char *cmd = token->Token[0];
            if (!StrCmpi(cmd, "exit") || !StrCmpi(cmd, "quit") || !StrCmpi(cmd, "q"))
            {
                FreeToken(token);
                break;
            }
            else if (StrCmpi(cmd, "?") == 0 || StrCmpi(cmd, "help") == 0)
            {
                // ��ʾ��������
                UINT max_len = 0;
                Print("Available commands:\n\n");
                num = sizeof(test_list) / sizeof(TEST_LIST);
                for (i = 0; i < num; i++)
                {
                    TEST_LIST *t = &test_list[i];
                    max_len = MAX(max_len, StrLen(t->command_str));
                }
                for (i = 0; i < num; i++)
                {
                    TEST_LIST *t = &test_list[i];
                    UINT len = StrLen(t->command_str);
                    char *pad = NULL;
                    if (len < max_len)
                    {
                        UINT padlen = max_len - len;
                        pad = MakeCharArray(' ', padlen);
                    }
                    Print(" '%s'%s : %s\n", t->command_str, pad == NULL ? "" : pad, t->help);
                    if (pad != NULL)
                    {
                        Free(pad);
                    }
                }
                Print("\n");
            }
            else if (StartWith(tmp, "vpncmd"))
            {
                wchar_t *s = CopyStrToUni(tmp);
                CommandMain(s);
                Free(s);
            }
            else
            {
                num = sizeof(test_list) / sizeof(TEST_LIST);
                for (i = 0; i < num; i++)
                {
                    if (!StrCmpi(test_list[i].command_str, cmd))
                    {
                        char **arg = Malloc(sizeof(char *) * (token->NumTokens - 1));
                        UINT j;
                        for (j = 0; j < token->NumTokens - 1; j++)
                        {
                            arg[j] = CopyStr(token->Token[j + 1]);
                        }
                        test_list[i].proc(token->NumTokens - 1, arg);
                        for (j = 0; j < token->NumTokens - 1; j++)
                        {
                            Free(arg[j]);
                        }
                        Free(arg);
                        b = true;
                        Print("\n");
                        break;
                    }
                }
                if (b == false)
                {
                    status = 2;
                    Print("Invalid Command: %s\n\n", cmd);
                }
            }
            FreeToken(token);

            if (exit_now)
            {
                break;
            }
        }
    }
    Print("Exiting...\n\n");
    return status;
}

// ������
int main(int argc, char *argv[])
{
    bool memchk = false;
    UINT i;
    char cmd[MAX_SIZE];
    char *s;
    int status = 0;

    InitProcessCallOnce();

    // ��ʼ�������в���
    cmd[0] = 0;
    if (argc >= 2)
    {
        for (i = 1; i < (UINT)argc; i++)
        {
            s = argv[i];
            if (s[0] == '/')
            {
                if (!StrCmpi(s, "/memcheck"))
                {
                    memchk = true;
                }
            }
            else
            {
                StrCpy(cmd, sizeof(cmd), &s[0]);
            }
        }
    }

    InitMayaqua(memchk, true, argc, argv);
    EnableProbe(true);
    InitCedar();
    SetHamMode();
    status = TestMain(cmd);
    FreeCedar();
    FreeMayaqua();

    return status;
}