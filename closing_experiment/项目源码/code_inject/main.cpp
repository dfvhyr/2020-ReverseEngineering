#include "Windows.h"
#include "stdio.h"
#include <versionhelpers.h>
#include <tlhelp32.h>
#include<string.h>

LPVOID g_pfWriteFile = NULL;
CREATE_PROCESS_DEBUG_INFO g_cpdi;
BYTE g_chINT3 = 0xCC, g_chOrgByte = 0;

//��ʼ����������дWriteFile���ڴ棬�Դ����öϵ�
BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT pde)
{
	//���Ƚ�Ŀ��DLL��kernel32.dll���ؽ��ڴ棬Ȼ��õ�Ŀ�꺯����WriteFile�ĵ�ַ
	g_pfWriteFile = GetProcAddress(LoadLibraryA("kernel32.dll"), "WriteFile");

	//CREATE_PROCESS_DEBUG_INFO�ṹ���hProcess��ԱΪ�������Խ��̵ľ����

	//˼·Ϊͨ�������Խ��̵ľ����ȡWriteFile��������������API����ʼλ�����öϵ�

	//��CreateProcessInfo�ṹ���п�����CREATE_PROCESS_DEBUG_INFO��С���ֽڸ�g_cpdi
	memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));

	//ReadProcessMemory�����ɶ�ȡָ�����̵�ĳ���ڴ�ռ�
	//����Ϊ���̾�����������ݵĵ�ַ����Ŷ�ȡ���ݵĵ�ַ���������ݵĴ�С���������ݵ�ʵ�ʴ�С
	//��һ����Ŀ���Ƕ�ȡWriteFile�ĵ�һ���ֽڣ����ں����Ļָ�
	ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chOrgByte, sizeof(BYTE), NULL);

	//WriteProcessMemory�����ɽ�����д��ָ�����̵�ĳ���ڴ�ռ䣬������ReadProcessMemory����
	//��һ����Ŀ���ǰ�WriteFile�ĵ�һ���ֽڸ���Ϊ0xCC�������öϵ�
	WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chINT3, sizeof(BYTE), NULL);

	//ԭ���ǣ�CPU����0xCC��Ҳ����INT 3ָ��ʱ������ִͣ�г��򲢴����쳣������ǰ���������ڵ���״̬���򽫿���Ȩ�ƽ���������
	//������������ר��������һ���쳣�жϣ����ڴ˴����ж����ݵĸ�д

	return TRUE;
}

//�쳣�����������������Ԥ�ڵ����ݸ�д
BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde)
{
	//ÿ���߳��ں˶���ά����һ��CONTEXT�ṹ�壬���汣�����߳����е�״̬���������Ϊ����ġ������ġ�
	//ʹ��CPU���Լǵ��ϴ����и��߳����е������ˣ��ô����￪ʼ���У����߳��ڲ�����������
	//�ýṹ����CPU�йصģ��ض���CPU��Ӧ���ض���CONTEXT�ṹ
	//���������Ϣʵ������CPU�мĴ�������Ϣ
	CONTEXT ctx;
	PBYTE lpBuffer = NULL;
	DWORD dwNumOfBytesToWrite, dwAddrOfBuffer;

	//��pde�ṹ���е�ExceptionRecord���쳣��¼���ṹ���per
	PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;

	// �ж��쳣��¼�������Ƿ��Ƕϵ��쳣���ϵ��쳣�������INT 3�쳣��
	if (per->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		// �ж϶ϵ��ַ�Ƿ�ΪWriteFile�ĵ�ַ
		if (g_pfWriteFile == per->ExceptionAddress)
		{
			//�ѹ����������޸ĺ�����ֽ�0xCC�ָ�Ϊԭ���ֽڣ�6A��
			WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chOrgByte, sizeof(BYTE), NULL);

			//CONTEXT�ṹ���б�����CPU����Ϣ����Щ��Ϣ�ǿ��Զ�д�ģ�������Ҫ����ContextFlags��Ա��ֵ��ѡ���д�ļĴ�������
			//CONTEXT_CONTROL��Ϊָ��ʹ�ÿ��ƼĴ����飬����ʹ�����¼Ĵ����������ǵ���ҪĿ����ʹ��ESP�Ĵ������Ի�ȡWriteFile�Ļ��������ݣ�
				/*
				DWORD   Ebp;
				DWORD   Eip;
				DWORD   SegCs;              
				DWORD   EFlags;             
				DWORD   Esp;
				DWORD   SegSs;
				*/
			ctx.ContextFlags = CONTEXT_CONTROL;
			//��ȡָ���̵߳������ģ����䴢����CONTEXT�ṹ���У�ʵ�����Ǹ���ContextFlags��Ա��ֵ��ȡ��Ӧ�ļĴ�����ַ
			GetThreadContext(g_cpdi.hThread, &ctx);

			//WriteFile�ĵڶ��������ǽ�Ҫд������ݻ�������ַ�������������ǽ�Ҫд�����ݵ��ֽ���
			//�����Ĳ�����������Ӧ���̵�ջ�У���ʹ��ESP�Ĵ�����ȡ���ǵ�ֵ���������ĵ�ַΪ ESP + 0x8���������ĵ�ַΪ ESP + 0xC
			//��ȡ���ݻ�������ַ�����������߳������ڴ�ռ��еĵ�ַ
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0x8), &dwAddrOfBuffer, sizeof(DWORD), NULL);
			//��ȡ��Ҫд�����ݵ��ֽ����������ݻ������Ĵ�С
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0xC), &dwNumOfBytesToWrite, sizeof(DWORD), NULL);

			//������ʱ����������1����Ϊ��ǰ����WriteFile() + 1λ��
			lpBuffer = (PBYTE)malloc(dwNumOfBytesToWrite + 1);
			//��lpBuffer������ȫ����ֵΪ0����ֵ�ĳ���ΪdwNumOfBytesToWrite + 1
			memset(lpBuffer, 0, dwNumOfBytesToWrite + 1);

			//�ָ�WriteFile�Ļ���������ʱ����������buffer�����ݴ浽lpBuffer
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer, lpBuffer, dwNumOfBytesToWrite, NULL);

			//���������ڵ����ݸ���Ϊhelloword���˲����д����









			return TRUE;
		}
	}
	return FALSE;
}

//�ȴ������Խ��̷���Ԥ�ڵ��¼�
void DebugLoop()
{
	//DEBUG_EVENT�ṹ�����������������Ϊ�Ķ��󣬼�����һϵ�����ڵ��ԵĹ���
	DEBUG_EVENT dubug_object;
	//����״̬
	DWORD dwContinueStatus;

	//���������¼���WaitForDebugEvent�ͻὫ����¼���Ϣд��Ŀ��ṹ���У�Ȼ�󷵻�һ��BOOLֵ
	//��һ������ָ��һ��DEBUG_EVENT�ṹ�壬��������һ�������¼����ڶ�������Ϊ�ȴ��¼��ĺ�������infinite��������ȴ�
	while (WaitForDebugEvent(&dubug_object, INFINITE))
	{
		dwContinueStatus = DBG_CONTINUE;

		//�ṹ���dwDebugEventCode��Ա��Ϊ�������¼������ࡱ������9��

		//CREATE_PROCESS_DEBUG_EVENT��Ϊ�������̣����ǵ������յ��ĵ�һ�������¼�
		//�������ڱ����Խ��������򱻸���ʱ����ִ��
		if (dubug_object.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
		{
			OnCreateProcessDebugEvent(&dubug_object);
		}
		//EXCEPTION_DEBUG_EVENT��Ϊ�����쳣����ʱ��ִ���쳣�������
		else if (dubug_object.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
		{
			if (OnExceptionDebugEvent(&dubug_object))
				continue;
		}
		//EXIT_PROCESS_DEBUG_EVENT��Ϊ�����ԵĽ�����ֹ�ˣ���ʱ�������뱻�����߽�һ����ֹ���������Ϊ����������ѭ��
		else if (dubug_object.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
		{
			break;
		}

		//ContinueDebugEvent��WaitForDebugEvent�������෴�������������Խ��̵�ִ��
		//��һ�͵ڶ��������ֱ��ǽ���ID���߳�ID��������������ΪDBG_CONTINUE�����ʾ�������Ѵ����˸��쳣�������ڷ����쳣�ĵط�����ִ��
		ContinueDebugEvent(dubug_object.dwProcessId, dubug_object.dwThreadId, dwContinueStatus);
	}
}

//����ǰ��������Ȩ��
BOOL SetSePrivilege()
{
	TOKEN_PRIVILEGES tp = { 0 };
	HANDLE hToken = NULL;
	//OpenProcessToken�õ���ǰ���̵�����
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		//�õ�ǰ����ӵ�е�������Ȩ�ޣ�SE_DEBUG_NAME
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
		{
			if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL) == 0)
			{
				printf(TEXT("[-] Error: AdjustTokenPrivilege failed! %u\n"), GetLastError());

				if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
				{
					printf(TEXT("[*] Warning: The token does not have the specified privilege.\n"));
					return FALSE;
				}
			}
#ifdef _DEBUG
			else
				printf(TEXT("[+] SeDebugPrivilege Enabled.\n"));
#endif
		}

		CloseHandle(hToken);
	}
	else
		return FALSE;

	return TRUE;
}

//���ݽ������Ʋ��ҽ���PID
DWORD findPidByName(char * pname)
{
	HANDLE h;
	PROCESSENTRY32 procSnapshot;
	//hΪ��ǰ���н��̵ľ��
	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	procSnapshot.dwSize = sizeof(PROCESSENTRY32);
	//���̱���
	do
	{
		//��PROCESSENTRY32�ṹ���szExeFile��Ϊ����������н��̵����ƣ�������pname�Ƚ�
		if (!strcmp(procSnapshot.szExeFile, pname))
		{
			DWORD pid = procSnapshot.th32ProcessID;
			CloseHandle(h);
#ifdef _DEBUG
			printf(TEXT("[+] PID found: %ld\n"), pid);
#endif
			return pid;
		}
	} while (Process32Next(h, &procSnapshot));

	CloseHandle(h);
	return 0;
}

int main()
{
	DWORD dwProcessId = 0;
	char * strProcName = "notepad.exe";

	//ͨ��Ŀ��������ҵ�PID��û�ҵ�����
	dwProcessId = findPidByName(strProcName);
	if (dwProcessId == 0)
	{
		printf(TEXT("[-] Error: Could not find PID (%d).\n"), dwProcessId);
		return(1);
	}

	//��߽���Ȩ��
	SetSePrivilege();

	//DebugActiveProcess���ѵ��������ӵ�һ��������в��ҵ�����������Ϊ�����ӽ��̵�PID
	//���ӳɹ���ſ��Ե��Ըý���
	if (!DebugActiveProcess(dwProcessId))//�������ʧ�ܣ��᷵��0��if����ִ��
	{
		printf("DebugActiveProcess(%d) failed!!!\n"
			"Error Code = %d\n", dwProcessId, GetLastError());//��ȡ�������
		return 1;
	}

	//���������ӳɹ��Ժ������ѭ��
	DebugLoop();

	return 0;
}