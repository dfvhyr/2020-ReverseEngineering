#include "Windows.h"
#include "stdio.h"
#include <versionhelpers.h>
#include <tlhelp32.h>
#include<string.h>

LPVOID g_pfWriteFile = NULL;
CREATE_PROCESS_DEBUG_INFO g_cpdi;
BYTE g_chINT3 = 0xCC, g_chOrgByte = 0;

//初始化函数，改写WriteFile的内存，以此设置断点
BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT pde)
{
	//首先将目标DLL：kernel32.dll加载进内存，然后得到目标函数：WriteFile的地址
	g_pfWriteFile = GetProcAddress(LoadLibraryA("kernel32.dll"), "WriteFile");

	//CREATE_PROCESS_DEBUG_INFO结构体的hProcess成员为“被调试进程的句柄”

	//思路为通过被调试进程的句柄钩取WriteFile，具体做法是在API的起始位置设置断点

	//从CreateProcessInfo结构体中拷贝出CREATE_PROCESS_DEBUG_INFO大小的字节给g_cpdi
	memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));

	//ReadProcessMemory函数可读取指定进程的某个内存空间
	//参数为进程句柄、欲读数据的地址、存放读取数据的地址、读出数据的大小、读出数据的实际大小
	//这一步的目的是读取WriteFile的第一个字节，用于后续的恢复
	ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chOrgByte, sizeof(BYTE), NULL);

	//WriteProcessMemory函数可将数据写入指定进程的某个内存空间，参数与ReadProcessMemory类似
	//这一步的目的是把WriteFile的第一个字节覆盖为0xCC，即设置断点
	WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chINT3, sizeof(BYTE), NULL);

	//原理是：CPU遇到0xCC，也就是INT 3指令时，会暂停执行程序并触发异常。若当前进程正处于调试状态，则将控制权移交给调试器
	//而后续我们又专门设置了一个异常判断，会在此处进行对数据的改写

	return TRUE;
}

//异常处理函数，在这里完成预期的数据改写
BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde)
{
	//每个线程内核对象都维护着一个CONTEXT结构体，里面保存了线程运行的状态，可以理解为程序的“上下文”
	//使得CPU可以记得上次运行该线程运行到哪里了，该从哪里开始运行，该线程内部数据如何如何
	//该结构是与CPU有关的，特定的CPU对应着特定的CONTEXT结构
	//它保存的信息实质上是CPU中寄存器的信息
	CONTEXT ctx;
	PBYTE lpBuffer = NULL;
	DWORD dwNumOfBytesToWrite, dwAddrOfBuffer;

	//把pde结构体中的ExceptionRecord（异常记录）结构体给per
	PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;

	// 判断异常记录的内容是否是断点异常（断点异常里面包括INT 3异常）
	if (per->ExceptionCode == EXCEPTION_BREAKPOINT)
	{
		// 判断断点地址是否为WriteFile的地址
		if (g_pfWriteFile == per->ExceptionAddress)
		{
			//脱钩，将函数修改后的首字节0xCC恢复为原首字节（6A）
			WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, &g_chOrgByte, sizeof(BYTE), NULL);

			//CONTEXT结构体中保存着CPU的信息，这些信息是可以读写的，但首先要设置ContextFlags成员的值以选择读写的寄存器对象
			//CONTEXT_CONTROL意为指定使用控制寄存器组，即将使用如下寄存器：（我们的主要目的是使用ESP寄存器，以获取WriteFile的缓冲区内容）
				/*
				DWORD   Ebp;
				DWORD   Eip;
				DWORD   SegCs;              
				DWORD   EFlags;             
				DWORD   Esp;
				DWORD   SegSs;
				*/
			ctx.ContextFlags = CONTEXT_CONTROL;
			//获取指定线程的上下文，将其储存在CONTEXT结构体中；实质上是根据ContextFlags成员的值获取对应的寄存器地址
			GetThreadContext(g_cpdi.hThread, &ctx);

			//WriteFile的第二个参数是将要写入的数据缓冲区地址，第三个参数是将要写入数据的字节数
			//函数的参数存在于相应进程的栈中，可使用ESP寄存器获取它们的值。参数二的地址为 ESP + 0x8；参数三的地址为 ESP + 0xC
			//获取数据缓冲区地址，即被调试线程虚拟内存空间中的地址
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0x8), &dwAddrOfBuffer, sizeof(DWORD), NULL);
			//获取将要写入数据的字节数，即数据缓冲区的大小
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0xC), &dwNumOfBytesToWrite, sizeof(DWORD), NULL);

			//分配临时缓冲区，加1是因为当前断在WriteFile() + 1位置
			lpBuffer = (PBYTE)malloc(dwNumOfBytesToWrite + 1);
			//把lpBuffer的内容全部赋值为0，赋值的长度为dwNumOfBytesToWrite + 1
			memset(lpBuffer, 0, dwNumOfBytesToWrite + 1);

			//恢复WriteFile的缓冲区到临时缓冲区，把buffer的内容存到lpBuffer
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer, lpBuffer, dwNumOfBytesToWrite, NULL);

			//将缓冲区内的数据覆盖为helloword，此部分尚待完成









			return TRUE;
		}
	}
	return FALSE;
}

//等待被调试进程发生预期的事件
void DebugLoop()
{
	//DEBUG_EVENT结构体类似于面向调试行为的对象，集成了一系列用于调试的功能
	DEBUG_EVENT dubug_object;
	//继续状态
	DWORD dwContinueStatus;

	//发生调试事件后，WaitForDebugEvent就会将相关事件信息写入目标结构体中，然后返回一个BOOL值
	//第一个参数指向一个DEBUG_EVENT结构体，用于描述一个调试事件；第二个参数为等待事件的毫秒数，infinite代表无穷等待
	while (WaitForDebugEvent(&dubug_object, INFINITE))
	{
		dwContinueStatus = DBG_CONTINUE;

		//结构体的dwDebugEventCode成员意为“调试事件的种类”，共有9种

		//CREATE_PROCESS_DEBUG_EVENT意为创建进程，这是调试器收到的第一个调试事件
		//该语句会在被调试进程启动或被附加时调用执行
		if (dubug_object.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
		{
			OnCreateProcessDebugEvent(&dubug_object);
		}
		//EXCEPTION_DEBUG_EVENT意为出现异常，此时会执行异常处理程序
		else if (dubug_object.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
		{
			if (OnExceptionDebugEvent(&dubug_object))
				continue;
		}
		//EXIT_PROCESS_DEBUG_EVENT意为被调试的进程终止了，此时调试器与被调试者将一起被终止，具体表现为跳出调试器循环
		else if (dubug_object.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
		{
			break;
		}

		//ContinueDebugEvent与WaitForDebugEvent的作用相反，它继续被调试进程的执行
		//第一和第二个参数分别是进程ID和线程ID；第三个参数若为DBG_CONTINUE，则表示调试器已处理了该异常，程序在发生异常的地方继续执行
		ContinueDebugEvent(dubug_object.dwProcessId, dubug_object.dwThreadId, dwContinueStatus);
	}
}

//给当前进程提升权限
BOOL SetSePrivilege()
{
	TOKEN_PRIVILEGES tp = { 0 };
	HANDLE hToken = NULL;
	//OpenProcessToken得到当前进程的令牌
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		//让当前进程拥有调试器的权限：SE_DEBUG_NAME
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

//根据进程名称查找进程PID
DWORD findPidByName(char * pname)
{
	HANDLE h;
	PROCESSENTRY32 procSnapshot;
	//h为当前所有进程的句柄
	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	procSnapshot.dwSize = sizeof(PROCESSENTRY32);
	//进程遍历
	do
	{
		//用PROCESSENTRY32结构体的szExeFile，为任务管理器中进程的名称，将其与pname比较
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

	//通过目标进程名找到PID，没找到报错
	dwProcessId = findPidByName(strProcName);
	if (dwProcessId == 0)
	{
		printf(TEXT("[-] Error: Could not find PID (%d).\n"), dwProcessId);
		return(1);
	}

	//提高进程权限
	SetSePrivilege();

	//DebugActiveProcess：把调试器附加到一个活动进程中并且调试它，参数为欲附加进程的PID
	//附加成功后才可以调试该进程
	if (!DebugActiveProcess(dwProcessId))//如果附加失败，会返回0，if语句会执行
	{
		printf("DebugActiveProcess(%d) failed!!!\n"
			"Error Code = %d\n", dwProcessId, GetLastError());//获取错误参数
		return 1;
	}

	//调试器附加成功以后会进入该循环
	DebugLoop();

	return 0;
}