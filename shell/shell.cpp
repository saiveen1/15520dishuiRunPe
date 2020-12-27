
#include <iostream>
#include <windows.h>
#include "pe.h"
#include "fileMethod.h"
#include "Process.h"
HANDLE hProcess = 0;
HANDLE hThread = 0;
int __cdecl main()
{
	//char shellPath[256] = { 0 };
	LPVOID pSrcFileBuffer = NULL;
	PROCESS_INFORMATION src_pi = { 0 };
	char shellPath[256] = "";
	GetModuleFileNameA(NULL, shellPath, 256);

	shellPe = std::make_unique<Pe>(shellPath);

	//从shell最后一个区段取出源数据解密
	pSrcFileBuffer = shellPe->GetLastSectionBuffer(shellPath);
	pSrcFileBuffer = Coding::Xor(pSrcFileBuffer, shellPe->GetLastSectionSizeOfRaw());
	Pe* srcPe = new Pe(pSrcFileBuffer,shellPe->GetLastSectionSizeOfRaw());

	//挂起创建, 卸载shell, 申请空间
	src_pi = Process::CreateProcessSuspend(shellPath);
	hProcess = src_pi.hProcess;
	hThread = src_pi.hThread;
	if (hProcess == hThread)
		return 0;

	ShellUtils::UnmapShell(hProcess,Process::GetProcessImageBase(src_pi));
	LPVOID lpAddress = ShellUtils::VirtualAllocate(hProcess, (PVOID)Process::GetProcessImageBase(src_pi), srcPe->GetSizeOfImage());
	//LPVOID lpAddress = ShellUtils::VirtualAllocate(hProcess, (PVOID)srcPe->GetImageBase(), srcPe->GetSizeOfImage());
	//LPVOID lpAddress = ShellUtils::VirtualAllocate(hProcess, (PVOID)0x400000, srcPe->GetSizeOfImage());
	if (lpAddress)
	{
		if ((DWORD)lpAddress == srcPe->GetImageBase())
			printf("初始ImageBase申请内存成功, 修改baseAddress, EntryPoint.\n");
		else
		{
			printf("申请成功, 但ImageBase改变了\n");
			if(!srcPe->HasRolocationTable())
				printf("当前文件无重定位表, 无需修改.\n");
			else
			{
				srcPe->RestoreRelocation((DWORD)lpAddress);
				printf("已修复重定位表.\n");
			}
		}
		LPVOID pSrcImageBuffer = srcPe->GetImageBuffer();
		DWORD sizeOfWritten = 0;
		if (!WriteProcessMemory(hProcess, lpAddress, pSrcImageBuffer, srcPe->GetSizeOfImage(), &sizeOfWritten))
		{
			printf("文件写入失败. 原因: %d\n", (int)GetLastError());
			return 0;
		}
		//修改ImageBase EntryPoint
		CONTEXT context = Process::GetThreadContext(hThread);
		WriteProcessMemory(hProcess, (LPVOID)(context.Ebx + 8), &lpAddress, 4, NULL);
		context.Eax = srcPe->GetEntryPoint() + (DWORD)lpAddress;
		context.ContextFlags = CONTEXT_FULL;
		::SetThreadContext(hThread, &context);
		delete srcPe;
		ResumeThread(hThread);

		printf("GetLastError: %d\n", (int)GetLastError());
	}
	else
		printf("没有足够空间, 程序退出.");
	WaitForSingleObject(src_pi.hProcess, INFINITE);
	WaitForSingleObject(src_pi.hThread, INFINITE);
	CloseHandle(src_pi.hProcess);
	CloseHandle(src_pi.hThread);
	system("pause");
	return 0;
}
