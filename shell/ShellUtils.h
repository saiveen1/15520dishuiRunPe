#pragma once
#include <windows.h>
#include <iostream>

#pragma comment(lib,"ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtTerminateProcess(HANDLE, NTSTATUS);
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtGetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
EXTERN_C NTSTATUS NTAPI NtResumeThread(HANDLE, PULONG);
namespace ShellUtils
{
	DWORD UnmapShell(HANDLE hProcess, DWORD shellImageBase);

	//����ɹ��򷵻�ԭʼImageBase ���򷵻���������ImageBase
	LPVOID VirtualAllocate(HANDLE hProcess, PVOID pAddress, DWORD size_t);
}