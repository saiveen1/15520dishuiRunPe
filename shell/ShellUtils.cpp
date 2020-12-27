#include "ShellUtils.h"

DWORD ShellUtils::UnmapShell(HANDLE hProcess, DWORD shellImageBase)
{
	HMODULE hModuleNt = LoadLibraryA("ntdll.dll");
	if (!hModuleNt)
	{
		printf("��ȡntdllʧ��\n");
		TerminateProcess(hProcess, 1);
		return 0;
	}

	////����Dword����Ϊhandle pvoid �ĺ���ָ��
	//typedef DWORD(WINAPI* pfZwUnmapViewOfSection)(HANDLE, PVOID);
	//pfZwUnmapViewOfSection ZwUnmapViewOfSection = (pfZwUnmapViewOfSection)GetProcAddress(hModuleNt, "ZwUnmapViewOfSection");
	//if (!ZwUnmapViewOfSection)
	//{
	//	printf("δ��ȡ��unmapָ��\n");
	//	TerminateProcess(hProcess, 1);
	//	return 0;
	//}

	// ���� ZwUnmapViewOfSection ж���½����ڴ澵��
	NtUnmapViewOfSection(hProcess, (PVOID)shellImageBase);
	FreeLibrary(hModuleNt);
	return 1;
}

LPVOID ShellUtils::VirtualAllocate(HANDLE hProcess, PVOID pAddress, DWORD size_t)
{
	HMODULE hModuleKernel = LoadLibraryA("kernel32.dll");
	if (!hModuleKernel)
	{
		printf("��ȡkernelʧ��\n");
		TerminateProcess(hProcess, 1);
		return NULL;
	}
	typedef void* (__stdcall* pfVirtualAllocEx)(
		HANDLE hProcess,
		LPVOID lpAddress,
		DWORD dwSize,
		DWORD flAllocationType,
		DWORD flProtect);
	pfVirtualAllocEx VirtualAllocEx = NULL;
	VirtualAllocEx = (pfVirtualAllocEx)GetProcAddress((hModuleKernel), "VirtualAllocEx");
	if (!VirtualAllocEx(
		hProcess,
		pAddress,
		size_t,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_EXECUTE_READWRITE
	))
	{
		//������ɹ�, ����ᱨ487�ڴ���ʴ���, ������, ��Ϊ����Դ��ַ�ж���
		printf("GetLastError: %d\n", (int)GetLastError());
		//printf("ImageBase��ռ��, ���������ռ�. ���޸��ض�λ��");
		LPVOID newImageBase = NULL;
		if ((newImageBase = VirtualAllocEx(
			hProcess,
			NULL,
			size_t,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE
		)))
			return newImageBase;
		printf("û���㹻�ռ�");
		return NULL;
	}

	FreeLibrary(hModuleKernel);
	return pAddress;
}
