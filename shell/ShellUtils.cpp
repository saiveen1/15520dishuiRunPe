#include "ShellUtils.h"

DWORD ShellUtils::UnmapShell(HANDLE hProcess, DWORD shellImageBase)
{
	HMODULE hModuleNt = LoadLibraryA("ntdll.dll");
	if (!hModuleNt)
	{
		printf("获取ntdll失败\n");
		TerminateProcess(hProcess, 1);
		return 0;
	}

	////返回Dword参数为handle pvoid 的函数指针
	//typedef DWORD(WINAPI* pfZwUnmapViewOfSection)(HANDLE, PVOID);
	//pfZwUnmapViewOfSection ZwUnmapViewOfSection = (pfZwUnmapViewOfSection)GetProcAddress(hModuleNt, "ZwUnmapViewOfSection");
	//if (!ZwUnmapViewOfSection)
	//{
	//	printf("未获取到unmap指针\n");
	//	TerminateProcess(hProcess, 1);
	//	return 0;
	//}

	// 调用 ZwUnmapViewOfSection 卸载新进程内存镜像
	NtUnmapViewOfSection(hProcess, (PVOID)shellImageBase);
	FreeLibrary(hModuleNt);
	return 1;
}

LPVOID ShellUtils::VirtualAllocate(HANDLE hProcess, PVOID pAddress, DWORD size_t)
{
	HMODULE hModuleKernel = LoadLibraryA("kernel32.dll");
	if (!hModuleKernel)
	{
		printf("获取kernel失败\n");
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
		//如果不成功, 这里会报487内存访问错误, 很正常, 因为申请源地址有东西
		printf("GetLastError: %d\n", (int)GetLastError());
		//printf("ImageBase被占用, 将随机申请空间. 请修复重定位表");
		LPVOID newImageBase = NULL;
		if ((newImageBase = VirtualAllocEx(
			hProcess,
			NULL,
			size_t,
			MEM_RESERVE | MEM_COMMIT,
			PAGE_EXECUTE_READWRITE
		)))
			return newImageBase;
		printf("没有足够空间");
		return NULL;
	}

	FreeLibrary(hModuleKernel);
	return pAddress;
}
