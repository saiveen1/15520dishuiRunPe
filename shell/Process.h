#pragma once
#include <iostream>
#include <windows.h>
#include "ShellUtils.h"

//__declspec(selectany) CONTEXT contxt;
namespace Process
{
	PROCESS_INFORMATION CreateProcessSuspend(LPSTR processName);
	CONTEXT GetThreadContext(HANDLE hThread);
	DWORD GetProcessImageBase(PROCESS_INFORMATION procInfo);
};

