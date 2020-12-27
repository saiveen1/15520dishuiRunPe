#include "Process.h"

PROCESS_INFORMATION Process::CreateProcessSuspend(LPSTR processName)
{
	STARTUPINFOA src_si = { 0 };
	PROCESS_INFORMATION src_pi;
	src_si.cb = sizeof(src_si);

	//以挂起的方式创建进程						
	CreateProcessA(
		NULL,                    // name of executable module					
		processName,                // command line string					
		NULL, 					 // SD
		NULL,  		             // SD			
		FALSE,                   // handle inheritance option					
		CREATE_SUSPENDED,     	 // creation flags  				
		NULL,                    // new environment block					
		NULL,                    // current directory name					
		&src_si,                  // startup information					
		&src_pi                   // process information					
	);	
	return src_pi;
	//DWORD dwEntryPoint = contxt.Eax;			

	////子程序的ImageBase在baseAddress里面但是不能直接读, 因为直接读的话只是当前父进程的地址
	////需要读子进程内存才能得到他的ImageBase
	//char* baseAddress = (CHAR*)contxt.Ebx + 8;
	//DWORD pImageBase = 0;
	//ReadProcessMemory(src_pi.hProcess, baseAddress, &pImageBase, 4, NULL);
	
}


CONTEXT Process::GetThreadContext(HANDLE hThread)
{
	CONTEXT ct;
	
	ct.ContextFlags = CONTEXT_FULL;
	//获取主线程信息 ImageBase 入口点	
	GetThreadContext(hThread, &ct);
	return ct;
}

DWORD Process::GetProcessImageBase(PROCESS_INFORMATION procInfo)
{
	char* baseAddress = (CHAR*)GetThreadContext(procInfo.hThread).Ebx + 8;
	DWORD ImageBase = 0;

	ReadProcessMemory(procInfo.hProcess, baseAddress, &ImageBase, 4, NULL);
	return ImageBase;
}
