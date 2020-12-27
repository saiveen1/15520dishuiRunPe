#include "Process.h"

PROCESS_INFORMATION Process::CreateProcessSuspend(LPSTR processName)
{
	STARTUPINFOA src_si = { 0 };
	PROCESS_INFORMATION src_pi;
	src_si.cb = sizeof(src_si);

	//�Թ���ķ�ʽ��������						
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

	////�ӳ����ImageBase��baseAddress���浫�ǲ���ֱ�Ӷ�, ��Ϊֱ�Ӷ��Ļ�ֻ�ǵ�ǰ�����̵ĵ�ַ
	////��Ҫ���ӽ����ڴ���ܵõ�����ImageBase
	//char* baseAddress = (CHAR*)contxt.Ebx + 8;
	//DWORD pImageBase = 0;
	//ReadProcessMemory(src_pi.hProcess, baseAddress, &pImageBase, 4, NULL);
	
}


CONTEXT Process::GetThreadContext(HANDLE hThread)
{
	CONTEXT ct;
	
	ct.ContextFlags = CONTEXT_FULL;
	//��ȡ���߳���Ϣ ImageBase ��ڵ�	
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
