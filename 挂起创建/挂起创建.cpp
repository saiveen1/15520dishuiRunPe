// 挂起创建.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include "../shell/pe.cpp"
int main()
{
	char path[] = "C:/Users/Admin/Desktop/PETEST/demo/restore.exe";
	char path2[] = "C:/Users/Admin/Desktop/PETEST/demo/restoreImage.exe";
 	shellPe= std::make_unique<Pe>(path);
	LPVOID image = shellPe->GetImageBuffer();
	shellPe->BufferToFile(image, 131072, path2);

	//HANDLE hGame = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 15324);
	////TerminateProcess(hGame, 1);
	STARTUPINFOA src_si = { 0 };
	PROCESS_INFORMATION src_pi;
	src_si.cb = sizeof(src_si);
	char currentFileName[256] = {NULL};
	::GetModuleFileNameA(NULL, currentFileName, 256);
	printf("%s", currentFileName);
	//char processName[]= "C:/Users/Admin/Desktop/PETEST/src.EXE";
	//以挂起的方式创建进程						
	CreateProcessA(
		NULL,                    // name of executable module					
		currentFileName,                // command line string					
		NULL, 					 // SD
		NULL,  		             // SD			
		FALSE,                   // handle inheritance option					
		CREATE_SUSPENDED,     	 // creation flags  				
		NULL,                    // new environment block					
		NULL,                    // current directory name					
		&src_si,                  // startup information					
		&src_pi                   // process information					
	);

	CONTEXT contxt;
	contxt.ContextFlags = CONTEXT_FULL;
	//获取主线程信息 ImageBase 入口点	
	GetThreadContext(src_pi.hThread, &contxt);
	DWORD dwEntryPoint = contxt.Eax;

	//子程序的ImageBase在baseAddress里面但是不能直接读, 因为直接读的话只是当前父进程的地址
	//需要读子进程内存才能得到他的ImageBase
	char* baseAddress = (CHAR*)contxt.Ebx + 8;
	DWORD pImageBase = 0;
	ReadProcessMemory(src_pi.hProcess, baseAddress, &pImageBase, 4, NULL);
	system("pause");
	ResumeThread(src_pi.hThread);

	
}
