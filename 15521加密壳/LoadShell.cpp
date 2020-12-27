// 15521加密壳.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "../shell/pe.cpp"
#include "../shell/fileMethod.cpp"
int main()
{

#ifdef _DEBUG
    char shellPath[] = "E:\\Win10_Main\\windows_sd\\own\\Vs2017\\15521_encryption_pack\\Debug\\shell.exe";
#else
    char shellPath[] = "E:\\Win10_Main\\windows_sd\\own\\Vs2017\\15521_encryption_pack\\release\\shell.exe";
#endif
   
    char srcPath[] = "E:\\Win10_Main\\windows_sd\\own\\Vs2017\\15521_encryption_pack\\Debug\\demo.exe";

    shellPe = std::make_unique<Pe>(shellPath);

    BYTE newSectionName[8] = { 0x2E,0X6E,0X65,0X77,0x72 };
    Pe *srcPe = new Pe(srcPath);
    LPVOID pEncryptBuffer = Coding::Xor(srcPe->GetFileBuffer(), srcPe->GetFileSize());
    shellPe->AllocateNewSecion(newSectionName, srcPe->GetFileSize(), pEncryptBuffer, shellPath);
    system("pause");
    return 0;
}