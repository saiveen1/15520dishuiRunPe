#include "fileMethod.h"

LPVOID Coding::Xor(IN LPVOID pBuffer, DWORD size)
{
	//DWORD count = 0;
	char* pNewBuffer = NULL;
	if (!(pNewBuffer = (char*)malloc(size)))
		return NULL;
	char* pTmp = (char *)pBuffer;
	//if (size % 4)
	//	count = size / 4 + 1;
	//count = size / 4;
	//4×Ö½Ú¼ÓÃÜ
	//Òì»ò0
	for (DWORD i = 0; i < size; i++)
	{
		*pNewBuffer = *((char*)pTmp) ^ 0x2;
		pTmp++;
		pNewBuffer++;
	}
	return (LPVOID)((DWORD)pNewBuffer - size);
}

