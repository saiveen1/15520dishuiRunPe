#pragma once

#include <windows.h>
#include "iostream"
#include "helpers.h"
#pragma warning(disable:4996)


class Pe  
{
public:	
	Pe(LPSTR fileName);
	Pe(LPVOID pFileBuffer, DWORD sizeOfFile);
	~Pe();
	DWORD GetFileBufferAndSize(LPSTR IN filePath);
	DWORD BufferToFile(IN LPVOID pBuffer, IN size_t sizeOfFile, OUT LPSTR outFilePath);
	DWORD AllocateNewSecion(BYTE* newSectionName, DWORD newSectionSize, LPVOID newSectionBuffer, OUT LPSTR newFilePath);
	LPVOID GetImageBuffer();
	DWORD IsStandardPeFile(LPVOID pBuffer);
	DWORD __BUFFER RestoreRelocation(DWORD newImageBase);
	LPVOID GetLastSectionBuffer(LPSTR IN filePath);


public:
	DWORD Rva2Foa(LPVOID pImageBuffer, DWORD rva);
	DWORD GetFileSize();
	DWORD GetImageBase();
	DWORD GetSizeOfImage();
	DWORD GetEntryPoint();
	LPVOID GetFileBuffer();
	DWORD GetLastSectionSizeOfRaw();
	BOOL HasRolocationTable();
private:
	BOOL isX64;
	DWORD mFileSize;
	LPVOID mFileBuffer;

	struct
	{
		PIMAGE_DOS_HEADER pDosHeader = NULL;
		PIMAGE_NT_HEADERS pNTheaders = NULL;
		PIMAGE_FILE_HEADER pFileHeader = NULL;
		union
		{
			PIMAGE_OPTIONAL_HEADER32 pOptionalHeader32 = NULL;
			PIMAGE_OPTIONAL_HEADER64 pOptionalHeader64;
			PIMAGE_OPTIONAL_HEADER pOptionalHeader;
		};
		PIMAGE_SECTION_HEADER pSectionHeader = NULL;
		PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
		DWORD sectionAlignment = 0;
		DWORD fileAlignment = 0;
	}base;
private:
	DWORD InitHeaders(LPVOID pFileBuffer);
};

inline std::unique_ptr<Pe> shellPe;
