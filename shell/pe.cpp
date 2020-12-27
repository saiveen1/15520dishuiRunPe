#include "Pe.h"

Pe::Pe(LPSTR fileName)
{
	GetFileBufferAndSize(fileName);
	InitHeaders(mFileBuffer);
}

Pe::Pe(LPVOID pFileBuffer, DWORD sizeOfFile)
{
	mFileBuffer = pFileBuffer;
	InitHeaders(mFileBuffer);
	mFileSize = sizeOfFile;
}

Pe::~Pe()
{
	free(mFileBuffer);
}

DWORD Pe::InitHeaders(LPVOID pFileBuffer)
{
	base.pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	//pNTheaders = (PIMAGE_NT_HEADERS)((QWORD)pDosHeader + pDosHeader->e_lfanew);
	base.pFileHeader = (PIMAGE_FILE_HEADER)((DWORD)base.pDosHeader + base.pDosHeader->e_lfanew + 0x4);
	base.pOptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)((DWORD)base.pFileHeader + 0x14);

	//
	if (base.pFileHeader->Machine == IMAGE_FILE_MACHINE_AMD64 || base.pFileHeader->Machine == IMAGE_FILE_MACHINE_IA64)
	{
		isX64 = TRUE;
		base.pSectionHeader = (PIMAGE_SECTION_HEADER)((QWORD)base.pOptionalHeader64 + base.pFileHeader->SizeOfOptionalHeader);
		base.pDataDirectory = base.pOptionalHeader64->DataDirectory;
	}
	else
	{
		isX64 = FALSE;
		base.pOptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)base.pOptionalHeader64;
		base.pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)base.pOptionalHeader32 + base.pFileHeader->SizeOfOptionalHeader);
		base.pDataDirectory = base.pOptionalHeader32->DataDirectory;
	}
	base.sectionAlignment = base.pOptionalHeader->SectionAlignment;
	base.fileAlignment = base.pOptionalHeader->FileAlignment;
	return 1;
}

DWORD Pe::GetFileBufferAndSize(LPSTR IN filePath)
{
	FILE* pFile = NULL;

	//Open file.
	if (!(pFile = fopen(filePath, "rb")))
	{
		printf("Can't open the executable file");
		exit(OPEN_FILE_FAILED);
	}

	//Read the length of file.
	fseek(pFile, 0, SEEK_END);
	mFileSize = ftell(pFile);

	//Allocate memory.
	//д��sectionAllocate�ŷ���������� ���������Զ��ڷ���ռ�ĺ���+0x30���ռ�
	if (!(mFileBuffer = (LPVOID)malloc(mFileSize)))
	{
		printf("Allocate memory failed.");
		fclose(pFile);
		exit(0);
	}

	fseek(pFile, 0, SEEK_SET);
	size_t n = fread(mFileBuffer, mFileSize, 1, pFile);
	//�ɹ�����1
	if (!n)
	{
		printf("Read data failed!");
		free(mFileBuffer);
		fclose(pFile);
		exit(0);
	}

	fclose(pFile);
	return 1;
}

DWORD Pe::IsStandardPeFile(LPVOID pBuffer)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	pDosHeader = (PIMAGE_DOS_HEADER)pBuffer;

	if (*(PWORD)pBuffer != IMAGE_DOS_SIGNATURE)
	{
		printf("It's not a available MZ signature.");
		free(pBuffer);
		return FALSE;
	}

	if (*((PDWORD)((DWORD)pBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("It's not a available PE signature.");
		free(pBuffer);
		return FALSE;
	}

	return TRUE;
}

DWORD __BUFFER Pe::RestoreRelocation(DWORD newImageBase)
{
	DWORD foaBaseRelocation = 0;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_BASE_RELOCATION pBaseRelocation = NULL;


	InitHeaders(mFileBuffer);
	pDataDirectory = base.pOptionalHeader->DataDirectory;
	foaBaseRelocation = Rva2Foa(mFileBuffer, (*(pDataDirectory + 5)).VirtualAddress);
	pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)mFileBuffer + foaBaseRelocation);

	DWORD foaOfData = 0;
	DWORD rvaOfData = 0;
	DWORD currentBlockItems = 0;
	DWORD foaOfBlock = 0;
	DWORD differenceOfImageBase = 0;
	DWORD addressOf_rvaOfData = 0;
	DWORD* pFarAddress = NULL;

	differenceOfImageBase = newImageBase - base.pOptionalHeader->ImageBase;
	while (pBaseRelocation->SizeOfBlock)
	{
		//Ҫ�޸ĵ����ݴ�����ļ��е�ƫ�� ��� + word ��ƫ��
		foaOfBlock = (DWORD)pBaseRelocation - (DWORD)mFileBuffer;
		currentBlockItems = (pBaseRelocation->SizeOfBlock - 8) / 2;	//word ��ʾ
		addressOf_rvaOfData = pBaseRelocation->VirtualAddress;
		base.pOptionalHeader->ImageBase = newImageBase;
		while (--currentBlockItems)
		{
			rvaOfData = ((*(WORD*)(foaOfBlock + (DWORD)mFileBuffer + 8)) & 0x0fff) + addressOf_rvaOfData;
			foaOfData = (DWORD)Rva2Foa(mFileBuffer, rvaOfData);
			pFarAddress = (DWORD*)(foaOfData + (DWORD)mFileBuffer);
			*pFarAddress += differenceOfImageBase;
			foaOfBlock += 2;
		}

		pBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD)pBaseRelocation + pBaseRelocation->SizeOfBlock);
	}
	return 1;
}

LPVOID Pe::GetLastSectionBuffer(LPSTR IN filePath)
{
	GetFileBufferAndSize(filePath);
	InitHeaders(mFileBuffer);
	//���㿪ʼ......
	PIMAGE_SECTION_HEADER pLastSectionHeader = base.pSectionHeader + base.pFileHeader->NumberOfSections - 1;
	return (LPVOID)((DWORD)mFileBuffer + (pLastSectionHeader - 1)->PointerToRawData + (pLastSectionHeader - 1)->SizeOfRawData);
}

DWORD Pe::GetFileSize()
{
	return mFileSize;
}

DWORD Pe::GetImageBase()
{
	return base.pOptionalHeader->ImageBase;
}

DWORD Pe::GetSizeOfImage()
{
	return base.pOptionalHeader->SizeOfImage;
}

DWORD Pe::GetEntryPoint()
{
	return base.pOptionalHeader->AddressOfEntryPoint;
}

LPVOID Pe::GetFileBuffer()
{
	return mFileBuffer;
}

DWORD Pe::GetLastSectionSizeOfRaw()
{
	return (base.pSectionHeader + base.pFileHeader->NumberOfSections - 1)->SizeOfRawData;
}

BOOL Pe::HasRolocationTable()
{
	return *(DWORD *)(base.pOptionalHeader->DataDirectory + 5);
}

DWORD Pe::Rva2Foa(LPVOID pImageBuffer, DWORD rva)
{
	DWORD virtualAddress = 0;
	DWORD imageSectionSize = 0;

	InitHeaders(pImageBuffer);

	//5.18�����󶨵������ʱ�� RVA 250����0��Ȼ��� , û���뵽������ǰ������ �����, ֱ�ӷ��ؼ���
	if (rva < base.pSectionHeader->PointerToRawData)
		return rva;

	for (DWORD i = 0; i < base.pFileHeader->NumberOfSections; i++)
	{
		virtualAddress = base.pSectionHeader->VirtualAddress;
		imageSectionSize = virtualAddress + base.pSectionHeader->Misc.VirtualSize;

		if (rva >= virtualAddress && rva < imageSectionSize)
			return rva - virtualAddress + base.pSectionHeader->PointerToRawData;	//fileOffset

		base.pSectionHeader++;
	}
	return 0;
}

DWORD Pe::BufferToFile(IN LPVOID pBuffer, IN size_t sizeOfFile, OUT LPSTR outFilePath)
{

	FILE* pfile = NULL;
	if (!(pfile = fopen(outFilePath, "wb")))
	{
		printf("Create file failed.");
		exit(0);
	}

	if (!fwrite(pBuffer, sizeOfFile, 1, pfile))
	{
		printf("Create a executable file failed.");
		fclose(pfile);
		return 0;
	}

	if (!IsStandardPeFile(pBuffer))
	{
		printf("��������Ǳ�׼PE�ļ�.");
		fclose(pfile);
		return 0;
	}


	fclose(pfile);
	return sizeOfFile;
}

/// <summary>
/// ����һ����
/// </summary>
/// <param name="newSectionName"></param>
/// <param name="newSectionSize"></param>
/// <param name="newSectionBuffer"></param>
/// <param name="newFilePath">out�����õ����ļ�·��, ֱ���������ļ�</param>
/// <returns>�Ƿ�ɹ�</returns>
DWORD Pe::AllocateNewSecion(BYTE *newSectionName, DWORD newSectionSize, LPVOID newSectionBuffer, OUT LPSTR newFilePath)
{
	DWORD sizeOfAllocation = 0;
	DWORD sizeOfDosStub = 0;
	DWORD foaNewSection = 0;
	LPVOID pNewFileBuffer = NULL;
	PIMAGE_SECTION_HEADER newSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pOriginalLastSectionHeader = base.pSectionHeader + base.pFileHeader->NumberOfSections - 1;

	//if ((DWORD)base.pOptionalHeader->SizeOfHeaders-(DWORD)(base.pSectionHeader+base.pFileHeader->NumberOfSections))
	//{
	//	//ɾȥDos Stub, ��PEͷֱ��ָ��(dos ͷ��pe ͷ�м������)
	//	DWORD dw_temp = base.pDosHeader->e_lfanew;
	//	base.pDosHeader->e_lfanew = SIZE_OF_DOSHEADER;
	//	//���������Ƶ�ȻoepҲҪ
	//	sizeOfDosStub = dw_temp - SIZE_OF_DOSHEADER;
	//	base.pOptionalHeader32->AddressOfEntryPoint -= sizeOfDosStub;
	//	//���
	//	if (sizeOfDosStub < 0x40)
	//	{
	//		printf("DosStubС��0x40,��Ҫ�����ƶ����������½�\n.");
	//		exit(-1);
	//	}
	//	//sizeOfHeaders��С-ntHeaders�Ĵ�С
	//	sizeOfAllocation = (DWORD)(base.pDosHeader+base.pOptionalHeader->SizeOfHeaders) + IMAGE_SIZEOF_SECTION_HEADER - (DWORD)base.pNTheaders;
	//	memcpy((LPVOID)((DWORD)base.pDosHeader + SIZE_OF_DOSHEADER), (LPVOID)base.pNTheaders, sizeOfAllocation);
	//}

	sizeOfAllocation = newSectionSize;
	base.pFileHeader->NumberOfSections++;
	base.pOptionalHeader->SizeOfImage += newSectionSize;
	//slist.numOfSections++;	//��������ݿ������õ��޷����� ��Ҫָ��ָ��
	//slist.sizeOfImage += newSectionSize;

	//printf("%x", (header.pSecitonHeader + slist.numOfSections - 2)->SizeOfRawData);
	//printf("%x", (header.pSecitonHeader + slist.numOfSections - 2)->PointerToRawData);

	//12.21����������������������(��dos stub) ��Ȩ��Ϣ
	foaNewSection = pOriginalLastSectionHeader->SizeOfRawData + pOriginalLastSectionHeader->PointerToRawData;
	mFileSize += sizeOfAllocation;
	if (!(pNewFileBuffer = (LPVOID)malloc(mFileSize)))
		return 0;
	memset(pNewFileBuffer, 0, mFileSize);
	memcpy(pNewFileBuffer, mFileBuffer, mFileSize - sizeOfAllocation);
	InitHeaders(pNewFileBuffer);

	//���Ƶ�һ�����ε���Ϣ
	newSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)(base.pSectionHeader + base.pFileHeader->NumberOfSections - 1));
	memcpy(newSectionHeader, base.pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);
	memset(newSectionHeader + 1, 0, IMAGE_SIZEOF_SECTION_HEADER);
	
	//�ı��½���Ϣ
	//������Ҫ�ر�ע��, ����������������������ͷŵ�, ���Բ�����Ҫִ����ô��, ��0Ҳ����, ��Ϊ��������ݿ�������һ�����߸�src�Ĵ�С	
	//���μ���, (virtualsize / sectionalignment + 1) * sectionalignment, �������εĴ�С
	//����Ƿ�����������Ҫ���һ����������֤�����ڸ�����
	//��������� ��ô�ö��ٶ�����ö��ٶ���
	for (DWORD i = 0; i < SIZE_OF_SECTION_NAME; i++)
		newSectionHeader->Name[i] = newSectionName[i];
	newSectionHeader->SizeOfRawData = newSectionSize;
	newSectionHeader->Misc.VirtualSize = newSectionSize;
	DWORD dw_temp = pOriginalLastSectionHeader->Misc.VirtualSize / base.sectionAlignment;
	if (pOriginalLastSectionHeader->Misc.VirtualSize % base.sectionAlignment)	
		newSectionHeader->VirtualAddress = (newSectionHeader - 1)->VirtualAddress + (dw_temp + 1) * base.sectionAlignment;
	else
		newSectionHeader->VirtualAddress = (newSectionHeader - 1)->VirtualAddress + (dw_temp - 1) * base.sectionAlignment;
	newSectionHeader->PointerToRawData = (newSectionHeader - 1)->PointerToRawData + (newSectionHeader - 1)->SizeOfRawData;
	//5.25̫�����Ĵ����� section��Characteristic��ΪҪ����dllд����CALL��ַ ��Ҫ��ȡ��ַȻ���뵽���� ����˿��д Ȼ��һֱû�����������
	//������, һ��Ϊ1��Ϊ1
	newSectionHeader->Characteristics |= 0xf0000000;
	LPVOID newSectionAddress = (LPVOID)((DWORD)pNewFileBuffer + pOriginalLastSectionHeader->PointerToRawData + pOriginalLastSectionHeader->SizeOfRawData);
	memcpy(newSectionAddress, newSectionBuffer, newSectionSize);
	if ((base.pFileHeader->Characteristics & 0x2000) == IMAGE_FILE_DLL)
	{
		//BufferToFile(pNewFileBuffer, fileSize, newSectionOutFilePathForDLL);
		//*addrOutFilePath = (DWORD)newSectionOutFilePathForDLL;
		TODO;
	}
	else
		BufferToFile(pNewFileBuffer, mFileSize, newFilePath);

	free(pNewFileBuffer);

	return foaNewSection;
}

LPVOID Pe::GetImageBuffer()
{
	LPVOID pImageBuffer = NULL;
	InitHeaders(mFileBuffer);

	if (!IsStandardPeFile(mFileBuffer))
	{
		printf("IMAGETOFILE����.");
		free(mFileBuffer);
		return 0;
	}

	if (!(pImageBuffer = malloc(base.pOptionalHeader->SizeOfImage)))
		return 0;
	memset(pImageBuffer, 0, base.pOptionalHeader->SizeOfImage);
	memcpy(pImageBuffer, mFileBuffer, base.pOptionalHeader->SizeOfHeaders);

	for (DWORD i = 0; i < base.pFileHeader->NumberOfSections; i++)
	{
		//��С�ô�� size of raw data
		memcpy((LPVOID)((DWORD)pImageBuffer + base.pSectionHeader->VirtualAddress), (LPVOID)((DWORD)mFileBuffer + base.pSectionHeader->PointerToRawData), base.pSectionHeader->SizeOfRawData);
		base.pSectionHeader++;
	}

	if (!IsStandardPeFile(mFileBuffer))
	{
		printf("Copy from FileBuffer to ImageBuffer failed.\n");
		free(pImageBuffer);
		free(mFileBuffer);
		return NULL;
	}

	//free(mFileBuffer);

	return pImageBuffer;
}
