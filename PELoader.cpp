#include <windows.h>
#include <stdio.h>


//跳转到入口点执行
bool CallEntry(char* chBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);
	char* ExeEntry = (char*)(chBaseAddress + pNt->OptionalHeader.AddressOfEntryPoint);

	// 跳转到入口点处执行
	__asm
	{
		mov eax, ExeEntry
		jmp eax
	}

	return TRUE;
}


//设置默认加载基址
bool SetImageBase(char* chBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);
	pNt->OptionalHeader.ImageBase = (ULONG32)chBaseAddress;

	return TRUE;
}


//填写导入表
bool ImportTable(char* chBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)pDos +
		pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	// 循环遍历DLL导入表中的DLL及获取导入表中的函数地址
	char* lpDllName = NULL;
	HMODULE hDll = NULL;
	PIMAGE_THUNK_DATA lpImportNameArray = NULL;
	PIMAGE_IMPORT_BY_NAME lpImportByName = NULL;
	PIMAGE_THUNK_DATA lpImportFuncAddrArray = NULL;
	FARPROC lpFuncAddress = NULL;
	DWORD i = 0;

	while (TRUE)
	{
		if (0 == pImportTable->OriginalFirstThunk)
		{
			break;
		}

		// 获取导入表中DLL的名称并加载DLL
		lpDllName = (char*)((DWORD)pDos + pImportTable->Name);
		hDll = GetModuleHandleA(lpDllName);
		if (NULL == hDll)
		{
			hDll = LoadLibraryA(lpDllName);
			if (NULL == hDll)
			{
				pImportTable++;
				continue;
			}
		}

		i = 0;
		// 获取OriginalFirstThunk以及对应的导入函数名称表首地址
		lpImportNameArray = (PIMAGE_THUNK_DATA)((DWORD)pDos + pImportTable->OriginalFirstThunk);
		// 获取FirstThunk以及对应的导入函数地址表首地址
		lpImportFuncAddrArray = (PIMAGE_THUNK_DATA)((DWORD)pDos + pImportTable->FirstThunk);
		while (TRUE)
		{
			if (0 == lpImportNameArray[i].u1.AddressOfData)
			{
				break;
			}

			// 获取IMAGE_IMPORT_BY_NAME结构
			lpImportByName = (PIMAGE_IMPORT_BY_NAME)((DWORD)pDos + lpImportNameArray[i].u1.AddressOfData);

			// 判断导出函数是序号导出还是函数名称导出
			if (0x80000000 & lpImportNameArray[i].u1.Ordinal)
			{
				// 序号导出
				// 当IMAGE_THUNK_DATA值的最高位为1时，表示函数以序号方式输入，这时，低位被看做是一个函数序号
				lpFuncAddress = GetProcAddress(hDll, (LPCSTR)(lpImportNameArray[i].u1.Ordinal & 0x0000FFFF));
			}
			else
			{
				// 名称导出
				lpFuncAddress = GetProcAddress(hDll, (LPCSTR)lpImportByName->Name);
			}
			// 注意此处的函数地址表的赋值，要对照PE格式进行装载，不要理解错了！！！
			lpImportFuncAddrArray[i].u1.Function = (DWORD)lpFuncAddress;
			i++;
		}

		pImportTable++;
	}

	return TRUE;


}


//修复重定位表
bool RelocationTable(char* chBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)chBaseAddress;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(chBaseAddress + pDos->e_lfanew);
	PIMAGE_BASE_RELOCATION pLoc = (PIMAGE_BASE_RELOCATION)(chBaseAddress + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	//判断是否有重定位表
	if ((char*)pLoc == (char*)pDos)
	{
		return TRUE;
	}

	while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //开始扫描重定位表
	{
		WORD* pLocData = (WORD*)((PBYTE)pLoc + sizeof(IMAGE_BASE_RELOCATION));
		//计算需要修正的重定位项（地址）的数目
		int nNumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (int i = 0; i < nNumberOfReloc; i++)
		{
			if ((DWORD)(pLocData[i] & 0x0000F000) == 0x00003000) //这是一个需要修正的地址
			{
				DWORD* pAddress = (DWORD*)((PBYTE)pDos + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
				DWORD dwDelta = (DWORD)pDos - pNt->OptionalHeader.ImageBase;
				*pAddress += dwDelta;
			}
		}

		//转移到下一个节进行处理
		pLoc = (PIMAGE_BASE_RELOCATION)((PBYTE)pLoc + pLoc->SizeOfBlock);
	}

	return TRUE;
}


//将内存中的文件映射到进程内存空间中
bool MapFile(char* pFileBuff, char* chBaseAddress)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFileBuff + pDos->e_lfanew);
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);

	//所有头 + 结表头的大小
	DWORD dwSizeOfHeaders = pNt->OptionalHeader.SizeOfHeaders;

	//获取区段数量
	int nNumerOfSections = pNt->FileHeader.NumberOfSections;

	// 将前一部分都拷贝过去
	RtlCopyMemory(chBaseAddress, pFileBuff, dwSizeOfHeaders);

	char* chSrcMem = NULL;
	char* chDestMem = NULL;
	DWORD dwSizeOfRawData = 0;

	for (int i = 0; i < nNumerOfSections; i++)
	{
		if ((0 == pSection->VirtualAddress) ||
			(0 == pSection->SizeOfRawData))
		{
			pSection++;
			continue;
		}

		// 拷贝节区
		chSrcMem = (char*)((DWORD)pFileBuff + pSection->PointerToRawData);
		chDestMem = (char*)((DWORD)chBaseAddress + pSection->VirtualAddress);
		dwSizeOfRawData = pSection->SizeOfRawData;
		RtlCopyMemory(chDestMem, chSrcMem, dwSizeOfRawData);

		pSection++;
	}

	return TRUE;
}


//获取镜像大小
DWORD GetSizeOfImage(char* pFileBuff)
{
	DWORD dwSizeOfImage = 0;
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pFileBuff;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pFileBuff + pDos->e_lfanew);
	dwSizeOfImage = pNt->OptionalHeader.SizeOfImage;

	return dwSizeOfImage;
}


//运行文件
char* RunExe(char* pFileBuff, DWORD dwSize)
{
	char* chBaseAddress = NULL;

	//获取镜像大小
	DWORD dwSizeOfImage = GetSizeOfImage(pFileBuff);

	//根据镜像大小在进程中开辟一块内存空间
	chBaseAddress = (char*)VirtualAlloc(NULL, dwSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (NULL == chBaseAddress)
	{
		printf("申请进程空间失败\n");
		return NULL;
	}

	//将申请的进程空间全部填0
	RtlZeroMemory(chBaseAddress, dwSizeOfImage);

	//将内存中的exe数据映射到进程内存中
	if (FALSE == MapFile(pFileBuff, chBaseAddress))
	{
		printf("内存映射失败\n");
		return NULL;
	}

	//修复重定位
	if (FALSE == RelocationTable(chBaseAddress))
	{
		printf("重定位修复失败\n");
		return NULL;
	}

	//填写导入表
	if (FALSE == ImportTable(chBaseAddress))
	{
		printf("填写导入表失败\n");
		return NULL;
	}

	//将页属性都设置为可读可写可执行
	DWORD dwOldProtect = 0;
	if (FALSE == VirtualProtect(chBaseAddress, dwSizeOfImage, PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		printf("设置页属性失败\n");
		return NULL;
	}

	//设置默认加载基址
	if (FALSE == SetImageBase(chBaseAddress))
	{
		printf("设置默认加载基址失败\n");
		return NULL;
	}

	//跳转到入口点执行
	if (FALSE == CallEntry(chBaseAddress))
	{
		printf("跳转到入口点失败\n");
		return NULL;
	}

	return chBaseAddress;

}


int main()
{
	char szFileName[] = "E:\\CppWorkspace\\PEParser\\Debug\\PEParser.exe";

	//打开文件,设置属性可读可写
	HANDLE hFile = CreateFileA(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);

	if (INVALID_HANDLE_VALUE == hFile)
	{
		printf("文件打开失败\n");
		return 1;
	}

	//获取文件大小
	DWORD dwFileSize = GetFileSize(hFile, NULL);

	//申请空间
	char* pData = new char[dwFileSize];
	if (NULL == pData)
	{
		printf("空间申请失败\n");
		return 2;
	}

	//将文件读取到内存中
	DWORD dwRet = 0;
	ReadFile(hFile, pData, dwFileSize, &dwRet, NULL);
	CloseHandle(hFile);


	//将内存中exe加载到程序中
	char* chBaseAddress = RunExe(pData, dwFileSize);


	delete[] pData;
	system("pause");
	return 0;
}