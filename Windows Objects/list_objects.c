/*+===================================================================
  File:      list_objects.c
  Summary:   List objects from a Windows Object Manager directory.
  Classes:   N/A
  Functions: N/A
  Origin:    https://github.com/am0nsec
##
  Author: Paul Laine (@am0nsec)
===================================================================+*/
#pragma once
#include <Windows.h>
#include <stdio.h>
#include "ntstructs.h"

#pragma comment(lib, "ntdll")

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
VOID RtlInitUnicodeString(
	_In_ PUNICODE_STRING DestinationString,
	_In_ PCWSTR          SourceString
);
NTSTATUS WINAPI NtOpenDirectoryObject(
	_Out_ PHANDLE            DirectoryHandle,
	_In_  ACCESS_MASK        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES ObjectAttributes
);
NTSTATUS WINAPI NtQueryDirectoryObject(
	_In_      HANDLE  DirectoryHandle,
	_Out_opt_ PVOID   Buffer,
	_In_      ULONG   Length,
	_In_      BOOLEAN ReturnSingleEntry,
	_In_      BOOLEAN RestartScan,
	_Inout_   PULONG  Context,
	_Out_opt_ PULONG  ReturnLength
);

INT wmain(INT argc, PWCHAR argv[]) {
	wprintf(L"------------------------------------------------------\n");
	wprintf(L" List objects from a Windows Object Manager directory\n");
	wprintf(L"         Copyright (C) Paul Laine (@amonsec)\n");
	wprintf(L"------------------------------------------------------\n\n");

	/*--------------------------------------------------------------------
	  Check user input.
	--------------------------------------------------------------------*/
	if (argc == 1) {
		wprintf(L"[-] Usage: \n");
		wprintf(L"    - WindowsObjects.exe <directory> \n");
		wprintf(L"[-] Examples: \n");
		wprintf(L"    - WindowsObjects.exe \\ \n");
		wprintf(L"    - WindowsObjects.exe \\ObjectTypes \n");
		wprintf(L"    - WindowsObjects.exe \\Sessions\\1\\BaseNamedObjects \n\n");
		return 0x1;
	}
	
	/*--------------------------------------------------------------------
	  Get a handle to the directory object.
	--------------------------------------------------------------------*/
	UNICODE_STRING RootDirectory = { 0 };
	RtlInitUnicodeString(&RootDirectory, argv[1]);

	HANDLE hRootDirectory = NULL;
	HANDLE hProcessHeap = GetProcessHeap();

	OBJECT_ATTRIBUTES ObjAttributes;
	ObjAttributes.Attributes = OBJ_CASE_INSENSITIVE;
	ObjAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
	ObjAttributes.ObjectName = &RootDirectory;
	ObjAttributes.RootDirectory = NULL;
	ObjAttributes.SecurityDescriptor = NULL;
	ObjAttributes.SecurityQualityOfService = NULL;

	NTSTATUS status = NtOpenDirectoryObject(&hRootDirectory, DIRECTORY_QUERY, &ObjAttributes);
	if (!NT_SUCCESS(status) || hRootDirectory == INVALID_HANDLE_VALUE) {
		wprintf(L"[-] Error invoking ntdll!NtOpenDirectoryObject (0x%08x)\n", (DWORD)status);
		return 0x1;
	}

	/*--------------------------------------------------------------------
	  Parse all objects from the directory.
	--------------------------------------------------------------------*/
	POBJECT_DIRECTORY_INFORMATION pObjInformation = NULL;
	ULONG uStructureSize = 0;
	ULONG uContext = 0;

	wprintf(L" %+-32ws %ws\n\n", L"Type", L"Name");
	do {
		// Get length of the structure
		status = NtQueryDirectoryObject(hRootDirectory, NULL, 0, TRUE, FALSE, &uContext, &uStructureSize);
		if (status == STATUS_NO_MORE_ENTRIES)
			break;
		
		if (status != STATUS_BUFFER_TOO_SMALL || uStructureSize == 0) {
			wprintf(L"[-] Error invoking ntdll!NtQueryDirectoryObject (0x%08x)\n", (DWORD)status);
			CloseHandle(hRootDirectory);
			return 0x1;
		}

		// Get the information about the object
		pObjInformation = HeapAlloc(hProcessHeap, HEAP_ZERO_MEMORY, uStructureSize);
		status = NtQueryDirectoryObject(hRootDirectory, pObjInformation, uStructureSize, TRUE, FALSE, &uContext, NULL);
		if (!NT_SUCCESS(status)) {
			wprintf(L"[-] Error invoking ntdll!NtQueryDirectoryObject (0x%08x)\n", (DWORD)status);
			CloseHandle(hRootDirectory);
			return 0x1;
		}

		wprintf(L" %+-32ws %ws\n", pObjInformation->TypeName.Buffer, pObjInformation->Name.Buffer);
		HeapFree(hProcessHeap, 0, pObjInformation);
		uStructureSize = 0;
	} while (status != STATUS_NO_MORE_ENTRIES);
	
	// Cleanup and exit
	if (hRootDirectory)
		CloseHandle(hRootDirectory);
	return 0x0;
}
