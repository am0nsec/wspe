/*+===================================================================
  File:      main.c
  Summary:   List handles from a remote process.
  Classes:   N/A
  Functions: N/A
  Origin:    https://github.com/am0nsec/wspe/blob/master/Object%20Manager/
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
VOID WINAPI RtlInitUnicodeString(
    _In_ PUNICODE_STRING DestinationString,
    _In_ PCWSTR          SourceString
);

NTSTATUS WINAPI NtQueryInformationProcess(
    _In_  HANDLE ProcessHandle,
    _In_  DWORD  ProcessInformationClass,
    _Out_ PVOID  ProcessInformation,
    _In_  ULONG  ProcessInformationLength,
    _Out_ PULONG ReturnLength
);

NTSTATUS WINAPI NtQueryObject(
    _In_opt_  HANDLE Handle,
    _In_      DWORD  ObjectInformationClass,
    _Out_     PVOID  ObjectInformation,
    _In_      ULONG  ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength
);

/*--------------------------------------------------------------------
  Private Function
--------------------------------------------------------------------*/
HRESULT GetRemoteProcessHandlesSnapshotInformation(
    _Out_ PPROCESS_HANDLE_SNAPSHOT_INFORMATION* ppHandleSnapshotInfo
);

HRESULT GetObjNameByHandle(
    _In_  PHANDLE         phObjHandle,
    _Out_ PUNICODE_STRING pObjName,
    _Out_ PVOID*          ppHeapNameBuffer
);

HRESULT GetObjTypeByHandle(
    _In_  PHANDLE         phObjHandle,
    _Out_ PUNICODE_STRING pObjType,
    _Out_ PVOID*          ppHeapTypeBuffer
);

NTSTATUS GetObjBasicInformationByHandle(
    _In_  PHANDLE pObjHandle,
    _Out_ PACCESS_MASK pAccessMask,
    _Out_ PDWORD pdwReferenceCount
);

/*--------------------------------------------------------------------
  Global Variables
--------------------------------------------------------------------*/
HANDLE g_hRemoteProcess    = INVALID_HANDLE_VALUE;
HANDLE g_hCurrentProcess   = INVALID_HANDLE_VALUE;
HANDLE g_hProcessHeap      = INVALID_HANDLE_VALUE;
DWORD  g_dwRemoteProcessId = 0;

INT wmain(INT argc, PWCHAR argv[]) {
    wprintf(L"-----------------------------------------\n");
    wprintf(L"      List handles from remote process\n");
    wprintf(L"     Copyright (C) Paul Laine (@am0nsec)\n");
    wprintf(L"-----------------------------------------\n\n");

    /*--------------------------------------------------------------------
      Check user input.
    --------------------------------------------------------------------*/
    if (argc == 1) {
        wprintf(L"[-] Usage: \n");
        wprintf(L"    - WindowsHandles.exe <process ID> \n\n");
        return 0x1;
    }
    
    // Initialise variables
    g_dwRemoteProcessId = _wtoi(argv[1]);
    g_hProcessHeap = GetProcessHeap();
    g_hCurrentProcess = GetCurrentProcess();

    // Get the an handle to the remote process with the correct permissions
    g_hRemoteProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, g_dwRemoteProcessId);
    if (g_hRemoteProcess == INVALID_HANDLE_VALUE) {
        wprintf(L"[-] Error invoking kernel32!OpenProcess (%d)\n", GetLastError());
        return 0x1;
    }

    // Get list of handles
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION pHandleSnapshotInfo = NULL;
    if (GetRemoteProcessHandlesSnapshotInformation(&pHandleSnapshotInfo) == STATUS_UNSUCCESSFUL) {
        HeapFree(g_hProcessHeap, 0, pHandleSnapshotInfo);
        CloseHandle(g_hRemoteProcess);
        return 0x1;
    }
    wprintf(L"[>] Number of handles: %d\n\n", (DWORD)pHandleSnapshotInfo->NumberOfHandles);
    

    // Loop through all the handles
    wprintf(L"%+-13ws %+-13ws %+-13ws %+-25ws %ws\n\n", L"Handle", L"Access Mask", L"References", L"Type", L"Name");
    for (DWORD cx = 0; cx < pHandleSnapshotInfo->NumberOfHandles; cx++) {
        HANDLE hRemoteHandle = pHandleSnapshotInfo->Handles[cx].HandleValue;
        HANDLE hDuplicate = INVALID_HANDLE_VALUE;

        // Duplicate handle in the current process
        BOOL success = DuplicateHandle(g_hRemoteProcess, hRemoteHandle, g_hCurrentProcess, &hDuplicate, 0, FALSE, DUPLICATE_SAME_ACCESS);
        if (!success) {
            CloseHandle(hDuplicate);
            continue;
        }

        UNICODE_STRING ObjType = { 0, 0, NULL };
        PVOID pHeapTypeBuffer = NULL;
        if (GetObjTypeByHandle(&hDuplicate, &ObjType, &pHeapTypeBuffer) == STATUS_UNSUCCESSFUL) {
            CloseHandle(hDuplicate);
            continue;
        }

        UNICODE_STRING ObjName = { 0, 0, NULL };
        PVOID pHeapNameBuffer = NULL;
        if (GetObjNameByHandle(&hDuplicate, &ObjName, &pHeapNameBuffer) == STATUS_UNSUCCESSFUL) {
            CloseHandle(hDuplicate);
            continue;
        }

        ACCESS_MASK dwAccessMask = 0;
        DWORD dwReferenceCount = 0;
        if (GetObjBasicInformationByHandle(&hDuplicate, &dwAccessMask, &dwReferenceCount) == STATUS_UNSUCCESSFUL) {
            CloseHandle(hDuplicate);
            continue;
        }

        // Print information to console
        wprintf(L"0x%08llx    0x%08llx    %-13d %+-25ws %ws\n", (DWORD64)hRemoteHandle, (DWORD64)dwAccessMask, dwReferenceCount, ObjType.Buffer, ObjName.Buffer);

        // Cleanup
        if (pHeapTypeBuffer != NULL)
            HeapFree(g_hProcessHeap, 0, pHeapTypeBuffer);
        if (pHeapNameBuffer != NULL)
            HeapFree(g_hProcessHeap, 0, pHeapNameBuffer);
        CloseHandle(hDuplicate);
    }

    // Cleanup
    HeapFree(g_hProcessHeap, 0, pHandleSnapshotInfo);
    CloseHandle(g_hRemoteProcess);
    return 0x00;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: GetRemoteProcessHandlesSnapshotInformation
  Summary:  Get the PROCESS_HANDLE_SNAPSHOT_INFORMATION structure of a remote process.

  Args:     PPROCESS_HANDLE_SNAPSHOT_INFORMATION* ppHandleSnapshotInfo
              - Pointer to pointer of a PROCESS_HANDLE_SNAPSHOT_INFORMATION structure.

  Returns: NTSTATUS
-----------------------------------------------------------------F-F*/
NTSTATUS GetRemoteProcessHandlesSnapshotInformation(PPROCESS_HANDLE_SNAPSHOT_INFORMATION* ppHandleSnapshotInfo) {
    NTSTATUS dwNtStatus = STATUS_UNSUCCESSFUL;
    ULONG lTableSize = 0;

    // ProcessHandleInformation = 51
    *ppHandleSnapshotInfo = HeapAlloc(g_hProcessHeap, HEAP_ZERO_MEMORY, 1024);
    dwNtStatus = NtQueryInformationProcess(g_hRemoteProcess, 51, *ppHandleSnapshotInfo, 1024, &lTableSize);
    if ((!NT_SUCCESS(dwNtStatus) && dwNtStatus != STATUS_INFO_LENGTH_MISMATCH) || lTableSize == 0) {
        wprintf(L"[-] Error invoking ntdll!NtQueryInformationProcess (0x%08x)\n", dwNtStatus);
        HeapFree(g_hProcessHeap, 0, *ppHandleSnapshotInfo);
        return STATUS_UNSUCCESSFUL;
    }

    // Reallocate the memory
    *ppHandleSnapshotInfo = HeapReAlloc(g_hProcessHeap, HEAP_ZERO_MEMORY, *ppHandleSnapshotInfo, lTableSize);
    dwNtStatus = NtQueryInformationProcess(g_hRemoteProcess, 51, *ppHandleSnapshotInfo, lTableSize, &lTableSize);
    if (!NT_SUCCESS(dwNtStatus) && dwNtStatus != STATUS_INFO_LENGTH_MISMATCH) {
        wprintf(L"[-] Error invoking ntdll!NtQueryInformationProcess (0x%08x)\n", dwNtStatus);
        HeapFree(g_hProcessHeap, 0, *ppHandleSnapshotInfo);
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: GetObjNameByHandle
  Summary:  Get the name of a named object with an handle.

  Args:     PHANDLE pObjHandle
              - Pointer to the handle of the object.
            PUNICODE_STRING pObjName
              - Pointer to a UNICODE_STRING to store the name of the named object.
            PVOID* ppHeapNameBuffer
              - Pointer to pointer used to store the address of the buffer in the heap.

  Returns: NTSTATUS
-----------------------------------------------------------------F-F*/
NTSTATUS GetObjNameByHandle(PHANDLE pObjHandle, PUNICODE_STRING pObjName, PVOID* ppHeapNameBuffer) {
    NTSTATUS dwNtStatus = STATUS_UNSUCCESSFUL;

    ULONG lNameSize = 0;
    dwNtStatus = NtQueryObject(*pObjHandle, 1, NULL, 0, &lNameSize);
    if ((!NT_SUCCESS(dwNtStatus) && dwNtStatus != STATUS_INFO_LENGTH_MISMATCH) || lNameSize == 0) {
        wprintf(L"[-] Error invoking ntdll!NtQueryObject (0x%08x)\n", dwNtStatus);
        return STATUS_UNSUCCESSFUL;
    }

    *ppHeapNameBuffer = HeapAlloc(g_hProcessHeap, HEAP_ZERO_MEMORY, lNameSize);
    dwNtStatus = NtQueryObject(*pObjHandle, 1, *ppHeapNameBuffer, lNameSize, &lNameSize);
    if ((!NT_SUCCESS(dwNtStatus) && dwNtStatus != STATUS_INFO_LENGTH_MISMATCH)) {
        wprintf(L"[-] Error invoking ntdll!NtQueryObject (0x%08x)\n", dwNtStatus);
        return STATUS_UNSUCCESSFUL;
    }

    *pObjName = ((POBJECT_NAME_INFORMATION)*ppHeapNameBuffer)->Name;
    return STATUS_SUCCESS;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: GetObjTypeByHandle
  Summary:  Get the type of a object with an handle.

  Args:     PHANDLE pObjHandle
              - Pointer to the handle of the object.
            PUNICODE_STRING pObjType
              - Pointer to a UNICODE_STRING to store the type of an object.
            PVOID* ppHeapTypeBuffer
              - Pointer to pointer used to store the address of the buffer in the heap.

  Returns: NTSTATUS
-----------------------------------------------------------------F-F*/
NTSTATUS GetObjTypeByHandle(PHANDLE pObjHandle, PUNICODE_STRING pObjType, PVOID* ppHeapTypeBuffer) {
    NTSTATUS dwNtStatus = STATUS_UNSUCCESSFUL;

    ULONG lTypeSize = 0;
    dwNtStatus = NtQueryObject(*pObjHandle, 2, NULL, 0, &lTypeSize);
    if ((!NT_SUCCESS(dwNtStatus) && dwNtStatus != STATUS_INFO_LENGTH_MISMATCH) || lTypeSize == 0) {
        wprintf(L"[-] Error invoking ntdll!NtQueryObject (0x%08x)\n", dwNtStatus);
        return STATUS_UNSUCCESSFUL;
    }

    *ppHeapTypeBuffer = HeapAlloc(g_hProcessHeap, HEAP_ZERO_MEMORY, lTypeSize);
    dwNtStatus = NtQueryObject(*pObjHandle, 2, *ppHeapTypeBuffer, lTypeSize, &lTypeSize);
    if ((!NT_SUCCESS(dwNtStatus) && dwNtStatus != STATUS_INFO_LENGTH_MISMATCH)) {
        wprintf(L"[-] Error invoking ntdll!NtQueryObject (0x%08x)\n", dwNtStatus);
        return STATUS_UNSUCCESSFUL;
    }

    *pObjType = ((PPUBLIC_OBJECT_TYPE_INFORMATION)*ppHeapTypeBuffer)->TypeName;
    return STATUS_SUCCESS;
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
  Function: GetObjBasicInformationByHandle
  Summary:  Get the access mask and reference count of an object with an handle.

  Args:     PHANDLE pObjHandle
              - Pointer to the handle of the object.
            PACCESS_MASK pAccessMask
              - Pointer to a ACCESS_MASK to store the permissions of the object.
            PDWORD pdwReferenceCount
              - Pointer to the number of references to the object.

  Returns: NTSTATUS
-----------------------------------------------------------------F-F*/
NTSTATUS GetObjBasicInformationByHandle(PHANDLE pObjHandle, PACCESS_MASK pAccessMask, PDWORD pdwReferenceCount) {
    ULONG lStructureSize = sizeof(PUBLIC_OBJECT_BASIC_INFORMATION);
    PVOID pBuffer = HeapAlloc(g_hProcessHeap, HEAP_ZERO_MEMORY, lStructureSize);

    NTSTATUS dwNtStatus = NtQueryObject(*pObjHandle, 0, pBuffer, lStructureSize, &lStructureSize);
    if (!NT_SUCCESS(dwNtStatus) || lStructureSize == 0) {
        wprintf(L"[-] Error invoking ntdll!NtQueryObject (0x%08x)\n", dwNtStatus);
        HeapFree(g_hProcessHeap, 0, pBuffer);
        return STATUS_UNSUCCESSFUL;
    }

    PPUBLIC_OBJECT_BASIC_INFORMATION pObjectBasicInformation = (PPUBLIC_OBJECT_BASIC_INFORMATION)pBuffer;
    pObjectBasicInformation->HandleCount -= 1;
    pObjectBasicInformation->PointerCount -= 2;

    *pAccessMask = pObjectBasicInformation->GrantedAccess;
    *pdwReferenceCount = pObjectBasicInformation->HandleCount + pObjectBasicInformation->PointerCount;

    HeapFree(g_hProcessHeap, 0, pBuffer);
    return STATUS_SUCCESS;
}
