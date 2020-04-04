#pragma once
#include <windows.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "ntdll")
#define NT_SUCCESS(status) (status >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

// https://github.com/processhacker/processhacker/blob/0e9cf471e06a59cdb3a7c89f0b92b253a6a93999/phnt/include/ntpsapi.h#L96
enum PROCESSINFOCLASS {
	ProcessHandleInformation = 51
};

typedef enum _OBJECT_INFORMATION_CLASS {
	ObjectBasicInformation = 0,
	ObjectNameInformation = 1,
	ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

// https://docs.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

// https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject
typedef struct _PUBLIC_OBJECT_TYPE_INFORMATION {
	UNICODE_STRING TypeName;
	ULONG          Reserved[22];
} PUBLIC_OBJECT_TYPE_INFORMATION, * PPUBLIC_OBJECT_TYPE_INFORMATION;

// https://github.com/processhacker/processhacker/blob/0e9cf471e06a59cdb3a7c89f0b92b253a6a93999/phnt/include/ntpsapi.h#L610
typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
	HANDLE    HandleValue;
	ULONG_PTR HandleCount;
	ULONG_PTR PointerCount;
	ULONG     GrantedAccess;
	ULONG     ObjectTypeIndex;
	ULONG     HandleAttributes;
	ULONG     Reserved;
} PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

// https://github.com/processhacker/processhacker/blob/0e9cf471e06a59cdb3a7c89f0b92b253a6a93999/phnt/include/ntpsapi.h#L622
typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
	ULONG_PTR                       NumberOfHandles;
	ULONG_PTR                       Reserved;
	PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
} PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PPROCESS_HANDLE_SNAPSHOT_INFORMATION;

// https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess
extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
	__in  HANDLE           ProcessHandle,
	__in  PROCESSINFOCLASS ProcessInformationClass,
	__out PVOID            ProcessInformation,
	__in  ULONG            ProcessInformationLength,
	__out PULONG           ReturnLength
);

// https://docs.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryobject
extern "C" NTSTATUS NTAPI NtQueryObject(
	__in_opt  HANDLE                   Handle,
	__in      OBJECT_INFORMATION_CLASS ObjectInformationClass,
	__out     PVOID                    ObjectInformation,
	__in      ULONG                    ObjectInformationLength,
	__out_opt PULONG                   ReturnLength
);

BOOL GetProcessHandleSnapshotInformation(std::vector<BYTE>& buffer, HANDLE& hProcess) {
	BOOL success = TRUE;
	HRESULT hr = S_OK;

	// Get size of the structure
	ULONG size = 0;
	hr = ::NtQueryInformationProcess(hProcess, ProcessHandleInformation, NULL, size, &size);
	hr = ::NtQueryInformationProcess(hProcess, ProcessHandleInformation, NULL, size, &size);

	// Get the structure
	buffer.resize(size);
	hr = ::NtQueryInformationProcess(hProcess, ProcessHandleInformation, buffer.data(), buffer.size(), NULL);
	if (!NT_SUCCESS(hr)) {
		::wprintf(L"[-] ntdll!NtQueryInformationProcess error: 0x%08X\n", ::GetLastError());
		return 1;
	}
	
	return success;
}

std::wstring GetHandleType(HANDLE& hObject) {
	HRESULT hr = S_OK;
	ULONG size = 0;
	std::vector<BYTE> buffer;

	// Get size of the object
	hr = NtQueryObject(hObject, ObjectTypeInformation, NULL, 0, &size);
	buffer.resize(size);

	// Get name of the object
	hr = NtQueryObject(hObject, ObjectTypeInformation, buffer.data(), buffer.size(), NULL);
	if (NT_SUCCESS(hr)) {
		PPUBLIC_OBJECT_TYPE_INFORMATION ObjectType = (PPUBLIC_OBJECT_TYPE_INFORMATION)buffer.data();
		UNICODE_STRING name = ObjectType->TypeName;
		if (name.Length > 0) {
			return std::wstring(name.Buffer);
		}
	}

	buffer.erase(buffer.begin(), buffer.end());
	return std::wstring();
}

std::wstring GetHandleName(HANDLE& hObject) {
	HRESULT hr = S_OK;
	ULONG size = 0;
	std::vector<BYTE> buffer;

	// Get size of the object
	hr = NtQueryObject(hObject, ObjectNameInformation, NULL, 0, &size);
	buffer.resize(size);

	// Get name of the object
	hr = NtQueryObject(hObject, ObjectNameInformation, buffer.data(), buffer.size(), NULL);
	if (NT_SUCCESS(hr)) {
		POBJECT_NAME_INFORMATION NameInformation = (POBJECT_NAME_INFORMATION)buffer.data();;
		UNICODE_STRING name = NameInformation->Name;
		if (name.Length > 0) {
			return std::wstring(name.Buffer);
		}
	}

	buffer.erase(buffer.begin(), buffer.end());
	return std::wstring();
}

INT wmain() {
	::wprintf(L"\n[>] Process Hanles Enumeration\n");
	::wprintf(L"   -------------------------------\n\n");

	HRESULT hr = S_OK;
	BOOL success = TRUE;
	
	DWORD dwProcessId = 9540;
	HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, dwProcessId);
	if (hProcess == INVALID_HANDLE_VALUE) {
		::wprintf(L"[-] kernel32!OpenProcess error: %d\n", ::GetLastError());
		return 1;
	}
	::wprintf(L"[>] Process ID: %d\n", ::GetProcessId(hProcess));

	// Get remote process handle information
	PPROCESS_HANDLE_SNAPSHOT_INFORMATION pHandleSnapshotInformation = NULL;
	std::vector<BYTE> buffer;
	success = GetProcessHandleSnapshotInformation(buffer, hProcess);
	if (!success) {
		::CloseHandle(hProcess);
		buffer.erase(buffer.begin(), buffer.end());

		::wprintf(L"[-] Unable to access process handle information\n");
		return 1;
	}
	pHandleSnapshotInformation = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)buffer.data();
	::wprintf(L"[>] Number of handles: %d\n\n", pHandleSnapshotInformation->NumberOfHandles);

	// Print table header
	::wprintf(L"%+-15s", L"Handle");
	::wprintf(L"%+-20s", L"Type");
	::wprintf(L"%s\n\n", L"Name");

	// Loop through the handles
	for (ULONG i = 0; i < pHandleSnapshotInformation->NumberOfHandles; i++) {
		HANDLE hObject = pHandleSnapshotInformation->Handles[i].HandleValue;
		HANDLE hDuplicate;

		success = ::DuplicateHandle(hProcess, hObject, ::GetCurrentProcess(), &hDuplicate, 0, FALSE, DUPLICATE_SAME_ACCESS);
		if (!success) {
			//::CloseHandle(hObject);
			continue;
		}

		std::wstring name = GetHandleName(hDuplicate);
		std::wstring type = GetHandleType(hDuplicate);
		if (!name.empty() && !type.empty()) {
			::wprintf(L"0x%08X%5s", hObject, L" ");
			::wprintf(L"%+-20s", type.c_str());
			::wprintf(L"%s\n", name.c_str());
		}


		//::CloseHandle(hDuplicate);
		//::CloseHandle(hObject);
	}

	// Cleanup
	buffer.erase(buffer.begin(), buffer.end());
	::CloseHandle(hProcess);
	return 0;
}
