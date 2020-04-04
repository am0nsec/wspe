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
typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION {
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG Reserved[10];
} PUBLIC_OBJECT_BASIC_INFORMATION, * PPUBLIC_OBJECT_BASIC_INFORMATION;

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

BOOL GetHandleBasicInformation(HANDLE& hObject, ACCESS_MASK& dwAccessMask, ULONG& ulReferences) {
	HRESULT hr = S_OK;
	ULONG size = 1024;
	std::vector<BYTE> buffer;
	buffer.resize(sizeof(PUBLIC_OBJECT_BASIC_INFORMATION));
	ulReferences = 0;
	dwAccessMask = 0;

	// Get name of the object
	hr = NtQueryObject(hObject, ObjectBasicInformation, buffer.data(), buffer.size(), NULL);
	if (NT_SUCCESS(hr)) {
		PPUBLIC_OBJECT_BASIC_INFORMATION ObjectBasicInformation = (PPUBLIC_OBJECT_BASIC_INFORMATION)buffer.data();
		ObjectBasicInformation->HandleCount -= 1;
		ObjectBasicInformation->PointerCount -= 2;

		ulReferences = ObjectBasicInformation->HandleCount + ObjectBasicInformation->PointerCount;
		dwAccessMask = ObjectBasicInformation->GrantedAccess;
		return TRUE;
	}

	buffer.erase(buffer.begin(), buffer.end());
	return FALSE;
}

INT wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {
	::wprintf(L"\n[>] Process Hanles Enumeration\n");
	::wprintf(L"   -------------------------------\n\n");

	HRESULT hr = S_OK;
	BOOL success = TRUE;
	
	//DWORD dwProcessId = _wtoi(argv[1]);
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
	::wprintf(L"%+-13s", L"Handle");
	::wprintf(L"%+-13s", L"Acces Mask");
	::wprintf(L"%+-13s", L"References");
	::wprintf(L"%+-15s", L"Type");
	::wprintf(L"%s\n\n", L"Name");
	s
	// Loop through the handles
	for (ULONG i = 0; i < pHandleSnapshotInformation->NumberOfHandles; i++) {
		HANDLE hObject = pHandleSnapshotInformation->Handles[i].HandleValue;
		HANDLE hDuplicate;

		success = ::DuplicateHandle(hProcess, hObject, ::GetCurrentProcess(), &hDuplicate, 0, FALSE, DUPLICATE_SAME_ACCESS);
		if (!success) {
			::CloseHandle(hDuplicate);
			continue;
		}

		ACCESS_MASK dwAccessMask = 0;
		ULONG ulReferences = 0;
		std::wstring name = GetHandleName(hDuplicate);
		std::wstring type = GetHandleType(hDuplicate);
		GetHandleBasicInformation(hDuplicate, dwAccessMask, ulReferences);
		if (!name.empty() && !type.empty()) {
			::wprintf(L"0x%08X%3s", hObject, L" ");
			::wprintf(L"0x%08X%3s", dwAccessMask, L" ");
			::wprintf(L"%-13d", ulReferences);
			::wprintf(L"%+-15s", type.c_str());
			::wprintf(L"%s\n", name.c_str());
		}

		if (hDuplicate)
			::CloseHandle(hDuplicate);
	}

	// Cleanup
	buffer.erase(buffer.begin(), buffer.end());
	::CloseHandle(hProcess);
	return 0;
}
