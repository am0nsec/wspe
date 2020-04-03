#pragma once
#include <windows.h>
#include <stdio.h>

#define HADNLE_FLAG_INHERIT             0x00000001
#define HANDLE_FLAG_PROTECT_FROM_CLOSE  0x00000002
#define HANDLE_FLAG_AUDIT_ON_CLOSE      0x00000003

INT wmain() {
	SECURITY_ATTRIBUTES sa;
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);

	BOOL success = ::CreateProcess(L"C:\\Windows\\System32\\notepad.exe", NULL, &sa, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
	if (success) {
		DWORD dwHandleAccessMask;
		::GetHandleInformation(pi.hProcess, &dwHandleAccessMask);

		::wprintf(L"[>] Process ID:           %d\n", pi.dwProcessId);
		::wprintf(L"[>] Process HANDLE:       0x%08X\n", pi.hProcess);
		::wprintf(L"[>] Handle Access Mask:   %d\n", dwHandleAccessMask);

		// Protect handle from being closed
		success = ::SetHandleInformation(pi.hProcess, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
		success = ::CloseHandle(pi.hProcess);
		if (!success) {
			::wprintf(L"[-] Error: %d\n", ::GetLastError());
		}

		// This should work fine
		success = ::SetHandleInformation(pi.hProcess, HANDLE_FLAG_PROTECT_FROM_CLOSE, 0);
		success = ::TerminateProcess(pi.hProcess, 1);
		success = ::CloseHandle(pi.hProcess);
		if (!success) {
			::wprintf(L"[-] Error: %d\n", ::GetLastError());
		}
		::wprintf(L"\n[+] Process terminated and handle closed\n");
	} else {
		::wprintf(L"Error Error: %d\n", ::GetLastError());
		return 1;
	}
	
	return 0;
}
