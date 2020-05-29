/*+===================================================================
  File:      amsi_scanner.c
  Summary:   Scan string, file or URL via AMSI.
  Classes:   N/A
  Functions: N/A
  Origin:    https://github.com/am0nsec
##
  Author: Paul Laine (@am0nsec)
===================================================================+*/
#pragma once
#include <Windows.h>
#include <amsi.h>
#include <stdio.h>

#pragma comment(lib, "amsi.lib")

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
BOOL GetStringLenght(_In_  LPWSTR szString,	_Out_ PULONG plStringSize);
BOOL ScanString(_In_ LPWSTR* pszString, _Out_ AMSI_RESULT* pAmsiResult);
BOOL ScanFile(_In_ LPWSTR* pszFileName,	_Out_ AMSI_RESULT* pAmsiResult);
BOOL ScanUrl(_In_ LPWSTR* pszUrl, _Out_ AMSI_RESULT* pAmsiResult);
VOID Cleanup();

/*--------------------------------------------------------------------
  Global variables.
--------------------------------------------------------------------*/
HAMSICONTEXT g_hAmsiContext      = NULL;
HAMSISESSION g_hAmsiSession      = NULL;
LPCWSTR      g_szApplicationName = L"AMSI Scanner v1.0";
HANDLE       g_hProcessHeap      = INVALID_HANDLE_VALUE;

INT wmain(INT argc, PWCHAR argv[]) {
	wprintf(L"[>] Copyright (C) 2020 Paul Laine (@am0nsec)\n");
	wprintf(L"[>] AMSI Scanner v1.0\n");
	wprintf(L"[>] https://github.com/am0nsec/wspe\n");
	wprintf(L"   -----------------------------------------\n\n");

	// Check arguments supplied by the user
	if (argc < 3 || (argc >= 2 && wcscmp(argv[1], L"-h") == 0)) {
		wprintf(L"[-] Usage: scanner [ -f | -s | -u ] [data]\n");
		wprintf(L"\t-f\tScan content of a file.\n");
		wprintf(L"\t-s\tScan a string.\n");
		wprintf(L"\t-u\tScan an URL.\n\n");

		wprintf(L"Leverage the Antimalware Scan Interface (AMSI) Win32 API to scan user supplied content.\n");
		wprintf(L"Microsoft documentation: https://docs.microsoft.com/en-us/windows/win32/api/_amsi/\n\n");
		return 0x01;
	}

	// Initialise variables
	HRESULT hr = S_OK;
	g_hProcessHeap = GetProcessHeap();

	// Initialise AMSI
	hr = AmsiInitialize(g_szApplicationName, &g_hAmsiContext);
	if (FAILED(hr)) {
		wprintf(L"[-] Error while invoking amsi!AmsiInitialize (0x%08x)\n", hr);
		wprintf(L"[-] Check that Windows Defender is enabled or that the currently running AV support AMSI.\n");
		return 0x01;
	}

	// Open new session
	hr = AmsiOpenSession(g_hAmsiContext, &g_hAmsiSession);
	if (FAILED(hr)) {
		wprintf(L"[-] Error while invoking amsi!AmsiOpenSession (0x%08x)\n", hr);
		Cleanup();
		return 0x01;
	}

	// Scan data
	AMSI_RESULT AmsiResult;
	BOOL bScanSuccess = FALSE;
	if (wcscmp(argv[1], L"-s") == 0)
		bScanSuccess = ScanString(&argv[2], &AmsiResult);
	else if (wcscmp(argv[1], L"-u") == 0)
		bScanSuccess = ScanString(&argv[2], &AmsiResult);
	else if (wcscmp(argv[1], L"-f") == 0)
		bScanSuccess = ScanFile(&argv[2], &AmsiResult);

	// Display result of the scan
	if (bScanSuccess) {
		switch (AmsiResult) {
		case AMSI_RESULT_CLEAN:
			wprintf(L"[>] Scan score: %d (AMSI_RESULT_CLEAN)\n", AmsiResult);
			wprintf(L"Known good. No detection found, and the result is likely not going to change after a future definition update.\n\n");
			break;
		case AMSI_RESULT_NOT_DETECTED:
			wprintf(L"[>] Scan score: %d (AMSI_RESULT_NOT_DETECTED)\n", AmsiResult);
			wprintf(L"No detection found, but the result might change after a future definition update.\n\n");
			break;
		case AMSI_RESULT_BLOCKED_BY_ADMIN_START:
			wprintf(L"[>] Scan score: %d (AMSI_RESULT_BLOCKED_BY_ADMIN_START)\n", AmsiResult);
			wprintf(L"Administrator policy blocked this content on this machine (beginning of range).\n\n");
			break;
		case AMSI_RESULT_BLOCKED_BY_ADMIN_END:
			wprintf(L"[>] Scan score: %d (AMSI_RESULT_BLOCKED_BY_ADMIN_END)\n", AmsiResult);
			wprintf(L"Administrator policy blocked this content on this machine (end of range).\n\n");
			break;
		case AMSI_RESULT_DETECTED:
			wprintf(L"[>] Scan score: %d (AMSI_RESULT_DETECTED)\n", AmsiResult);
			wprintf(L"Detection found. The content is considered malware and should be blocked.\n\n");
			break;
		}
	}

	// Cleanup
	Cleanup();
	return 0x00;
}

BOOL GetStringLenght(LPWSTR szString, PULONG plStringSize) {
	if (!szString) {
		plStringSize = 0;
		return FALSE;
	}

	while (*szString++ != '\0')
		*plStringSize += sizeof(WCHAR);

	return TRUE;
}

BOOL ScanString(LPWSTR* pszString, AMSI_RESULT* pAmsiResult) {
	if (!*pszString) {
		wprintf(L"[-] Empty string provided.\n");
		return FALSE;
	}

	ULONG lStringSize = 0;
	if (!GetStringLenght(*pszString, &lStringSize) || lStringSize == 0) {
		wprintf(L"[-] Empty string provided.\n");
		return FALSE;
	}

	PVOID pBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lStringSize);
	RtlCopyMemory(pBuffer, *pszString, lStringSize);

	HRESULT hr = AmsiScanBuffer(g_hAmsiContext, pBuffer, lStringSize, L"scan-string", g_hAmsiSession, pAmsiResult);
	if (FAILED(hr)) {
		wprintf(L"[-] Error while invoking amsi!AmsiScanBuffer (0x%08x)\n", hr);
		Cleanup();
		return 0x01;
	}

	HeapFree(GetProcessHeap(), 0, pBuffer);
	return TRUE;
}

BOOL ScanFile(LPWSTR* pszFileName, AMSI_RESULT* pAmsiResult) {
	// Check if file name is not empty
	if (!*pszFileName) {
		wprintf(L"[-] Empty file name provided.\n");
		return FALSE;
	}

	// Check if file exist
	DWORD dwFileAttributes = GetFileAttributes(*pszFileName);
	if (dwFileAttributes == INVALID_FILE_ATTRIBUTES) {
		wprintf(L"[-] File doesn't exist.\n");
		return FALSE;
	}

	// Get an handle to the file object
	HANDLE hFile = CreateFile(*pszFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, dwFileAttributes, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		wprintf(L"[-] Unable to open the file (%d)\n", GetLastError());
		return FALSE;
	}

	// Get size of the file
	DWORD dwFileSize = GetFileSize(hFile, NULL);
	if (dwFileSize == 0) {
		wprintf(L"[-] Unable to get size of the file (%d)\n", GetLastError());
		CloseHandle(hFile);
		return FALSE;
	}

	// Read content of the file
	DWORD dwBytesRead = 0;
	PVOID pAsciiBuffer = HeapAlloc(g_hProcessHeap, HEAP_ZERO_MEMORY, dwFileSize);
	BOOL bSuccess = ReadFile(hFile, pAsciiBuffer, dwFileSize, &dwBytesRead, NULL);
	if (!bSuccess || dwBytesRead < dwFileSize) {
		wprintf(L"[-] Unable to get size of the file (%d)\n", GetLastError());
		CloseHandle(hFile);
		HeapFree(g_hProcessHeap, 0, pAsciiBuffer);
		return FALSE;
	}

	// Convert from ASCII to Unicode
	int UnicodeBufferSize = MultiByteToWideChar(CP_ACP, 0, pAsciiBuffer, -1, NULL, 0);
	PVOID pUnicodeBuffer = HeapAlloc(g_hProcessHeap, HEAP_ZERO_MEMORY, UnicodeBufferSize * sizeof(WCHAR));
	MultiByteToWideChar(CP_ACP, 0, pAsciiBuffer, -1, pUnicodeBuffer, UnicodeBufferSize);
	HeapFree(g_hProcessHeap, 0, pAsciiBuffer);

	// Scan file content
	ULONG lUnicodeBufferLength = 0;
	GetStringLenght(pUnicodeBuffer, &lUnicodeBufferLength);

	HRESULT hr = AmsiScanBuffer(g_hAmsiContext, pUnicodeBuffer, lUnicodeBufferLength, *pszFileName, g_hAmsiSession, pAmsiResult);
	if (FAILED(hr)) {
		wprintf(L"[-] Error while invoking amsi!AmsiScanBuffer (0x%08x)\n", hr);
		Cleanup();
		return FALSE;
	}

	HeapFree(g_hProcessHeap, 0, pUnicodeBuffer);
	CloseHandle(hFile);
	return TRUE;
}

VOID Cleanup() {
	if (!g_hAmsiContext && !g_hAmsiSession)
		AmsiCloseSession(g_hAmsiContext, g_hAmsiSession);

	if (!g_hAmsiSession)
		AmsiUninitialize(g_hAmsiSession);
}
