/**
* @file         main.c
* @data         06-09-2020
* @author       Paul Laîné (@am0nsec)
* @version      1.0
* @brief        List Assemblies from the Global Assembly Cache (GAC).
* @details
* @link         https://github.com/am0nsec/wspe
* @copyright    This project has been released under the GNU Public License v3 license.
*/
#include <Windows.h>
#include <fusion.h>
#include <stdio.h>

#include "gacutil.h"

/**
 * @brief Global HANDLE for Heap allocation/deallocation.
*/
static HANDLE g_hProcessHeap = INVALID_HANDLE_VALUE;

/**
 * @brief Entry point.
 * @param argc Number of arguments.
 * @param argv List of arguments.
 * @return Application exit code.
*/
INT wmain(INT argc, PWCHAR* argv[]) {
	wprintf(L"\nList .NET Framework Assemblies from the Global Assembly Cache (GAC).\n");
	wprintf(L"Copyright (C) 2020 Paul Laine (@am0nsec)\n");
	wprintf(L"https://ntamonsec.blogpost.com\n\n");

	HMODULE hFusionModule = LoadLibraryW(FUSION_MODULE_PATH);
	if (hFusionModule == NULL) {
		wprintf(L"[-] Unable to load fusion.dll.\n\n");
		return 0x01;
	}
	wprintf(L"[+] Module loaded: fusion.dll.\n");
	
	// Get CreateAssemblyEnum function
	CreateAssemblyEnumFunc pCreateAssemblyEnumFunc = (CreateAssemblyEnumFunc)GetProcAddress(hFusionModule, "CreateAssemblyEnum");
	if (pCreateAssemblyEnumFunc == NULL) {
		wprintf(L"[-] Unable to find CreateAssemblyEnum function address.\n\n");
		return 0x01;
	}
	wprintf(L"[+] Function found: CreateAssemblyEnum.\n");

	// Get CreateAssemblyCache function
	CreateAssemblyCacheFunc pCreateAssemblyCacheFunc = (CreateAssemblyCacheFunc)GetProcAddress(hFusionModule, "CreateAssemblyCache");
	if (pCreateAssemblyEnumFunc == NULL) {
		wprintf(L"[-] Unable to find CreateAssemblyCache function address.\n\n");
		return 0x01;
	}
	wprintf(L"[+] Function found: CreateAssemblyCache.\n");

	// Get assembly enum interface
	IAssemblyEnum* pIAssemblyEnum = NULL;
	pCreateAssemblyEnumFunc(&pIAssemblyEnum, 0, NULL, ASM_CACHE_GAC, NULL);
	if (pIAssemblyEnum == NULL) {
		wprintf(L"[-] Unable to create fusion!IAssemblyEnum interface.\n\n");
		return 0x01;
	}
	wprintf(L"[+] Interface successfully created: fusion!IAssemblyEnum.\n");

	// Get assembly cache
	IAssemblyCache* pIAssemblyCache = NULL;
	pCreateAssemblyCacheFunc(&pIAssemblyCache, 0);
	if (pIAssemblyCache == NULL) {
		wprintf(L"[-] Unable to create fusion!IAssemblyCache interface.\n\n");
		return 0x01;
	}
	wprintf(L"[+] Interface successfully created: fusion!IAssemblyCache.\n\n");

	// Parse all Assemblies
	ParseAllAssemblies(&pIAssemblyEnum, &pIAssemblyCache);
	pIAssemblyCache->lpVtbl->Release(pIAssemblyCache);
	pIAssemblyEnum->lpVtbl->Release(pIAssemblyEnum);
	return 0x00;
}

/**
 * @brief Parse all Assemblies from the Global Assembly Cache (GAC)
 * @param ppIAssemblyEnum Pointer to an IAssemblyEnum interface.
 * @param ppIAssemblyCache Pointer to an IAssemblyCache interface.
 * @return Whether the function successfully executed.
*/
HRESULT ParseAllAssemblies(PPIAssemblyEnum ppIAssemblyEnum, PPIAssemblyCache ppIAssemblyCache) {
	IAssemblyEnum* pEnum = *ppIAssemblyEnum;
	IAssemblyCache* pCache = *ppIAssemblyCache;
	if (pEnum == NULL || pCache == NULL)
		return E_FAIL;

	HRESULT hr = S_OK;
	g_hProcessHeap = GetProcessHeap();

	while (TRUE) {
		IAssemblyName* pIAssemblyName = NULL;
		hr = pEnum->lpVtbl->GetNextAssembly(pEnum, NULL, &pIAssemblyName, 0);
		if (!SUCCEEDED(hr) || pIAssemblyName == NULL)
			break;

		// Get name
		LPWSTR wszAssemblyName = NULL;
		hr = GetAssemblyName(&pIAssemblyName, &wszAssemblyName);

		// Get assembly path in GAC
		LPWSTR wszAssemblyGacPath = NULL;
		hr = GetAssemblyGACPath(&pCache, &wszAssemblyName, &wszAssemblyGacPath);

		// Get assembly version
		ASSEMBLY_VERSION AssemblyVersion = { 0 };
		hr = GetAssemblyVersion(&pIAssemblyName, &AssemblyVersion);

		// Display information
		wprintf(L"Name:    %ws\n", wszAssemblyName);
		wprintf(L"Path:    %ws\n", wszAssemblyGacPath);
		wprintf(L"Version: %d.%d.%d.%d\n\n", AssemblyVersion.dwMajor, AssemblyVersion.dwMinor, AssemblyVersion.dwBuild, AssemblyVersion.dwRevision);

		// Release memory
		if (wszAssemblyName != NULL)
			HeapFree(g_hProcessHeap, 0, wszAssemblyName);
		if (wszAssemblyGacPath != NULL)
			HeapFree(g_hProcessHeap, 0, wszAssemblyGacPath);

		// Release interface
		pIAssemblyName->lpVtbl->Finalize(pIAssemblyName);
		pIAssemblyName->lpVtbl->Release(pIAssemblyName);
		pIAssemblyName = NULL;
	}

	pEnum = NULL;
	pCache = NULL;
	return S_OK;
}

/**
 * @brief Get the name of an Assembly.
 * @param ppIAssemblyName Pointer to an IAssemblyName interface.
 * @param pwszAssemblyName Pointer to the name of the Assembly.
 * @return Whether the function successfully executed.
*/
HRESULT GetAssemblyName(PPIAssemblyName ppIAssemblyName, LPWSTR* pwszAssemblyName) {
	PIAssemblyName pInterface = *ppIAssemblyName;
	if (pInterface == NULL || *pwszAssemblyName != NULL)
		return E_FAIL;

	// Get buffer size
	DWORD dwBufferSize = 0;
	HRESULT hr = pInterface->lpVtbl->GetName(pInterface, &dwBufferSize, 0);
	if (dwBufferSize == 0) {
		pInterface = NULL;
		return E_FAIL;
	}

	// Get name
	*pwszAssemblyName = (LPWSTR)HeapAlloc(g_hProcessHeap, HEAP_ZERO_MEMORY, dwBufferSize * sizeof(WCHAR));
	hr = pInterface->lpVtbl->GetName(pInterface, &dwBufferSize, *pwszAssemblyName);
	if (!SUCCEEDED(hr) || *pwszAssemblyName == NULL) {
		HeapFree(g_hProcessHeap, 0, *pwszAssemblyName);
		pInterface = NULL;
		return E_FAIL;
	}

	pInterface = NULL;
	return S_OK;
}

/**
 * @brief Get the path of the Assembly in the Global Assembly Cache (GAC).
 * @param ppIAssemblyCache Pointer to an IAssemblyCache interface.
 * @param pwszAssemblyName Pointer to the name of the assembly to query information.
 * @param pwszAssemblyGacPath Pointer to the path of the assembly in the GAC.
 * @return Whether the function successfully executed.
*/
HRESULT GetAssemblyGACPath(PPIAssemblyCache ppIAssemblyCache, LPWSTR* pwszAssemblyName, LPWSTR* pwszAssemblyGacPath) {
	PIAssemblyCache pInterface = *ppIAssemblyCache;
	if (pInterface == NULL || *pwszAssemblyName == NULL)
		return E_FAIL;

	// Get buffer size
	ASSEMBLY_INFO AssemblyInfo = { 0 };
	HRESULT hr = pInterface->lpVtbl->QueryAssemblyInfo(pInterface, QUERYASMINFO_FLAG_GETSIZE, *pwszAssemblyName, &AssemblyInfo);
	if (AssemblyInfo.cchBuf == 0) {
		pInterface = NULL;
		return E_FAIL;
	}

	// Get path
	AssemblyInfo.pszCurrentAssemblyPathBuf = (LPWSTR)HeapAlloc(g_hProcessHeap, HEAP_ZERO_MEMORY, AssemblyInfo.cchBuf * sizeof(WCHAR));
	hr = pInterface->lpVtbl->QueryAssemblyInfo(pInterface, QUERYASMINFO_FLAG_VALIDATE, *pwszAssemblyName, &AssemblyInfo);
	if (!SUCCEEDED(hr) || AssemblyInfo.pszCurrentAssemblyPathBuf == NULL) {
		HeapFree(g_hProcessHeap, 0, AssemblyInfo.pszCurrentAssemblyPathBuf);
		pInterface = NULL;
		return E_FAIL;
	}


	// Copy data
	*pwszAssemblyGacPath = (LPWSTR)HeapAlloc(g_hProcessHeap, HEAP_ZERO_MEMORY, AssemblyInfo.cchBuf * sizeof(WCHAR));
	RtlCopyMemory(*pwszAssemblyGacPath, AssemblyInfo.pszCurrentAssemblyPathBuf, AssemblyInfo.cchBuf * sizeof(WCHAR));
	HeapFree(g_hProcessHeap, 0, AssemblyInfo.pszCurrentAssemblyPathBuf);

	pInterface = NULL;
	return S_OK;
}

/**
 * @brief Get the version of an Assembly
 * @param ppIAssemblyName Pointer to an IAssemblyName interface.
 * @param pAssemblyVersion Pointer to an ASSEMBLY_VERSION structure.
 * @return Whether the function executed successfully
*/
HRESULT GetAssemblyVersion(PPIAssemblyName ppIAssemblyName, PASSEMBLY_VERSION pAssemblyVersion) {
	IAssemblyName* pInterface = *ppIAssemblyName;
	if (pInterface == NULL || pAssemblyVersion == NULL)
		return E_FAIL;

	// Get version
	DWORD dwHigh = 0;
	DWORD dwLow = 0;
	HRESULT hr = pInterface->lpVtbl->GetVersion(pInterface, &dwHigh, &dwLow);
	if (!SUCCEEDED(hr))
		return E_FAIL;

	pAssemblyVersion->dwMajor = dwHigh >> 0x10;
	pAssemblyVersion->dwMinor = dwHigh & 0xff;
	pAssemblyVersion->dwBuild = dwLow >> 0x10;
	pAssemblyVersion->dwRevision = dwLow & 0xff;

	pInterface = NULL;
	return S_OK;
}
