/*+================================================================================================
Module Name: interface.c
Author     : Paul L. (@am0nsec)
Origin     : https://github.com/am0nsec/wspe/
Copyright  : This project has been released under the GNU Public License v3 license.

Abstract:
Abstraction of the Microsoft Debug Interface Access (DIA) SDK.

Documentation available at: https://docs.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/debug-interface-access-sdk
Most of the code is based on the Dia2Dump code sample shipped with the MS DIA SDK.
================================================================================================+*/

#include <Windows.h>
#include <stdio.h>

#include "interface.h"

// e6756135-1e65-4d17-8576-610761398c3c
CONST CLSID CLSID_DiaSource = {
	0xe6756135, 0x1e65, 0x4d17, { 0x85, 0x76, 0x61, 0x07, 0x61, 0x39, 0x8c, 0x3c }
};

// 79F1BB5F-B66E-48e5-B6A9-1545C323CA3D
CONST IID IID_IDiaDataSource = {
	0x79F1BB5F, 0xB66E, 0x48e5, { 0xB6, 0xA9, 0x15, 0x45, 0xC3, 0x23, 0xCA, 0x3D }
};

// Global Data Source COM interface
IDiaDataSource* g_DataSource = NULL;

// Global Session COM interface
IDiaSession* g_Session = NULL;

// Global Symbol COM interface
IDiaSymbol* g_GlobalSymbol = NULL;

// Global Callback COM interface
IDiaLoadCallback2* g_Callback = NULL;


_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE DiaInitialise(
	_In_ PWCHAR DllName
) {
	// Check if already initialised
	HRESULT Result = S_OK;
	if (g_DataSource != NULL)
		return Result;

	// Initialise COM runtime
	if (!SUCCEEDED(CoInitialize(NULL)))
		return E_FAIL;

	// Load the module
	HMODULE hModule = LoadLibraryExW(GetMsdiaModulePath(), NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
	if (hModule == NULL)
		return E_FAIL;
	ResetDirectory();

	// Get exported routine
	TDllGetClassObject DllGetClassObject = (TDllGetClassObject)GetProcAddress(hModule, "DllGetClassObject");
	if (DllGetClassObject == NULL)
		return GetLastError();

	// Create Instance of the IDiaDataSource COM interface
	IClassFactory* ClassFactory = NULL;
	if (SUCCEEDED(DllGetClassObject(&CLSID_DiaSource, &IID_IClassFactory, (LPVOID*)&ClassFactory))) {
		Result = ClassFactory->lpVtbl->CreateInstance(ClassFactory, NULL, &IID_IDiaDataSource, &g_DataSource);
		if (SUCCEEDED(Result))
			ClassFactory->lpVtbl->AddRef(ClassFactory);
		return Result;
	}
	else {
		HRESULT Result = GetLastError();
		if (Result > 0x00)
			Result |= REASON_LEGACY_API;
		return Result;
	}
}


_Use_decl_annotations_
VOID STDMETHODCALLTYPE DiaUninitialise() {
	if (g_GlobalSymbol != NULL) {
		g_GlobalSymbol->lpVtbl->Release(g_GlobalSymbol);
		g_GlobalSymbol = NULL;
	}

	if (g_Session != NULL) {
		g_Session->lpVtbl->Release(g_Session);
		g_Session = NULL;
	}

	if (g_DataSource != NULL) {
		g_DataSource->lpVtbl->Release(g_DataSource);
		g_DataSource = NULL;
	}

	if (g_Callback != NULL) {
		g_Callback->lpVtbl->Release(g_Callback);
		g_Callback = NULL;
	}

	CoUninitialize();
}


_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE DiaLoadDataFromPdb(
	_In_ PWCHAR FilePath
) {
	// Check if already initialised
	if (g_DataSource == NULL)
		return E_FAIL;
	HRESULT Result = S_OK;

	// Extract the file extension from the path
	PWCHAR FileExtension = calloc(1, MAX_PATH * sizeof(WCHAR));
	if (FileExtension == NULL)
		return E_OUTOFMEMORY;
	_wsplitpath_s(FilePath, NULL, 0, NULL, 0, NULL, 0, FileExtension, MAX_PATH);

	// File is a ".PDB"
	if (!_wcsicmp(FileExtension, L".pdb")) {
		free(FileExtension);

		Result = g_DataSource->lpVtbl->loadDataFromPdb(g_DataSource, FilePath);
		if (FAILED(Result)) {
			wprintf(L"[-] Failed to load data from the PDB file (%08X).\r\n", Result);
			return Result;
		}
	}
	// File is a ".EXE"
	else if(!_wcsicmp(FileExtension, L".exe")) {
		free(FileExtension);

		// Create the callback COM implementation
		if (FAILED(DiaCallbackHelper(TRUE, (PVOID)&g_Callback))) {
			wprintf(L"[-] Failed to create the DIA Callback.\r\n");
			return E_FAIL;
		}
		g_Callback->lpVtbl->AddRef(g_Callback);

		// Forge the Symbol search path
		ChangeDirectory(L"pdb", 4);

		// Load the PDB from Microsoft symbol server
		Result = g_DataSource->lpVtbl->loadDataForExe(
			g_DataSource,
			FilePath,
			GetSymSrvSearchPath(),
			(PVOID)g_Callback
		);
		if (FAILED(Result)) {
			wprintf(L"[-] Failed to load PDB file (%08X).\r\n", Result);
			ResetDirectory();

			g_Callback->lpVtbl->Release(g_Callback);
			return Result;
		}

		ResetDirectory();
	}
	
	// Open session to access symbols
	Result = g_DataSource->lpVtbl->openSession(g_DataSource, &g_Session);
	if (FAILED(Result)) {
		wprintf(L"[-] Failed to open session (%08X).\r\n", Result);
		return Result;
	}

	// Get the global scope
	Result = g_Session->lpVtbl->get_globalScope(g_Session, &g_GlobalSymbol);
	if (FAILED(Result)) {
		wprintf(L"[-] Failed to get global scope (%08X).\r\n", Result);
		return Result;
	}

	return Result;
}


_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE DiaFindPublicSymbols(
	_In_ PUBLIC_SYMBOL PublicSymbols[],
	_In_ DWORD         Elements
) {
	// Check if everything has been properly initialised.
	if (g_DataSource == NULL || g_Session == NULL || g_GlobalSymbol == NULL)
		return E_FAIL;

	// Enumerates the various symbols contained in the data source.
	IDiaEnumSymbols* EnumSymbols = NULL;
	HRESULT Result = g_GlobalSymbol->lpVtbl->findChildren(
		g_GlobalSymbol,
		SymTagPublicSymbol,
		NULL,
		nsNone,
		&EnumSymbols
	);
	if (FAILED(Result)) {
		wprintf(L"[-] Failed to load symbol enumerator (%08X).\r\n", Result);
		return Result;
	}

	// Parse all symbols
	IDiaSymbol* Symbol = NULL;
	ULONG       celt   = 0x00;
	while (SUCCEEDED(EnumSymbols->lpVtbl->Next(EnumSymbols, 0x01, &Symbol, &celt)) && (celt == 1)) {

		DWORD dwTag = 0x00;
		DWORD dwRVA = 0x00;
		DWORD dwOff = 0x00;
		DWORD dwSeg = 0x00;
		BSTR  Name  = NULL;

		// Make sure we have a tag for the symbol
		if (FAILED(Symbol->lpVtbl->get_symTag(Symbol, &dwTag)))
			goto next_symbol;

		// Get the name of the global variable
		if (SUCCEEDED(Symbol->lpVtbl->get_name(Symbol, &Name))) {

			// Find the symbol
			BOOLEAN Found = FALSE;
			DWORD Index = 0x00;
			for (DWORD cx = 0x00; cx < Elements; cx++) {
				if (wcscmp(PublicSymbols[cx].Name, Name) == 0x00) {
					Index = cx;
					Found = TRUE;
					break;
				}
			}
			if (!Found)
				goto next_symbol;

			// Get the Relative Virtual Address (RVA), the offset and section
			if (FAILED(Symbol->lpVtbl->get_relativeVirtualAddress(Symbol, &dwRVA)))
				dwRVA = 0xFFFFFFFF;
			Symbol->lpVtbl->get_addressSection(Symbol, &dwSeg);
			Symbol->lpVtbl->get_addressOffset(Symbol, &dwOff);
			
			PublicSymbols[Index].dwTag = dwTag;
			PublicSymbols[Index].dwRVA = dwRVA;
			PublicSymbols[Index].dwOff = dwOff;
			PublicSymbols[Index].dwSeg = dwSeg;

			// Release current interface
next_symbol:
			Symbol->lpVtbl->Release(Symbol);
		}
	}
	EnumSymbols->lpVtbl->Release(EnumSymbols);
	return S_OK;
}