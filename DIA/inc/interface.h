/*+================================================================================================
Module Name: interface.h
Author     : Paul L. (@am0nsec)
Origin     : https://github.com/am0nsec/wspe/
Copyright  : This project has been released under the GNU Public License v3 license.

Abstract:
Abstraction of the Microsoft Debug Interface Access (DIA) SDK.

Documentation available at: https://docs.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/debug-interface-access-sdk
Most of the code is based on the Dia2Dump code sample shipped with the MS DIA SDK.
================================================================================================+*/

#ifndef __DIA_INTERFACE_H_GUARD__
#define __DIA_INTERFACE_H_GUARD__

#include <Windows.h>

#include "msdia/include/dia2.h"
#include "msdia/include/cvconst.h"

#include "callback.h"
#include "dirutil.h"

// Type definition of the "DllGetClassObject" routine from the msdiaXXX.dll module.
typedef HRESULT(STDMETHODCALLTYPE* TDllGetClassObject)(
	_In_  REFCLSID rclsid,
	_In_  REFIID   riid,
	_Out_ LPVOID* ppv
);

/// <summary>
/// Simple structure to store all the information
/// </summary>
typedef struct _PUBLIC_SYMBOL {
	DWORD dwTag;
	DWORD dwRVA;
	DWORD dwOff;
	DWORD dwSeg;
	BSTR  Name;
} PUBLIC_SYMBOL, *PPUBLIC_SYMBOL;


/// <summary>
/// Initialise the COM runtime and IDiaDataSource interface.
/// </summary>
HRESULT STDMETHODCALLTYPE
_Must_inspect_result_
_Success_(return == S_OK)
DiaInitialise(
	_In_ PWCHAR DllName
);


/// <summary>
/// Uninitialise the COM runtime and general cleanup.
/// </summary>
VOID STDMETHODCALLTYPE DiaUninitialise();


/// <summary>
/// Load the data from the PDB file provided.
/// </summary>

HRESULT STDMETHODCALLTYPE
_Must_inspect_result_
_Success_(return == S_OK)
DiaLoadDataFromPdb(
	_In_ PWCHAR FilePath
);


/// <summary>
/// Parse the PDB file to find all symbols requested.
/// </summary>
HRESULT STDMETHODCALLTYPE
_Must_inspect_result_
_Success_(return == S_OK)
DiaFindPublicSymbols(
	_In_ PUBLIC_SYMBOL PublicSymbols[],
	_In_ DWORD         Elements
);

#endif // !__DIA_INTERFACE_H_GUARD__
