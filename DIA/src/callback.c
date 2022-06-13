/*+================================================================================================
Module Name: callback.c
Author     : Paul L. (@am0nsec)
Origin     : https://github.com/am0nsec/wspe/
Copyright  : This project has been released under the GNU Public License v3 license.

Abstract:
Abstraction of the Microsoft Debug Interface Access (DIA) SDK.

In this case this module contains the code for the CCallback COM interface implementation when loading PDB from
a PE EXE file.

Documentation available at: https://docs.microsoft.com/en-us/visualstudio/debugger/debug-interface-access/debug-interface-access-sdk
Most of the code is based on the Dia2Dump code sample shipped with the MS DIA SDK.
================================================================================================+*/

#include <Windows.h>
#include <stdio.h>

#include "callback.h"

// 4688a074-5a4d-4486-aea8-7b90711d9f7c
CONST IID IID_IDiaLoadCallback2 = {
    0x4688a074, 0x5a4d, 0x4486, { 0xae, 0xa8, 0x7b, 0x90, 0x71, 0x1d, 0x9f, 0x7c }
};

// C32ADB82-73F4-421b-95D5-A4706EDF5DBE
CONST IID IID_IDiaLoadCallback = {
    0xC32ADB82, 0x73F4, 0x421b, { 0x95, 0xD5, 0xA4, 0x70, 0x6E, 0xDF, 0x5D, 0xBE }
};

// Global handle variable used to allocate/free executable heap memory.
HANDLE g_HeapHandle = INVALID_HANDLE_VALUE;


HRESULT STDMETHODCALLTYPE QueryInterface(
    IDiaLoadCallback2* This,
    REFIID             rid,
    PVOID*             ppUnk
) {
    if (ppUnk == NULL) {
        return E_INVALIDARG;
    }

    if (IsEqualIID(rid, &IID_IDiaLoadCallback2))
        *ppUnk = (IDiaLoadCallback2*)This;
    else if (IsEqualIID(rid, &IID_IDiaLoadCallback))
        *ppUnk = (IDiaLoadCallback*)This;
    else if (IsEqualIID(rid, &IID_IUnknown))
        *ppUnk = (IUnknown*)This;
    else
        *ppUnk = NULL;
    if (*ppUnk != NULL) {
        This->lpVtbl->AddRef(This);
        return S_OK;
    }
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE AddRef(
    IDiaLoadCallback2* This
) {
    DiaCallback* Callback = (DiaCallback*)This;
    return ++Callback->m_nRefCount;
}

ULONG STDMETHODCALLTYPE Release(
    IDiaLoadCallback2* This
) {
    DiaCallback* Callback = (DiaCallback*)This;

    if ((--Callback->m_nRefCount) == 0) {
        DiaCallbackHelper(FALSE, (PVOID)&This);
        return 0x00;
    }
    return Callback->m_nRefCount;
}

HRESULT STDMETHODCALLTYPE NotifyDebugDir(
    IDiaLoadCallback2* This,
    BOOL               fExecutable,
    DWORD              cbData,
    BYTE               data[]     // really a const struct _IMAGE_DEBUG_DIRECTORY *
) {
    return S_OK;
}

HRESULT STDMETHODCALLTYPE NotifyOpenDBG(
    IDiaLoadCallback2* This,
    LPCOLESTR          dbgPath,
    HRESULT            resultCode
) {
    return S_OK;
}

HRESULT STDMETHODCALLTYPE NotifyOpenPDB(
    IDiaLoadCallback2* This,
    LPCOLESTR          pdbPath,
    HRESULT            resultCode
) {
    if (SUCCEEDED(resultCode)) {
        wprintf(L"[*] Open: %s\r\n", pdbPath);
    }
    return S_OK;
}

HRESULT STDMETHODCALLTYPE RestrictRegistryAccess(
    IDiaLoadCallback2* This
) {
    // return hr != S_OK to prevent querying the registry for symbol search paths
    return S_OK;
}

HRESULT STDMETHODCALLTYPE RestrictSymbolServerAccess(
    IDiaLoadCallback2* This
) {
    // return hr != S_OK to prevent accessing a symbol server
    return S_OK;
}

HRESULT STDMETHODCALLTYPE RestrictOriginalPathAccess(
    IDiaLoadCallback2* This
) {
    // return hr != S_OK to prevent querying the registry for symbol search paths
    return S_OK;
}

HRESULT STDMETHODCALLTYPE RestrictReferencePathAccess(
    IDiaLoadCallback2* This
) {
    // return hr != S_OK to prevent accessing a symbol server
    return S_OK;
}

HRESULT STDMETHODCALLTYPE RestrictDBGAccess(
    IDiaLoadCallback2* This
) {
    return S_OK;
}

HRESULT STDMETHODCALLTYPE RestrictSystemRootAccess(
    IDiaLoadCallback2* This
) {
    return S_OK;
}


static CONST IDiaLoadCallback2Vtbl CallbackVirtualTable = {
    // IUnknown
    QueryInterface,
    AddRef,
    Release,

    // IDiaLoadCallback
    NotifyDebugDir,
    NotifyOpenDBG,
    NotifyOpenPDB,
    RestrictRegistryAccess,
    RestrictSymbolServerAccess,

    // IDiaLoadCallback2
    RestrictOriginalPathAccess,
    RestrictReferencePathAccess,
    RestrictDBGAccess,
    RestrictSystemRootAccess
};

_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE DiaCallbackHelper(
    _In_    BOOLEAN Initialise,
    _Inout_ PVOID** Callback
) {
    if (Callback == NULL)
        return E_FAIL;

    // Create the structure for the callback
    if (Initialise) {
        if (g_HeapHandle != INVALID_HANDLE_VALUE)
            return E_FAIL;

        // Create executable heap
        g_HeapHandle = HeapCreate(
            HEAP_CREATE_ENABLE_EXECUTE,
            sizeof(IDiaLoadCallback2Vtbl) + sizeof(DiaCallback),
            0x1000
        );
        if (g_HeapHandle == INVALID_HANDLE_VALUE)
            return E_FAIL;

        // Allocate memory in the new heap
        DiaCallback* Buffer = HeapAlloc(g_HeapHandle, HEAP_ZERO_MEMORY, sizeof(DiaCallback) + sizeof(IDiaLoadCallback2Vtbl));
        if (Buffer == NULL) {
            HeapDestroy(g_HeapHandle);
            return E_FAIL;
        }

        PVOID cstruct = HeapAlloc(g_HeapHandle, HEAP_ZERO_MEMORY, sizeof(DiaCallback));;
        PVOID vtable  = NULL;


        // Assemble everything
        Buffer->m_nRefCount = 0x00;
        Buffer->lpVtbl = (IDiaLoadCallback2*)&CallbackVirtualTable;

        *Callback = (PVOID)Buffer;
        return S_OK;
    }
    // Delete the structure for the callback
    else {
        if (g_HeapHandle == INVALID_HANDLE_VALUE || Callback == NULL)
            return E_FAIL;

        // Check that the reference count is zero
        DiaCallback* src = (DiaCallback*)*Callback;
        if (src->m_nRefCount != 0x00)
            return E_FAIL;

        // Free the memory and destroy the executable heap
        HeapFree(g_HeapHandle, 0x00, src);
        HeapDestroy(g_HeapHandle);
        g_HeapHandle = INVALID_HANDLE_VALUE;
    }

    return E_FAIL;
}