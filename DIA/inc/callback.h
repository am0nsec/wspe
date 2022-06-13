/*+================================================================================================
Module Name: callback.h
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

#ifndef __DIA_CALLBACK_H_GUARD__
#define __DIA_CALLBACK_H_GUARD__

#include <Windows.h>

#include "msdia/include/dia2.h"

typedef struct DiaCallback {

    // Virtual Table for the callback
    CONST_VTBL struct IDiaLoadCallback2* lpVtbl;

    // Reference counter for the AddRef/Release methods
    int m_nRefCount;
} DiaCallback;


HRESULT STDMETHODCALLTYPE
_Must_inspect_result_
_Success_(return == S_OK)
DiaCallbackHelper(
    _In_    BOOLEAN Initialise,
    _Inout_ PVOID** Callback
);

#endif // !__DIA_CALLBACK_H_GUARD__
