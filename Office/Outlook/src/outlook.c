/**
* @file        outlook.c
* @data        10/03/2021
* @author      Paul L. (@am0nsec)
* @version     1.0
* @brief       Outlook utility class.
* @details
* @link        https://github.com/am0nsec/wspe
* @copyright   This project has been released under the GNU Public License v3 license.
*/

#include <Windows.h>
#include <sal.h>

#include "outlook.h"

_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE Initialise(
	_In_ OutlookUtil* pOutlookUtil
) {
	if (!pOutlookUtil->m_bInitialised)
		if (CoInitializeEx(NULL, COINIT_MULTITHREADED) != S_OK)
			return E_FAIL;

	pOutlookUtil->m_bInitialised = TRUE;
	return S_OK;
}

_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE Uninitialise(
	_In_ OutlookUtil* pOutlookUtil
) {
	if (!pOutlookUtil->m_bInitialised)
		return E_FAIL;

	CoUninitialize();
	RtlSecureZeroMemory(pOutlookUtil, sizeof(OutlookUtil));
	return S_OK;
}

_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE OuCreateOutlookUtilClass(
	_Inout_ OutlookUtil** ppOutlookUtil,
	_Out_   PHANDLE       pHeapHandle
) {
	if (ppOutlookUtil == NULL || pHeapHandle == NULL)
		return E_INVALIDARG;

	// 1. Create executable heap
	*pHeapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, sizeof(OutlookUtil), 0x1000);
	if (*pHeapHandle == INVALID_HANDLE_VALUE || *pHeapHandle == NULL)
		return E_FAIL;
	
	// 2. Allocate memory
	*ppOutlookUtil = HeapAlloc(*pHeapHandle, HEAP_ZERO_MEMORY, sizeof(OutlookUtil));
	if (*ppOutlookUtil == NULL) {
		HeapDestroy(*pHeapHandle);
		return E_FAIL;
	}

	// 3. Set the function addresses.
	OutlookUtil* dst = *ppOutlookUtil;
	dst->lpVtbl.Initialise = &Initialise;
	dst->lpVtbl.Uninitialise = &Uninitialise;
	dst->lpVtbl.GetGlobalAddressList = &GetGlobalAddressList;
	return S_OK;
}

_Use_decl_annotations_
HRESULT __stdcall OuFreeOutlookUtilClass(
	_In_ OutlookUtil** ppOutlookUtil,
	_In_ PHANDLE       pHeapHandle
) {
	if (ppOutlookUtil == NULL || pHeapHandle == NULL)
		return E_INVALIDARG;

	*ppOutlookUtil = NULL;
	HeapDestroy(*pHeapHandle);
	return S_OK;
}

_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE GetGlobalAddressList(
	_In_  OutlookUtil*           pOutlookUtil,
	_Out_ PLONG                  plCount,
	_Out_ OutlookContactRecord** ppContactRecords
) {
	if (pOutlookUtil == NULL || ppContactRecords == NULL)
		return E_INVALIDARG;
	if (!pOutlookUtil->m_bInitialised)
		return E_FAIL;

	// 1. Get the different dispatch interfaces ready
	IDispatch* pIApplication = NULL;
	EXIT_ON_ERROR(OupGetApplicationDispatchInterface(&pIApplication));

	IDispatch* pINamespace = NULL;
	VARIANT Namespace = { 0x00 };
	Namespace.vt = VT_BSTR;
	Namespace.bstrVal = SysAllocString(L"MAPI");
	EXIT_ON_ERROR(OupGetDispatchInterface(
		pIApplication,
		L"GetNamespace",
		&Namespace,
		0x01,
		&pINamespace,
		(DISPID*)NULL
	));

	IDispatch* pIAddressList = NULL;
	EXIT_ON_ERROR(OupGetDispatchInterface(
		pINamespace,
		L"GetGlobalAddressList",
		(VARIANT*)NULL,
		0x00,
		&pIAddressList,
		(DISPID*)NULL
	));

	IDispatch* pIAddressEntries = NULL;
	EXIT_ON_ERROR(OupGetDispatchInterface(
		pIAddressList,
		L"AddressEntries",
		(VARIANT*)NULL,
		0x00,
		&pIAddressEntries,
		(DISPID*)NULL
	));

	// 2. Get total number of entries
	VARIANT vRecords = { 0x00 };
	EXIT_ON_ERROR(OupGetDispatchInterfaceProperty(
		pIAddressEntries,
		L"Count",
		VT_I4,
		NULL,
		&vRecords
	));

	// 3. Allocate memory for all the records
	SIZE_T llMaxSize = sizeof(OutlookContactRecord) * vRecords.llVal;
	*ppContactRecords = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, llMaxSize);

	// 4. Loop through each AddressEntry dispatch interfaces
	DISPID ItemId = 0x00;
	DISPID AddressEntryUserTypeId = 0x00;
	DISPID GetExchangeUserId = 0x00;
	OutlookContactRecord* dst = *ppContactRecords;

	VARIANT ItemIndex = { 0x00 };
	ItemIndex.vt = VT_I4;

	LONG cx = 0x00;
	for (; cx < vRecords.llVal; cx++) {
		IDispatch* pAddressEntry = NULL;
		ItemIndex.llVal = cx + 1;

		// Get the IAddressEntry dispatch interface
		EXIT_ON_ERROR(OupGetDispatchInterface(
			pIAddressEntries,
			L"Item",
			&ItemIndex,
			0x01,
			&pAddressEntry,
			&ItemId
		));

		// Get the contact type and avoid mail-chain
		VARIANT EntryType = { 0x00 };
		EXIT_ON_ERROR(OupGetDispatchInterfaceProperty(
			pAddressEntry,
			L"AddressEntryUserType",
			VT_I4,
			&AddressEntryUserTypeId,
			&EntryType
		));
		if ((OlAddressEntryUserType)EntryType.llVal != olExchangeUserAddressEntry)
			continue;

		// Get the Exchange User dispatch interface
		IDispatch* pExchangeUser = NULL;
		EXIT_ON_ERROR(OupGetDispatchInterface(
			pAddressEntry,
			L"GetExchangeUser",
			NULL,
			0x00,
			&pExchangeUser,
			&GetExchangeUserId
		));

		// Get the data out of the ExchangeUser dispatch interface
		VARIANT Data = { 0x00 };
		OupGetDispatchInterfaceProperty(pExchangeUser, L"Name", VT_BSTR, NULL, &Data);
		dst->Name = SysAllocString(Data.bstrVal);

		OupGetDispatchInterfaceProperty(pExchangeUser, L"FirstName", VT_BSTR, NULL, &Data);
		dst->FirstName = SysAllocString(Data.bstrVal);

		OupGetDispatchInterfaceProperty(pExchangeUser, L"LastName", VT_BSTR, NULL, &Data);
		dst->LastName = SysAllocString(Data.bstrVal);

		OupGetDispatchInterfaceProperty(pExchangeUser, L"PrimarySmtpAddress", VT_BSTR, NULL, &Data);
		dst->PrimarySmtpAddress = SysAllocString(Data.bstrVal);

		OupGetDispatchInterfaceProperty(pExchangeUser, L"JobTitle", VT_BSTR, NULL, &Data);
		dst->JobTitle = SysAllocString(Data.bstrVal);

		OupGetDispatchInterfaceProperty(pExchangeUser, L"Department", VT_BSTR, NULL, &Data);
		dst->Department = SysAllocString(Data.bstrVal);

		OupGetDispatchInterfaceProperty(pExchangeUser, L"OfficeLocation", VT_BSTR, NULL, &Data);
		dst->OfficeLocation = SysAllocString(Data.bstrVal);

		OupGetDispatchInterfaceProperty(pExchangeUser, L"City", VT_BSTR, NULL, &Data);
		dst->City = SysAllocString(Data.bstrVal);

		dst++;
		(*plCount)++;
	}

	return S_OK;
}

_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE OupGetApplicationDispatchInterface(
	_Out_ IDispatch** ppIDispatch
) {
	if (ppIDispatch == NULL)
		return E_INVALIDARG;

	// 1. Get the CLSID of Outlook.Application.
	CLSID CLSIDOutlookApplication = { 0x00 };
	if (FAILED(CLSIDFromProgID(L"Outlook.Application", &CLSIDOutlookApplication)))
		return E_FAIL;

	// 2. Get instance of the dispatch interface
	EXIT_ON_ERROR(CoCreateInstance(
		&CLSIDOutlookApplication,
		NULL,
		CLSCTX_LOCAL_SERVER,
		&IID_IDispatch,
		ppIDispatch
	));

	// 3. Exit
	if (*ppIDispatch == NULL)
		return E_FAIL;
	return S_OK;
}

_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE OupGetDispatchInterface(
	_In_        IDispatch*  pInterface,
	_In_        LPOLESTR    szMethodName,
	_In_opt_    VARIANT*    pVariables,
	_In_        DWORD       dwVaraibles,
	_Out_       IDispatch** ppIDispatch,
	_Inout_opt_ DISPID*     pDispatchId
) {
	if (pInterface == NULL || szMethodName == NULL || ppIDispatch == NULL)
		return E_INVALIDARG;

	// 1. Get the dispatch ID of the method.
	DISPID DispatchId = 0x00;
	if (pDispatchId != NULL && *pDispatchId != 0x00) {
		DispatchId = *pDispatchId;
	}
	else {
		EXIT_ON_ERROR(pInterface->lpVtbl->GetIDsOfNames(
			pInterface,
			&IID_NULL,
			&szMethodName,
			0x01,
			NULL,
			&DispatchId
		));
		if (pDispatchId != NULL)
			*pDispatchId = DispatchId;
	}
	
	// 2. Get the parameters ready
	EXCEPINFO Exception = { 0x00 };
	VARIANT Result = { 0x00 };

	DISPPARAMS Parameters = { 0x00 };
	if (dwVaraibles != 0x00) {
		Parameters.cArgs = dwVaraibles;
		Parameters.rgvarg = pVariables;
	}

	// 3. Get the dispatch interface via the initial interface
	EXIT_ON_ERROR(pInterface->lpVtbl->Invoke(
		pInterface,
		DispatchId,
		&IID_NULL,
		LOCALE_SYSTEM_DEFAULT,
		DISPATCH_METHOD,
		&Parameters,
		&Result,
		&Exception,
		NULL
	));

	// 4. Check that this is the correct VARIANT type
	if (Result.vt != VT_DISPATCH)
		return E_FAIL;
	*ppIDispatch = Result.pdispVal;

	// 5. Exit
	return S_OK;
}

_Use_decl_annotations_
HRESULT STDMETHODCALLTYPE OupGetDispatchInterfaceProperty(
	_In_        IDispatch* pInterface,
	_In_        LPOLESTR   szProperty,
	_In_        DWORD      dwPropertyType,
	_Inout_opt_ DISPID*    pDispatchId,
	_Out_       VARIANT*   pProperty
) {
	if (pInterface == NULL || szProperty == NULL || pProperty == NULL)
		return E_INVALIDARG;

	// 1. Get the dispatch ID of the method.
	DISPID DispatchId = 0x00;
	if (pDispatchId != NULL && *pDispatchId != 0x00) {
		DispatchId = *pDispatchId;
	}
	else {
		EXIT_ON_ERROR(pInterface->lpVtbl->GetIDsOfNames(
			pInterface,
			&IID_NULL,
			&szProperty,
			0x01,
			NULL,
			&DispatchId
		));
		if (pDispatchId != NULL)
			*pDispatchId = DispatchId;
	}
	
	// 2. Get the parameters ready
	EXCEPINFO Exception = { 0x00 };
	VARIANT Result = { 0x00 };

	DISPPARAMS Parameters = { 0x00 };
	Parameters.cArgs = 0;

	// 3. Get the property
	EXIT_ON_ERROR(pInterface->lpVtbl->Invoke(
		pInterface,
		DispatchId,
		&IID_NULL,
		LOCALE_SYSTEM_DEFAULT,
		DISPATCH_PROPERTYGET,
		&Parameters,
		&Result,
		&Exception,
		NULL
	));

	// 4. Check that this is the correct VARIANT type
	if (Result.vt != dwPropertyType)
		return E_FAIL;
	*pProperty = Result;

	// 5. Exit
	return S_OK;
}
