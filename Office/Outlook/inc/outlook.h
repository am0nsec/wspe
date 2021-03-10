/**
* @file        outlook.h
* @data        10/03/2021
* @author      Paul L. (@am0nsec)
* @version     1.0
* @brief       Outlook utility class.
* @details
* @link        https://github.com/am0nsec/wspe
* @copyright   This project has been released under the GNU Public License v3 license.
*/

#ifndef __OUTLOOK_H_GUARD__
#define __OUTLOOK_H_GUARD__

#include <windows.h>
#include <sal.h>

/**
 * @brief Helps making the code a little bit less bloated.
*/
#define EXIT_ON_ERROR(x) \
	if(FAILED(x)) {return E_FAIL;}

/**
 * @brief Outlook contact record.
*/
typedef struct _OutlookContactRecord {
	BSTR Name;
	BSTR FirstName;
	BSTR LastName;
	BSTR PrimarySmtpAddress;
	BSTR JobTitle;
	BSTR Department;
	BSTR OfficeLocation;
	BSTR City;
} OutlookContactRecord, * POutlookContactRecord;

/**
 * @brief Different type of AddressEntry
*/
typedef enum _OlAddressEntryUserType {
	olExchangeUserAddressEntry = 0,
	olExchangeDistributionListAddressEntry = 1,
	olExchangePublicFolderAddressEntry = 2,
	olExchangeAgentAddressEntry = 3,
	olExchangeOrganizationAddressEntry = 4,
	olExchangeRemoteUserAddressEntry = 5,
	olOutlookContactAddressEntry = 10,
	olOutlookDistributionListAddressEntry = 11,
	olLdapAddressEntry = 20,
	olSmtpAddressEntry = 30,
	olOtherAddressEntry = 40
} OlAddressEntryUserType;

/**
 * @brief Internal Outlook class.
*/
typedef struct OutlookUtil OutlookUtil;

typedef struct OutlookUtilVtbl OutlookUtilVtbl;

/**
 * @brief Virtual table of the OutlookUtil structure.
*/
typedef struct OutlookUtilVtbl {
	/**
	 * @brief Initialises the COM library.
	*/
	HRESULT(STDMETHODCALLTYPE* Initialise)(
		_In_ OutlookUtil* pThis
	);

	/**
	 * @brief Uninitialises the COM library. COM and make cleanup the data.
	*/
	HRESULT(STDMETHODCALLTYPE* Uninitialise)(
		_In_ OutlookUtil* pThis
	);

	/**
	 * @brief Get the list of addresses.
	*/
	HRESULT(STDMETHODCALLTYPE* GetGlobalAddressList)(
		_In_  OutlookUtil*           pOutlookUtil,
		_Out_ PLONG                  plCount,
		_Out_ OutlookContactRecord** ppContactRecords
	);
};

/**
 * @brief C implementation of a class.
*/
typedef struct OutlookUtil {
	/**
	 * @brief Virtual table of the OutlookUtil structure.
	*/
	struct OutlookUtilVtbl lpVtbl;

	/**
	 * @brief Pointer to an _Application dispatch interface.
	*/
	IDispatch* pOutlookApplication;

	/**
	 * @brief Whether the class has been initialised.
	*/
	BOOLEAN m_bInitialised;
};

/**
 * @brief Create a OutlookUtil C class.
 * @param ppOutlookUtil Pointer to a OutlookUtil class.
 * @param pHeapHandle Pointer to a RWX Heap handle.
 * @return Whether the class has been successfully created.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT STDMETHODCALLTYPE OuCreateOutlookUtilClass(
	_Inout_ OutlookUtil** ppOutlookUtil,
	_Out_   PHANDLE       pHeapHandle
);

/**
 * @brief Free a OutlookUtil C class.
 * @param ppOutlookUtil Pointer to a OutlookUtil class.
 * @param pHeapHandle Pointer to a RWX Heap handle.
 * @return Whether the class has been successfully free'ed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT STDMETHODCALLTYPE OuFreeOutlookUtilClass(
	_In_ OutlookUtil** ppOutlookUtil,
	_In_ PHANDLE       pHeapHandle
);

/**
 * @brief Initializes the COM library.
 * @param pOutlookUtil Pointer to a OutlookUtil class.
 * @return Whether the COM library has been successfully initialised.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT STDMETHODCALLTYPE Initialise(
	_In_ OutlookUtil* pOutlookUtil
);

/**
 * @brief Uninitialise the COM library and cleanup the data.
 * @param pOutlookUtil Pointer to a OutlookUtil class.
 * @return Whether the COM library has been successfully uninitialised and the data removed.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT STDMETHODCALLTYPE Uninitialise(
	_In_ OutlookUtil* pOutlookUtil
);

/**
 * @brief
 * @param pOutlookUtil
 * @param plCount
 * @param ppContactRecords
 * @return
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT STDMETHODCALLTYPE GetGlobalAddressList(
	_In_  OutlookUtil*           pOutlookUtil,
	_Out_ PLONG                  plCount,
	_Out_ OutlookContactRecord** ppContactRecords
);

/**
 * @brief Get a pointer to a Outlook.Application dispatch interface.
 * @param ppIDispatch Pointer to a IDispatch interface.
 * @return Whether the Outlook.Application dispatch interface has been created.
*/
_Success_(return == S_OK) _Must_inspect_result_
HRESULT STDMETHODCALLTYPE OupGetApplicationDispatchInterface(
	_Out_ IDispatch** ppIDispatch
);

/**
 * @brief 
 * @param pInterface 
 * @param szMethodName 
 * @param pVariables 
 * @param dwVaraibles 
 * @param ppIDispatch 
 * @param pDispatchId 
 * @return 
*/
HRESULT STDMETHODCALLTYPE OupGetDispatchInterface(
	_In_        IDispatch*  pInterface,
	_In_        LPOLESTR    szMethodName,
	_In_opt_    VARIANT*    pVariables,
	_In_        DWORD       dwVaraibles,
	_Out_       IDispatch** ppIDispatch,
	_Inout_opt_ DISPID*     pDispatchId
);

/**
 * @brief 
 * @param pInterface 
 * @param szProperty 
 * @param dwPropertyType
 * @param pDispatchId
 * @param pProperty 
 * @return 
*/
HRESULT STDMETHODCALLTYPE OupGetDispatchInterfaceProperty(
	_In_        IDispatch* pInterface,
	_In_        LPOLESTR   szProperty,
	_In_        DWORD      dwPropertyType,
	_Inout_opt_ DISPID*    pDispatchId,
	_Out_       VARIANT*   pProperty
);

#endif // !__OUTLOOK_H_GUARD__

