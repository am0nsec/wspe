/**
* @file     interfaces.h
* @date     02-08-2020
* @author   Paul Laîné (@am0nsec)
* @version  1.0
* @brief    Enumerate AppLocker policies via IAppIdPolicyHandler COM interface.
* @details
* @link     https://ntamonsec.blogspot.com/
*
* @copyright This project has been released under the GNU Public License v3 license.
*/
#include <Windows.h>

#ifndef _INTERFACES_H
#define _INTERFACES_H

/**
 * @brief GUID of the IAppIdPolicyHandler COM interface: B6FEA19E-32DD-4367-B5B7-2F5DA140E87D
*/
CONST IID IID_IAppIdPolicyHandler = { 0xB6FEA19E, 0x32DD, 0x4367, {0xB5, 0xB7, 0x2F, 0x5D, 0xA1, 0x40, 0xE8, 0x7D} };

/**
 * @brief GUID of the IAppIdPolicyHandler class factory: F1ED7D4C-F863-4DE6-A1CA-7253EFDEE1F3
*/
CONST IID CLSID_AppIdPolicyHandlerClass = { 0xF1ED7D4C, 0xF863, 0x4DE6, {0xA1, 0xCA, 0x72, 0x53, 0xEF, 0xDE, 0xE1, 0xF3} };

typedef interface IAppIdPolicyHandler IAppIdPolicyHandler;

typedef struct AppIdPolicyHandlerVtbl {
	BEGIN_INTERFACE

	HRESULT(STDMETHODCALLTYPE* QueryInterface) (
		_In_    IAppIdPolicyHandler* This,
		_In_    REFIID riid,
		_Inout_ PVOID* ppvObject
	);

	ULONG(STDMETHODCALLTYPE* AddRef)(
		_In_ IAppIdPolicyHandler* This
	);

	ULONG(STDMETHODCALLTYPE* Release)(
		_In_ IAppIdPolicyHandler* This
	);

	// Unknown functions 
	HRESULT(*GetTypeInfoCount)(LPVOID, UINT*);
	HRESULT(*GetTypeInfo)(LPVOID, UINT, LCID, LPVOID*);
	HRESULT(*GetIDsOfNames)(LPVOID, IID*, LPOLESTR*, UINT, LCID, DISPID*);
	HRESULT(*Invoke)(LPVOID, DISPID, IID*, LCID, WORD, DISPPARAMS*, VARIANT*, EXCEPINFO*, UINT*);

	VOID(STDMETHODCALLTYPE* SetPolicy)(
		_In_ IAppIdPolicyHandler* This,
		_In_ BSTR bstrLdapPath,
		_In_ BSTR bstrXmlPolicy
	);

	BSTR(STDMETHODCALLTYPE *GetPolicy)(
		_In_ IAppIdPolicyHandler* This,
		_In_ BSTR bstrLdapPath
	);

	BSTR(STDMETHODCALLTYPE *GetEffectivePolicy)(
		_In_ IAppIdPolicyHandler* This
	);

	INT(STDMETHODCALLTYPE *IsFileAllowed)(
		_In_  IAppIdPolicyHandler* This,
		_In_  BSTR bstrXmlPolicy,
		_In_  BSTR bstrFilePath,
		_In_  BSTR bstrUserSid,
		_Out_ GUID* pguidResponsibleRuleId
	);

	INT(STDMETHODCALLTYPE *IsPackageAllowed)(
		_In_  IAppIdPolicyHandler* This,
		_In_  BSTR bstrXmlPolicy,
		_In_  BSTR bstrPublisherName,
		_In_  BSTR bstrPackageName,
		_In_  ULONG ullPackageVersion,
		_In_  BSTR bstrUserSid,
		_Out_ GUID* pguidResponsibleRuleId
	);

	END_INTERFACE
} AppIdPolicyHandlerVtbl;

interface IAppIdPolicyHandler {
	CONST_VTBL struct AppIdPolicyHandlerVtbl* lpVtbl;
};
#endif // !_INTERFACES_H
