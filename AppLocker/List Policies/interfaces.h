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

#if defined(__cplusplus) && !defined(CINTERFACE)
	
MIDL_INTERFACE("B6FEA19E-32DD-4367-B5B7-2F5DA140E87D")
IAppIdPolicyHandler : public IUnknown, public IDispatch {
public:
	virtual VOID STDMETHODCALLTYPE SetPolicy (
		_In_ BSTR bstrLdapPath,
		_In_ BSTR bstrXmlPolicy
	);

	virtual BSTR STDMETHODCALLTYPE GetPolicy(
		_In_  BSTR   bstrLdapPath,
		_Out_ LPBSTR pbstrXmlPolicy
	);

	virtual BSTR STDMETHODCALLTYPE GetEffectivePolicy(
		_Out_ LPBSTR pbstrXmlPolicy
	);

	virtual INT STDMETHODCALLTYPE IsFileAllowed(
		_In_  BSTR   bstrXmlPolicy,
		_In_  BSTR   bstrFilePath,
		_In_  BSTR   bstrUserSid,
		_Out_ LPGUID pguidResponsibleRuleId,
		_Out_ PLONG  pbStatus
	);

	virtual INT STDMETHODCALLTYPE IsPackageAllowed(
		_In_  BSTR   bstrXmlPolicy,
		_In_  BSTR   bstrPublisherName,
		_In_  BSTR   bstrPackageName,
		_In_  ULONG  ullPackageVersion,
		_In_  BSTR   bstrUserSid,
		_Out_ LPGUID pguidResponsibleRuleId,
		_Out_ PLONG  pbStatus
	);
};

#else 
typedef struct AppIdPolicyHandlerVtbl {
	BEGIN_INTERFACE

	/**
	 * @brief QueryInterface method from IUnknown
	*/
	HRESULT(STDMETHODCALLTYPE* QueryInterface) (
		_In_  IAppIdPolicyHandler* This,
		_In_  REFIID               riid,
		_Out_ PVOID*               ppvObject
	);

	/**
	 * @brief AddRef from IUnknown
	*/
	ULONG(STDMETHODCALLTYPE* AddRef)(
		_In_ IAppIdPolicyHandler* This
	);

	/**
	 * @brief Release from IUnknown
	*/
	ULONG(STDMETHODCALLTYPE* Release)(
		_In_ IAppIdPolicyHandler* This
	);

	/**
	 * @brief GetTypeInfoCount from IDispatch
	*/
	HRESULT(STDMETHODCALLTYPE* GetTypeInfoCount)(
		_In_  IAppIdPolicyHandler* This,
		_Out_ PUINT                pctinfo
	);

	/**
	 * @brief GetTypeInfo from IDispatch
	*/
	HRESULT(STDMETHODCALLTYPE* GetTypeInfo)(
		_In_  IAppIdPolicyHandler* This,
		_In_  UINT                 itinfo,
		_In_  ULONG                lcid,
		_Out_ LPVOID*              pptinfo
	);

	/**
	 * @brief GetIDsOfNames from IDispatch
	*/
	HRESULT(STDMETHODCALLTYPE* GetIDsOfNames)(
		_In_  IAppIdPolicyHandler* This, 
		_In_  LPIID                riid,
		_In_  LPOLESTR*            rgszNames,
		_In_  UINT                 cNames,
		_In_  LCID                 lcid,
		_Out_ DISPID*              rgdispid
	);

	/**
	 * @brief Invoke from IDispatch
	*/
	HRESULT(STDMETHODCALLTYPE* Invoke)(
		_In_  IAppIdPolicyHandler* This,
		_In_  DISPID               dispidMember,
		_In_  LPIID                riid,
		_In_  LCID                 lcid,
		_In_  WORD                 wFlags,
		_In_  DISPPARAMS*          pdispparams,
		_In_  LPVARIANT            pvarResult,
		_Out_ LPEXCEPINFO          pexcepinfo,
		_Out_ PUINT                puArgErr
	);

	/**
	 * @brief SetPolicy from IAppIdPolicyHandler
	*/
	HRESULT(STDMETHODCALLTYPE* SetPolicy)(
		_In_ IAppIdPolicyHandler* This,
		_In_ BSTR bstrLdapPath,
		_In_ BSTR bstrXmlPolicy
	);

	/**
	 * @brief GetPolicy from IAppIdPolicyHandler
	*/
	HRESULT(STDMETHODCALLTYPE *GetPolicy)(
		_In_  IAppIdPolicyHandler* This,
		_In_  BSTR                 bstrLdapPath,
		_Out_ LPBSTR               pbstrXmlPolicy
	);

	/**
	 * @brief GetEffectivePolicy from IAppIdPolicyHandler
	*/
	HRESULT(STDMETHODCALLTYPE *GetEffectivePolicy)(
		_In_  IAppIdPolicyHandler* This,
		_Out_ LPBSTR               pbstrXmlPolicies
	);

	/**
	 * @brief IsFileAllowed from IAppIdPolicyHandler
	*/
	HRESULT(STDMETHODCALLTYPE *IsFileAllowed)(
		_In_  IAppIdPolicyHandler* This,
		_In_  BSTR                 bstrXmlPolicy,
		_In_  BSTR                 bstrFilePath,
		_In_  BSTR                 bstrUserSid,
		_Out_ LPGUID               pguidResponsibleRuleId,
		_Out_ PLONG                pbStatus
	);

	/**
	 * @brief IsPackageAllowed from IAppIdPolicyHandler
	*/
	HRESULT(STDMETHODCALLTYPE *IsPackageAllowed)(
		_In_  IAppIdPolicyHandler* This,
		_In_  BSTR                 bstrXmlPolicy,
		_In_  BSTR                 bstrPublisherName,
		_In_  BSTR                 bstrPackageName,
		_In_  ULONG                ullPackageVersion,
		_In_  BSTR                 bstrUserSid,
		_Out_ LPGUID               pguidResponsibleRuleId,
		_Out_ PLONG                pbStatus
	);

	END_INTERFACE
} AppIdPolicyHandlerVtbl;

interface IAppIdPolicyHandler {
	CONST_VTBL struct AppIdPolicyHandlerVtbl* lpVtbl;
};
#endif

#endif // !_INTERFACES_H
