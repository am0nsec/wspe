/**
* @file     main.c
* @date     02-08-2020
* @author   Paul Laîné (@am0nsec)
* @version  1.0
* @brief    Enumerate AppLocker policies via IAppIdPolicyHandler COM interface.
* @details
* @link     https://ntamonsec.blogspot.com/
*
* @copyright This project has been released under the GNU Public License v3 license.
*/
#include <windows.h>
#include <stdio.h>
#include "interfaces.h"

#define APPLOCKER_MODE_LOCAL     0x01 // Application will retrieve the local AppLocker policies.
#define APPLOCKER_MODE_DOMAIN    0x02 // Application will retrieve the domain AppLocker policies .
#define APPLOCKER_MODE_EFFECTIVE 0x03 // Application will retrieve the effective AppLocker policies.

/**
 * @brief Return the help banner of the application.
*/
VOID ShowUsage() {
	wprintf(L"usage: applocker.exe [-l|-e|-d] {ldap query}\n");
	wprintf(L"\t-l\t\tList local AppLocker policies. Default mode.\n");
	wprintf(L"\t-e\t\tList effective AppLocker policies.\n");
	wprintf(L"\t-d\t\tList domain AppLocker policies. In this case the last parameter is the LDAP path.\n\n");

	wprintf(L"examples:\n");
	wprintf(L"\tapplocker.exe -e\n");
	wprintf(L"\tapplocker.exe -l\n");
	wprintf(L"\tapplocker.exe -d \"DC=example,DC=com\"\n");
}

/**
 * @brief Get the local, domain or effective AppLocker policies.
 * @param pwAppLockerMode One of the following mode: APPLOCKER_MODE_LOCAL, APPLOCKER_MODE_DOMAIN or APPLOCKER_MODE_EFFECTIVE.
 * @param pbstrLdapPath The LPAP search path in case domain AppLocker policies have to be retrieved,
 * @param pbstrPolicies The retrieved AppLocker policies.
 * @return Whether the policies have been successfully retrieved.
*/
BOOL GetAppLockerPolicies(PWORD pwAppLockerMode, LPBSTR pbstrLdapPath, LPBSTR pbstrPolicies) {
	BOOL bResult = FALSE;
	HRESULT result = S_FALSE;
	result = CoInitialize(NULL);
	if (result != S_OK)
		return FALSE;

	// Get the COM interface
	IAppIdPolicyHandler* pIAppIdPolicyHandler = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(IAppIdPolicyHandler));
	result = CoCreateInstance(&CLSID_AppIdPolicyHandlerClass, NULL, CLSCTX_INPROC_SERVER, &IID_IAppIdPolicyHandler, &pIAppIdPolicyHandler);
	if (result != S_OK || pIAppIdPolicyHandler == NULL)
		goto failure;

	// Get the AppLocker policies
	switch (*pwAppLockerMode) {
	case APPLOCKER_MODE_LOCAL:
	case APPLOCKER_MODE_DOMAIN:
		result = pIAppIdPolicyHandler->lpVtbl->GetPolicy(pIAppIdPolicyHandler, *pbstrLdapPath, pbstrPolicies);
		break;

	case APPLOCKER_MODE_EFFECTIVE:
		result = pIAppIdPolicyHandler->lpVtbl->GetEffectivePolicy(pIAppIdPolicyHandler, pbstrPolicies);
		break;
	}

	// Check if an error occurred
	if (result != S_OK || *pbstrPolicies == NULL)
		goto failure;

	bResult = TRUE;
failure:
	if (pIAppIdPolicyHandler) {
		pIAppIdPolicyHandler->lpVtbl->Release(pIAppIdPolicyHandler);
		pIAppIdPolicyHandler = NULL;
	}
	CoUninitialize();
	return bResult;
}

/**
 * @brief Entry point of the application.
 * @param argc Number of command line arguments. 
 * @param argv Command line arguments.
 * @return The execution status code.
*/
INT wmain(INT argc, PWCHAR argv[]) {
	// Banner
	wprintf(L"List local, domain and effective AppLocker policies\n");
	wprintf(L"Copyright (C) 2020 Paul Laine (@am0nsec)\n");
	wprintf(L"https://ntamonsec.blogspot.com/\n\n");

	// Variable early definition
	INT iStatusCode = 1;
	WORD wAppLockerMode = APPLOCKER_MODE_LOCAL;
	BSTR bstrLdapPath = NULL;

	// Parse user arguments
	if (argc < 2) {
		ShowUsage();
		return;
	}
	if (wcscmp(argv[1], L"-l") == 0)
		wAppLockerMode = APPLOCKER_MODE_LOCAL;
	else if (wcscmp(argv[1], L"-e") == 0)
		wAppLockerMode = APPLOCKER_MODE_EFFECTIVE;
	else if (wcscmp(argv[1], L"-d") == 0 && argc >= 3) {
		wAppLockerMode = APPLOCKER_MODE_DOMAIN;
		bstrLdapPath = SysAllocString(argv[2]);
	}
	else {
		ShowUsage();
		return;
	}

	// Get the AppLocker Policies
	BSTR bstrAppLockerPolicies = NULL;
	if (GetAppLockerPolicies(&wAppLockerMode, &bstrLdapPath, &bstrAppLockerPolicies)) {
		printf("AppLocker policies: \n%S\n", bstrAppLockerPolicies);
		return 0;
	}

	return 1;
}
