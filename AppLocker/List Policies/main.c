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

INT wmain(INT argc, PWCHAR argv[]) {
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);
	INT iStatusCode = 1;

	// Initialise COM
	HRESULT result = S_FALSE;
	result = CoInitialize(NULL);
	if (result != S_OK)
		goto failure;

	// Get the interface
	IAppIdPolicyHandler* pIAppIdPolicyHandler = NULL;
	result = CoCreateInstance(&CLSID_AppIdPolicyHandlerClass, NULL, CLSCTX_INPROC_SERVER, &IID_IAppIdPolicyHandler, &pIAppIdPolicyHandler);
	if (result != S_OK || pIAppIdPolicyHandler == NULL)
		goto failure;

	// Get the effective policies??
	BSTR bstrPolicies = pIAppIdPolicyHandler->lpVtbl->GetEffectivePolicy(pIAppIdPolicyHandler);
	printf("%S\n", bstrPolicies);

	iStatusCode = 0;
failure:
	CoUninitialize();
	return iStatusCode;
}
