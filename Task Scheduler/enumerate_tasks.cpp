#pragma once
#include <Windows.h>
#include <comdef.h>
#include <taskschd.h>
#pragma comment(lib, "taskschd.lib")

VOID wprintf_indent(LPCWSTR string, DWORD indent, BOOL bIsTaskName) {
	BSTR bstrString = ::SysAllocString(string);
	for (DWORD i = 0; i < indent; i++) {
		::wprintf(L" ");
	}
	if (bIsTaskName) {
		::wprintf(L"- ");
	} else {
		::wprintf(L"+ ");
	}
	::wprintf(L"%s\n", string);
	::SysFreeString(bstrString);
}

BOOL IsAdministrator() {
	BOOL bSuccess = FALSE;
	HANDLE hProcessToken = NULL;

	bSuccess = ::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &hProcessToken);
	if (bSuccess) {
		TOKEN_ELEVATION bIsElevated;
		DWORD dwSize = sizeof(bIsElevated);

		bSuccess = GetTokenInformation(hProcessToken, TokenElevation, &bIsElevated, dwSize, &dwSize);
		bSuccess = bIsElevated.TokenIsElevated;
	}

	if (hProcessToken) {
		::CloseHandle(hProcessToken);
	}

	return bSuccess;
}

BOOL InitialiseCOM() {
	HRESULT hResult;

	hResult = ::CoInitialize(NULL);
	if (!SUCCEEDED(hResult)) {
		::wprintf(L"[>] [-] Error while initialising COM\n");
		return FALSE;
	}

	hResult = ::CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (!SUCCEEDED(hResult)) {
		::wprintf(L"[-] Error while initialising COM security\n");
		return FALSE;
	}

	return TRUE;
}

BOOL CreateTaskServiceInstance(ITaskService*& pTaskService) {
	HRESULT hResult = ::CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pTaskService);
	if (!SUCCEEDED(hResult)) {
		::wprintf(L"[-] Error while creating TaskService instance\n");
		return FALSE;
	}

	return TRUE;
}

BOOL ConnectToTaskService(ITaskService*& pTaskService) {
	VARIANT username;
	VARIANT password;
	VARIANT server;
	VARIANT domain;
	::VariantInit(&username);
	::VariantInit(&password);
	::VariantInit(&server);
	::VariantInit(&domain);

	HRESULT hResult = pTaskService->Connect(server, username, domain, password);
	if (!SUCCEEDED(hResult)) {
		::wprintf(L"[-] Error while connecting to the TaskService\n");
		return FALSE;
	}

	::VariantClear(&username);
	::VariantClear(&password);
	::VariantClear(&server);
	::VariantClear(&domain);
	return TRUE;
}

BOOL GetRootTaskFolder(ITaskFolder*& pTaskFolder, ITaskService*& pTaskService, BSTR& bstrRootFolder) {
	HRESULT hResult = pTaskService->GetFolder(bstrRootFolder, &pTaskFolder);
	if (!SUCCEEDED(hResult)) {
		::wprintf(L"[-] Error while getting the task root folder\n");
		return FALSE;
	}

	return TRUE;
}

BOOL EnumerateTasks(ITaskFolder*& pTaskFolder, DWORD indent) {
	HRESULT hResult;

	// Get current folder name
	BSTR bstrFolderName = NULL;
	pTaskFolder->get_Name(&bstrFolderName);
	wprintf_indent(bstrFolderName, indent, FALSE);

	// Get tasks in folder
	LONG lTasks = 0;
	IRegisteredTaskCollection* pTaskCollection = NULL;
	pTaskFolder->GetTasks(TASK_ENUM_HIDDEN, &pTaskCollection);
	pTaskCollection->get_Count(&lTasks);
	
	// Loop through all tasks
	for (LONG i = 0; i < lTasks; i++) {
		IRegisteredTask* pTask = NULL;
		VARIANT item;
		::VariantInit(&item);
		item.vt = VT_I4;
		item.lVal = i + 1;
		hResult = pTaskCollection->get_Item(item, &pTask);
		if (SUCCEEDED(hResult)) {
			BSTR bstrTaskName = NULL;
			hResult = pTask->get_Name(&bstrTaskName);
			if (SUCCEEDED(hResult)) {
				wprintf_indent(bstrTaskName, indent + 3, TRUE);
			}
			::SysFreeString(bstrTaskName);
		} else {
			::wprintf(L"[-] Error while retriving task %d\n", i + 1);
		}
	}

	// Get all sub folders in current folder
	LONG lTaskFolders = 0;
	ITaskFolderCollection* pNewTaskFolderCollections = NULL;
	pTaskFolder->GetFolders(0, &pNewTaskFolderCollections);
	pNewTaskFolderCollections->get_Count(&lTaskFolders);

	// Loop through all the folders
	for (LONG i = 0; i < lTaskFolders; i++) {
		ITaskFolder* pNewTaskFolder = NULL;
		VARIANT item;
		::VariantInit(&item);
		item.vt = VT_I4;
		item.lVal = i + 1;

		pNewTaskFolderCollections->get_Item(item, &pNewTaskFolder);
		EnumerateTasks(pNewTaskFolder, indent + 3);
		pNewTaskFolder->Release();
	}

	pTaskCollection->Release();
	return TRUE;
}

INT wmain() {
	::wprintf(L"[>] Windows Task Scheduler Experiments\n");
	::wprintf(L"[>] Author: Paul Laîné (@am0nsec)\n");
	::wprintf(L"   ----------------------------------------------------------------------------------\n\n");

	if (IsAdministrator())
		::wprintf(L"[>] Executed with elevated privileges\n\n");
	else
		::wprintf(L"[>] Executed without elevated privileges\n\n");

	ITaskService* pTaskService = NULL;
	ITaskFolder* pTaskFolder = NULL;
	IRegisteredTaskCollection* pTaskCollection = NULL;
	BSTR bstrRootFolder = ::SysAllocString(L"\\");

	InitialiseCOM();
	CreateTaskServiceInstance(pTaskService);
	ConnectToTaskService(pTaskService);
	GetRootTaskFolder(pTaskFolder, pTaskService, bstrRootFolder);

	::wprintf(L"[>] Parsing tasks ...\n");
	EnumerateTasks(pTaskFolder, 0);

	// Cleanup
	::wprintf(L"\n[>] Cleaning everything ...\n");
	pTaskFolder->Release();
	pTaskService->Release();
	::SysFreeString(bstrRootFolder);
	::CoUninitialize();
	::wprintf(L"[+] Cleaning everything ... OK\n\n");

	return 0;
}
