#pragma once
#include <Windows.h>
#include <bcrypt.h>

namespace CNG {
	static const BYTE rgbIV[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};

	static const BYTE rgbAES128Key[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
	};

	class AES {
		public:
			BOOL WINAPI Initialise();
		
		protected:
			~AES();

			BCRYPT_ALG_HANDLE hBcryptAlgHandle = NULL;
			BCRYPT_KEY_HANDLE hKeyHandle = NULL;

			BOOL bIsInitialised = FALSE;
			BOOL bAlreadyUsed = FALSE;

			DWORD cbKeyObject = 0;
			DWORD cbData = 0;
			DWORD cbBlockLen = 0;
			DWORD cbPlainText = 0;
			DWORD cbCipherText = 0;

			PBYTE pbKeyObject = NULL;
			PBYTE pbIV = NULL;
			PBYTE pbPlainText = NULL;
			PBYTE pbCipherText = NULL;
	};

	class AESEncrypt : public AES {
		public:
			~AESEncrypt();
			BOOL WINAPI Encrypt();
			BOOL WINAPI SetStringToEncrypt(std::string sPlaintext);
			BOOL WINAPI SetBase64StringToEncrypt(std::string sPlaintext);
			std::string WINAPI GetEncryptedString();
			std::string WINAPI GetEncryptedBase64String();
	};

	class AESDecrypt : public AES {
		public:
			~AESDecrypt();
			BOOL WINAPI Decrypt();
			BOOL WINAPI SetStringToDecrypt(std::string sCipherText);
			BOOL WINAPI SetBase64StringToDecrypt(std::string sCipherText);
			std::string WINAPI GetDecryptedString();
			std::string WINAPI GetDecryptedBase64String();
	};
}