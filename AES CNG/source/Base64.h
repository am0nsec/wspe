#pragma once
#include <Windows.h>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#pragma comment(lib, "libcrypto.lib")

size_t GetDecodedLength(std::string EncodedString) {
	size_t len = EncodedString.size();
	size_t padding = 0;

	if (EncodedString[len - 1] == '=' && EncodedString[len - 2] == '=') {
		padding = 2;
	} else if (EncodedString[len - 1] == '=') {
		padding = 1;
	}

	len = ((len * 3) / 4) - padding;
	return len;
}

namespace Base64 {
	std::string Base64Encode(PUCHAR input, int Length) {
		BIO* bio = NULL;
		BIO* b64 = NULL;
		BUF_MEM* bPointer = NULL;

		b64 = BIO_new(BIO_f_base64());
		bio = BIO_new(BIO_s_mem());
		bio = BIO_push(b64, bio);

		BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

		BIO_write(b64, input, Length);
		BIO_flush(bio);
		BIO_get_mem_ptr(bio, &bPointer);
		BIO_set_close(bio, BIO_NOCLOSE);
		BIO_free_all(bio);

		std::string result(bPointer->length, '\0');
		RtlCopyMemory(&result[0], bPointer->data, bPointer->length);
		BUF_MEM_free(bPointer);

		return result;
	}

	std::vector<uint8_t> Base64Decode(std::string input) {
		BIO* bio = NULL;
		BIO* b64 = NULL;

		bio = BIO_new_mem_buf(input.c_str(), -1);
		b64 = BIO_new(BIO_f_base64());
		bio = BIO_push(b64, bio);

		BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

		size_t DecodedLength = GetDecodedLength(input);
		std::vector<uint8_t> OriginalEncryptedValues(DecodedLength, 0);

		BIO_read(bio, OriginalEncryptedValues.data(), static_cast<int>(DecodedLength));
		BIO_free_all(bio);

		return OriginalEncryptedValues;
	}
}