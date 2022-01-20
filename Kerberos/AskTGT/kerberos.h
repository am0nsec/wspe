
#ifndef __TGT_H_GUARD__
#define __TGT_H_GUARD__

#include <Windows.h>

#define STATUS_SUCCESS            0x00000000
#define STATUS_UNSUCCESSFUL       0xC0000001
#define STATUS_PRIVILEGE_NOT_HELD 0xC0000061
#define STATUS_NOT_SUPPORTED      0xC00000BB
#define STATUS_NO_TOKEN           0xC000007C

#ifndef NT_ERROR
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define KERBEROS_KEY_USAGE_AS_REQ_PA_ENC_TIMESTAMP        1
#define KERBEROS_KEY_USAGE_AS_REP_TGS_REP                 2
#define KERBEROS_KEY_USAGE_AS_REP_EP_SESSION_KEY          3
#define KERBEROS_KEY_USAGE_TGS_REQ_ENC_AUTHOIRZATION_DATA 4
#define KERBEROS_KEY_USAGE_TGS_REQ_PA_AUTHENTICATOR       7
#define KERBEROS_KEY_USAGE_TGS_REP_EP_SESSION_KEY         8
#define KERBEROS_KEY_USAGE_AP_REQ_AUTHENTICATOR           11
#define KERBEROS_KEY_USAGE_KRB_PRIV_ENCRYPTED_PART        13
#define KERBEROS_KEY_USAGE_KRB_CRED_ENCRYPTED_PART        14
#define KERBEROS_KEY_USAGE_KRB_NON_KERB_SALT              16
#define KERBEROS_KEY_USAGE_KRB_NON_KERB_CKSUM_SALT        17
#define KERBEROS_KEY_USAGE_PA_S4U_X509_USER               26

#define KERBEROS_PDATA_TYPE_NONE                     0
#define KERBEROS_PDATA_TYPE_TGS_REQ                  1
#define KERBEROS_PDATA_TYPE_AP_REQ                   1
#define KERBEROS_PDATA_TYPE_ENC_TIMESTAMP            2
#define KERBEROS_PDATA_TYPE_PW_SALT                  3
#define KERBEROS_PDATA_TYPE_ENC_UNIX_TIME            5
#define KERBEROS_PDATA_TYPE_SANDIA_SECUREID          6
#define KERBEROS_PDATA_TYPE_SESAME                   7
#define KERBEROS_PDATA_TYPE_OSF_DCE                  8
#define KERBEROS_PDATA_TYPE_CYBERSAFE_SECUREID       9
#define KERBEROS_PDATA_TYPE_AFS3_SALT                10
#define KERBEROS_PDATA_TYPE_ETYPE_INFO               11
#define KERBEROS_PDATA_TYPE_SAM_CHALLENGE            12
#define KERBEROS_PDATA_TYPE_SAM_RESPONSE             13
#define KERBEROS_PDATA_TYPE_SAM_RESPONSE             13
#define KERBEROS_PDATA_TYPE_PK_AS_REQ_19             14
#define KERBEROS_PDATA_TYPE_PK_AS_REP_19             15
#define KERBEROS_PDATA_TYPE_PK_AS_REQ_WIN            15
#define KERBEROS_PDATA_TYPE_PK_AS_REQ                16
#define KERBEROS_PDATA_TYPE_PK_AS_REP                17
#define KERBEROS_PDATA_TYPE_PA_PK_OCSP_RESPONSE      18
#define KERBEROS_PDATA_TYPE_ETYPE_INFO2              19
#define KERBEROS_PDATA_TYPE_USE_SPECIFIED_KVNO       20
#define KERBEROS_PDATA_TYPE_SVR_REFERRAL_INFO        20
#define KERBEROS_PDATA_TYPE_SAM_REDIRECT             21
#define KERBEROS_PDATA_TYPE_GET_FROM_TYPED_DATA      22
#define KERBEROS_PDATA_TYPE_SAM_ETYPE_INFO           23
#define KERBEROS_PDATA_TYPE_SERVER_REFERRAL          25
#define KERBEROS_PDATA_TYPE_TD_KRB_PRINCIPAL         102
#define KERBEROS_PDATA_TYPE_PK_TD_TRUSTED_CERTIFIERS 104
#define KERBEROS_PDATA_TYPE_PK_TD_CERTIFICATE_INDEX  105
#define KERBEROS_PDATA_TYPE_TD_APP_DEFINED_ERROR     106
#define KERBEROS_PDATA_TYPE_TD_REQ_NONCE             107
#define KERBEROS_PDATA_TYPE_TD_REQ_SEQ               108
#define KERBEROS_PDATA_TYPE_PA_PAC_REQUEST           128
#define KERBEROS_PDATA_TYPE_S4U2SELF                 129
#define KERBEROS_PDATA_TYPE_PA_S4U_X509_USER         130
#define KERBEROS_PDATA_TYPE_PA_PAC_OPTIONS           167
#define KERBEROS_PDATA_TYPE_PK_AS_09_BINDING         132
#define KERBEROS_PDATA_TYPE_CLIENT_CANONICALIZED     133

#define KERBEROS_MESSAGE_TYPE_AS_REQ   10
#define KERBEROS_MESSAGE_TYPE_AS_REP   11
#define KERBEROS_MESSAGE_TYPE_TGS_REQ  12
#define KERBEROS_MESSAGE_TYPE_TGS_REP  13
#define KERBEROS_MESSAGE_TYPE_AP_REQ   14
#define KERBEROS_MESSAGE_TYPE_AP_REP   15
#define KERBEROS_MESSAGE_TYPE_TGT_REQ  16
#define KERBEROS_MESSAGE_TYPE_TGT_REP  17
#define KERBEROS_MESSAGE_TYPE_SAFE     20
#define KERBEROS_MESSAGE_TYPE_PRIV     21
#define KERBEROS_MESSAGE_TYPE_CRED     22
#define KERBEROS_MESSAGE_TYPE_ERROR    30

#define KERBEROS_ETYPE_DES_CBC_CRC                     1
#define KERBEROS_ETYPE_DES_CBC_MD4                     2
#define KERBEROS_ETYPE_DES_CBC_MD5                     3
#define KERBEROS_ETYPE_DES3_CBC_MD5                    5
#define KERBEROS_ETYPE_DES3_CBC_SHA1                   7
#define KERBEROS_ETYPE_DSA_WITH_SHA1_CMSOID            9
#define KERBEROS_ETYPE_MD5_WITH_RSA_ENCRYPTION_CMSOID  10
#define KERBEROS_ETYPE_SHA1_WITH_RSA_ENCRYPTION_CMSOID 11
#define KERBEROS_ETYPE_RC2CBC_ENVOID                   12
#define KERBEROS_ETYPE_RSA_ENCRYPTION_ENVOID           13
#define KERBEROS_ETYPE_RSA_ES_OAEP_ENV_IOD             14
#define KERBEROS_ETYPE_DES_EDE3_CBC_ENV_OID            15
#define KERBEROS_ETYPE_DES3_CBC_SHA1_KD                16
#define KERBEROS_ETYPE_AES128_CTS_HMAC_SHA1            17
#define KERBEROS_ETYPE_AES256_CTS_HMAC_SHA1            18
#define KERBEROS_ETYPE_RC4_HMAC                        23
#define KERBEROS_ETYPE_RC4_HMAC_EXPORT                 24
#define KERBEROS_ETYPE_SUBKEY_MATERIAL                 65
#define KERBEROS_ETYPE_OLD_EXP                         -135

// ASN.1 Tag identifiers
#define ASN_TAG_INTEGER            0x02
#define ASN_TAG_BIT_STRING         0x03
#define ASN_TAG_OCTET_STRING       0x04
#define ASN_TAG_NULL               0x05
#define ASN_TAG_OBJECT_IDENTIFIER  0x06
#define ASN_TAG_UTF8STRING         0x0C
#define ASN_TAG_SEQUENCE           0x10
#define ASN_TAG_SEQUENCE_OF        (ASN_TAG_SEQUENCE)
#define ASN_TAG_SET                0x11
#define ASN_TAG_SET_OF             (ASN_TAG_SET)
#define ASN_TAG_PRINTABLE_STRING   0x13
#define ASN_TAG_IA5_STRING         0x16
#define ASN_TAG_UTC_TIME           0x17
#define ASN_TAG_GENERALIZED_TIME   0x18

// ASN.1 Tag classes
#define ASN_TAG_CLASS_UNIVERSAL        0
#define ASN_TAG_CLASS_APPLPICATION     1
#define ASN_TAG_CLASS_CONTEXT_SPECIFIC 2
#define ASN_TAG_CLASS_PRIVATE          3

/// <summary>
/// ASN.1 BER Element
/// </summary>
typedef struct _ASN_ELEMENT {
    INT32 TagValue;       // Tag of the element. Look at ASN_TAG_*
    INT32 TagClass;       // Tag class of the elemnt. Look at ASN_TAG_CLASS_*

    // Sub elements if composed
    PBYTE Sub;            // List of sub ASN.1 element
    UINT8 SubElements;    // If != 0x00 constructed element otherwise primitive element

    // Internal Values
    PBYTE   ObjectBuffer; // The final object to use
    INT32   ObjectLength; // Length of the encoded object
    INT32   ObjectOffset; // Offset of the objetc buffer
    INT32   ValueOffset;  // Offset of the value
    INT32   ValueLength;  // Length of the value held by the object
    BOOLEAN Encoded;      // Whether the object has been already encoded.
}ASN_ELEMENT, *PASN_ELEMENT;

///EncryptedData::= SEQUENCE {
///    etype[0] Int32 -- EncryptionType --,
///    kvno[1] UInt32 OPTIONAL,
///    cipher[2] OCTET STRING -- ciphertext
///}
typedef struct _ENCRYPTED_DATA {
    INT32  EType;
    UINT32 kvno;
    LPVOID cipher;
} ENCRYPTED_DATA, *PENCRYPTED_DATA;

/// <summary>
/// Used in conjunction with cryptdll.dll
/// </summary>
typedef struct _KERBEROS_ECRYPT {
    INT32  Type0;
    INT32  BlockSize;
    INT32  Type1;
    INT32  KeySize;
    INT32  Size;
    INT32  Unknown2;
    INT32  Unknown3;
    LPVOID AlgName;
    LPVOID Initialize;
    LPVOID Encrypt;
    LPVOID Decrypt;
    LPVOID Finish;
    LPVOID HashPassword;
    LPVOID RandomKey;
    LPVOID Control;
    LPVOID Unknown0Null;
    LPVOID Unknown1Null;
    LPVOID Unknown2Null;
} KERBEROS_ECRYPT, *PKERBEROS_ECRYPT;

//-------------------------------------------------------------------------------------------------//
// External functions
//-------------------------------------------------------------------------------------------------//
typedef INT32(STDMETHODCALLTYPE* fnCDLocateCSystem)(
    _In_  INT32  Etype,
    _Out_ LPVOID AddressOfStructure
);

typedef INT32(STDMETHODCALLTYPE* fnInitialize)(
    _In_  LPBYTE  Key,
    _In_  INT32   KeySize,
    _In_  INT32   KeyUsage,
    _Out_ LPVOID* Context
);

typedef INT32(STDMETHODCALLTYPE* fnEncrypt)(
    _In_  LPVOID Context,
    _In_  LPBYTE BufferIn,
    _In_  INT32  BufferInSize,
    _Out_ LPBYTE BufferOut,
    _Out_ DWORD* BufferOutSize
);

typedef INT32(STDMETHODCALLTYPE* fnFinish)(
    _In_ LPVOID Context
);

//-------------------------------------------------------------------------------------------------//
// Public functions
//-------------------------------------------------------------------------------------------------//
NTSTATUS KerbGeneratePvnoAndType(
    _Out_ ASN_ELEMENT* Pvno,
    _Out_ ASN_ELEMENT* MessageType
);

NTSTATUS KerbGenerateEncryptedData(
    _In_  LPCSTR       StringKey,
    _In_  DWORD        StringKeySize,
    _Out_ ASN_ELEMENT* EncryptedData
);

NTSTATUS KerbGeneratePac(
    _Out_ ASN_ELEMENT* pElement
);

//-------------------------------------------------------------------------------------------------//
// Private functions
//-------------------------------------------------------------------------------------------------/
INT32 KerbpGetAsnTagLength(
    _In_ INT32 Tag
);

INT32 KerbpGetAsnLengthLenght(
    _In_ INT32 Length
);

INT32 KerbpAsnGetEffectiveEncodedLength(
    _In_ ASN_ELEMENT* pElement
);

INT32 KerbpAsnGetEffectiveValueLenght(
    _In_ ASN_ELEMENT* pElement
);

NTSTATUS KerbpAsnMakePrimitive(
    _Inout_ ASN_ELEMENT* pElement,
    _In_    CONST INT8   TagClass,
    _In_    CONST INT8   TagValue,
    _In_    CONST PBYTE  pBuffer,
    _In_    CONST INT32  Offset,
    _In_    CONST INT32  Length
);

NTSTATUS KerbpAsnMakeConstructed(
    _Inout_ ASN_ELEMENT* pElement,
    _In_    CONST INT8         TagClass,
    _In_    CONST INT8         TagValue,
    _In_    CONST ASN_ELEMENT* pSubElements,
    _In_    CONST DWORD        NumberOfSubElements
);

NTSTATUS KerbpAsnMakeImplicit(
    _In_  ASN_ELEMENT* pElementIn,
    _In_  CONST INT8   TagClass,
    _In_  CONST INT8   TagValue,
    _Out_ ASN_ELEMENT* pElementOut
);

NTSTATUS KerbpAsnMakeInteger(
    _Inout_ ASN_ELEMENT* pElement,
    _In_    LONG         Value
);

INT32 KerbpAnsEncodeValue(
    _In_  ASN_ELEMENT* pElement,
    _In_  INT32        Start,
    _In_  INT32        End,
    _In_  INT32        RawElementOffset,
    _Out_ PBYTE        pRawElement
);

INT32 KerbpAsnEncode(
    _In_  ASN_ELEMENT* pElement,
    _In_  INT32        Start,
    _In_  INT32        End,
    _In_  DWORD        RawElementOffset,
    _Out_ PBYTE        pRawElement
);

NTSTATUS KerbpEncryptInternal(
    _In_  INT32            EType,
    _Out_ KERBEROS_ECRYPT* pECrypt
);

NTSTATUS KerbpEncrypt(
    _In_  INT32  EType,
    _In_  INT32  EncReason,
    _In_  PBYTE  Key,
    _In_  DWORD  KeyLength,
    _In_  PBYTE  BufferIn,
    _In_  DWORD  BufferInSize,
    _Out_ PBYTE* BufferOut,
    _Out_ DWORD* BufferOutSize
);

NTSTATUS KerbpGenerateTimestamp(
    _Out_ ASN_ELEMENT* Timestamp
);

NTSTATUS KerbpEncryptTimestamp(
    _In_  LPBYTE          Key,
    _In_  DWORD           KeySize,
    _In_  ASN_ELEMENT* Timestamp,
    _Out_ ENCRYPTED_DATA* EncryptedData,
    _Out_ DWORD* EncryptedDataSize
);

NTSTATUS KerbpEncodeEncryptedData(
    _In_  ENCRYPTED_DATA* EncryptedData,
    _In_  DWORD           EncryptedDataSize,
    _Out_ PBYTE* RawData,
    _Out_ DWORD* RawDataSize
);

NTSTATUS KerbpFormatTimestamp(
    _Out_ CHAR** pszBuffer,
    _In_  CONST DWORD dwBufferSize,
    _In_  CONST CHAR* Format,
    _In_  ...
);

#endif// !__TGT_H_GUARD__