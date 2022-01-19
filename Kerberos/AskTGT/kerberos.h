
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


// https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.2
//Padata and Data Type    Padata-type   Comment
//                         Value
//PA-TGS-REQ                  1
//PA-ENC-TIMESTAMP            2
//PA-PW-SALT                  3
//[reserved]                  4
//PA-ENC-UNIX-TIME            5        (deprecated)
//PA-SANDIA-SECUREID          6
//PA-SESAME                   7
//PA-OSF-DCE                  8
//PA-CYBERSAFE-SECUREID       9
//PA-AFS3-SALT                10
//PA-ETYPE-INFO               11
//PA-SAM-CHALLENGE            12       (sam/otp)
//PA-SAM-RESPONSE             13       (sam/otp)
//PA-PK-AS-REQ_OLD            14       (pkinit)
//PA-PK-AS-REP_OLD            15       (pkinit)
//PA-PK-AS-REQ                16       (pkinit)
//PA-PK-AS-REP                17       (pkinit)
//PA-ETYPE-INFO2              19       (replaces pa-etype-info)
//PA-USE-SPECIFIED-KVNO       20
//PA-SAM-REDIRECT             21       (sam/otp)
//PA-GET-FROM-TYPED-DATA      22       (embedded in typed data)
//TD-PADATA                   22       (embeds padata)
//PA-SAM-ETYPE-INFO           23       (sam/otp)
//PA-ALT-PRINC                24       (crawdad@fnal.gov)
//PA-SAM-CHALLENGE2           30       (kenh@pobox.com)
//PA-SAM-RESPONSE2            31       (kenh@pobox.com)
//PA-EXTRA-TGT                41       Reserved extra TGT
//TD-PKINIT-CMS-CERTIFICATES  101      CertificateSet from CMS
//TD-KRB-PRINCIPAL            102      PrincipalName
//TD-KRB-REALM                103      Realm
//TD-TRUSTED-CERTIFIERS       104      from PKINIT
//TD-CERTIFICATE-INDEX        105      from PKINIT
//TD-APP-DEFINED-ERROR        106      application specific
//TD-REQ-NONCE                107      INTEGER
//TD-REQ-SEQ                  108      INTEGER
//PA-PAC-REQUEST              128      (jbrezak@exchange.microsoft.com)

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

//https://datatracker.ietf.org/doc/html/rfc4120#section-7.5.7
//Message Type   Value  Meaning
//
//KRB_AS_REQ      10    Request for initial authentication
//KRB_AS_REP      11    Response to KRB_AS_REQ request
//KRB_TGS_REQ     12    Request for authentication based on TGT
//KRB_TGS_REP     13    Response to KRB_TGS_REQ request
//KRB_AP_REQ      14    Application request to server
//KRB_AP_REP      15    Response to KRB_AP_REQ_MUTUAL
//KRB_RESERVED16  16    Reserved for user-to-user krb_tgt_request
//KRB_RESERVED17  17    Reserved for user-to-user krb_tgt_reply
//KRB_SAFE        20    Safe (checksummed) application message
//KRB_PRIV        21    Private (encrypted) application message
//KRB_CRED        22    Private (encrypted) message to forward
//                        credentials
//KRB_ERROR       30    Error response

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

// https://datatracker.ietf.org/doc/html/rfc3961#section-8
//     encryption type                etype      section or comment
//     -----------------------------------------------------------------
//     des-cbc-crc                        1             6.2.3
//     des-cbc-md4                        2             6.2.2
//     des-cbc-md5                        3             6.2.1
//     [reserved]                         4
//     des3-cbc-md5                       5
//     [reserved]                         6
//     des3-cbc-sha1                      7
//     dsaWithSHA1-CmsOID                 9           (pkinit)
//     md5WithRSAEncryption-CmsOID       10           (pkinit)
//     sha1WithRSAEncryption-CmsOID      11           (pkinit)
//     rc2CBC-EnvOID                     12           (pkinit)
//     rsaEncryption-EnvOID              13   (pkinit from PKCS#1 v1.5)
//     rsaES-OAEP-ENV-OID                14   (pkinit from PKCS#1 v2.0)
//     des-ede3-cbc-Env-OID              15           (pkinit)
//     des3-cbc-sha1-kd                  16              6.3
//     aes128-cts-hmac-sha1-96           17          [KRB5-AES]
//     aes256-cts-hmac-sha1-96           18          [KRB5-AES]
//     rc4-hmac                          23          (Microsoft)
//     rc4-hmac-exp                      24          (Microsoft)
//     subkey-keymaterial                65     (opaque; PacketCable)

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
    PBYTE Value;          // Value of the element

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


///PA-DATA         ::= SEQUENCE {
///        -- NOTE: first tag is [1], not [0]
///        padata-type     [1] Int32,
///        padata-value    [2] OCTET STRING -- might be encoded AP-REQ
///}
typedef struct _PA_DATA {
    UINT32 Type;
    LPVOID Value;
} PA_DATA, * PPA_DATA;

///KDC-REQ-BODY::= SEQUENCE {
///    kdc-options[0] KDCOptions,
///    cname[1] PrincipalName OPTIONAL
///                                -- Used only in AS-REQ --,
///    realm[2] Realm
///                                -- Server's realm
///                                -- Also client's in AS-REQ --,
///    sname[3] PrincipalName OPTIONAL,
///    from[4] KerberosTime OPTIONAL,
///    till[5] KerberosTime,
///    rtime[6] KerberosTime OPTIONAL,
///    nonce[7] UInt32,
///    etype[8] SEQUENCE OF Int32   -- EncryptionType
///                                 -- in preference order --,
///    addresses[9] HostAddresses OPTIONAL,
///    enc-authorization-data[10] EncryptedData OPTIONAL
///                                 -- AuthorizationData --,
///    additional-tickets[11] SEQUENCE OF Ticket OPTIONAL
///                                 -- NOTE: not empty
///}
typedef struct _KERBEROS_KDC_REQ_BODY {
    LPVOID Todo;
} KERBEROS_KDC_REQ_BODY, *PKERBEROS_KDC_REQ_BODY;


///AS-REQ          ::= [APPLICATION 10] KDC-REQ
///KDC-REQ         ::= SEQUENCE {
///    -- NOTE: first tag is [1], not [0]
///    pvno            [1] INTEGER (5) ,
///    msg-type        [2] INTEGER (10 -- AS),
///    padata          [3] SEQUENCE OF PA-DATA OPTIONAL
///                       -- NOTE: not empty --,
///    req-body        [4] KDC-REQ-BODY
///}
typedef struct _KERBEROS_AS_REQ {
    UINT64  pvno;
    UINT64  msg_type;



} KERBEROS_AS_REQ, * PKERBEROS_AS_REQ;

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


#endif// !__TGT_H_GUARD__

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
NTSTATUS KerbGenerateSystemTimestampPAData(
    _In_  LPCSTR StringKey,
    _In_  DWORD  StringKeySize,
    _Out_ PBYTE* EncryptedTimestamp,
    _Out_ DWORD* EncryptedTimestampSize
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

NTSTATUS KerbpFormatTimestamp(
    _Out_ CHAR** pszBuffer,
    _In_  CONST DWORD dwBufferSize,
    _In_  CONST CHAR* Format,
    _In_  ...
);
