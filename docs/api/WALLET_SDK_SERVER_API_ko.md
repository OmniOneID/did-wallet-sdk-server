---
puppeteer:
    pdf:
        format: A4
        displayHeaderFooter: true
        landscape: false
        scale: 0.8
        margin:
            top: 1.2cm
            right: 1cm
            bottom: 1cm
            left: 1cm
    image:
        quality: 100
        fullPage: false
---

Wallet SDK Server API
==

- 주제: Wallet SDK Server API
- 작성: 이영준
- 일자: 2024-08-29
- 버전: v1.0.0

| 버전   | 일자       | 변경 내용                 |
| ------ | ---------- | -------------------------|
| v1.0.0 | 2024-08-29 | 초안 작성                |


<div style="page-break-after: always;"></div>

## 목차

- [기능 목록(APIs)](#기능-목록)
  - [1. create](#1-create)
  - [2. connect](#2-connect)
  - [3. isConnect](#3-isConnect)
  - [4. disconnect](#4-disconnect)
  - [5. changePassword](#5-changepassword)
  - [6. generateCompactSignatureFromHash](#6-generatecompactsignaturefromhash)
  - [7. addKey](#7-addkey)
  - [8. generateRandomKey](#8-generaterandomkey)
  - [9. isExistKey](#9-isexistkey)
  - [10. getPublicKey](#10-getpublickey)
  - [11. getKeyAlgorithm](#11-getkeyalgorithm)
  - [12. getKeyElement](#12-getkeyelement)
  - [13. removeKey](#13-removekey)
  - [14. getKeyIdList](#14-getkeyidlist)
  - [15. removeAllKeys](#15-removeallkeys)
  - [16. getSharedSecret](#16-getsharedsecret)
- [기타 API 목록(APIs)](#기타-api-목록)
  - [1. encrypt](#1-encrypt)
  - [2. decrypt](#2-decrypt)
  - [3. sign](#3-sign)
  - [4. verify](#4-verify)
  - [5. getCompactSignature](#5-getcompactsignature)
- [enum 목록(Enumerators)](#enum-목록)
  - [1. WalletManagerType](#1-walletmanagertype)
  - [2. WalletEncryptType](#2-walletencrypttype)
  - [3. KeyAlgorithmType](#3-keyalgorithmtype)
- [Wallet](#wallet)
  - [Wallet 구조](#wallet-구조)
    - [Wallet 예시](#wallet-예시)
  - [1. File](#1-file)
  - [2. etc.](#2-etc)
- [데이터 모델(Models)](#데이터-모델)
  - [1. CryptoKeyPairInfo](#1-cryptokeypairinfo)
  - [2. KeyElement](#2-keyelement)
  



# 기능 목록
## 1. create

### Class Name

`WalletManagerInterface`

### Function Name

`create`

### Function Introduction

`지정된 매개변수로 wallet 파일을 생성합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| walletFilePath     | string | wallet 파일이 생성될 경로 |M|확장자(.wallet)까지 포함해야한다. |
| securePassword     | string | wallet 암호화를 위해 사용되는 보안 비밀번호 |M|비밀번호로 사용할 값|
| walletEncryptType  | string | wallet 암호화 스펙 |M| WalletEncryptType Enum의 값 사용 <br/>[Link](#2-walletencrypttype) <br/><br/>AES-256-CBC-PKCS5Padding, |

### Output Parameters

void

### Function Declaration

```cpp
// Function declaration in Java
walletManager.create(String walletFilePath, char[] securePassword, WalletEncryptType walletEncryptType);
```

### Function Usage

```cpp
walletManager.create("walletfile.wallet", "password123".toCharArray(), WalletEncryptType.AES_256_CBC_PKCS5Padding);
```

<br>

## 2. connect

### Class Name

`WalletManagerInterface`

### Function Name

`connect`

### Function Introduction

`지정된 매개변수로 기존 wallet 파일에 연결합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| walletFilePath | string | 기존 wallet의 경로     | M       | 확장자(.wallet)까지 포함해야한다. |
| securePassword | string | wallet 연결을 위해 사용되는 보안 비밀번호 | M | 비밀번호 값|

### Output Parameters

void

### Function Declaration

```cpp
// Function declaration in Java
walletManager.connect(String walletFilePath, char[] securePassword);
```

### Function Usage

```cpp
walletManager.connect("walletfile.wallet", "password123".toCharArray());
```

<br>

## 3. isConnect

### Class Name

`WalletManagerInterface`

### Function Name

`isConnect`

### Function Introduction

`wallet 현재 연결되어 있는지 확인합니다.`

### Input Parameters
n/a


### Output Parameters
| Type | Description                |**M/O** | **비고** |
|------|----------------------------|--------|----------|
| boolean | true / false            | M      | 연결되어 있으면 true, 그렇지 않으면 false |

### Function Declaration

```cpp
// Function declaration in Java
walletManager.isConnect();
```

### Function Usage

```cpp
boolean connectStatus = walletManager.isConnect();
```

<br>

## 4. disconnect

### Class Name

`WalletManagerInterface`

### Function Name

`disconnect`

### Function Introduction

`wallet 연결을 해제합니다.`

### Input Parameters

n/a


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|--------|---------|
| boolean | 성공적으로 연결이 해제되면 true, 그렇지 않으면 false | M | |

### Function Declaration

```cpp
// Function declaration in Java
walletManager.disConnect();
```

### Function Usage

```cpp
walletManager.disConnect();
```

<br>

## 5. changePassword

### Class Name

`WalletManagerInterface`

### Function Name

`changePassword`

### Function Introduction

`wallet의 보안 비밀번호를 변경합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|----------|
| currenSecurePassword | string | 현재 보안 비밀번호 | M      |         |
| newSecurePassword    | string | 새로운 보안 비밀번호 | M    |         |


### Output Parameters

void

### Function Declaration

```cpp
// Function declaration in Java
walletManager.changePassword(char[] currenSecurePassword, char[] newSecurePassword);
```

### Function Usage

```cpp
walletManager.changePassword("password123".toCharArray(), "newpassword123".toCharArray());
```

<br>

## 6. generateCompactSignatureFromHash

### Class Name

`WalletManagerInterface`

### Function Name

`generateCompactSignatureFromHash`

### Function Introduction

`키 ID에 해당하는 개인키와 해시된 원문 데이터로 compact 형태의 서명값을 생성합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|----------|
| keyId     | string | 서명에 사용할 개인키의 ID    | M       |         |
| hashedSource | byte[] | 해시된 원문 데이터       | M       |          |


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|--------|----------|
| byte[] | compact 형태의 서명값     | M      |          |


### Function Declaration

```cpp
// Function declaration in Java
walletManager.generateCompactSignatureFromHash(String keyId, byte[] hashedSource);
```

### Function Usage

```cpp
byte[] signatureBytes = walletManager.generateCompactSignatureFromHash("key1", DigestUtils.getDigest(originText.getBytes(), DigestType.SHA256));
```

<br>

## 7. addKey

### Class Name

`WalletManagerInterface`

### Function Name

`addKey`

### Function Introduction

`wallet에 키 쌍을 추가합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| cryptoKeyPairInfo | CryptoKeyPairInfo | 추가할 키 쌍의 정보 |M| [Link](#1-cryptokeypairinfo) |


### Output Parameters

void


### Function Declaration

```cpp
// Function declaration in Java
walletManager.addKey(CryptoKeyPairInfo cryptoKeyInfo);
```

### Function Usage

```cpp
KeyPairInterface keyParir = CryptoUtils.generateKeyPair(convertDidKeyType(keyAlgorithmType));
CryptoKeyPairInfo cryptoKeyPairInfo = new CryptoKeyPairInfo("key1", KeyAlgorithmType.SECP256r1.toString(), (PublicKey)keyParir.getPublicKey(), (PrivateKey)keyParir.getPrivateKey());
walletManager.addKey(CryptoKeyPairInfo cryptoKeyInfo);
```

<br>

## 8. generateRandomKey

### Class Name

`WalletManagerInterface`

### Function Name

`generateRandomKey`

### Function Introduction

`지정된 ID 및 알고리즘 유형으로 키쌍을 생성하여 wallet에 추가 합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|----------|
| keyId     | string | 생성할 키의 ID              | M       |         |
| keyAlgorithmType | KeyAlgorithmType | 키 생성에 사용할 알고리즘 유형 <br/><br/> SECP256R1, SECP256K1, RSA2048 |M| [Link](#3-KeyAlgorithmType) |


### Output Parameters

void


### Function Declaration

```cpp
// Function declaration in Java
walletManager.generateRandomKey(String keyId, KeyAlgorithmType keyAlgorithmType);
```

### Function Usage

```cpp
walletManager.generateRandomKey("assertion", KeyAlgorithmType.SECP256r1);
```

<br>

## 9. isExistKey

### Class Name

`WalletManagerInterface`

### Function Name

`isExistKey`

### Function Introduction

`지정된 ID로 키쌍 정보가 wallet에 존재하는지 확인합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| keyId     | string | 키의 ID                    | M       |         |


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|--------|----------|
| boolean | 키가 존재하면 true, 그렇지 않으면 false | M | |


### Function Declaration

```cpp
// Function declaration in Java
walletManager.isExistKey(String keyId);
```

### Function Usage

```cpp
boolean isSavedKey = walletManager.isExistKey("key1");
```

<br>

## 10. getPublicKey

### Class Name

`WalletManagerInterface`

### Function Name

`getPublicKey`

### Function Introduction

`지정된 키 ID에 해당하는 공개키를 반환합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|----------|
| keyId     | string | 키의 ID                    | M       |          |


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|---------|---------|
| String | base58 타입으로 멀티 인코딩된 공개키 문자열  |M| |


### Function Declaration

```cpp
// Function declaration in Java
walletManager.getPublicKey(String keyId);
```

### Function Usage

```cpp
String pubKey = walletManager.getPublicKey("key1");
```

<br>

## 11. getKeyAlgorithm

### Class Name

`WalletManagerInterface`

### Function Name

`getKeyAlgorithm`

### Function Introduction

`지정된 키 ID의  알고리즘을 반환합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| keyId     | string | 키의 ID                    | M       |          |


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|--------|---------|
| String | 키 알고리즘               | M      |         |


### Function Declaration

```cpp
// Function declaration in Java
walletManager.getKeyAlgorithm(String keyId);
```

### Function Usage

```cpp
String algorithm = walletManager.getKeyAlgorithm("key1");
```

<br>

## 12. getKeyElement

### Class Name

`WalletManagerInterface`

### Function Name

`getKeyElement`

### Function Introduction

`지정된 키 ID에 해당하는 키쌍 정보를 반환합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| keyId    | string    | 키의 ID |M||


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|--------|----------|
| KeyElement | 키쌍 정보             | M      |         |


### Function Declaration

```cpp
// Function declaration in Java
walletManager.getKeyElement(String keyId);
```

### Function Usage

```cpp
KeyElement key = walletManager.getKeyElement("key1");
```

<br>

## 13. removeKey

### Class Name

`WalletManagerInterface`

### Function Name

`removeKey`

### Function Introduction

`키 ID에 해당하는 키 쌍 정보를 wallet에서 삭제합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|----------|
| keyId     | string | 삭제할 키의 ID              | M       |         |


### Output Parameters

void


### Function Declaration

```cpp
// Function declaration in Java
walletManager.removeKey(String keyId);
```

### Function Usage

```cpp
walletManager.removeKey("key1");
```

<br>

## 14. 키 목록 조회

### Class Name

`WalletManagerInterface`

### Function Name

`getKeyIdList`

### Function Introduction

`wallet에 있는 모든 키 ID 목록을 반환합니다.`

### Input Parameters

n/a


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|--------|----------|
| List&lt;String&gt; | 키 ID 목록   | M       |         |


### Function Declaration

```cpp
// Function declaration in Java
walletManager.getKeyIdList();
```

### Function Usage

```cpp
List<String> walletKeyIds = walletManager.getKeyIdList();
```

<br>

## 15. removeAllKeys

### Class Name

`WalletManagerInterface`

### Function Name

`removeAllKeys`

### Function Introduction

`wallet에 저장된 모든 키를 삭제합니다.`

### Input Parameters
n/a


### Output Parameters
void


### Function Declaration

```cpp
// Function declaration in Java
walletManager.removeAllKeys();
```

### Function Usage

```cpp
walletManager.removeAllKeys();
```

<br>

## 16. getSharedSecret

### Class Name

`WalletManagerInterface`

### Function Name

`getSharedSecret`

### Function Introduction

`키 ID에 해당하는 개인키와 전달받은 압축 공개키로 SharedSecret을 생성합니다.`

### Input Parameters
| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| keyId     | string | 키의 ID                    | M       |          |
| mEncodedCompressedKey | string | 멀티 인코딩된 압축 공개키 | M |      |

### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|--------|---------|
| byte[] | 바이트 배열               | M      |         |


### Function Declaration

```cpp
// Function declaration in Java
walletManager.getSharedSecret(String keyId, String mEncodedCompressedKey);
```

### Function Usage

```cpp
// 상대방의 Base58인코딩된 compressedKey
String mEncodedCompressedKey = request.getPubKey;

byte[] sharedSecret = walletManager.getSharedSecret("key1", mEncodedCompressedKey);
```

<br>

# 기타 API 목록
## 1. encrypt

### Class Name

`EncryptionHelper`

### Function Name

`encrypt`

### Function Introduction

`파일 월렛에 저장되어 있는 키로 데이터를 암호화합니다. 키는 SECP256R1, SECP256K1 종류만 사용 가능합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|----------|
| source    | byte[] | 원문                       | M       |          |
| key       | byte[] | 키의 Byte값                | M       |          |
| iv        | byte[] | Initialization Vector      | M       |          |
| cipherSpec | String | SymmetricCipherType(암복호화 모드) Enum의 값 <br/><br/> AES-128-CBC, AES-128-ECB, AES-256-CBC, AES-256-ECB |M| crypto-SDK 참조 |
| padding   | String | SymmetricPaddingType(암복호화 패딩) Enum의 값 <br/><br/> NoPadding, PKCS5Padding |M| crypto-SDK 참조 |


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|--------|----------|
| byte[] | 암호화된 값               | M      |         |


### Function Declaration

```cpp
// Function declaration in Java
encryptionHelper.encrypt(byte[] source, byte[] key, byte[] iv, String cipherSpec, String padding);
```

### Function Usage

```cpp
byte[] iv = CryptoUtils.generateNonce(16);
byte[] nonce = CryptoUtils.generateNonce(32);
byte[] drivedKey = new byte[nonce.length + sharedSecret.length];
System.arraycopy(nonce, 0, drivedKey, 0, nonce.length);
System.arraycopy(sharedSecret, 0, drivedKey, nonce.length, sharedSecret.length);
byte[] key = Arrays.copyOfRange(DigestUtils.getDigest(drivedKey, DigestType.SHA256), 0, 32);
byte[] encryptedData = encryptionHelper.encrypt("originText".getBytes("UTF-8"), key, iv, "AES-256-CBC", "PKCS5Padding");
```

<br>

## 2. decrypt

### Class Name

`EncryptionHelper`

### Function Name

`decrypt`

### Function Introduction

`파일 월렛에 저장되어 있는 키로 데이터를 복호화합니다. 키는 SECP256R1, SECP256K1 종류만 사용 가능합니다.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|----------|
| cipherText | byte[] | 암호화된 값                | M       |          |
| key       | byte[] | 키의 Byte값                 | M       |         |
| iv        | byte[] | Initialization Vector      | M       |          |
| cipherSpec | String | SymmetricCipherType(암복호화 모드) Enum의 값 <br/><br/> AES-128-CBC, AES-128-ECB, AES-256-CBC, AES-256-ECB |M| crypto-SDK 참조 |
| padding   | String | SymmetricPaddingType(암복호화 패딩) Enum의 값 <br/><br/> NoPadding, PKCS5Padding |M| crypto-SDK 참조 |


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|--------|----------|
| byte[] | 원문                     | M      |          |


### Function Declaration

```cpp
// Function declaration in Java
encryptionHelper.decrypt(byte[] cipherText, byte[] key, byte[] iv, String cipherSpec, String padding);
```

### Function Usage

```cpp
byte[] opponentDrivedKey = new byte[nonce.length + opponentSharedSecret.length];
System.arraycopy(nonce, 0, opponentDrivedKey, 0, nonce.length);
System.arraycopy(opponentSharedSecret, 0, opponentDrivedKey, nonce.length, opponentSharedSecret.length);
byte[] opponentKey = Arrays.copyOfRange(DigestUtils.getDigest(opponentDrivedKey, DigestType.SHA256), 0, 32);
byte[] decryptedData = encryptionHelper.decrypt(encryptedData, opponentKey, iv, "AES-256-CBC", "PKCS5Padding");
```

<br>

## 3. sign

### Class Name

`SignatureHelper`

### Function Name

`sign`

### Function Introduction

`지정된 알고리즘을 사용하여 원본 해시 메시지에 대해 서명을 생성합니다.`

### Input Parameters
| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| algorithm | string | 개인키의 ID                 | M       |         |
| originalHashedMessage | byte[] | 원본 해시 메시지 | M      |          |
| privateKey | PrivateKey | 서명에 사용할 개인 키   | M       |         |


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|--------|---------|
| byte[] | 서명값 바이트 배열        | M      |          |


### Function Declaration

```cpp
// Function declaration in Java
SignatureHelper.sign(String algorithm, byte[] originalHashedMessage, PrivateKey privateKey);
```

### Function Usage

```cpp
byte[] hashedSource = DigestUtils.getDigest("원문".getBytes(), DigestType.SHA256);
byte[] signature = signatureHelper.sign(keyPairInfo.getAlgorithm(), hashedSource, (ECPrivateKey) keyPairInfo.getKeyPair().getPrivateKey());
```

<br>

## 4. verify

### Class Name

`SignatureHelper`

### Function Name

`verify`

### Function Introduction

`지정된 알고리즘을 사용하여 서명을 검증합니다.`

### Input Parameters
| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|---------|
| algorithm | string | 서명 검증에 사용할 알고리즘  | M       |          |
| signData  | byte[] | 검증할 서명 데이터          | M       |          |
| publicKeyBytes | byte[] | 검증에 사용할 압축 공개키 | M     |         |
| originalHashedMessage | byte[] | 원본 해시 메시지 | M      |          |


### Output Parameters

void <br/>
(서명 검증 실패시, Exception발생)


### Function Declaration

```cpp
// Function declaration in Java
SignatureHelper.verify(String algorithm, byte[] signData, byte[] publicKeyBytes, byte[] originalHashedMessage);
```

### Function Usage

```cpp
KeyElement key = request.getPubKey;
byte[] unCompressedPublicKeyBytes = encryptionHelper.getUncompressPublicKey(keyElement.getPublicKey(), keyElement.getAlgorithm());
byte[] originalHashedMessage = request.getHashedSource;
signatureHelper.verify(keyPairInfo.getAlgorithm(), signData, unCompressedPublicKeyBytes, originalHashedMessage);
```

<br>

## 5. getCompactSignature

### Class Name

`SignatureHelper`

### Function Name

`getCompactSignature`

### Function Introduction

`서명 데이터를 compact 서명 형식으로 변환합니다.`

### Input Parameters
| Parameter | Type   | Description                | **M/O** | **비고** |
|-----------|--------|----------------------------|---------|----------|
| algorithm | string | 서명 알고리즘               | M       |          |
| signData  | byte[] | 서명값                     | M       |          |
| publicKey | PublicKey | 공개키                  | M       |          |
| originalHashedMessage | byte[] | 원본 해시 메시지 | M      |          |


### Output Parameters

| Type | Description                |**M/O** | **비고** |
|------|----------------------------|--------|---------|
| byte[] | compact 형태의 서명값     | M      |          |


### Function Declaration

```cpp
// Function declaration in Java
SignatureHelper.getCompactSignature(String algorithm, byte[] signedData, PublicKey publicKey, byte[] originalHashedMessage);
```

### Function Usage

```cpp
byte[] compactSignature = signatureHelper.getCompactSignature(keyPairInfo.getAlgorithm(), signature, (PublicKey)keyPairInfo.getKeyPair().getPublicKey(), hashedSource);
```

<br><br><br><br>

# enum 목록

## 1. WalletManagerType

### Description
`Wallet Manager 종류`

### Declaration
```cpp
// Declaration in Java
public enum WalletManagerType {
    FILE, ;
}
```

## 2. WalletEncryptType

### Description
`Wallet의 암호화 Algorithm 종류`

### Declaration
```cpp
// Declaration in Java
public enum WalletEncryptType {
    AES_256_CBC_PKCS5Padding("AES-256-CBC-PKCS5Padding");
}
```

## 3. KeyAlgorithmType

### Description
`Key의 Algorithm 종류`

### Declaration
```cpp
// Declaration in Java
public enum KeyAlgorithmType {
    SECP256k1("Secp256k1"),
    SECP256r1("Secp256r1"),
    RSA2048("Rsa2048");
}
```

<br><br><br><br>

# Wallet

## wallet 구조

```cpp
{
    "head": {
        "encryptionInfo": {  // privateKey 암호화 방법 정의. + WalletEncryptType 참조
            "aesAlgorithm": "...",  // 암호화 알고리즘
            "padding": "...",  // 암호화시 padding 방식
            "mode": "...",  // 암호화 방식
            "keySize": ...  // 암호화시 사용할 key길이
        },
        "secureKeyInfo": {  // wallet 비밀번호 확인용 데이터
            "salt": "...",  // pbkdf2 암호화시 salt(=nonce)
            "iterations": ...,  // pbkdf2 암호화 라운드 수
            "secretPhrase": "..."  // wallet 비밀번호 확인용 데이터(특정 데이터를 암호화한 값)
        },
        "version": ...,  // wallet의 버전
        "encoding": {    // wallet의 인코딩 타입
            "keyEncodingType": "..."  // 멀티베이스인코딩 타입 : f(base16), F(base16upper), z(base58btc), u(base64url), m(base64)
        }
    },
    "keys": [  // wallet에 저장된 key List
        {
            "keyId": "...",  // key의 id
            "alg": ...,      // key 알고리즘의 Curve 종류 : 0(Secp256k1), 1(Secp256r1)
            "algString": "...",  // key 알고리즘의 Curve 종류 : Secp256k1, Secp256r1
            "publicKey": "...",  // 멀티베이스인코딩된 publicKey
            "privateKey": "..."  // 멀티베이스인코딩된 암호화된 privateKey
        }, ...
    ]
}
```

### wallet 예시
```cpp
{
    "head": {
        "encryptionInfo": {
            "aesAlgorithm": "AES",
            "padding": "PKCS5Padding",
            "mode": "CBC",
            "keySize": 32
        },
        "secureKeyInfo": {
            "salt": "z5ST3qQDyAnNwAfHQpFDLYVciAn1XEVAfs41S5zjTJAiH",
            "iterations": 2048,
            "secretPhrase": "zYCtayQKfR8ai3q9YUg1Jor"
        },
        "version": 0,
        "encoding": {
            "keyEncodingType": "z"
        }
    },
    "keys": [
        {
            "keyId": "assert",
            "alg": 1,
            "algString": "Secp256r1",
            "publicKey": "z2BYYpW33szPTBMmsVWfVgHUvZ6prSEs9x1S3ruFtBsp1N",
            "privateKey": "z4edB9qUTvRNARGpq7tqkki5b4TXH4BJxpULvsv81kRmi1jeNWZWxUbUtpqt4ngxC2hrMEZViJNGMi9KV5qcaKrYYp6U6phQXJ6dhPNM75X9tDUNpUF5uGGkXWxk8DjJBncFDaKCv6xhjZmVBuXGHX78aJqnM83XJ2CGwZfDDaerd76NRqWbQTm9FKaJyBje9MRBst1JswVt1CN9nAd5QcXQmVto"
        },
        {
            "keyId": "auth",
            "alg": 1,
            "algString": "Secp256r1",
            "publicKey": "zky3CWL7tCvJbaimcxAwuNr9L9gsD6Vm7pbJypKCA2Ts2",
            "privateKey": "z4edB9qUTvRNARGpq7tqkki5b4TXH4BJxpULvsv81kRmhpGqbMbzqx9L37fVDFBmCUnuDL7iQMbnXXdesG89mvNPzMLwEpS9QcVe4PhrraAjViti3r4TXSZkzX1H8NtsRoUowWJ2MmfKxhPceeacbUhf5r9icQAB8Q3S1qgP4Nbp52TDYqWgb9nC8B1JSGRirZxd762qYV2R3DZF62vUxPowyoHC"
        },
        {
            "keyId": "invoke",
            "alg": 1,
            "algString": "Secp256r1",
            "publicKey": "zupm7yV2VhTKF7KG7Rc4aUkdv8HHpY5vUdbqvVhkfgeG5",
            "privateKey": "z4edB9qUTvRNARGpq7tqkki5b4TXH4BJxpULvsv81kRmhx9C4aEpR3HzM9uLNcmineEwvgtVJv5pjydhQ8HGGuBshohXD9EX3oEVe9oXKUWSaQCwSmgFxydZuhq9SDftQBVuoR3knoh2pVtywE35sgUagS5y71ALATKzEAMJEteFLZoAb7eecAN7JodD8iLgaqezp2dahYJcy4T3wyNyubu3eiAy"
        },
        {
            "keyId": "keyagree",
            "alg": 1,
            "algString": "Secp256r1",
            "publicKey": "z22KMujD83k9WJMvMgq3tJMWeyQUhuokpoE5z6vQbJSLtd",
            "privateKey": "z4edB9qUTvRNARGpq7tqkki5b4TXH4BJxpULvsv81kRmhmNs568H1AF8CJoEjNiqidw46zdTreD5ECCvY6yHPN77WVLF7YBaJ13NaYByxvY41dvUbjVKUryekeG7pZPEuM6WsLcNdTCRb84vbioPAaWEhyzSq6L8YX2YharbGcZX6vAsSWSPR3w3Qes4boqQG4jY9AP9uyLLQ2bNXiSig61foHer"
        }
    ]
}
```

## 1. File

### Description

`file을 이용한 wallet`

### Declaration

```cpp
// Declaration in Java
WalletManagerInterface walletManager = WalletManagerFactory.getWalletManager(WalletManagerType.FILE);
walletManager.connect(fileName, password.toCharArray());
```

### Property

n/a

## 2. etc.

### Description

`HSM등을 이용하여, interface로 추가 자율 구현이 가능합니다.`

<br><br><br><br>

# 데이터 모델

## 1. CryptoKeyPairInfo

### Description

`Key 페어 정보의 Data Model`

### Declaration

```cpp
// Declaration in Java
public class CryptoKeyPairInfo {
	private String keyId;
	private String algorithm;
    //private int alg;
	private KeyPairInterface keyPair;
}
```

### Property
| Name | Type   | Description                | **M/O** | **비고** |
|-------|-------|----------------------------|---------|----------|
| keyId | String | 키 아이디                  |    M    |          |
| algorithm | String | Key 알고리즘           |    M    |          |
| ~~alg~~   | ~~int~~   | ~~Key 알고리즘의 Curve 종류 <br/><br/> 0(k1), 1(r1)~~|    ~~M~~    |          |
| keyPair | KeyPairInterface | Key 객체      |    M    | crypto-SDK 참조 |


## 2. KeyElement

### Description

`Key의 Data Model`

### Declaration

```cpp
// Declaration in Java
public class KeyElement{
	private String keyId;
	private String algorithm;
	private String publicKey;
	private String privateKey;
}
```

### Property
| Name | Type   | Description                | **M/O** | **비고** |
|-------|-------|----------------------------|---------|----------|
| keyId | String | 키 아이디                  |    M    |          |
| algorithm | String | Key 알고리즘           |    M    |          |
| publicKey | String | 문자열 형태의 Public Key |  M    | 멀티베이스인코딩된 publicKey |
| privateKey | String | 문자열 형태의 Private Key | M   | 멀티베이스인코딩된 암호화된 privateKey |