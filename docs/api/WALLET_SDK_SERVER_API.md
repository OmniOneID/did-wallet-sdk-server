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

- Subject: Wallet SDK Server API
- Author: Youngjun Lee
- Date: 2024-08-29
- Version: v1.0.0

| Version   | Date      | Changes                 |
| ------ | ---------- | -------------------------|
| v1.0.0 | 2024-08-29 |  Initial version |


<div style="page-break-after: always;"></div>

## Table of Contents

- [API List(APIs)](#api-list)
    - [1. create](#1-create)
    - [2. connect](#2-connect)
    - [3. isConnect](#3-isconnect)
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
- [Miscellaneous API List(APIs)](#miscellaneous-api-list)
    - [1. encrypt](#1-encrypt)
    - [2. decrypt](#2-decrypt)
    - [3. sign](#3-sign)
    - [4. verify](#4-verify)
    - [5. getCompactSignature](#5-getcompactsignature)
- [enum List(Enumerators)](#enum-List)
    - [1. WalletManagerType](#1-walletmanagertype)
    - [2. WalletEncryptType](#2-walletencrypttype)
    - [3. KeyAlgorithmType](#3-keyalgorithmtype)
- [Wallet](#wallet)
    - [Wallet Structure](#wallet-structure)
       - [Wallet Example](#wallet-example)
    - [1. File](#1-file)
    - [2. etc.](#2-etc)
- [Data Models(Models)](#data-models)
    - [1. CryptoKeyPairInfo](#1-cryptokeypairinfo)
    - [2. KeyElement](#2-keyelement)
  



# API list
## 1. create

### Class Name

`WalletManagerInterface`

### Function Name

`create`

### Function Description

`Creates a wallet file with the specified parameters.`

### Input Parameters

| Parameter          | Type   | Description                        | **M/O** | **Remarks** |
|--------------------|--------|------------------------------------|---------|-------------|
| walletFilePath     | string | Path where the wallet file will be created | M       | Must include the extension (.wallet) |
| securePassword     | string | Secure password used for wallet encryption | M       | Value to be used as a password |
| walletEncryptType  | string | Wallet encryption specification    | M       | Use values from WalletEncryptType Enum <br/>[Link](#2-walletencrypttype) <br/><br/>AES-256-CBC-PKCS5Padding |

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

### Function Description

`Connects to an existing wallet file with the specified parameters.`

### Input Parameters

| Parameter          | Type   | Description                        | **M/O** | **Remarks** |
|--------------------|--------|------------------------------------|---------|-------------|
| walletFilePath     | string | Path of the existing wallet        | M       | Must include the extension (.wallet) |
| securePassword     | string | Secure password used for wallet connection | M | Password value |

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

### Function Description

`Check if the wallet is currently connected.`

### Input Parameters
n/a


### Output Parameters
| Type | Description                |**M/O** | **비고** |
|------|----------------------------|--------|----------|
| boolean | true / false            | M      | true if connected, false otherwise |

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

### Function Description

`Disconnect the wallet.`

### Input Parameters

n/a


### Output Parameters

| Type | Description                |**M/O** | **Notes** |
|------|----------------------------|--------|---------|
| boolean | Returns true if successfully disconnected, false otherwise. | M | |

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

### Function Description

`Change the wallet's security password.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|----------|
| currenSecurePassword | string | Current security password | M      |         |
| newSecurePassword    | string | New security password | M    |         |


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

### Function Description

`Generates a compact signature using the private key corresponding to the key ID and the hashed source data.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|----------|
| keyId     | string | ID of the private key to be used for signing    | M       |         |
| hashedSource | byte[] | Hashed source data      | M       |          |


### Output Parameters

| Type | Description                |**M/O** | **Notes** |
|------|----------------------------|--------|----------|
| byte[] | Compact signature     | M      |          |


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

### Function Description

`Adds a key pair to the wallet.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|---------|
| cryptoKeyPairInfo | CryptoKeyPairInfo | Information of the key pair to be added |M| [Link](#1-cryptokeypairinfo) |


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

### Function Description

`Generates a key pair with the specified ID and algorithm type, and adds it to the wallet.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|----------|
| keyId     | string | ID of the key to be generated             | M       |         |
| keyAlgorithmType | KeyAlgorithmType | Algorithm type to be used for key generation <br/><br/> SECP256R1, SECP256K1, RSA2048 |M| [Link](#3-KeyAlgorithmType) |


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

### Function Description

`Checks if the key pair information with the specified ID exists in the wallet.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|---------|
| keyId     | string | ID of the key                    | M       |         |


### Output Parameters

| Type | Description                |**M/O** | **Notes** |
|------|----------------------------|--------|----------|
| boolean | true if the key exists, false otherwise | M | |


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

### Function Description

`Returns the public key corresponding to the specified key ID.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|----------|
| keyId     | string | ID of the key                   | M       |          |


### Output Parameters

| Type | Description                |**M/O** | **Notes** |
|------|----------------------------|---------|---------|
| String | 	Public key string encoded in base58 format  |M| |


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

### Function Description

`Returns the algorithm of the specified key ID.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|---------|
| keyId     | string | ID of the key                    | M       |          |


### Output Parameters

| Type | Description                |**M/O** | **Notes** |
|------|----------------------------|--------|---------|
| String | Key algorithm               | M      |         |


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

### Function Description

`Returns the key pair information corresponding to the specified key ID.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|---------|
| keyId    | string    | ID of the key |M||


### Output Parameters

| Type | Description                |**M/O** | **Notes** |
|------|----------------------------|--------|----------|
| KeyElement | Key pair information             | M      |         |


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

### Function Description

`Removes the key pair information corresponding to the key ID from the wallet.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|----------|
| keyId     | string | ID of the key to be removed              | M       |         |


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

## 14. getKeyIdList

### Class Name

`WalletManagerInterface`

### Function Name

`getKeyIdList`

### Function Description

`Returns a list of all key IDs in the wallet.`

### Input Parameters

n/a


### Output Parameters

| Type | Description                |**M/O** | **Notes** |
|------|----------------------------|--------|----------|
| List&lt;String&gt; | List of key IDs  | M       |         |


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

### Function Description

`Deletes all keys stored in the wallet.`

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

### Function Description

`Generates a SharedSecret using the private key corresponding to the key ID and the provided compressed public key.`

### Input Parameters
| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|---------|
| keyId     | string | ID of the key                    | M       |          |
| mEncodedCompressedKey | string | Multi-encoded compressed public key | M |      |

### Output Parameters

| Type | Description                |**M/O** | **Notes** |
|------|----------------------------|--------|---------|
| byte[] | Byte array               | M      |         |


### Function Declaration

```cpp
// Function declaration in Java
walletManager.getSharedSecret(String keyId, String mEncodedCompressedKey);
```

### Function Usage

```cpp
// Counterparty's Base58 encoded compressedKey
String mEncodedCompressedKey = request.getPubKey;

byte[] sharedSecret = walletManager.getSharedSecret("key1", mEncodedCompressedKey);
```

<br>

# Miscellaneous API list
## 1. encrypt

### Class Name

`EncryptionHelper`

### Function Name

`encrypt`

### Function Description

`Encrypts data using a key stored in the file wallet. Only SECP256R1 and SECP256K1 key types are supported.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|----------|
| source    | byte[] | Original data                       | M       |          |
| key       | byte[] | Byte value of the key                | M       |          |
| iv        | byte[] | Initialization Vector      | M       |          |
| cipherSpec | String | Value from SymmetricCipherType(encryption mode) Enum <br/><br/> AES-128-CBC, AES-128-ECB, AES-256-CBC, AES-256-ECB |M| Refer to crypto-SDK |
| padding   | String | Value from SymmetricPaddingType (encryption padding) Enum  <br/><br/> NoPadding, PKCS5Padding |M| Refer to crypto-SDK |


### Output Parameters

| Type | Description                |**M/O** | **Notes** |
|------|----------------------------|--------|----------|
| byte[] | Encrypted value              | M      |         |


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

### Function Description

`Decrypts data using a key stored in the file wallet. Only SECP256R1 and SECP256K1 key types are supported.`

### Input Parameters

| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|----------|
| cipherText | byte[] | Encrypted value               | M       |          |
| key       | byte[] | Byte value of the key                | M       |         |
| iv        | byte[] | Initialization Vector      | M       |          |
| cipherSpec | String | Value from SymmetricCipherType (encryption mode) Enum  <br/><br/> AES-128-CBC, AES-128-ECB, AES-256-CBC, AES-256-ECB |M| Refer to crypto-SDK |
| padding   | String | Value from SymmetricPaddingType (encryption padding) Enum <br/><br/> NoPadding, PKCS5Padding |M| Refer to crypto-SDK |


### Output Parameters

| Type | Description                |**M/O** | **Notes** |
|------|----------------------------|--------|----------|
| byte[] | Original data                  | M      |          |


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

### Function Description

`Generates a signature for the original hashed message using the specified algorithm.`

### Input Parameters
| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|---------|
| originalHashedMessage | byte[] | Original hashed message | M      |          |
| privateKey | PrivateKey | Private key to be used for signing   | M       |         |


### Output Parameters

| Type | Description                |**M/O** | **Notes** |
|------|----------------------------|--------|---------|
| byte[] | Signature byte array        | M      |          |


### Function Declaration

```cpp
// Function declaration in Java
SignatureHelper.sign(byte[] originalHashedMessage, PrivateKey privateKey);
```

### Function Usage

```cpp
byte[] hashedSource = DigestUtils.getDigest("original text".getBytes(), DigestType.SHA256);
byte[] signature = signatureHelper.sign(hashedSource, (ECPrivateKey) keyPairInfo.getKeyPair().getPrivateKey());
```

<br>

## 4. verify

### Class Name

`SignatureHelper`

### Function Name

`verify`

### Function Description

`Verifies a signature using the specified algorithm.`

### Input Parameters
| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|---------|
| algorithm | string | Algorithm to be used for verification  | M       |          |
| signData  | byte[] | 	Signature data to be verified          | M       |          |
| publicKeyBytes | byte[] | Compressed public key to be used for verification | M     |         |
| originalHashedMessage | byte[] | Original hashed message | M      |          |


### Output Parameters

void <br/>
(Throws Exception on verification failure)


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

### Function Description

`Converts signature data into compact signature format.`

### Input Parameters
| Parameter | Type   | Description                | **M/O** | **Notes** |
|-----------|--------|----------------------------|---------|----------|
| algorithm | string | Signature algorithm               | M       |          |
| signData  | byte[] | Signature value                     | M       |          |
| publicKey | PublicKey | Public key                  | M       |          |
| originalHashedMessage | byte[] | Original hashed message | M      |          |


### Output Parameters

| Type | Description                |**M/O** | **Notes** |
|------|----------------------------|--------|---------|
| byte[] | 	Compact signature value     | M      |          |


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

# enum List

## 1. WalletManagerType

### Description
`Types of Wallet Managers`

### Declaration
```cpp
// Declaration in Java
public enum WalletManagerType {
    FILE, ;
}
```

## 2. WalletEncryptType

### Description
`Types of Wallet Encryption Algorithms`

### Declaration
```cpp
// Declaration in Java
public enum WalletEncryptType {
    AES_256_CBC_PKCS5Padding("AES-256-CBC-PKCS5Padding");
}
```

## 3. KeyAlgorithmType

### Description
`Types of Key Algorithms`

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

## wallet Structure

```cpp
{
    "head": {
        "encryptionInfo": {  // Defines the private key encryption method. Refer to WalletEncryptType
            "aesAlgorithm": "...",  // Encryption algorithm
            "padding": "...",  // Padding method used during encryption
            "mode": "...",  // Encryption mode
            "keySize": ...  // Key length used for encryption
        },
        "secureKeyInfo": {  // Data for wallet password verification
            "salt": "...",  // Salt (nonce) used in PBKDF2 encryption
            "iterations": ...,  // Number of PBKDF2 encryption rounds
            "secretPhrase": "..."  // Data for wallet password verification (encrypted specific data)
        },
        "version": ...,  // Wallet version
        "encoding": {  // Wallet encoding type
            "keyEncodingType": "..."  // Multibase encoding type: f(base16), F(base16upper), z(base58btc), u(base64url), m(base64)
        }
    },
    "keys": [  // List of keys stored in the wallet
        {
            "keyId": "...",  // Key ID
            "alg": ...,  // Key algorithm curve type: 0(Secp256k1), 1(Secp256r1)
            "algString": "...",  // Key algorithm curve type: Secp256k1, Secp256r1
            "publicKey": "...",  // Multibase encoded public key
            "privateKey": "..."  // Multibase encoded encrypted private key
        }
    ]
}
```

### wallet example
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

`Wallet Structure using File`

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

`Custom implementations can be added via interface using HSM, etc.`

<br><br><br><br>

# Data Models

## 1. CryptoKeyPairInfo

### Description

`Data model for key pair information`

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
| Name | Type   | Description                | **M/O** | **Notes** |
|-------|-------|----------------------------|---------|----------|
| keyId | String | Key ID                  |    M    |          |
| algorithm | String | Key algorithm          |    M    |          |
| ~~alg~~   | ~~int~~   | ~~Key algorithm curve type <br/><br/> 0(k1), 1(r1)~~|    ~~M~~    |          |
| keyPair | KeyPairInterface | Key object      |    M    | Refer to crypto-SDK |


## 2. KeyElement

### Description

`Data Model of Key`

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
| Name | Type   | Description                | **M/O** | **Notes** |
|-------|-------|----------------------------|---------|----------|
| keyId | String | Key ID                 |    M    |          |
| algorithm | String | Key algorithm           |    M    |          |
| publicKey | String | 	Public key in string format |  M    | Multibase encoded public key |
| privateKey | String | Private key in string format | M   | Multibase encoded encrypted private key
 |