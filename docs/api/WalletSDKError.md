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

Wallet SDK Error
==

- Topic: WalletSDKError
- Author: Eunjeong Lee
- Date: 2024-08-29
- Version: v1.0.0

| Version          | Date       | Changes                  |
| ---------------- | ---------- | ------------------------ |
| v1.0.0  | 2024-08-29| Initial version          |

<div style="page-break-after: always;"></div>

# Table of Contents
- [Model](#model)
  - [Error Response](#error-response)
- [Error Code](#error-code)
  - [1.1. Crypto, Sign (01xxx)](#11-crypto-sign-01xxx)
  - [1.2. Wallet (02xxx)](#12-wallet-02xxx)

# Model
## Error Response

### Description
```
Error struct for Wallet SDK. It has code and message pair.
Code starts with SSDKWLT.
```

### Declaration
```java
public class WalletErrorCode {
	private String code;
	private String msg;
}
```

### Property

| Name            | Type       | Description                            | **M/O** | **Note**              |
|-----------------|------------|----------------------------------------|---------|-----------------------|
| code       | String     | Error code. It starts with SSDKWLT     |    M    |                       | 
| msg        | String     | Error Message.                  |    M    |                       | 

<br>

# Error Code
## 1. Wallet SDK
### 1.1. Crypto, Sign (01xxx)

| Error Code   | Error Message                     | Description      | Action Required                             |
|--------------|-----------------------------------|------------------|---------------------------------------------|
| SSDKWLT01001 | Failed to encrypt.                | -                | Check the encrypt variable.    |
| SSDKWLT01002 | Failed to decrypt.                | -                | Check the decrypt variable. |
| SSDKWLT01003 | Failed to generate random byte.   | -                | Confirm SecureRandom.                 |
| SSDKWLT01004 | Failed to generate key.           | -      | Check key generation variables.      |
| SSDKWLT01005 | Failed to compress PublicKey.     | -                | Check the publicKey or algorithm.      |
| SSDKWLT01006 | Failed to uncompress PublicKey.   | -                |Check the publicKey or algorithm.   |
| SSDKWLT01007 | Failed to signature.              | -                | Check the signature generation variable. |
| SSDKWLT01008 | Verify signature is failed.       | -                | Verification request variables.             |
| SSDKWLT01009 | Failed to compress signature.     | -                | Check the signature generation variable. |


<br>

### 1.2. Wallet (02xxx)

| Error Code   | Error Message                                | Description      | Action Required                        |
|--------------|----------------------------------------------|------------------|----------------------------------------|
| SSDKWLT02001 | WalletManager is disconnected.   | -                | Check the wallet password or wallet file.   |
| SSDKWLT02002 | Failed to load the WalletFile.   | -                | Check the wallet path or wallet file.|
| SSDKWLT02003 | Failed to write the WalletFile.   | -                | Check the wallet path or wallet file. |
| SSDKWLT02004 | The keyId does not exist.           | -                | Add keyId to wallet.     |
| SSDKWLT02005 | The KeyId is already existed.     | -                | Add another keyId to wallet. |
| SSDKWLT02006 | The Name for KeyId is empty.   | -                | Confirm keyId name.  |
| SSDKWLT02007 | Algorithm type is invalid.              | -                | Retry with valid algorithms.    |
| SSDKWLT02008 | The Name for KeyId must only be alphaNumeric.       | -     |Change to a valid keyId name.|
| SSDKWLT02009 | IWKey is null.     | -                | Check key settings.    |
| SSDKWLT02010 | Invalid PrivateKey.                | -                | Check key information. |
| SSDKWLT02011 | Invalid PublicKey.                | -                | Check key information.|
| SSDKWLT02012 | KeyInfo is empty.   | -                | Check key information.   |
| SSDKWLT02013 | The password does not set.   | -                | Set a password and try again.      |
| SSDKWLT02014 | The password does not match with the set one.     | -    |Confirm password and retry.|
| SSDKWLT02015 | The password is(are) invalid for use.   | -                | Set password to a valid value.    |
| SSDKWLT02016 | New password is the same as the old one.  | -     | Reset a different password. |
| SSDKWLT02017 | AES Encryption is failed.       | -                | Check the Encryption variable.  |
| SSDKWLT02018 | AES Decryption is failed.     | -                | Check the Decryption variable.   |
| SSDKWLT02019 | Failed to generate shared secret.  | -       |Check the variable for SharedSecret. |
| SSDKWLT02020 | Sign value is invalid.    | -         | Verify signature data for valid values. |
| SSDKWLT02021 | could not find recid.  | -                | Verify the signed key information is correct.  |
| SSDKWLT02022 | fail convert sign data to eostype.     | -                | Verify signature data. |
| SSDKWLT02023 | The r value must be 32 bytes.     | -                | Check R data generation variables.     |
| SSDKWLT02024 | Key generation in DefaultKeyStore is fail. | -  |Check or retry wallet key generation variables.   |
| SSDKWLT02025 | Password authentication failed.   | -                | Reconfirm your password. |
| SSDKWLT02026 | Method name must be lower case alphanumeric (colon accepted) and have range between from 1 to 20 length.  | -     | Name methods for validity.   |
| SSDKWLT02027 | Failed to add the key.     | -                | Confirm or retry the key add variable.|
| SSDKWLT02028 | SecretPhrase already exists.   | -     |Use as the current value or create a new wallet to use it. |
| SSDKWLT02029 | Invalid SecretPhrase.                | -                | Check the SecretPhrase generation variable. |
| SSDKWLT02030 |The file already exists.   | -                | Use as current file or create as another file.  |
| SSDKWLT02031 | The file not exists.           | -     | Set to valid file information.   |
| SSDKWLT02032 | Invalid wallet file path with name.     | -  | Specify a valid wallet path, including extension.|

<br>