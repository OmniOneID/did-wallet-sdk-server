# Server Wallet SDK Guide
This document is a guide to using the OpenDID Server Wallet SDK, which provides the ability to create, modify, and manage the wallet information required for Open DID.


## S/W Specifications
| Component | Requirement     |
|------|----------------------------|
| Language  | Java 17|
| Build System  | Gradle 8.8 |

## Build Method
: Create a JAR file based on the build.gradle file of this SDK project.
1. Open the `build.gradle` file of your project and add a task from the configuration file as shown below.

```groovy
plugins {
    id 'java-library'
}

repositories {
    mavenCentral()
    jcenter()
}

group = 'org.omnione.did'
jar {
    archiveBaseName.set('did-wallet-sdk-server') 
    archiveVersion.set('1.0.0')
    archiveClassifier.set('') 
}

java {
	sourceCompatibility = '17'
	targetCompatibility = '17'
}

dependencies {
    implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'
    implementation 'com.google.guava:guava:33.2.1-jre'
    implementation 'com.google.code.gson:gson:2.8.9'
    implementation 'org.slf4j:slf4j-api:2.0.7'

    implementation files('libs/did-crypto-sdk-server-1.0.0.jar')
}

```

2. Open the `Gradle` tab in IDE and run the project's `Task > Build > Clean and Build` task, or type './gradlew clean and build' in a terminal.
3. Once the execution is complete, the `did-wallet-sdk-server-1.0.0.jar`  file will be generated in the `{projetPath}/build/libs/` folder.


<br>

## SDK Application Method
1. Copy each of the files `did-crypto-sdk-server-1.0.0.jar`, `did-wallet-sdk-server-1.0.0.jar` to libs in the server project.
2. Add the following dependencies to the `build.gradle` of the server project.

```groovy
    implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'
    implementation 'com.google.guava:guava:33.2.1-jre'
    implementation 'com.google.code.gson:gson:2.8.9'
    implementation 'org.slf4j:slf4j-api:2.0.7'

    implementation files('libs/did-crypto-sdk-server-1.0.0.jar')
    implementation files('libs/did-wallet-sdk-server-1.0.0.jar')
```
3. Sync `Gradle` to ensure the dependencies are properly added.

<br>

## API Specification
| Classification | API Document Link |
|------|----------------------------|
| WalletManagerInterface  | [WALLET SDK SERVER API](../../docs/api/WALLET_SDK_SERVER_API.md)  |
| EncryptionHelper  | [WALLET SDK SERVER API](../../docs/api/WALLET_SDK_SERVER_API.md)  |
| SignatureHelper  | [WALLET SDK SERVER API](../../docs/api/WALLET_SDK_SERVER_API.md)  |

### WalletManagerInterface
WalletManagerInterface provides functionality for creating and managing wallets.
<br>The main features are as follows:

* <b>Create a wallet</b>: Create a wallet and save it as a file.
* <b>Connect/disconnect wallets</b>: Connect and disconnect wallets.
* <b>Check Wallet</b>: Make sure your wallet is connected.
* <b>Change wallet password</b>: Change wallet password.
* <b>Generating a wallet key signature</b>: Generate a signature with the hashed source data and private key.
* <b>Confirm wallet key</b>: Make sure the key exists in your wallet.
* <b>Return wallet public key</b>: Returns the specified public key information for the wallet.
* <b>Returning wallet key algorithm</b>: Returns the algorithm information for the specified key in the wallet.
* <b>Returning wallet key info</b>: Returns the wallet's key information.
* <b>Deleting a wallet key</b>: Delete the key information for wallet.
* <b>Lookup wallet key</b>: Get the wallet's key information.
* <b>Create a SharedSecret</b>: Create a SharedSecret.



### EncryptionHelper
EncryptionHelper provides the ability to encrypt/decrypt data with the key stored in the wallet file.
<br>The main features are as follows:

* <b>encrypt</b>: Encrypt the data with the key in the wallet.
* <b>decrypt</b>: Decrypt the data with the key in the wallet.
  
### SignatureHelper
SignatureHelper provides signature functionality through the Wallet module.
<br>The main features are as follows:

* <b>Signature</b>: Provides a regular signature and a compact signature (65 bytes) using the ECDSA algorithm.
* <b>Verifying signatures</b>: Verify the signature.

## SDK Enumerator
 Enumerators used by OpenDID Server Crypto SDK.
<br>The main features are as follows:

* <b>WalletManagerType</b>: Define the wallet manager type.
* <b>WalletEncryptType</b>: Define the type of wallet encryption algorithm.
* <b>KeyAlgorithmType</b>: Define the key algorithm type.