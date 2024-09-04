# Server Wallet SDK

Welcome to the Server Wallet SDK Repository. <br>
This repository provides an SDK for developing a server wallet.

## Folder Structure
```
did-wallet-sdk-server
├── CHANGELOG.md
├── CLA.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE.dependencies.md
├── MAINTAINERS.md
├── README_ko.md
├── README.md
├── RELEASE-PROCESS.md
├── SECURITY.md
├── docs
│   └── api
│        ├── WALLET_SDK_SERVER_API.md
│        ├── WALLET_SDK_SERVER_API_ko.md
│        └── WalletSDKError.md
└── source
    └── did-wallet-sdk-server
        ├── .gitignore
        ├── build.gradle
        ├── gradle
        │    └── wrapper
        ├── gradlew
        ├── gradlew.bat
        ├── libs
        │    └── did-crypto-sdk-server-1.0.0.jar 
        ├── README_ko.md
        ├── README.md
        ├── settings.gradle
        └── src
```

| Name                    | Description                                     |
| ----------------------- | ----------------------------------------------- |
| source                  | SDK source code project                         |
| docs                    | Documentation                                   |
| ┖ api                   | API guide documentation                         |
| ┖ design                | Design documentation                            |
| sample                  | Samples and data                                |
| README.md               | Overview and description of the project         |
| CLA.md                  | Contributor License Agreement                   |
| CHANGELOG.md            | Version-specific changes in the project         |
| CODE_OF_CONDUCT.md      | Code of conduct for contributors                |
| CONTRIBUTING.md         | Contribution guidelines and procedures          |
| LICENSE.dependencies.md | Licenses for the project’s dependency libraries |
| MAINTAINERS.md          | General guidelines for maintaining              |
| RELEASE-PROCESS.md      | Release process                                 |
| SECURITY.md             | Security policies and vulnerability reporting   |

## Libraries

Libraries can be found in the [build folder](did-wallet-sdk-server/source/did-wallet-sdk-server/build/libs).

1. Copy the `did-crypto-sdk-server-1.0.0.jar` file to the libs of the server project.
2. Add the following dependencies to the build.gradle of the server project.

```groovy
    implementation files('libs/did-crypto-sdk-server-1.0.0.jar')

    implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'
    implementation 'com.google.guava:guava:33.2.1-jre'
    implementation 'com.google.code.gson:gson:2.8.9'
    implementation 'org.slf4j:slf4j-api:2.0.7'
```
3. Sync `Gradle` to ensure the dependencies are properly added.

## API Reference

API Reference can be found [here](docs/api/WALLET_SDK_SERVER_API.md)


## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details on our code of conduct, and the process for submitting pull requests to us.


## License
Copyright 2024 Raonsecure