# Server Wallet SDK Guide
본 문서는 OpenDID Server Wallet SDK 사용을 위한 가이드로, Open DID에 필요한 Wallet 정보를 생성, 수정 등 관리하는 기능을 제공한다.


## S/W 사양
| 구분 | 내용                |
|------|----------------------------|
| Language  | Java 17|
| Build System  | Gradle 8.2.1 |

## 빌드 방법
: 본 SDK 프로젝트의 build.gradle 파일을 기반으로 JAR 파일을 생성한다.
1. 프로젝트의 `build.gradle` 파일을 열고 아래와 같은 구성파일의 태스크를 추가한다.

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

2. IDE에서 `Gradle` 창을 열고, 프로젝트의 `Tasks > build > clean & build` 태스크를 실행 또는 `./gradlew clean & build` 를 터미널 창에 입력한다.
3. 실행이 완료되면 `{projetPath}/build/libs/` 폴더에 `did-wallet-sdk-server-1.0.0.jar` 파일이 생성된다.


<br>

## SDK 적용 방법
1. 서버 프로젝트의 libs에 각 `did-crypto-sdk-server-1.0.0.jar`, `did-wallet-sdk-server-1.0.0.jar` 파일을 복사한다.
2. 서버 프로젝트의 build gradle에 아래 의존성을 추가한다.

```groovy
    implementation 'org.bouncycastle:bcprov-jdk18on:1.78.1'
    implementation 'com.google.guava:guava:33.2.1-jre'
    implementation 'com.google.code.gson:gson:2.8.9'
    implementation 'org.slf4j:slf4j-api:2.0.7'

    implementation files('libs/did-crypto-sdk-server-1.0.0.jar')
    implementation files('libs/did-wallet-sdk-server-1.0.0.jar')
```
3. `Gradle`을 동기화하여 의존성이 제대로 추가되었는지 확인한다.

<br>

## API 규격서
| 구분 | API 문서 Link |
|------|----------------------------|
| WalletManagerInterface  | [WALLET SDK SERVER API](../../docs/api/WALLET_SDK_SERVER_API_ko.md)  |
| EncryptionHelper  | [WALLET SDK SERVER API](../../docs/api/WALLET_SDK_SERVER_API_ko.md)  |
| SignatureHelper  | [WALLET SDK SERVER API](../../docs/api/WALLET_SDK_SERVER_API_ko.md)  |

### WalletManagerInterface
WalletManagerInterface은 월렛 생성하고 관리하는 기능을 제공한다.<br>주요 기능은 다음과 같다:

* <b>월렛 생성</b>: 월렛을 생성하여 파일로 저장한다.
* <b>월렛 연결/해제</b>: 월렛을 연결하고 해제한다.
* <b>월렛 확인</b>: 월렛이 연결됐는 지 확인한다.
* <b>월렛 비밀번호 변경</b>: 월렛의 비밀번호를 변경한다.
* <b>월렛 키 서명값 생성</b>: 해시된 원문 데이터와 개인키로 서명값을 생성한다.
* <b>월렛 키 확인</b>: 월렛에 키가 존재하는 지 확인한다.
* <b>월렛 공개키 반환</b>: 월렛의 지정한 공개키 정보를 반환한다.
* <b>월렛 키 알고리즘 반환</b>: 월렛의 지정한 키의 알고리즘 정보를 반환한다.
* <b>월렛 키 정보 반환</b>: 월렛의 키 정보를 반환한다.
* <b>월렛 키 삭제</b>: 월렛의 키 정보를 삭제한다.
* <b>월렛 키 조회</b>: 월렛의 키 정보를 조회한다.
* <b>SharedSecret 생성</b>: SharedSecret을 생성한다.



### EncryptionHelper
EncryptionHelper는 월렛 파일에 저장된 키로 데이터를 암호화/복호화 하는 기능을 제공한다.<br>
주요 기능은 다음과 같다:

* <b>암호화</b>: 월렛에 있는 키로 데이터를 암호화한다.
* <b>복호화</b>: 월렛에 있는 키로 데이터를 복호화한다.
  
### SignatureHelper
SignatureHelper는 월렛 모듈을 통한 서명 기능을 제공한다.<br>
주요 기능은 다음과 같다:

* <b>서명</b>: ECDSA 알고리즘을 이용하여 일반 서명과 콤팩트 서명(65byte)을 제공한다.
* <b>서명 검증</b>: 서명값을 검증한다.

## SDK Enumerator
OpenDID Server Crypto SDK 에서 사용하는 Enumerator<br>
주요 기능은 다음과 같다:

* <b>WalletManagerType</b>: 월렛 매니저 종류를 정의한다.
* <b>WalletEncryptType</b>: 월렛 암호화 알고리즘 종류를 정의한다.
* <b>KeyAlgorithmType</b>: 키 알고리즘 종류를 정의한다.