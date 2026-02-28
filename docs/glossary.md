# 용어 정리

## 기본 용어

| 용어 | 의미 |
|---|---|
| eMRTD | 전자여권. 칩이 들어간 Machine Readable Travel Document |
| MRTD | Machine Readable Travel Document |
| MRZ | 여권 하단 OCR 영역. 문서번호·생년월일·만료일 등 |
| CAN | Card Access Number. PACE에서 MRZ 대신 쓰는 접근 번호 |
| LDS | Logical Data Structure. 칩 내부 데이터 구조 |
| EF | Elementary File. 칩 안 파일 단위 |
| DG | Data Group. LDS 데이터 그룹 |
| SOD | Security Object Document. DG 해시·서명 파일 |
| DSC | Document Signer Certificate. SOD 서명 검증용 인증서 |
| CSCA | Country Signing Certification Authority. 국가 최상위 인증서 |

## APDU

| 용어 | 의미 |
|---|---|
| APDU | 단말·칩 간 명령/응답 메시지 |
| Command APDU | 단말→칩 명령. `CLA INS P1 P2 [Lc Data] [Le]` |
| Response APDU | 칩→단말 응답. `[Data] SW1 SW2` |
| CLA | 명령 클래스. SM 적용 여부 등 |
| INS | 명령 코드 (`SELECT`, `READ BINARY` 등) |
| P1/P2 | 명령 파라미터. 같은 INS 내 세부 동작 |
| Lc | Command APDU Data 길이 |
| Le | 기대 응답 Data 길이 (코드의 `ne`) |
| SW | Status Word. 응답 마지막 2바이트 |
| SW1/SW2 | SW 상위/하위 1바이트 |

### CLA (ISO/IEC 7816-4 §5.4.1)

- 명령 클래스 바이트. Secure Messaging 적용 여부와 명령 체이닝 여부를 나타낸다.

| CLA | 의미 |
|---|---|
| `0x00` | 평문 명령 (`CLA_PLAIN`) |
| `0x0C` | Secure Messaging 적용 명령 (`CLA_SM`, ICAO 9303-11 §9.8) |
| `0x10` | 명령 체이닝 (`CLA_CHAINING`) |

### INS (ISO/IEC 7816-4 §7)

- 명령 코드 바이트. 어떤 동작(SELECT, READ BINARY, GENERAL AUTHENTICATE 등)을 수행할지 지정한다.

| INS | 의미 |
|---|---|
| `0xA4` | SELECT. 애플리케이션/파일 선택 (§7.1.1) |
| `0xB0` | READ BINARY. 선택 EF 읽기 (§7.2.3) |
| `0xB1` | READ BINARY odd INS 변형 |
| `0x84` | GET CHALLENGE. BAC용 8바이트 칩 난수 요청 (§7.5.3) |
| `0x82` | EXTERNAL AUTHENTICATE. BAC 상호 인증 (§7.5.4) |
| `0x88` | INTERNAL AUTHENTICATE (§7.5.5) |
| `0x22` | MSE. PACE/CA 보안 환경 설정 (§7.5.11) |
| `0x86` | GENERAL AUTHENTICATE. PACE/CA 인증 데이터 교환 (§7.5.12) |

### P1/P2

- 명령 파라미터 2바이트. 같은 INS라도 P1/P2 값에 따라 세부 동작·인자가 달라진다(예: SELECT 선택 방식, READ BINARY offset).

| 명령 | P1 | P2 |
|---|---|---|
| SELECT (AID) | `0x04` 로 선택 | `0x0C` FCI 미반환 |
| SELECT (File ID) | `0x00` 로 선택 | `0x0C` FCI 미반환 |
| READ BINARY | offset 상위 7비트 | offset 하위 8비트 |
| MSE:Set AT (PACE) | `0xC1` | `0xA4` Authentication Template |
| MSE:Set AT (CA) | `0x41` | `0xA4` Authentication Template |
| MSE:Set KAT (CA v1) | `0x41` | `0xA6` Key Agreement Template |

### SW (ISO/IEC 7816-4)

- 응답 APDU 마지막 2바이트(Status Word). 명령 처리 결과(성공·오류 종류)를 나타낸다.

`StatusWord` 상수로 정의된 값:

| SW | 의미 |
|---|---|
| `0x9000` | 성공 (`SUCCESS`) |
| `0x6282` | EOF 도달 (`END_OF_FILE_REACHED`) |
| `0x6700` | 길이 오류 (`WRONG_LENGTH`) |
| `0x6982` | 보안 상태 불충족 (`SECURITY_STATUS_NOT_SATISFIED`) |
| `0x6985` | 사용 조건 불충족 (`CONDITIONS_NOT_SATISFIED`) |
| `0x6988` | SM 데이터 객체 오류 (`SM_DATA_OBJECTS_INCORRECT`) |
| `0x6A82` | 파일/애플리케이션 없음 (`FILE_NOT_FOUND`) |
| `0x6A86` | P1/P2 오류 (`INCORRECT_PARAMETERS_P1P2`) |

칩에서 함께 볼 수 있는 표준 SW(상수 미정의):

| SW | 의미 |
|---|---|
| `0x6A88` | 참조 데이터 없음 (CA에서 칩 키 참조 실패 등) |
| `0x6B00` | P1/P2 또는 offset 오류 |
| `0x6300` | 인증 실패(시도 횟수 미제공) |

## OID

전자여권 보안 정보 OID는 BSI TR-03110 / ICAO Doc 9303 Part 11 의 `0.4.0.127.0.7.2.2.*` 트리를 쓴다.

### 프로토콜 OID 접두사

| 접두사 | 의미 |
|---|---|
| `0.4.0.127.0.7.2.2.1` | ChipAuthenticationPublicKey (CA 공개키) |
| `0.4.0.127.0.7.2.2.3` | ChipAuthentication (CA 프로토콜) |
| `0.4.0.127.0.7.2.2.4` | PACE |

### CA 공개키 OID (`...2.2.1.*`)

| OID | 키 합의 |
|---|---|
| `0.4.0.127.0.7.2.2.1.1` | DH |
| `0.4.0.127.0.7.2.2.1.2` | ECDH |

### CA 프로토콜 OID (`...2.2.3.{합의}.{암호}`)

- 합의 코드: `1`=DH, `2`=ECDH
- 암호 코드: `1`=3DES(112bit), `2`=AES-128, `3`=AES-192, `4`=AES-256

| OID | 의미 |
|---|---|
| `0.4.0.127.0.7.2.2.3.1.1` | DH + 3DES (구형 CA v1, DG14에 CA 정보 생략 시 DH 공개키로 추론) |
| `0.4.0.127.0.7.2.2.3.2.1` | ECDH + 3DES (구형 CA v1, ECDH 공개키로 추론) |
| `0.4.0.127.0.7.2.2.3.2.2` | ECDH + AES-128 (신형) |

### PACE OID (`...2.2.4.{매핑·합의}.{암호}`)

- 현재 지원: 매핑·합의 `2` = ECDH Generic Mapping
- 암호 코드: `2`=AES-128, `3`=AES-192, `4`=AES-256

| OID | 의미 |
|---|---|
| `0.4.0.127.0.7.2.2.4.2.2` | PACE ECDH-GM + AES-128 |

PACE 도메인 파라미터 ID → 곡선 (TR-03110 표준화 곡선):

| ID | 곡선 | ID | 곡선 |
|---|---|---|---|
| 8 | secp192r1 | 13 | brainpoolP256r1 |
| 9 | brainpoolP192r1 | 14 | brainpoolP320r1 |
| 10 | secp224r1 | 15 | secp384r1 |
| 11 | brainpoolP224r1 | 16 | brainpoolP384r1 |
| 12 | secp256r1 | 17 | brainpoolP512r1 |
| | | 18 | secp521r1 |

### 해시 OID (SOD / PA)

| OID | 알고리즘 |
|---|---|
| `1.3.14.3.2.26` | SHA-1 |
| `2.16.840.1.101.3.4.2.4` | SHA-224 |
| `2.16.840.1.101.3.4.2.1` | SHA-256 |
| `2.16.840.1.101.3.4.2.2` | SHA-384 |
| `2.16.840.1.101.3.4.2.3` | SHA-512 |

### AID

| AID | 의미 |
|---|---|
| `A0 00 00 02 47 10 01` | eMRTD 애플리케이션 (ICAO Doc 9303-9 §4.6) |

## 접근 제어와 인증

| 용어 | 의미 |
|---|---|
| BAC | Basic Access Control. MRZ 기반. PACE 미지원/실패 시 BAC로 전환 |
| PACE | Password Authenticated Connection Establishment. 신형 우선 |
| GM | Generic Mapping. PACE에서 nonce로 도메인 생성자 매핑. 현재 지원 |
| PA | Passive Authentication. SOD 서명·DG 해시로 무결성 검증 |
| CA | Chip Authentication. DG14 칩 공개키로 칩 진위·세션키 재확립 |
| CA v1 | `MSE:Set KAT`로 단말 공개키 일괄 전달. 주로 구형 3DES/DH·ECDH |
| CA v2 | `MSE:Set AT` + `GENERAL AUTHENTICATE`. 주로 신형 AES |
| EAC | Extended Access Control. CA/TA 계열 |
| TA | Terminal Authentication. DG3/DG4 생체정보 접근용. 현재 범위 밖 |

패스워드 참조값(PACE MSE:Set AT, BSI TR-03110-2 §3.3.1):

| 값 | 의미 |
|---|---|
| `0x01` | MRZ |
| `0x02` | CAN |
| `0x03` | PIN |
| `0x04` | PUK |

> 구형·신형은 규격명이 아니라 `EF.CardAccess`·DG14 보안 정보로 결정되는 실행 경로 구분이다. [구형·신형 전자여권 프로토콜](구형-신형-전자여권-프로토콜.md) 참고.

## Secure Messaging

| 용어 | 의미 |
|---|---|
| SM | Secure Messaging. APDU 암호화·MAC 보호 |
| SSC | Send Sequence Counter. MAC 계산용 명령/응답 카운터 |
| MAC | Message Authentication Code. 위변조 검증값 |
| CMAC | AES 기반 MAC. PACE/CA AES SM |
| Retail-MAC | 3DES 기반 MAC. BAC DES SM |

SM 데이터 객체 태그 (ICAO Doc 9303-11 §9.8 Table 10):

| 태그 | 의미 |
|---|---|
| DO`87` | 암호화 데이터(Cryptogram). 선두 `0x01`은 패딩-콘텐츠 지시자 |
| DO`97` | 기대 응답 길이 Le |
| DO`99` | 처리 상태 SW1·SW2 |
| DO`8E` | MAC(Checksum) |

`Secure Messaging MAC verification failed` = 응답 MAC 검증 실패. 키·SSC·보호 APDU 구성, 또는 이전 명령 실패 뒤 채널 상태 불일치가 흔한 원인.

## MSE / General Authenticate TLV 태그

MSE 데이터 필드 태그 (BSI TR-03110-2 §3.3.1):

| 태그 | 의미 |
|---|---|
| `0x80` | 알고리즘 OID |
| `0x83` | 패스워드 참조 (PACE) |
| `0x84` | 키 참조 (CA keyId) |

General Authenticate 동적 인증 데이터 태그 (ICAO 9303-11 Table 9, BSI TR-03110):

| 태그 | 의미 |
|---|---|
| `0x7C` | 동적 인증 데이터를 감싸는 묶음 태그 |
| `0x80` | 암호화 nonce(PACE 1단계) / CA 단말 임시 공개키 |
| `0x81` | 단말 매핑 공개키 (PACE 2단계) |
| `0x82` | 칩 매핑 공개키 (PACE 2단계 응답) |
| `0x83` | 단말 키합의 공개키 (PACE 3단계) |
| `0x84` | 칩 키합의 공개키 (PACE 3단계 응답) |
| `0x85` | 단말 인증 토큰 (PACE 4단계) |
| `0x86` | 칩 인증 토큰 / CA 임시 공개키 점 |
| `0x7F49` | PACE 인증 토큰 입력 템플릿 (TR-03110-3 §3.2.1) |
| `0x91` | CA v1 MSE:Set KAT 단말 임시 공개키 (TR-03110-3 Table 3.18) |

## LDS 파일

| 파일 | File ID | BER 태그 | 의미 |
|---|---|---|---|
| EF.CardAccess | `0x011C` | — | PACEInfo 등 접근 제어 정보 |
| EF.COM | `0x011E` | `0x60` | DG 목록·LDS 버전 |
| EF.SOD | `0x011D` | `0x77` | DG 해시·서명 |
| DG1 | `0x0101` | `0x61` | MRZ (MRZ 데이터 `0x5F1F`) |
| DG2 | `0x0102` | `0x75` | 얼굴 이미지 (CBEFF, ISO/IEC 19794-5) |
| DG14 | `0x010E` | `0x6E` | Chip Authentication 보안 정보 |

DG2 CBEFF 내부 태그: `0x7F61` 생체 그룹 템플릿, `0x7F60` 생체 템플릿, `0x5F2E`/`0x7F2E` 생체 데이터 블록.

## 기타

| 이름 | 의미 |
|---|---|
| `CommandApdu` | 명령 APDU 모델 |
| `ResponseApdu` | 응답 APDU 모델 |
| `ApduChannel` | APDU 송수신 추상화 |
| `SecureMessaging` | SM wrap/unwrap 추상화 |
| `BACKey` | MRZ에서 만든 BAC/PACE 입력 키 |
| `PassportReader` | PACE/BAC/CA/PA·DG 읽기 코어 리더 |
| `ApduSpec` | ISO 7816-4 / ICAO 9303 공개 표준 상수 |
| `EacSpec` | BSI TR-03110(EAC) 전용 상수 |
| `StatusWord` | SW1·SW2 값 클래스 |
| `CaParameterResolver` | CA OID → 키합의·암호 해석 |
| `PaceParameterResolver` | PACE OID·parameterId → 암호·곡선 해석 |
