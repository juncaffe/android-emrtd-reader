# Android eMrtd Reader
ICAO Doc 9303을 참고해 구현한 안드로이드 eMRTD NFC 리더 라이브러리입니다.

## 모듈 구성

| 모듈 | 설명                                                |
|---|---------------------------------------------------|
| `:mrtdcore` | JVM 코어 — PACE/BAC/CA/PA, LDS 파싱, Secure Messaging |
| `:ePassport` | Android 래퍼 — NFC IsoDep transport                 |
| `:app` | 안드로이드 테스트 앱                                       |

## 지원 범위 (TD3 여권)

- 접근 제어: `PACE`(ECDH Generic Mapping, AES) 우선 / `BAC` fallback
- 인증: `CA` - `Chip Authentication`, `PA` - `Passive Authentication` (SOD 서명 + DG 해시 검증)
- 데이터 그룹: `DG1`(MRZ), `DG2`(얼굴 이미지), `DG14`(보안 정보)
- 미지원: TA, DG3/DG4(생체), Active Authentication

## 메모리 보안
MRZ, 세션 키 등 민감 데이터는 `String`으로 다루지 않고 byte/char 버퍼로 처리, 사용 후에는 버퍼를 0으로 덮어써 메모리 덤프에 평문 흔적을 최소화 합니다.

## 라이선스
Apache License 2.0 ([LICENSE](LICENSE)). 본 프로젝트는 ICAO 9303 표준 기반 구현입니다.

### 서드파티
- `Bouncy Castle` — Copyright (c) 2000-2024 The Legion of the Bouncy Castle Inc.  
  MIT-style 라이선스 ([LICENSES/LICENSE.BOUNCYCASTLE.md](LICENSES/LICENSE.BOUNCYCASTLE.md))

### 관련 표준
전자여권의 NFC 데이터 읽기 및 검증을 위해 아래 ICAO Doc 9303 표준을 참고하여 구현되었습니다.
- [ICAO Doc 9303 Part 10 - Logical Data Structure (LDS)](https://www.icao.int/sites/default/files/publications/DocSeries/9303_p10_cons_en.pdf)
- [ICAO Doc 9303 Part 11 - Security Mechanisms for MRTDs](https://www.icao.int/sites/default/files/publications/DocSeries/9303_p11_cons_en.pdf)
- [ICAO Doc 9303 Part 12 - Public Key Infrastructure for MRTDs](https://www.icao.int/sites/default/files/publications/DocSeries/9303_p12_cons_en.pdf)
