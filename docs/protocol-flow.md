# 전자여권 단계별 프로토콜
칩에서 읽은 `EF.CardAccess`로 접근 제어 방식을 결정하고, 접근 제어 이후 읽은 `DG14`의 SecurityInfo로 Chip Authentication 경로를 결정한다.  
최종 판단 기준은 칩에서 읽은 OID, keyId, 알고리즘 파라미터다.

## 전체 순서
```
NFC 연결 → EF.CardAccess → PACE 또는 BAC → DG14 → CA → DG1/DG2 → SOD → PA
```

| 단계 | 구형 | 신형 |
|---|---|---|
| 접근 제어 | BAC | PACE (실패 시 BAC) |
| 첫 SM | 3DES + Retail-MAC | AES + CMAC |
| CA 키 합의 | DH 또는 ECDH | 주로 ECDH |
| CA 명령 | CA v1 `MSE:Set KAT` | `MSE:Set AT` + `GENERAL AUTHENTICATE` |
| CA 이후 SM | 3DES 또는 OID 지정 방식 | AES |
| 데이터 읽기 | DG14 → DG1/DG2 → SOD | 동일 |
| PA | SOD 서명·DG 해시 검증 | 동일 |

## 1. NFC 연결
- `IsoDep`로 연결, 통신 제한시간 5초 (IsoDep 기본값보다 길게 잡아 구형 칩의 느린 암호 연산을 기다림)
- APDU는 한 번씩 차례로 전송
- 하나의 태그 읽기가 끝나기 전까지 다른 태그를 읽지 않음
- 구형 BAC 경로: MRTD 애플릿 선택 후 750ms 기다린 뒤 BAC 시작 실패시 3회 재시도 — 일부 구형 칩이 첫 BAC 명령에서 `TagLostException` 발생 방지

## 2. 접근 제어 방식 결정
평문으로 `EF.CardAccess`를 읽어 `SecurityInfo`를 파싱 사용가능 접근 제어방식 결정
- 접근 제어 방식(`AccessControlMode`)을 선택한다.
   - `PACE`: `PACEInfo` + `parameterId` 있으면 PACE 시도 → 성공 시 AES SM, 실패 시 BAC로 전환.
   - `BAC`: PACE를 시도하지 않고 항상 BAC → 3DES SM

`EF.CardAccess`가 없거나 `PACEInfo`가 없는 칩은 구형이라 판단 BAC 를 적용한다.

## 3. PACE
지원 경로: MRZ 기반, ECDH Generic Mapping, AES Secure Messaging.
1. MRZ로 PACE 비밀번호 키 생성
2. `MSE:Set AT`로 OID·파라미터 선택
3. `GENERAL AUTHENTICATE`로 nonce, 매핑 키, 임시 키, 인증 토큰 교환
4. 공유 비밀에서 `KSenc`, `KSmac` 유도
5. SSC=0으로 AES SM 수립
6. 새 채널로 MRTD 애플릿 선택

## 4. BAC
MRZ의 여권번호·생년월일·만료일과 각 체크디지트 사용.
1. MRZ에서 `Kenc`, `Kmac` 유도
2. `GET CHALLENGE`(INS=84)로 `RND.IC` 수신
3. 단말 난수 `RND.IFD`와 키 재료 `K.IFD` 생성
4. `EXTERNAL AUTHENTICATE`(INS=82)로 암호문·MAC 전송
5. 응답 40바이트 복호화 후 MAC·난수 검증
6. 양쪽 키 재료로 `KSenc`, `KSmac`, SSC 생성

## 5. Secure Messaging
| 접근 방식 | 암호화 | MAC | SSC |
|---|---|---|---|
| BAC | 3DES-CBC | Retail-MAC | BAC 난수에서 계산 |
| PACE | AES-CBC | AES-CMAC | 0에서 시작 |
| CA 이후 | DG14 OID 따름 | 3DES 또는 AES | 0으로 재설정 |

- 보호 APDU 구성: DO87(암호문), DO97(Le), DO8E(MAC)
- 응답 검증: DO87, DO99, DO8E

## 6. DG14 읽기
접근 제어 채널에서 DG14를 먼저 읽는다. 들어갈 수 있는 정보:
- `ChipAuthenticationInfo`: CA OID, 버전, keyId
- `ChipAuthenticationPublicKeyInfo`: DH/ECDH 정적 공개키, keyId
- 미지원 `SecurityInfo`

신형: CA 정보와 공개키가 함께 있고 `keyId`로 짝을 맞춤.
구형 허용 형식:
- `ChipAuthenticationInfo` 없이 공개키만 존재
- CA 정보에는 keyId, 단일 공개키에는 keyId 생략
- DH 공개키
- ECDH 공개키 + 3DES CA v1

CA 정보가 생략되고 공개키가 하나면 공개키 OID로 legacy CA 추론:
| 공개키 OID | 추론 CA |
|---|---|
| DH | DH + 3DES CA v1 |
| ECDH | ECDH + 3DES CA v1 |

## 7. Chip Authentication
칩 정적 공개키와 단말 임시 키로 칩의 개인키 보유를 확인하고 SM 키를 교체한다.

구형 CA v1:
1. DG14의 DH/ECDH 공개키 파싱
2. 단말 임시 키 쌍·공유 비밀 생성
3. `MSE:Set KAT`에 단말 공개키와 선택적 keyId 전송
4. 공유 비밀에서 3DES `KSenc`, `KSmac` 유도
5. SSC=0으로 채널 교체

신형 AES CA:
1. DG14의 CA OID·ECDH 공개키 선택
2. 단말 임시 ECDH 키·공유 비밀 생성
3. `MSE:Set AT`로 CA OID·keyId 선택
4. `GENERAL AUTHENTICATE`로 단말 임시 공개키 전달
5. 공유 비밀에서 AES `KSenc`, `KSmac` 유도
6. SSC=0으로 채널 교체

## 8. DG1·DG2 읽기
CA 성공 시 CA 채널, 실패 시 기존 PACE/BAC 채널 사용.
- DG1: MRZ
- DG2: 얼굴 이미지

각 파일은 `SELECT FILE` + `READ BINARY`. 큰 DG2는 여러 APDU로 분할 읽기.
읽기 진행률은 블록마다 `(읽은 바이트, 전체 바이트)`로 보고한다(`ReadEvent.DataGroupProgress`). 전체 길이는 선두 BER-TLV 헤더로 계산한다. 

## 9. SOD와 Passive Authentication
1. SOD의 CMS SignedData 파싱
2. Document Security Object 서명 검증
3. SOD에 기록된 DG별 해시 알고리즘·해시값 읽기
4. 실제 읽은 DG1/DG2/DG14 해시와 비교

PA는 BAC/PACE 동일하게 수행한다.

PA 성공 범위:
- SOD의 CMS SignedData 서명 검증
- SOD에 기록된 DG 해시와 실제 읽은 DG1/DG2/DG14 해시 일치

단, CSCA/DS 인증서 체인 신뢰성 검증은 별도 신뢰 저장소가 구성된 경우에만 수행한다.

## 10. 성공 상태 해석
| 항목 | 성공 의미 |
|---|---|
| PACE | 접근 제어 + AES 채널 수립 |
| BAC | 접근 제어 + 3DES 채널 수립 |
| CA | DG14 키로 칩 인증·세션키 재협상 |
| DG1 | MRZ 읽기·파싱 |
| DG2 | 얼굴 이미지 읽기·파싱 |
| DG14 | 보안 정보 읽기·파싱 |
| SOD | EF.SOD 읽기 |
| PA | SOD 서명·DG 해시 검증 |

- CA: 칩 개인키 보유·세션키 확인
   - CA 버전·암호 방식·OID는 DG14 값에 따라 달라진다.
- PA: 발급 후 변조 여부.
