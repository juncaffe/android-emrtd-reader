/*
 * Copyright 2026 JunCaffe
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.juncaffe.mrtdcore.apdu

/**
 * ISO/IEC 7816-4 및 ICAO Doc 9303 의 공개 표준 APDU 상수.
 * BSI TR-03110 (EAC) 전용 상수는 [EacSpec] 에 있다.
 */
object ApduSpec {

    // ── CLA ──────────────────────────────────────────────────────────────────
    // ISO/IEC 7816-4 §5.4.1

    /** 평문 명령 CLA. */
    const val CLA_PLAIN    = 0x00
    /** 명령 체이닝 CLA. */
    const val CLA_CHAINING = 0x10
    /** Secure Messaging 적용 명령 CLA. (ICAO Doc 9303-11 §9.8) */
    const val CLA_SM       = 0x0C

    // ── INS ──────────────────────────────────────────────────────────────────
    // ISO/IEC 7816-4 §7

    /** 파일·애플리케이션 선택 (§7.1.1). */
    const val INS_SELECT                      = 0xA4
    /** 선택된 EF 읽기 (§7.2.3). */
    const val INS_READ_BINARY                 = 0xB0
    /** READ BINARY odd INS 변형. */
    const val INS_READ_BINARY_ODD             = 0xB1
    /** 8바이트 챌린지 요청 — BAC (§7.5.3). */
    const val INS_GET_CHALLENGE               = 0x84
    /** 상호 인증 — BAC (§7.5.4). */
    const val INS_EXTERNAL_AUTHENTICATE       = 0x82
    /** 내부 인증 (§7.5.5). */
    const val INS_INTERNAL_AUTHENTICATE       = 0x88
    /** 보안 환경 설정 — PACE/CA MSE (§7.5.11). */
    const val INS_MANAGE_SECURITY_ENVIRONMENT = 0x22
    /** 동적 인증 데이터 교환 — PACE/CA GA (§7.5.12). */
    const val INS_GENERAL_AUTHENTICATE        = 0x86

    // ── SELECT P1/P2 ─────────────────────────────────────────────────────────
    // ISO/IEC 7816-4 §7.1.1

    /** SELECT P1: AID 로 선택. */
    const val P1_SELECT_BY_AID     = 0x04
    /** SELECT P1: File ID 로 선택. */
    const val P1_SELECT_BY_FILE_ID = 0x00
    /** SELECT P2: FCI 미반환. */
    const val P2_SELECT_NO_FCI     = 0x0C

    // ── MSE P1/P2 ────────────────────────────────────────────────────────────

    /** MSE P1: PACE MSE:Set AT (BSI TR-03110-2 §3.3.1). */
    const val P1_MSE_PACE_SET_AT = 0xC1
    /** MSE P1: CA MSE:Set AT + Set KAT 공용 P1 (ICAO Doc 9303-11 §6.2). */
    const val P1_MSE_CA_SET      = 0x41
    /** MSE P2: Authentication Template (AT). */
    const val P2_MSE_AT          = 0xA4
    /** MSE P2: Key Agreement Template (KAT). */
    const val P2_MSE_KAT         = 0xA6

    // ── MSE 데이터 오브젝트 태그 ──────────────────────────────────────────────
    // PACE MSE:Set AT / CA MSE:Set AT·KAT 데이터 필드 태그 (BSI TR-03110-2 §3.3.1)

    /** MSE data: 알고리즘 OID DO 태그. */
    const val TAG_MSE_OID     = 0x80
    /** MSE data: 패스워드 참조 DO 태그 (PACE). */
    const val TAG_MSE_PWD_REF = 0x83
    /** MSE data: 키 참조 DO 태그 (CA keyId). */
    const val TAG_MSE_KEY_REF = 0x84

    // ── General Authenticate 동적 인증 데이터 태그 ────────────────────────────
    // PACE/CA GA 명령·응답 내부 TLV 태그 (ICAO Doc 9303-11 Table 9, BSI TR-03110)
    //
    // 주의: TAG_MSE_OID(0x80)·TAG_MSE_PWD_REF(0x83)·TAG_MSE_KEY_REF(0x84) 와 값이 같지만
    //       TLV 컨텍스트(GA 내부 vs MSE 데이터)가 다르므로 별도 상수로 정의한다.

    /** GA 동적 인증 데이터 래퍼 `7C{...}`. */
    const val TAG_GA_WRAPPER      = 0x7C
    /**
     * PACE step 1 응답: 암호화된 nonce (칩→단말).
     * CA General Authenticate 에서는 단말 임시 공개키 DO 로도 사용.
     */
    const val TAG_GA_NONCE_OR_PK  = 0x80
    /** PACE step 2: 단말 매핑 공개키 (단말→칩). */
    const val TAG_GA_MAP_PK_IFD   = 0x81
    /** PACE step 2 응답: 칩 매핑 공개키 (칩→단말). */
    const val TAG_GA_MAP_PK_IC    = 0x82
    /** PACE step 3: 단말 키합의 공개키 (단말→칩). */
    const val TAG_GA_KA_PK_IFD    = 0x83
    /** PACE step 3 응답: 칩 키합의 공개키 (칩→단말). */
    const val TAG_GA_KA_PK_IC     = 0x84
    /** PACE step 4: 단말 인증 토큰 (단말→칩). */
    const val TAG_GA_TOKEN_IFD    = 0x85
    /** PACE step 4 응답 / CA 임시 공개키 점: 공개키 점 바이트. */
    const val TAG_GA_PUBKEY_POINT = 0x86

    // ── Secure Messaging 데이터 오브젝트 태그 ─────────────────────────────────
    // ICAO Doc 9303-11 §9.8 Table 10

    /** DO'87: 암호화 데이터 (Cryptogram). 선두 0x01 은 패딩-콘텐츠 지시자. */
    const val TAG_SM_ENCRYPTED_DATA    = 0x87
    /** DO'97: 기대 응답 길이 Le. */
    const val TAG_SM_EXPECTED_LENGTH   = 0x97
    /** DO'99: 처리 상태 SW1·SW2. */
    const val TAG_SM_PROCESSING_STATUS = 0x99
    /** DO'8E: MAC (Checksum). */
    const val TAG_SM_MAC               = 0x8E

    // ── eMRTD AID ────────────────────────────────────────────────────────────
    // ICAO Doc 9303-9 §4.6

    /** eMRTD 애플리케이션 AID: A0 00 00 02 47 10 01 */
    val AID_MRTD: ByteArray = byteArrayOf(
        0xA0.toByte(), 0x00, 0x00, 0x02, 0x47, 0x10, 0x01,
    )
}
