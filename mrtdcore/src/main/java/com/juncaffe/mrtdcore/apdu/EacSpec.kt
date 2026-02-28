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
 * BSI TR-03110 (EAC — Extended Access Control) 전용 상수.
 * ISO/IEC 7816-4 / ICAO Doc 9303 범위에 속하지 않는 PACE·CA 고유 값.
 * 범용 APDU 상수는 [ApduSpec] 에 있다.
 */
object EacSpec {

    // ── PACE 인증 토큰 ──────────────────────────────────────────────────────

    /**
     * PACE 인증 토큰 입력 구조 템플릿 태그 (BSI TR-03110-3 §3.2.1 Table A.6).
     * CMAC(KSmac, `7F49{ OID || 86{공개키 점} }`) 형태로 사용.
     */
    const val TAG_AUTH_TOKEN_TEMPLATE = 0x7F49

    // ── CA v1 MSE:Set KAT ───────────────────────────────────────────────────

    /**
     * CA v1 MSE:Set KAT 데이터 — 단말 임시 공개키 DO 태그 (BSI TR-03110-3 Table 3.18).
     * `91 L [공개키 바이트]` 형태.
     */
    const val TAG_CA_TERMINAL_PUBKEY = 0x91

    // ── PACE MSE:Set AT 패스워드 참조값 ────────────────────────────────────
    // BSI TR-03110-2 §3.3.1 Table 3.24

    /** MRZ (Machine Readable Zone). */
    const val PWD_REF_MRZ = 0x01
    /** CAN (Card Access Number). */
    const val PWD_REF_CAN = 0x02
    /** PIN. */
    const val PWD_REF_PIN = 0x03
    /** PUK (PIN Unblocking Key). */
    const val PWD_REF_PUK = 0x04
}
