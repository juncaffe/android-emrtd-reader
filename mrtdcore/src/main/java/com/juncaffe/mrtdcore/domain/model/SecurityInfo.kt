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
package com.juncaffe.mrtdcore.domain.model

import java.math.BigInteger

/**
 * DG14 / EF.CardAccess 의 SecurityInfo (BSI TR-03110, ICAO Doc 9303 Part 11).
 * OID 로 종류를 구분하며, 미지원 OID 는 [UnsupportedSecurityInfo] 로 보존한다.
 */
sealed interface SecurityInfo {
    /** 프로토콜 식별 OID (점 표기 문자열) */
    val oid: String
}

/**
 * ChipAuthenticationInfo — 칩 인증 프로토콜 정보.
 * @property version CA 버전 @property keyId 다중 키일 때의 식별자(없으면 null)
 */
data class ChipAuthInfo(
    override val oid: String,
    val version: Int,
    val keyId: BigInteger?,
) : SecurityInfo

/**
 * ChipAuthenticationPublicKeyInfo — 칩의 정적 공개키.
 * 공개키는 DER 인코딩된 SubjectPublicKeyInfo 바이트로 보관한다
 * (실제 PublicKey 복원은 CA 단계에서 도메인 파라미터와 함께 수행).
 */
class ChipAuthPublicKeyInfo(
    override val oid: String,
    val subjectPublicKeyInfo: ByteArray,
    val keyId: BigInteger?,
) : SecurityInfo

/**
 * PACEInfo — PACE 프로토콜/표준화 도메인 파라미터 정보.
 * @property version PACE 버전 @property parameterId 표준화 파라미터 ID(없으면 null)
 */
data class PaceInfo(
    override val oid: String,
    val version: Int,
    val parameterId: BigInteger?,
) : SecurityInfo

/** 코어가 아직 지원하지 않는 SecurityInfo — OID 만 보존한다. */
data class UnsupportedSecurityInfo(
    override val oid: String,
) : SecurityInfo
