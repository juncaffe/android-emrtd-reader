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
package com.juncaffe.mrtdcore.auth.pace

import com.juncaffe.mrtdcore.domain.error.MrtdException

/**
 * PACE 프로토콜 파라미터(암호/키길이/도메인 곡선). OID 와 parameterId 로부터 해석한다.
 * 현재 범위: ECDH + Generic Mapping + AES (대상 여권 우선).
 *
 * @property keyBits AES 키 길이(128/192/256)
 * @property curveName BouncyCastle 명명 곡선 이름
 */
class PaceParameters(val keyBits: Int, val curveName: String)

/**
 * PACE OID/parameterId → [PaceParameters] 해석기. (BSI TR-03110, ICAO Doc 9303 Part 11)
 */
object PaceParameterResolver {

    private const val PACE_BASE = "0.4.0.127.0.7.2.2.4."

    // mapping/agreement 코드 (OID 끝에서 두 번째 arc)
    private const val ECDH_GM = 2

    // TR-03110 표준화 도메인 파라미터 ID → BouncyCastle 곡선명
    private val STANDARDIZED_CURVES = mapOf(
        8 to "secp192r1", 9 to "brainpoolP192r1",
        10 to "secp224r1", 11 to "brainpoolP224r1",
        12 to "secp256r1", 13 to "brainpoolP256r1",
        14 to "brainpoolP320r1", 15 to "secp384r1",
        16 to "brainpoolP384r1", 17 to "brainpoolP512r1",
        18 to "secp521r1",
    )

    /**
     * OID/parameterId 를 해석한다. ECDH-GM + AES 외에는 [MrtdException.UnsupportedFeature].
     */
    fun resolve(oid: String, parameterId: Int): PaceParameters {
        if (!oid.startsWith(PACE_BASE)) throw MrtdException.UnsupportedFeature("not a PACE OID: $oid")
        val parts = oid.removePrefix(PACE_BASE).split(".")
        val mappingAgreement = parts.getOrNull(0)?.toIntOrNull()
        val cipher = parts.getOrNull(1)?.toIntOrNull()
        if (mappingAgreement != ECDH_GM) {
            throw MrtdException.UnsupportedFeature("only ECDH-GM PACE is supported (code=$mappingAgreement)")
        }
        val keyBits = when (cipher) {
            2 -> 128
            3 -> 192
            4 -> 256
            else -> throw MrtdException.UnsupportedFeature("only AES PACE is supported (code=$cipher)")
        }
        val curve = STANDARDIZED_CURVES[parameterId]
            ?: throw MrtdException.UnsupportedFeature("unsupported domain parameter id=$parameterId")
        return PaceParameters(keyBits, curve)
    }
}
