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
package com.juncaffe.mrtdcore.auth.ca

import com.juncaffe.mrtdcore.domain.error.MrtdException

/**
 * Chip Authentication 파라미터(암호/키길이). CA OID 로부터 해석한다.
 * 현재 범위: ECDH + 3DES/AES.
 *
 * @property keyBits AES 키 길이(128/192/256)
 */
class CaParameters(
    val agreement: Agreement,
    val cipher: Cipher,
    val keyBits: Int,
) {
    enum class Agreement { DH, ECDH }
    enum class Cipher { TDES, AES }
}

/**
 * CA OID → [CaParameters] 해석기. (BSI TR-03110, ICAO Doc 9303 Part 11 §6.2)
 */
object CaParameterResolver {

    private const val CA_BASE = "0.4.0.127.0.7.2.2.3."
    /** CA OID 를 해석한다. ECDH + 3DES/AES 외에는 [MrtdException.UnsupportedFeature]. */
    fun resolve(oid: String): CaParameters {
        if (!oid.startsWith(CA_BASE)) throw MrtdException.UnsupportedFeature("not a CA OID: $oid")
        val parts = oid.removePrefix(CA_BASE).split(".")
        val agreement = when (val code = parts.getOrNull(0)?.toIntOrNull()) {
            1 -> CaParameters.Agreement.DH
            2 -> CaParameters.Agreement.ECDH
            else -> throw MrtdException.UnsupportedFeature("unsupported CA agreement code: $code")
        }
        val cipher = parts.getOrNull(1)?.toIntOrNull()
        return when (cipher) {
            1 -> CaParameters(agreement, CaParameters.Cipher.TDES, 112)
            2 -> CaParameters(agreement, CaParameters.Cipher.AES, 128)
            3 -> CaParameters(agreement, CaParameters.Cipher.AES, 192)
            4 -> CaParameters(agreement, CaParameters.Cipher.AES, 256)
            else -> throw MrtdException.UnsupportedFeature("unsupported CA cipher code: $cipher")
        }
    }
}
