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
package com.juncaffe.mrtdcore.lds.sod

/**
 * 해시 알고리즘 OID ↔ JCA 이름 매핑 (NIST/ISO 표준 OID).
 */
object DigestAlgorithms {

    private val OID_TO_NAME = mapOf(
        "1.3.14.3.2.26" to "SHA-1",
        "2.16.840.1.101.3.4.2.4" to "SHA-224",
        "2.16.840.1.101.3.4.2.1" to "SHA-256",
        "2.16.840.1.101.3.4.2.2" to "SHA-384",
        "2.16.840.1.101.3.4.2.3" to "SHA-512",
    )

    /**
     * 해시 OID 를 JCA `MessageDigest` 이름으로 변환한다.
     * 알 수 없는 OID 는 OID 문자열을 그대로 반환한다(상위에서 처리).
     */
    fun jcaName(oid: String): String = OID_TO_NAME[oid] ?: oid
}
