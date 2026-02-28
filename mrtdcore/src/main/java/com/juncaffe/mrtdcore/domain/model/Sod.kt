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

import java.security.cert.X509Certificate

/**
 * EF.SOD (Document Security Object) 파싱 결과. (ICAO Doc 9303 Part 12)
 *
 * 파싱만 담당하며 서명 검증은 Passive Authentication(별도 단계)에서 [eContent]/[signature]/
 * [docSigningCertificate] 와 [dataGroupHashes] 를 사용해 수행한다.
 *
 * @property digestAlgorithm     DG 해시 알고리즘 JCA 이름 (예: "SHA-256")
 * @property dataGroupHashes     DG 번호 → 해시값
 * @property eContent            서명 대상(LDSSecurityObject DER) 원본 바이트
 * @property signature           SignerInfo 의 encryptedDigest(서명값)
 * @property signatureAlgorithmOid 서명 알고리즘 OID
 * @property docSigningCertificate 문서 서명 인증서(DSC), 없으면 null
 */
class Sod(
    val digestAlgorithm: String,
    val dataGroupHashes: Map<Int, ByteArray>,
    val eContent: ByteArray,
    val signature: ByteArray,
    val signatureAlgorithmOid: String?,
    val docSigningCertificate: X509Certificate?,
)
