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
 * Passive Authentication 결과. (ICAO Doc 9303 Part 12)
 *
 * "검증 실패"(서명 무효/해시 불일치)와 "검증 불가"([error]; SOD 읽기·CMS 파싱 실패)는 구분된다.
 * 전자는 [performed]=true·[isValid]=false, 후자는 [performed]=false 로 표현하며 두 경우 모두 여권
 * 데이터는 정상 반환된다(호출자가 [isValid]/[performed] 로 신뢰 여부를 판단).
 *
 * @property signatureValid SOD 의 SignerInfo 서명이 DSC 로 검증됨(서명 속성·eContent 다이제스트 포함)
 * @property hashesValid    읽은 모든 DG 의 실제 해시가 SOD 기록과 일치
 * @property perDataGroup   DG 번호 → 해시 일치 여부
 * @property documentSignerSubject DSC 주체 DN
 * @property documentSignerCertificate DSC(X.509)
 * @property error          PA 를 수행하지 못한 사유(SOD 읽기/파싱 실패 등). null 이면 검증을 수행함.
 */
class PaResult(
    val signatureValid: Boolean,
    val hashesValid: Boolean,
    val perDataGroup: Map<Int, Boolean>,
    val documentSignerSubject: String?,
    val documentSignerCertificate: X509Certificate?,
    val error: String? = null,
) {
    /** PA 검증을 실제로 수행했는가(SOD 읽기·파싱 성공). false 면 [error] 에 사유가 담긴다. */
    val performed: Boolean get() = error == null

    /** PA 통과 여부(수행됨 + 서명 + 해시 모두 유효). DSC→CSCA 체인 검증은 본 범위 밖이다. */
    val isValid: Boolean get() = performed && signatureValid && hashesValid

    companion object {
        /** SOD 읽기/파싱 실패 등으로 PA 를 수행하지 못한 결과(검증 실패와 구분). */
        fun notPerformed(reason: String): PaResult =
            PaResult(signatureValid = false, hashesValid = false, perDataGroup = emptyMap(),
                documentSignerSubject = null, documentSignerCertificate = null, error = reason)
    }
}
