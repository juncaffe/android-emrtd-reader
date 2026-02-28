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
package com.juncaffe.mrtdcore.domain.error

/**
 * 코어의 도메인 에러 계층. 상위 모듈은 sealed 분기로 사용자 메시지를 매핑한다.
 */
sealed class MrtdException(message: String?, cause: Throwable? = null) : Exception(message, cause) {

    /** 카드 통신 실패 (전송 오류, 예기치 못한 SW 등) */
    class TransportError(message: String?, cause: Throwable? = null) : MrtdException(message, cause)

    /** 접근 제어 실패 (BAC/PACE) */
    class AccessDenied(message: String?, cause: Throwable? = null) : MrtdException(message, cause)

    /** 칩 인증(EAC-CA) 실패 */
    class ChipAuthenticationFailed(message: String?, cause: Throwable? = null) : MrtdException(message, cause)

    /** 수동 인증(PA) 실패 — 서명/해시 불일치 */
    class PassiveAuthenticationFailed(message: String?, cause: Throwable? = null) : MrtdException(message, cause)

    /** LDS/TLV/ASN.1 파싱 실패 */
    class ParseError(message: String?, cause: Throwable? = null) : MrtdException(message, cause)

    /** 미지원 기능/알고리즘/문서타입 */
    class UnsupportedFeature(message: String?, cause: Throwable? = null) : MrtdException(message, cause)
}
