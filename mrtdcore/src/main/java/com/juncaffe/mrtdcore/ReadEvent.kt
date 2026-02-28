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
package com.juncaffe.mrtdcore

import com.juncaffe.mrtdcore.domain.model.DataGroupId

/** [PassportReader] 진행 단계 이벤트(진행 상태 표시용). */
sealed interface ReadEvent {
    enum class AccessControl { PACE, BAC }

    /** PACE/BAC 보안 채널 수립 중 */
    data object EstablishingSecureChannel : ReadEvent

    /** PACE 또는 BAC 보안 채널 수립 성공 */
    data class AccessControlEstablished(val method: AccessControl) : ReadEvent

    /** 시도한 접근 제어가 실패하여 다른 방식으로 폴백함 */
    data class AccessControlFailed(val method: AccessControl, val reason: String?) : ReadEvent

    /** Chip Authentication 수행 중 */
    data object ChipAuthenticating : ReadEvent

    /** Chip Authentication 수행 결과 */
    data class ChipAuthenticationCompleted(val success: Boolean, val reason: String? = null) : ReadEvent

    /** 데이터 그룹 읽는 중 */
    data class ReadingDataGroup(val dataGroup: DataGroupId) : ReadEvent

    /**
     * 데이터 그룹/SOD 의 바이트 단위 읽기 진행률. DG2 처럼 큰 파일의 0~100% 표시용.
     * @param bytesRead 누적 읽은 바이트 @param totalBytes 파일 전체 바이트
     */
    data class DataGroupProgress(
        val dataGroup: DataGroupId,
        val bytesRead: Int,
        val totalBytes: Int,
    ) : ReadEvent

    /** 데이터 그룹 읽기 성공 */
    data class DataGroupRead(val dataGroup: DataGroupId) : ReadEvent

    /** EF.SOD 읽기 성공 */
    data object SodRead : ReadEvent

    /** Passive Authentication 수행 중 */
    data object PassiveAuthenticating : ReadEvent

    /** Passive Authentication 검증 결과 */
    data class PassiveAuthenticationCompleted(val success: Boolean, val reason: String? = null) : ReadEvent
}
