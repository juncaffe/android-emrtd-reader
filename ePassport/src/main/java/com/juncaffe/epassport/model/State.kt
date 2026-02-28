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
package com.juncaffe.epassport.model

import com.juncaffe.mrtdcore.domain.model.DataGroupId

/** 여권 읽기 진행 상태. */
sealed interface State {
    enum class AccessControl { PACE, BAC }

    /** PACE/BAC 보안 채널 수립 중 */
    data object EstablishingSecureChannel : State

    data class AccessControlEstablished(val method: AccessControl) : State

    data class AccessControlFailed(val method: AccessControl, val reason: String?) : State

    /** Chip Authentication 수행 중 */
    data object ChipAuthentication : State

    data class ChipAuthenticationCompleted(val success: Boolean, val reason: String?) : State

    /** Passive Authentication 수행 중 */
    data object PassiveAuthentication : State

    data class PassiveAuthenticationCompleted(val success: Boolean, val reason: String?) : State

    /** 데이터 그룹 읽는 중 */
    data class Reading(val dataGroup: DataGroupId) : State

    /**
     * 데이터 그룹/SOD 바이트 단위 읽기 진행률. DG2 등 큰 파일의 0~100% 표시용.
     * @param bytesRead 누적 읽은 바이트 @param totalBytes 파일 전체 바이트
     */
    data class ReadingProgress(
        val dataGroup: DataGroupId,
        val bytesRead: Int,
        val totalBytes: Int,
    ) : State

    data class DataGroupRead(val dataGroup: DataGroupId) : State

    data object SodRead : State
}
