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
package com.juncaffe.epassport.app.model

import com.juncaffe.mrtdcore.AccessControlMode

enum class ScanStatus { Idle, Authentication, Scanning, Done, Error }

enum class PassportCheck(
    val label: String,
) {
    PACE("PACE 인증"),
    BAC("BAC 인증"),
    CA("Chip Authentication"),
    PA("Passive Authentication"),
    SOD("EF.SOD"),
    DG1("DG1 신원정보"),
    DG2("DG2 얼굴정보"),
    DG14("DG14 보안정보"),
}

enum class CheckStatus { Pending, InProgress, Success, Failed, Skipped }

data class ScanUiState(
    val status: ScanStatus = ScanStatus.Idle,
    val accessControlMode: AccessControlMode = AccessControlMode.PACE,
    val useChipAuthentication: Boolean = true,
    val usePassiveAuthentication: Boolean = true,
    val overallProgress: Int = 0,
    val stageProgress: LinkedHashMap<String, Int> = linkedMapOf(),
    val dg2ImageBytes: ByteArray? = null,
    val mrzFetched: Boolean = false,
    val mrzText: String? = null,
    val message: String? = null,
    val errorMessage: String? = null,
    val checks: Map<PassportCheck, CheckStatus> = PassportCheck.entries.associateWith { CheckStatus.Pending },
)
