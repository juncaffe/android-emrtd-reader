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
package com.juncaffe.mrtdcore.lds

/**
 * LDS 파일/CBEFF 의 BER-TLV 태그 상수 (ICAO Doc 9303 Part 10, ISO/IEC 19794-5).
 * 표준에 정의된 태그 값이다.
 */
object LdsTag {
    const val COM = 0x60
    const val DG1 = 0x61
    const val MRZ_DATA = 0x5F1F
    const val DG2 = 0x75
    const val DG14 = 0x6E
    const val SOD = 0x77

    // DG2 / CBEFF (ISO/IEC 19794-5)
    const val BIOMETRIC_GROUP_TEMPLATE = 0x7F61
    const val BIOMETRIC_TEMPLATE = 0x7F60
    const val BIOMETRIC_DATA_BLOCK = 0x5F2E
    const val BIOMETRIC_DATA_BLOCK_CONSTRUCTED = 0x7F2E
}
