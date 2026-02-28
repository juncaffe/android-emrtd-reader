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

/** MRZ 성별 필드(ICAO Doc 9303 Part 3). */
enum class Gender {
    MALE,
    FEMALE,
    UNSPECIFIED;

    companion object {
        /**
         * MRZ 성별 바이트를 [Gender] 로 변환한다(String 미생성).
         * @param b 'M' | 'F' | '<'(미지정) ASCII 바이트 — 대소문자 무시
         */
        fun fromMrz(b: Byte): Gender = when ((b.toInt() and 0xFF).toChar().uppercaseChar()) {
            'M' -> MALE
            'F' -> FEMALE
            else -> UNSPECIFIED
        }
    }
}
