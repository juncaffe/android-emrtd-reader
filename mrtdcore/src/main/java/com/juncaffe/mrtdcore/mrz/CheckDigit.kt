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
package com.juncaffe.mrtdcore.mrz

import com.juncaffe.mrtdcore.domain.error.MrtdException

/**
 * MRZ 체크디지트 계산/검증 (ICAO Doc 9303 Part 3, 7-3-1 가중치).
 * `String` 을 사용하지 않고 ASCII 바이트로만 처리한다.
 */
object CheckDigit {

    private val WEIGHTS = intArrayOf(7, 3, 1)
    private const val FILLER: Byte = '<'.code.toByte()

    /**
     * MRZ 바이트의 숫자 값을 반환한다. 숫자=0~9, 'A'~'Z'=10~35, 채움문자 '<'=0.
     * @throws MrtdException.ParseError 허용되지 않는 문자
     */
    fun valueOf(b: Byte): Int = when (val c = b.toInt() and 0xFF) {
        in '0'.code..'9'.code -> c - '0'.code
        in 'A'.code..'Z'.code -> c - 'A'.code + 10
        '<'.code -> 0
        else -> throw MrtdException.ParseError("invalid MRZ byte: 0x%02X".format(c))
    }

    /**
     * [input] 의 `[from, from+length)` 구간 체크디지트를 계산한다(7-3-1 가중합 mod 10).
     * 슬라이스 복사 없이 계산해 중간 버퍼를 남기지 않는다.
     */
    fun compute(input: ByteArray, from: Int = 0, length: Int = input.size - from): Int {
        var sum = 0
        for (i in 0 until length) sum += valueOf(input[from + i]) * WEIGHTS[i % WEIGHTS.size]
        return sum % 10
    }

    /**
     * `[from, from+length)` 의 계산된 체크디지트가 [expected] 바이트와 일치하는지 검증한다.
     * 채움문자 '<' 는 0 으로 간주한다.
     */
    fun verify(input: ByteArray, expected: Byte, from: Int = 0, length: Int = input.size - from): Boolean {
        val exp = when (val e = expected.toInt() and 0xFF) {
            in '0'.code..'9'.code -> e - '0'.code
            '<'.code -> 0
            else -> return false
        }
        return compute(input, from, length) == exp
    }
}
