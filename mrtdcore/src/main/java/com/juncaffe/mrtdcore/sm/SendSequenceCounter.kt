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
package com.juncaffe.mrtdcore.sm

import java.math.BigInteger

/**
 * Send Sequence Counter. 명령/응답마다 1씩 증가하는 카운터.
 * 크기는 블록 크기에 맞춘다: 3DES SM = 8바이트, AES SM = 16바이트. (ICAO Doc 9303 Part 11 §9.8)
 */
class SendSequenceCounter(initial: ByteArray) {

    private val size = initial.size

    init { require(size == 8 || size == 16) { "SSC must be 8 or 16 bytes" } }

    private var value = BigInteger(1, initial)
    private val mask = BigInteger.ONE.shiftLeft(size * 8).subtract(BigInteger.ONE)

    /** SSC 를 1 증가시키고 증가된 값을 반환한다(크기 비트 폭에서 wrap). */
    fun increment(): ByteArray {
        value = value.add(BigInteger.ONE).and(mask)
        return bytes()
    }

    /** 현재 SSC 의 [size]바이트 빅엔디언 표현. */
    fun bytes(): ByteArray {
        val raw = value.toByteArray() // 부호 비트로 인해 한 바이트 길어질 수 있음
        val out = ByteArray(size)
        val src = if (raw.size > size) raw.copyOfRange(raw.size - size, raw.size) else raw
        System.arraycopy(src, 0, out, size - src.size, src.size)
        return out
    }
}
