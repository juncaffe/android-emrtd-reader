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
package com.juncaffe.mrtdcore.crypto

import com.juncaffe.mrtdcore.domain.error.MrtdException

/**
 * ISO/IEC 9797-1 패딩 방법 2 (= ISO 7816-4 패딩). 항상 `0x80` 한 바이트 이상을 덧붙이고
 * 블록 경계까지 `0x00` 으로 채운다. (ICAO Doc 9303 Part 11, Secure Messaging)
 */
object Padding {
    private const val MARKER: Byte = 0x80.toByte()

    /**
     * [data] 를 [blockSize] 배수로 패딩한다. 이미 정렬돼 있어도 한 블록을 더 추가한다(방법 2).
     */
    fun pad(data: ByteArray, blockSize: Int): ByteArray {
        val padLen = blockSize - (data.size % blockSize)
        val out = data.copyOf(data.size + padLen)
        out[data.size] = MARKER
        return out
    }

    /**
     * 방법 2 패딩을 제거한다. 뒤쪽 `0x00` 을 지나 마지막 `0x80` 까지 잘라낸다.
     * @throws MrtdException.ParseError 유효한 패딩이 아님
     */
    fun unpad(data: ByteArray): ByteArray {
        var i = data.size - 1
        while (i >= 0 && data[i] == 0.toByte()) i--
        if (i < 0 || data[i] != MARKER) throw MrtdException.ParseError("invalid ISO9797-1 method 2 padding")
        return data.copyOfRange(0, i)
    }
}
