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
package com.juncaffe.mrtdcore.apdu

import java.io.ByteArrayOutputStream

/**
 * ISO/IEC 7816-4 명령 APDU. 짧은/확장 길이(short/extended Lc·Le)를 모두 인코딩한다.
 *
 * 4가지 케이스:
 * - Case 1: 데이터 없음, Le 없음            → CLA INS P1 P2
 * - Case 2: 데이터 없음, Le 있음            → ... Le
 * - Case 3: 데이터 있음, Le 없음            → ... Lc data
 * - Case 4: 데이터 있음, Le 있음            → ... Lc data Le
 *
 * @param data 명령 데이터 (없으면 빈 배열)
 * @param ne   기대 응답 길이(Le). 0 이면 Le 미포함. short=최대 256, extended=최대 65536.
 * @param forceExtended 데이터/Le 가 짧아도 확장 길이 포맷을 강제
 */
class CommandApdu(
    val cla: Int,
    val ins: Int,
    val p1: Int,
    val p2: Int,
    data: ByteArray = EMPTY,
    val ne: Int = 0,
    forceExtended: Boolean = false,
) {
    val data: ByteArray = data.copyOf()
    val nc: Int get() = data.size

    /** 확장 길이 포맷 사용 여부 */
    val isExtended: Boolean = forceExtended || data.size > MAX_SHORT || ne > 256

    init {
        require(cla in 0..0xFF && ins in 0..0xFF && p1 in 0..0xFF && p2 in 0..0xFF) {
            "CLA/INS/P1/P2 must be a single byte"
        }
        require(ne in 0..65536) { "ne(Le) out of range: $ne" }
        require(data.size <= 65535) { "data too long: ${data.size}" }
    }

    /** 와이어 전송용 바이트로 인코딩한다. */
    fun toBytes(): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(cla and 0xFF)
        out.write(ins and 0xFF)
        out.write(p1 and 0xFF)
        out.write(p2 and 0xFF)

        if (nc > 0) {
            if (isExtended) {
                out.write(0x00)
                out.write((nc ushr 8) and 0xFF)
                out.write(nc and 0xFF)
            } else {
                out.write(nc and 0xFF)
            }
            out.write(data)
        }

        if (ne > 0) {
            if (isExtended) {
                if (nc == 0) out.write(0x00)            // Case 2E 선두 바이트
                if (ne == 65536) {
                    out.write(0x00); out.write(0x00)
                } else {
                    out.write((ne ushr 8) and 0xFF); out.write(ne and 0xFF)
                }
            } else {
                out.write(if (ne == 256) 0x00 else ne and 0xFF)
            }
        }
        return out.toByteArray()
    }

    companion object {
        val EMPTY = ByteArray(0)
        private const val MAX_SHORT = 255
    }
}
