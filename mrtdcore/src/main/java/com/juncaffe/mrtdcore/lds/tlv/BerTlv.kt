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
package com.juncaffe.mrtdcore.lds.tlv

import com.juncaffe.mrtdcore.domain.error.MrtdException

/**
 * BER 길이를 최소 형식으로 인코딩한다 (ISO/IEC 8825-1 §8.1.3).
 * short-form(< 0x80) = 1바이트, 0x80..0xFF = 0x81 + 1바이트, 그 이상 = 0x82 + 2바이트.
 */
internal fun berEncodeLength(len: Int): ByteArray = when {
    len < 0x80  -> byteArrayOf(len.toByte())
    len < 0x100 -> byteArrayOf(0x81.toByte(), len.toByte())
    else        -> byteArrayOf(0x82.toByte(), (len ushr 8).toByte(), len.toByte())
}

/**
 * 하나의 BER-TLV 요소. [tag] 는 다중 바이트 태그를 누적한 정수, [value] 는 콘텐츠 바이트.
 */
class Tlv(val tag: Int, val value: ByteArray) {
    /** 이 요소의 [value] 를 다시 TLV 로 순회하기 위한 리더를 만든다(중첩 구조용). */
    fun reader(): BerTlvReader = BerTlvReader(value)
}

/**
 * 최소 BER-TLV 리더 (ISO/IEC 8825-1 / ICAO Doc 9303 Part 10).
 *
 * 다중 바이트 태그와 long-form 길이를 지원하며, DER 가정 하에 indefinite length 는 거부한다.
 * LDS 컨테이너 헤더와 CBEFF 파싱에 사용한다(순수 ASN.1 은 BouncyCastle 에 위임).
 *
 * @param data   대상 바이트
 * @param offset 시작 위치
 * @param length 읽을 길이(기본: [offset] 부터 끝까지)
 */
class BerTlvReader(
    private val data: ByteArray,
    offset: Int = 0,
    length: Int = data.size - offset,
) {
    private var pos = offset
    private val end = offset + length

    /** 아직 읽을 바이트가 남아 있는지 여부. */
    fun hasNext(): Boolean = pos < end

    /**
     * 태그를 읽는다. 첫 바이트 하위 5비트가 모두 1이면 다중 바이트 태그로 이어 읽는다.
     * @return 누적된 태그 정수 (예: 0x5F1F, 0x7F61)
     */
    fun readTag(): Int {
        requireAvailable(1)
        var tag = data[pos++].toInt() and 0xFF
        if ((tag and 0x1F) == 0x1F) {
            var b: Int
            do {
                requireAvailable(1)
                b = data[pos++].toInt() and 0xFF
                tag = (tag shl 8) or b
            } while ((b and 0x80) != 0)
        }
        return tag
    }

    /**
     * 길이를 읽는다. short-form(<0x80)은 그대로, long-form 은 후속 바이트 수만큼 빅엔디언으로 읽는다.
     * @throws MrtdException.ParseError indefinite length 또는 과대 길이
     */
    fun readLength(): Int {
        requireAvailable(1)
        val first = data[pos++].toInt() and 0xFF
        if (first < 0x80) return first
        if (first == 0x80) throw MrtdException.ParseError("indefinite length not supported")
        val numBytes = first and 0x7F
        if (numBytes > 4) throw MrtdException.ParseError("length field too large: $numBytes bytes")
        requireAvailable(numBytes)
        var len = 0
        repeat(numBytes) { len = (len shl 8) or (data[pos++].toInt() and 0xFF) }
        if (len < 0) throw MrtdException.ParseError("negative length")
        return len
    }

    /** [length] 바이트의 값을 읽어 복사본으로 반환하고 커서를 전진시킨다. */
    fun readValue(length: Int): ByteArray {
        requireAvailable(length)
        val v = data.copyOfRange(pos, pos + length)
        pos += length
        return v
    }

    /** 현재 위치에서 TLV 하나(tag+length+value)를 읽는다. */
    fun readTlv(): Tlv {
        val tag = readTag()
        val len = readLength()
        return Tlv(tag, readValue(len))
    }

    /**
     * 현재 레벨에서 [tag] 와 일치하는 첫 TLV 를 찾을 때까지 순차적으로 읽는다(커서 전진).
     * @return 일치 TLV, 없으면 null
     */
    fun find(tag: Int): Tlv? {
        while (hasNext()) {
            val tlv = readTlv()
            if (tlv.tag == tag) return tlv
        }
        return null
    }

    /** 남은 바이트가 [n] 미만이면 ParseError 를 던진다. */
    private fun requireAvailable(n: Int) {
        if (pos + n > end) throw MrtdException.ParseError("unexpected end of TLV data")
    }
}
