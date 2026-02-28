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

import com.juncaffe.mrtdcore.apdu.ApduSpec
import com.juncaffe.mrtdcore.lds.tlv.BerTlvReader
import com.juncaffe.mrtdcore.lds.tlv.berEncodeLength

/**
 * Secure Messaging 데이터 오브젝트(DO87/DO97/DO99/DO8E)의 인코딩/디코딩 헬퍼.
 * 암호 알고리즘과 무관한 부분을 DES/AES SM 이 공유한다(중복 제거). (ICAO Doc 9303 Part 11 §9.8)
 */
internal object SmDataObjects {

    /** DO87 = `87 L 01 [암호문]` (선두 0x01 은 패딩-콘텐츠 지시자). */
    fun do87(encrypted: ByteArray): ByteArray {
        val body = byteArrayOf(0x01) + encrypted
        return byteArrayOf(ApduSpec.TAG_SM_ENCRYPTED_DATA.toByte()) + berEncodeLength(body.size) + body
    }

    /** DO97 = `97 L Le` (short=1바이트, extended=2바이트). */
    fun do97(ne: Int): ByteArray = if (ne <= 256) {
        byteArrayOf(ApduSpec.TAG_SM_EXPECTED_LENGTH.toByte(), 0x01, (if (ne == 256) 0 else ne).toByte())
    } else {
        byteArrayOf(ApduSpec.TAG_SM_EXPECTED_LENGTH.toByte(), 0x02, ((ne ushr 8) and 0xFF).toByte(), (ne and 0xFF).toByte())
    }

    /** DO8E = `8E 08 [MAC 8바이트]`. */
    fun do8e(mac8: ByteArray): ByteArray =
        byteArrayOf(ApduSpec.TAG_SM_MAC.toByte(), 0x08) + mac8

    /**
     * 보호 응답 데이터에서 DO 들을 파싱한다.
     * MAC 재계산에 필요한 DO87/DO99 의 원본 인코딩과, 복호 대상 암호문·SW·MAC 을 함께 돌려준다.
     */
    fun parseResponse(data: ByteArray): ParsedResponse {
        val reader = BerTlvReader(data)
        var do87Raw = EMPTY
        var do99Raw = EMPTY
        var encryptedData: ByteArray? = null
        var statusWord = 0
        var mac: ByteArray? = null
        while (reader.hasNext()) {
            val tlv = reader.readTlv()
            when (tlv.tag) {
                ApduSpec.TAG_SM_ENCRYPTED_DATA -> {
                    do87Raw = byteArrayOf(ApduSpec.TAG_SM_ENCRYPTED_DATA.toByte()) + berEncodeLength(tlv.value.size) + tlv.value
                    encryptedData = tlv.value.copyOfRange(1, tlv.value.size) // 0x01 지시자 제외
                }
                ApduSpec.TAG_SM_PROCESSING_STATUS -> {
                    do99Raw = byteArrayOf(ApduSpec.TAG_SM_PROCESSING_STATUS.toByte()) + berEncodeLength(tlv.value.size) + tlv.value
                    statusWord = ((tlv.value[0].toInt() and 0xFF) shl 8) or (tlv.value[1].toInt() and 0xFF)
                }
                ApduSpec.TAG_SM_MAC -> mac = tlv.value
            }
        }
        return ParsedResponse(do87Raw, do99Raw, encryptedData, statusWord, mac)
    }

    /** [parseResponse] 결과. */
    class ParsedResponse(
        val do87Raw: ByteArray,
        val do99Raw: ByteArray,
        val encryptedData: ByteArray?,
        val statusWord: Int,
        val mac: ByteArray?,
    )

    private val EMPTY = ByteArray(0)
}
