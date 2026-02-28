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
package com.juncaffe.epassport.nfc

import android.nfc.Tag
import android.nfc.TagLostException
import android.nfc.tech.IsoDep
import android.os.SystemClock
import com.juncaffe.mrtdcore.debug.MrtdDebug
import com.juncaffe.mrtdcore.domain.error.MrtdException
import com.juncaffe.mrtdcore.domain.port.CardTransport
import com.juncaffe.mrtdcore.domain.port.Reconnectable
import java.io.IOException

/**
 * Android NFC IsoDep(ISO 14443-4) 기반 [CardTransport] 구현.
 * mrtdcore 의 유일한 Android 의존 지점이다.
 */
class IsoDepCardTransport(tag: Tag, private val timeoutMillis: Int = 5_000) : CardTransport, Reconnectable {

    private val isoDep: IsoDep =
        IsoDep.get(tag) ?: throw IllegalArgumentException("tag does not support ISO-DEP")

    /** 카드 세션을 연결한다. */
    fun open() {
        if (!isoDep.isConnected) {
            try {
                // 응답이 느린 구형 eMRTD의 GET CHALLENGE/암호 연산을 위해
                // IsoDep 기본 타임아웃보다 여유 있게 설정한다.
                isoDep.timeout = timeoutMillis
                isoDep.connect()
                if (!isoDep.isConnected) {
                    throw MrtdException.TransportError("NFC connect failed: IsoDep is not connected")
                }
                MrtdDebug.log("NFC") {
                    "IsoDep connected timeout=${isoDep.timeout}ms maxTransceive=${isoDep.maxTransceiveLength} " +
                        "extended=${isoDep.isExtendedLengthApduSupported}"
                }
            } catch (e: IOException) {
                throw MrtdException.TransportError("NFC connect failed", e)
            }
        }
    }

    override fun transceive(commandApdu: ByteArray): ByteArray {
        if (!isoDep.isConnected) {
            throw MrtdException.TransportError("NFC transceive failed: IsoDep is not connected")
        }
        val startedAt = SystemClock.elapsedRealtime()
        MrtdDebug.log("NFC") {
            "TX INS=%02X len=%d".format(
                commandApdu.getOrNull(1)?.toInt()?.and(0xFF) ?: -1,
                commandApdu.size,
            )
        }
        return try {
            val response = isoDep.transceive(commandApdu)
            if (response.size < MIN_RESPONSE_LENGTH) {
                throw MrtdException.TransportError("NFC transceive failed: response shorter than SW1/SW2")
            }
            MrtdDebug.log("NFC") {
                "INS=%02X tx=%d rx=%d SW=%02X%02X elapsed=%dms".format(
                    commandApdu.getOrNull(1)?.toInt()?.and(0xFF) ?: -1,
                    commandApdu.size,
                    response.size,
                    response[response.size - 2].toInt() and 0xFF,
                    response[response.size - 1].toInt() and 0xFF,
                    SystemClock.elapsedRealtime() - startedAt,
                )
            }
            response
        } catch (e: TagLostException) {
            throw MrtdException.TransportError(
                "NFC tag lost after ${SystemClock.elapsedRealtime() - startedAt}ms. " +
                    "Keep the passport still against the phone and try again.",
                e,
            )
        } catch (e: IOException) {
            throw MrtdException.TransportError(
                "NFC transceive failed after ${SystemClock.elapsedRealtime() - startedAt}ms",
                e,
            )
        }
    }

    /**
     * 카드 세션을 끊고 다시 연결한다. 느린 구형 칩이 FWT 초과로 일시적 TagLost 를 낸 뒤
     * 칩이 아직 필드 안에 있을 때 프로토콜을 처음부터 재시도하기 위해 사용한다.
     */
    override fun reconnect() {
        try {
            if (isoDep.isConnected) {
                try {
                    isoDep.close()
                } catch (e: IOException) {
                    // 닫기 실패는 무시하고 재연결을 시도한다.
                }
            }
            isoDep.timeout = timeoutMillis
            isoDep.connect()
            if (!isoDep.isConnected) {
                throw MrtdException.TransportError("NFC reconnect failed: IsoDep is not connected")
            }
            MrtdDebug.log("NFC") { "IsoDep reconnected timeout=${isoDep.timeout}ms" }
        } catch (e: IOException) {
            throw MrtdException.TransportError("NFC reconnect failed (tag left the field?)", e)
        }
    }

    /** 확장 길이 APDU 지원 여부. */
    val isExtendedLengthSupported: Boolean get() = isoDep.isExtendedLengthApduSupported

    /** 카드 세션을 종료한다. */
    fun close() {
        try {
            if (isoDep.isConnected) isoDep.close()
        } catch (e: IOException) {
            // 종료 실패는 무시
        }
    }

    private companion object {
        const val MIN_RESPONSE_LENGTH = 2
    }
}
