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

import com.juncaffe.mrtdcore.security.Wipeable

/**
 * ISO/IEC 7816-4 응답 APDU. 마지막 2바이트는 SW1 SW2, 나머지는 응답 데이터.
 */
class ResponseApdu(bytes: ByteArray) : Wipeable {

    init {
        require(bytes.size >= 2) { "response APDU must contain at least SW1 SW2" }
    }

    private val raw: ByteArray = bytes.copyOf()

    val sw1: Int get() = raw[raw.size - 2].toInt() and 0xFF
    val sw2: Int get() = raw[raw.size - 1].toInt() and 0xFF
    val sw: Int get() = (sw1 shl 8) or sw2
    val statusWord: StatusWord get() = StatusWord(sw)
    val isSuccess: Boolean get() = sw == StatusWord.SUCCESS

    /** SW 를 제외한 응답 데이터(복사본) */
    val data: ByteArray get() = raw.copyOfRange(0, raw.size - 2)

    /** 전체 바이트(데이터+SW, 복사본) */
    fun toBytes(): ByteArray = raw.copyOf()

    /** 내부 응답 버퍼를 사용 직후 0으로 덮어쓴다. */
    override fun wipe() = raw.fill(0)
}
