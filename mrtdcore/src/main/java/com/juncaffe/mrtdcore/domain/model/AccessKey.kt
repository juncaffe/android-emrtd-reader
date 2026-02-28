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

import com.juncaffe.mrtdcore.mrz.CheckDigit
import com.juncaffe.mrtdcore.security.Wipeable
import com.juncaffe.mrtdcore.security.Zeroizer

/**
 * BAC/PACE 접근키의 입력인 MRZ information 을 담는다(문서번호+CD‖생년월일+CD‖만료일+CD).
 * 민감 정보이므로 [wipe] 로 0화한다.
 */
class AccessKey(mrzInfo: ByteArray) : Wipeable {

    /** MRZ information 바이트(24바이트). BAC 시드/PACE 패스워드 유도에 사용. */
    val mrzInfo: ByteArray = mrzInfo.copyOf()

    override fun wipe() = mrzInfo.fill(0)

    companion object {
        private const val FILLER: Byte = '<'.code.toByte()

        /**
         * 문서번호·생년월일·만료일로부터 MRZ information 을 만들어 [AccessKey] 를 생성한다.
         * 입력 바이트는 호출자 소유이며, 내부 임시 버퍼는 0화한다.
         *
         * @param documentNumber 문서번호(≤9, ASCII) @param dateOfBirth `YYMMDD`(6) @param dateOfExpiry `YYMMDD`(6)
         */
        fun fromMrzFields(documentNumber: ByteArray, dateOfBirth: ByteArray, dateOfExpiry: ByteArray): AccessKey {
            require(dateOfBirth.size == 6 && dateOfExpiry.size == 6) { "dates must be YYMMDD (6 bytes)" }
            val documentField = ByteArray(9) { if (it < documentNumber.size) documentNumber[it] else FILLER }
            val out = ByteArray(9 + 1 + 6 + 1 + 6 + 1)
            var p = 0
            documentField.copyInto(out, p); p += 9
            out[p++] = asciiDigit(CheckDigit.compute(documentField))
            dateOfBirth.copyInto(out, p); p += 6
            out[p++] = asciiDigit(CheckDigit.compute(dateOfBirth))
            dateOfExpiry.copyInto(out, p); p += 6
            out[p] = asciiDigit(CheckDigit.compute(dateOfExpiry))

            val key = AccessKey(out)
            Zeroizer.wipe(out); Zeroizer.wipe(documentField)
            return key
        }

        private fun asciiDigit(value: Int): Byte = ('0'.code + value).toByte()
    }
}
