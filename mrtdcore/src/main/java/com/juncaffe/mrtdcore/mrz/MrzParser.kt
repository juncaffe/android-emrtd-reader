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
import com.juncaffe.mrtdcore.domain.model.Gender
import com.juncaffe.mrtdcore.domain.model.Mrz
import com.juncaffe.mrtdcore.security.SecureByteArray
import com.juncaffe.mrtdcore.security.Zeroizer

/**
 * TD3(여권) MRZ 파서. (ICAO Doc 9303 Part 4)
 *
 * 입력 88바이트(2행 × 44)를 필드로 분해한다. 보안 요구상 [String] 으로 변환하지 않고
 * ASCII 바이트만 다루며, 정규화 작업 버퍼는 사용 직후 0으로 덮어쓴다.
 */
object MrzParser {

    private const val LINE_LENGTH = 44
    private const val TD3_LENGTH = LINE_LENGTH * 2
    private const val FILLER: Byte = '<'.code.toByte()
    private const val LF: Byte = '\n'.code.toByte()
    private const val CR: Byte = '\r'.code.toByte()
    private const val SP: Byte = ' '.code.toByte()

    /**
     * TD3 MRZ 바이트를 [Mrz] 로 파싱한다. 개행/공백은 제거하며 88바이트가 아니면 예외.
     * 입력 [mrzBytes] 는 호출자 소유이므로 소거하지 않는다(내부 정규화 사본만 소거).
     *
     * @throws MrtdException.ParseError 길이가 88이 아님
     */
    fun parse(mrzBytes: ByteArray): Mrz {
        val work = stripSeparators(mrzBytes)
        try {
            if (work.size != TD3_LENGTH) {
                throw MrtdException.ParseError("expected TD3 MRZ of $TD3_LENGTH bytes, got ${work.size}")
            }
            val l2 = LINE_LENGTH // 2행 시작 오프셋
            val (surname, givenNames) = parseName(work, 5, LINE_LENGTH)
            return Mrz(
                documentCode = slice(work, 0, 2),
                issuingState = slice(work, 2, 5),
                surname = surname,
                givenNames = givenNames,
                documentNumber = slice(work, l2 + 0, l2 + 9),
                documentNumberCheckDigit = work[l2 + 9],
                nationality = slice(work, l2 + 10, l2 + 13),
                dateOfBirth = slice(work, l2 + 13, l2 + 19),
                dateOfBirthCheckDigit = work[l2 + 19],
                gender = Gender.fromMrz(work[l2 + 20]),
                dateOfExpiry = slice(work, l2 + 21, l2 + 27),
                dateOfExpiryCheckDigit = work[l2 + 27],
                optionalData = slice(work, l2 + 28, l2 + 42),
            )
        } finally {
            Zeroizer.wipe(work)
        }
    }

    /** `[from, toExclusive)` 바이트를 소유권 이전 방식으로 [SecureByteArray] 에 담는다. */
    private fun slice(src: ByteArray, from: Int, toExclusive: Int): SecureByteArray =
        SecureByteArray.wrap(src.copyOfRange(from, toExclusive))

    /**
     * 이름 필드(`PRIMARY<<SECONDARY`)를 성/이름 바이트로 분리한다.
     * 구분자 "<<" 이전을 성, 이후를 이름으로 보고 각 끝의 채움문자만 트림한다('<' 치환은 표시 계층 담당).
     * @return (성, 이름) [SecureByteArray] 쌍
     */
    private fun parseName(work: ByteArray, from: Int, toExclusive: Int): Pair<SecureByteArray, SecureByteArray> {
        var sep = -1
        for (i in from until toExclusive - 1) {
            if (work[i] == FILLER && work[i + 1] == FILLER) { sep = i; break }
        }
        return if (sep >= 0) {
            val surname = work.copyOfRange(from, trimmedEnd(work, from, sep))
            val gStart = sep + 2
            val given = work.copyOfRange(gStart, trimmedEnd(work, gStart, toExclusive))
            SecureByteArray.wrap(surname) to SecureByteArray.wrap(given)
        } else {
            val surname = work.copyOfRange(from, trimmedEnd(work, from, toExclusive))
            SecureByteArray.wrap(surname) to SecureByteArray.wrap(ByteArray(0))
        }
    }

    /** `[start, end)` 에서 뒤쪽 채움문자('<')를 제외한 끝 인덱스를 반환한다. */
    private fun trimmedEnd(b: ByteArray, start: Int, end: Int): Int {
        var e = end
        while (e > start && b[e - 1] == FILLER) e--
        return e
    }

    /** 개행/공백 바이트를 제거한 새 작업 버퍼를 만든다(원본 불변). */
    private fun stripSeparators(input: ByteArray): ByteArray {
        var n = 0
        for (b in input) if (b != LF && b != CR && b != SP) n++
        val out = ByteArray(n)
        var p = 0
        for (b in input) if (b != LF && b != CR && b != SP) out[p++] = b
        return out
    }
}
