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

import com.juncaffe.mrtdcore.security.SecureByteArray
import com.juncaffe.mrtdcore.security.Wipeable
import com.juncaffe.mrtdcore.security.Zeroizer

/**
 * DG1(MRZ) 파싱 결과. (ICAO Doc 9303 Part 4, TD3)
 *
 * 텍스트 필드는 채움문자 '<'를 포함한 ASCII 바이트로 보관한다.
 * 사용이 끝나면 [wipe]를 호출해야 한다.
 *
 * @property dateOfBirth `YYMMDD` 6바이트 @property dateOfExpiry `YYMMDD` 6바이트
 */
class Mrz(
    val documentCode: SecureByteArray,
    val issuingState: SecureByteArray,
    val surname: SecureByteArray,
    val givenNames: SecureByteArray,
    val documentNumber: SecureByteArray,
    val documentNumberCheckDigit: Byte,
    val nationality: SecureByteArray,
    val dateOfBirth: SecureByteArray,
    val dateOfBirthCheckDigit: Byte,
    val gender: Gender,
    val dateOfExpiry: SecureByteArray,
    val dateOfExpiryCheckDigit: Byte,
    val optionalData: SecureByteArray,
) : Wipeable {

    /**
     * BAC 키 시드 산출용 "MRZ information" 바이트.
     * (문서번호 9바이트 ‖ 문서번호CD ‖ 생년월일 6 ‖ 생년월일CD ‖ 만료일 6 ‖ 만료일CD = 24바이트)
     *
     * 반환값은 사용 후 [SecureByteArray.wipe]로 소거해야 한다.
     */
    fun mrzInformation(): SecureByteArray {
        val dn = documentNumber.copyOf()
        // 문서번호는 9바이트로 채움문자 '<' 패딩(표준 TD3)
        val dnField = if (dn.size == 9) dn else ByteArray(9) { if (it < dn.size) dn[it] else FILLER }
        val dob = dateOfBirth.copyOf()
        val exp = dateOfExpiry.copyOf()

        val out = ByteArray(9 + 1 + 6 + 1 + 6 + 1)
        var p = 0
        dnField.copyInto(out, p); p += 9
        out[p++] = documentNumberCheckDigit
        dob.copyInto(out, p); p += 6
        out[p++] = dateOfBirthCheckDigit
        exp.copyInto(out, p); p += 6
        out[p] = dateOfExpiryCheckDigit

        Zeroizer.wipe(dn); Zeroizer.wipe(dob); Zeroizer.wipe(exp)
        if (dnField !== dn) Zeroizer.wipe(dnField)
        return SecureByteArray.wrap(out)
    }

    /** 모든 민감 버퍼를 0으로 덮어쓴다. */
    override fun wipe() {
        Zeroizer.wipe(
            documentCode, issuingState, surname, givenNames, documentNumber,
            nationality, dateOfBirth, dateOfExpiry, optionalData,
        )
    }

    /** 필드값을 노출하지 않는다. */
    override fun toString(): String = "Mrz(****)"

    private companion object {
        const val FILLER: Byte = '<'.code.toByte()
    }
}
