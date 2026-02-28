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
package com.juncaffe.mrtdcore.lds.dg1

import com.juncaffe.mrtdcore.domain.error.MrtdException
import com.juncaffe.mrtdcore.domain.model.DataGroupId
import com.juncaffe.mrtdcore.domain.model.Mrz
import com.juncaffe.mrtdcore.lds.DataGroupParser
import com.juncaffe.mrtdcore.lds.LdsTag
import com.juncaffe.mrtdcore.lds.tlv.BerTlvReader
import com.juncaffe.mrtdcore.mrz.MrzParser
import com.juncaffe.mrtdcore.security.Zeroizer

/**
 * DG1 파서. 구조: `61 { 5F1F MRZ }` → MRZ 바이트를 [Mrz] 로 파싱한다.
 * (ICAO Doc 9303 Part 10)
 */
object Dg1Parser : DataGroupParser<Mrz> {

    override val id: DataGroupId = DataGroupId.DG1

    /**
     * DG1 바이트에서 MRZ 를 추출해 파싱한다. String 으로 변환하지 않고 바이트로 처리하며,
     * 파싱 과정에서 만든 PII 중간 버퍼(컨테이너/ MRZ 복사본)는 반환 직전 0으로 소거한다.
     * 입력 [content] 는 호출자 소유이므로 여기서 소거하지 않는다.
     *
     * @throws MrtdException.ParseError 태그 불일치 또는 MRZ 누락
     */
    override fun parse(content: ByteArray): Mrz {
        val root = BerTlvReader(content).readTlv()
        var mrzValue: ByteArray? = null
        try {
            if (root.tag != LdsTag.DG1) {
                throw MrtdException.ParseError("not a DG1 (tag=0x%X)".format(root.tag))
            }
            val mrzTlv = root.reader().find(LdsTag.MRZ_DATA)
                ?: throw MrtdException.ParseError("MRZ data (0x5F1F) not found in DG1")
            mrzValue = mrzTlv.value
            return MrzParser.parse(mrzValue)
        } finally {
            Zeroizer.wipe(root.value)
            Zeroizer.wipe(mrzValue)
        }
    }
}
