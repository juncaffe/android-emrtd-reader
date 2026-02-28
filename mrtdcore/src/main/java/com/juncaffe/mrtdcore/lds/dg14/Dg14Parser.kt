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
package com.juncaffe.mrtdcore.lds.dg14

import com.juncaffe.mrtdcore.domain.error.MrtdException
import com.juncaffe.mrtdcore.domain.model.DataGroupId
import com.juncaffe.mrtdcore.domain.model.SecurityInfo
import com.juncaffe.mrtdcore.lds.DataGroupParser
import com.juncaffe.mrtdcore.lds.LdsTag
import com.juncaffe.mrtdcore.lds.SecurityInfoFactory
import com.juncaffe.mrtdcore.lds.tlv.BerTlvReader

/**
 * DG14 파서. 구조: `6E { SET OF SecurityInfo }` → [SecurityInfo] 목록.
 * (ICAO Doc 9303 Part 11)
 */
object Dg14Parser : DataGroupParser<List<SecurityInfo>> {

    override val id: DataGroupId = DataGroupId.DG14

    /**
     * DG14 바이트에서 SecurityInfos 를 추출해 파싱한다.
     * @throws MrtdException.ParseError 태그 불일치 또는 ASN.1 오류
     */
    override fun parse(content: ByteArray): List<SecurityInfo> {
        val root = BerTlvReader(content).readTlv()
        if (root.tag != LdsTag.DG14) {
            throw MrtdException.ParseError("not a DG14 (tag=0x%X)".format(root.tag))
        }
        return SecurityInfoFactory.parseSet(root.value)
    }
}
