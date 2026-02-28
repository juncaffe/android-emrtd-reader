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
package com.juncaffe.mrtdcore.lds

import com.juncaffe.mrtdcore.domain.model.DataGroupId
import com.juncaffe.mrtdcore.lds.dg1.Dg1Parser
import com.juncaffe.mrtdcore.lds.dg2.Dg2Parser
import com.juncaffe.mrtdcore.lds.dg14.Dg14Parser
import com.juncaffe.mrtdcore.lds.sod.SodParser

/**
 * 파일 식별자 → 파서 매핑. 파일을 지원하려면 여기에 한 줄만 추가한다(OCP).
 * (EF.CardAccess 는 태그 래퍼가 없어 [com.juncaffe.mrtdcore.lds.cardaccess.CardAccessParser] 로 별도 처리)
 */
object DataGroupRegistry {

    private val parsers: Map<DataGroupId, DataGroupParser<*>> = mapOf(
        DataGroupId.DG1 to Dg1Parser,
        DataGroupId.DG2 to Dg2Parser,
        DataGroupId.DG14 to Dg14Parser,
        DataGroupId.SOD to SodParser,
    )

    /** [id] 에 대응하는 파서를 반환한다. 미등록이면 null. */
    fun parserFor(id: DataGroupId): DataGroupParser<*>? = parsers[id]
}
