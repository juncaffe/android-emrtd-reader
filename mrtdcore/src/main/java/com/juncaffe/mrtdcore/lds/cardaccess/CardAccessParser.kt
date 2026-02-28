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
package com.juncaffe.mrtdcore.lds.cardaccess

import com.juncaffe.mrtdcore.domain.model.SecurityInfo
import com.juncaffe.mrtdcore.lds.SecurityInfoFactory

/**
 * EF.CardAccess 파서. 본문은 태그 래퍼 없이 곧바로 `SET OF SecurityInfo` 이다.
 * PACE 가용 여부 판단에 사용한다(주로 PACEInfo). (ICAO Doc 9303 Part 11)
 */
object CardAccessParser {

    /**
     * EF.CardAccess 바이트를 [SecurityInfo] 목록으로 파싱한다.
     * @param content EF.CardAccess 전체 바이트(SET OF SecurityInfo DER)
     */
    fun parse(content: ByteArray): List<SecurityInfo> = SecurityInfoFactory.parseSet(content)
}
