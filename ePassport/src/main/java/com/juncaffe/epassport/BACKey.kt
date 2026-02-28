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
package com.juncaffe.epassport

import com.juncaffe.mrtdcore.domain.model.AccessKey

/**
 * MRZ 기반 접근키. 문서번호·생년월일·만료일로 BAC/PACE 접근키를 구성한다.
 * 입력 바이트는 호출자 소유이며, [wipe] 로 내부 키를 0화한다.
 *
 * @param documentNumber 문서번호(ASCII) @param dateOfBirth `YYMMDD`(6) @param dateOfExpiry `YYMMDD`(6)
 */
class BACKey(
    documentNumber: ByteArray,
    dateOfBirth: ByteArray,
    dateOfExpiry: ByteArray,
) {
    internal val accessKey: AccessKey = AccessKey.fromMrzFields(documentNumber, dateOfBirth, dateOfExpiry)

    fun wipe() = accessKey.wipe()
}
