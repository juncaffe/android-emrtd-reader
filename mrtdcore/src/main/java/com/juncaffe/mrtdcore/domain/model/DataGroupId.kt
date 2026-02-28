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

/**
 * eMRTD 파일 식별자. ICAO Doc 9303 Part 10 의 표준 Short EF Identifier(FID)와
 * SOD 해시 매핑용 DG 번호를 함께 가진다.
 *
 * @property fid      파일 선택용 2바이트 File ID
 * @property dgNumber SOD 의 DataGroupHash 번호 (DG 가 아닌 파일은 null)
 */
enum class DataGroupId(val fid: Int, val dgNumber: Int?) {
    COM(0x011E, null),
    SOD(0x011D, null),
    DG1(0x0101, 1),
    DG2(0x0102, 2),
    DG14(0x010E, 14),
    CARD_ACCESS(0x011C, null);

    /** [fid] 를 빅엔디언 2바이트 배열로 반환한다 (SELECT 명령용). */
    fun fileIdBytes(): ByteArray = byteArrayOf((fid ushr 8).toByte(), fid.toByte())

    companion object {
        /** SOD 해시 번호([dgNumber])로 DataGroupId 를 찾는다. 없으면 null. */
        fun fromDgNumber(number: Int): DataGroupId? = entries.firstOrNull { it.dgNumber == number }
    }
}
