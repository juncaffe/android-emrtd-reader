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

import com.juncaffe.mrtdcore.lds.LdsTag
import com.juncaffe.mrtdcore.lds.tlv.BerTlvReader
import com.juncaffe.mrtdcore.security.Wipeable
import com.juncaffe.mrtdcore.security.Zeroizer
import java.security.cert.X509Certificate

/**
 * 여권 읽기 결과 집합. 표시 후 호출자가 [wipe] 로 민감 데이터를 0화해야 한다.
 *
 * @property mrz DG1 MRZ(없으면 null) @property faceImages DG2 얼굴 이미지
 * @property securityInfos DG14 보안 정보
 * @property encodedDataGroups 읽은 DG 원본 바이트(tag 포함)
 * @property passiveAuthentication PA 결과. SOD 읽기/파싱 실패 시에도 [PaResult.notPerformed] 로 채워진다
 *   (검증 실패는 isValid=false). null 은 PA 단계를 수행하지 않았을 때만(현재 read 경로에서는 항상 수행).
 */
class PassportData(
    val mrz: Mrz?,
    val faceImages: List<FaceImage>,
    val securityInfos: List<SecurityInfo>,
    val encodedDataGroups: Map<DataGroupId, ByteArray>,
    val passiveAuthentication: PaResult?,
) : Wipeable {

    /** DG1 원본 바이트(DG1 outer tag 0x61 포함, PA에 사용). */
    fun getDg1Encoded(): ByteArray? = getDataGroupEncoded(DataGroupId.DG1)

    /** DG1 MRZ 본문 바이트(DG1 outer 0x61 및 내부 0x5F1F tag/length 제외). */
    fun getDg1Value(): ByteArray? {
        val outerValue = getDataGroupOuterValue(DataGroupId.DG1) ?: return null
        return try {
            BerTlvReader(outerValue).find(LdsTag.MRZ_DATA)?.value
        } finally {
            Zeroizer.wipe(outerValue)
        }
    }

    /** DG2 원본 바이트(DG2 outer tag 0x75 포함, PA에 사용). */
    fun getDg2Encoded(): ByteArray? = getDataGroupEncoded(DataGroupId.DG2)

    /** DG2 value 바이트(outer 0x75 tag/length 제외). */
    fun getDg2Value(): ByteArray? = getDataGroupOuterValue(DataGroupId.DG2)

    /** DG14 원본 바이트(DG14 outer tag 0x6E 포함, PA에 사용). */
    fun getDg14Encoded(): ByteArray? = getDataGroupEncoded(DataGroupId.DG14)

    /** DG14 value 바이트(outer 0x6E tag/length 제외). */
    fun getDg14Value(): ByteArray? = getDataGroupOuterValue(DataGroupId.DG14)

    /** 읽은 DG 원본 바이트(DG outer tag/length 포함). */
    fun getDataGroupEncoded(dataGroupId: DataGroupId): ByteArray? = encodedDataGroups[dataGroupId]?.copyOf()

    /** DG outer tag/length 제외한 value 바이트. */
    fun getDataGroupOuterValue(dataGroupId: DataGroupId): ByteArray? =
        encodedDataGroups[dataGroupId]?.let { BerTlvReader(it).readTlv().value }

    /** EF.SOD 의 Document Signer X.509 인증서 */
    fun getSodDocSignerCertificate(): X509Certificate? = passiveAuthentication?.documentSignerCertificate

    override fun wipe() {
        mrz?.wipe()
        faceImages.forEach { it.wipe() }
        encodedDataGroups.values.forEach { it.fill(0) }
    }
}
