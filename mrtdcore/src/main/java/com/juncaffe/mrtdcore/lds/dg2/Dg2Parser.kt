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
package com.juncaffe.mrtdcore.lds.dg2

import com.juncaffe.mrtdcore.domain.error.MrtdException
import com.juncaffe.mrtdcore.domain.model.DataGroupId
import com.juncaffe.mrtdcore.domain.model.FaceImage
import com.juncaffe.mrtdcore.domain.model.ImageFormat
import com.juncaffe.mrtdcore.lds.DataGroupParser
import com.juncaffe.mrtdcore.lds.LdsTag
import com.juncaffe.mrtdcore.lds.tlv.BerTlvReader
import com.juncaffe.mrtdcore.security.SecureByteArray

/**
 * DG2 파서. CBEFF 컨테이너 → ISO/IEC 19794-5 얼굴 레코드에서 이미지 바이트를 추출한다.
 * (ICAO Doc 9303 Part 10)
 *
 * 구조: `75 → 7F61(그룹) → [02 count] 7F60(템플릿) → 5F2E/7F2E(생체 데이터 블록) → 얼굴 레코드`
 */
object Dg2Parser : DataGroupParser<List<FaceImage>> {

    override val id: DataGroupId = DataGroupId.DG2

    // ISO 19794-5 얼굴 레코드 헤더/블록 오프셋·크기
    private const val GENERAL_HEADER = 14      // "FAC\0" + 버전 + 레코드길이 + 얼굴수
    private const val FACIAL_INFO_BLOCK = 20   // 레코드데이터길이(4)+특징점수(2)+14
    private const val IMAGE_INFO_BLOCK = 12     // 얼굴이미지타입(1)+이미지데이터타입(1)+가로(2)+세로(2)+...
    private const val FEATURE_POINT_SIZE = 8

    /**
     * DG2 에서 얼굴 이미지 목록을 추출한다.
     * @throws MrtdException.ParseError 태그 불일치 또는 얼굴 레코드 누락
     */
    override fun parse(content: ByteArray): List<FaceImage> {
        val root = BerTlvReader(content).readTlv()
        if (root.tag != LdsTag.DG2) throw MrtdException.ParseError("not a DG2 (tag=0x%X)".format(root.tag))
        val group = BerTlvReader(root.value).find(LdsTag.BIOMETRIC_GROUP_TEMPLATE)
            ?: throw MrtdException.ParseError("biometric group template (0x7F61) not found")

        val faces = mutableListOf<FaceImage>()
        val reader = BerTlvReader(group.value)
        while (reader.hasNext()) {
            val tlv = reader.readTlv()
            if (tlv.tag == LdsTag.BIOMETRIC_TEMPLATE) {
                faces += parseFacialRecord(extractBiometricDataBlock(tlv.value))
            }
        }
        if (faces.isEmpty()) throw MrtdException.ParseError("no face image in DG2")
        return faces
    }

    /** 생체 정보 템플릿(7F60)에서 생체 데이터 블록(5F2E/7F2E) 값을 찾는다. */
    private fun extractBiometricDataBlock(template: ByteArray): ByteArray {
        val reader = BerTlvReader(template)
        while (reader.hasNext()) {
            val tlv = reader.readTlv()
            if (tlv.tag == LdsTag.BIOMETRIC_DATA_BLOCK || tlv.tag == LdsTag.BIOMETRIC_DATA_BLOCK_CONSTRUCTED) {
                return tlv.value
            }
        }
        throw MrtdException.ParseError("biometric data block (0x5F2E/0x7F2E) not found")
    }

    /** ISO 19794-5 얼굴 레코드를 파싱해 얼굴별 이미지 바이트를 추출한다. */
    private fun parseFacialRecord(record: ByteArray): List<FaceImage> {
        if (record.size < GENERAL_HEADER ||
            record[0] != 'F'.code.toByte() || record[1] != 'A'.code.toByte() || record[2] != 'C'.code.toByte()
        ) {
            throw MrtdException.ParseError("invalid ISO 19794-5 facial record header")
        }
        val numberOfFaces = u16(record, 12)
        val faces = mutableListOf<FaceImage>()
        var faceStart = GENERAL_HEADER
        repeat(numberOfFaces) {
            val recordDataLength = u32(record, faceStart)
            val numberOfFeaturePoints = u16(record, faceStart + 4)
            val imageInfoStart = faceStart + FACIAL_INFO_BLOCK + numberOfFeaturePoints * FEATURE_POINT_SIZE
            val imageDataType = record[imageInfoStart + 1].toInt() and 0xFF
            val width = u16(record, imageInfoStart + 2)
            val height = u16(record, imageInfoStart + 4)
            val imageStart = imageInfoStart + IMAGE_INFO_BLOCK
            val imageEnd = (faceStart + recordDataLength).coerceAtMost(record.size)
                .let { if (it <= imageStart) record.size else it }

            val format = if (imageDataType == 1) ImageFormat.JPEG2000 else ImageFormat.JPEG
            faces += FaceImage(format, SecureByteArray.of(record.copyOfRange(imageStart, imageEnd)), width, height)
            faceStart = imageEnd
        }
        return faces
    }

    private fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    private fun u32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xFF) shl 24) or ((b[off + 1].toInt() and 0xFF) shl 16) or
            ((b[off + 2].toInt() and 0xFF) shl 8) or (b[off + 3].toInt() and 0xFF)
}
