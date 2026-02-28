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

import com.juncaffe.mrtdcore.domain.error.MrtdException
import com.juncaffe.mrtdcore.domain.model.ChipAuthInfo
import com.juncaffe.mrtdcore.domain.model.ChipAuthPublicKeyInfo
import com.juncaffe.mrtdcore.domain.model.PaceInfo
import com.juncaffe.mrtdcore.domain.model.SecurityInfo
import com.juncaffe.mrtdcore.domain.model.UnsupportedSecurityInfo
import org.bouncycastle.asn1.ASN1Encoding
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.ASN1Set
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import java.math.BigInteger

/**
 * `SET OF SecurityInfo` 를 파싱한다 (BSI TR-03110). ASN.1 디코딩은 BouncyCastle 에 위임.
 */
object SecurityInfoFactory {

    // 프로토콜 OID 접두사 (BSI TR-03110 / ICAO Doc 9303 Part 11)
    private const val OID_PK = "0.4.0.127.0.7.2.2.1"    // ChipAuthenticationPublicKey
    private const val OID_CA = "0.4.0.127.0.7.2.2.3"    // ChipAuthentication
    private const val OID_PACE = "0.4.0.127.0.7.2.2.4"  // PACE

    /**
     * DER 인코딩된 `SET OF SecurityInfo` 바이트를 [SecurityInfo] 목록으로 파싱한다.
     * (DG14 의 value 또는 EF.CardAccess 본문)
     * @throws MrtdException.ParseError ASN.1 디코딩 실패
     */
    fun parseSet(der: ByteArray): List<SecurityInfo> {
        val set = try {
            ASN1Set.getInstance(ASN1Primitive.fromByteArray(der))
        } catch (e: Exception) {
            throw MrtdException.ParseError("invalid SecurityInfos SET", e)
        }
        return (0 until set.size()).map { create(ASN1Sequence.getInstance(set.getObjectAt(it))) }
    }

    /**
     * 단일 SecurityInfo 시퀀스를 OID 로 분기해 도메인 모델로 변환한다.
     * SecurityInfo ::= SEQUENCE { protocol OID, requiredData ANY, optionalData ANY OPTIONAL }
     */
    fun create(seq: ASN1Sequence): SecurityInfo {
        val oid = (seq.getObjectAt(0) as ASN1ObjectIdentifier).id
        return when {
            oid.startsWith(OID_PK) -> {
                // ChipAuthenticationPublicKeyInfo: { OID, SubjectPublicKeyInfo, keyId? }
                val spki = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(1))
                ChipAuthPublicKeyInfo(oid, spki.getEncoded(ASN1Encoding.DER), optionalInt(seq, 2))
            }
            oid.startsWith(OID_CA) -> {
                // ChipAuthenticationInfo: { OID, version INTEGER, keyId? }
                ChipAuthInfo(oid, intAt(seq, 1), optionalInt(seq, 2))
            }
            oid.startsWith(OID_PACE) -> {
                // PACEInfo: { OID, version INTEGER, parameterId? }
                PaceInfo(oid, intAt(seq, 1), optionalInt(seq, 2))
            }
            else -> UnsupportedSecurityInfo(oid)
        }
    }

    /** 시퀀스의 [index] 위치 INTEGER 를 Int 로 읽는다. */
    private fun intAt(seq: ASN1Sequence, index: Int): Int =
        (seq.getObjectAt(index) as ASN1Integer).value.toInt()

    /** [index] 위치에 INTEGER 가 있으면 BigInteger 로, 없으면 null 을 반환한다. */
    private fun optionalInt(seq: ASN1Sequence, index: Int): BigInteger? =
        if (seq.size() > index) (seq.getObjectAt(index) as? ASN1Integer)?.value else null
}
