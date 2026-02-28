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
package com.juncaffe.mrtdcore.lds.sod

import com.juncaffe.mrtdcore.domain.error.MrtdException
import com.juncaffe.mrtdcore.domain.model.DataGroupId
import com.juncaffe.mrtdcore.domain.model.Sod
import com.juncaffe.mrtdcore.lds.DataGroupParser
import com.juncaffe.mrtdcore.lds.LdsTag
import com.juncaffe.mrtdcore.lds.tlv.BerTlvReader
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.cms.ContentInfo
import org.bouncycastle.asn1.cms.SignedData
import org.bouncycastle.asn1.cms.SignerInfo
import org.bouncycastle.asn1.icao.LDSSecurityObject
import org.bouncycastle.asn1.x509.Certificate
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * EF.SOD 파서. 구조: `77 { ContentInfo(CMS SignedData) }`.
 * CMS/ASN.1 디코딩은 BouncyCastle 에 위임하고, 서명 검증은 PA 단계에서 수행한다.
 * (ICAO Doc 9303 Part 12)
 */
object SodParser : DataGroupParser<Sod> {

    override val id: DataGroupId = DataGroupId.SOD

    /**
     * EF.SOD 바이트에서 SignedData 를 파싱해 [Sod] 로 반환한다.
     * @throws MrtdException.ParseError 태그 불일치 또는 CMS 디코딩 실패
     */
    override fun parse(content: ByteArray): Sod {
        val root = BerTlvReader(content).readTlv()
        if (root.tag != LdsTag.SOD) {
            throw MrtdException.ParseError("not a SOD (tag=0x%X)".format(root.tag))
        }
        return parseSignedData(root.value)
    }

    /**
     * CMS ContentInfo(SignedData) DER 바이트를 파싱한다.
     * eContent(LDSSecurityObject), DSC 인증서, SignerInfo 서명값을 추출한다.
     */
    fun parseSignedData(der: ByteArray): Sod = try {
        val contentInfo = ContentInfo.getInstance(ASN1Primitive.fromByteArray(der))
        val signedData = SignedData.getInstance(contentInfo.content)

        // eContent = LDSSecurityObject (DG 해시 목록)
        val eContent = ASN1OctetString.getInstance(signedData.encapContentInfo.content).octets
        val lds = parseLdsSecurityObject(eContent)

        // SignerInfo (첫 번째) → 서명값/서명 알고리즘
        val signerInfo = SignerInfo.getInstance(signedData.signerInfos.getObjectAt(0))
        val signature = signerInfo.encryptedDigest.octets
        val signatureAlgorithmOid = signerInfo.digestEncryptionAlgorithm.algorithm.id

        Sod(
            digestAlgorithm = lds.digestAlgorithm,
            dataGroupHashes = lds.hashes,
            eContent = eContent,
            signature = signature,
            signatureAlgorithmOid = signatureAlgorithmOid,
            docSigningCertificate = firstCertificate(signedData),
        )
    } catch (e: MrtdException) {
        throw e
    } catch (e: Exception) {
        throw MrtdException.ParseError("invalid SOD/SignedData", e)
    }

    /**
     * LDSSecurityObject DER 바이트에서 해시 알고리즘과 DG별 해시를 추출한다.
     * (SignedData 래퍼와 분리해 단위테스트가 가능하도록 노출)
     * @return [LdsHashes]
     */
    fun parseLdsSecurityObject(eContent: ByteArray): LdsHashes {
        val lds = LDSSecurityObject.getInstance(ASN1Primitive.fromByteArray(eContent))
        val digestOid = lds.digestAlgorithmIdentifier.algorithm.id
        val hashes = lds.datagroupHash.associate { dgh ->
            dgh.dataGroupNumber to dgh.dataGroupHashValue.octets
        }
        return LdsHashes(DigestAlgorithms.jcaName(digestOid), hashes)
    }

    /** SignedData 의 인증서 집합에서 첫 X.509 인증서(DSC)를 복원한다. 없으면 null. */
    private fun firstCertificate(signedData: SignedData): X509Certificate? {
        val certs = signedData.certificates ?: return null
        if (certs.size() == 0) return null
        val certDer = Certificate.getInstance(certs.getObjectAt(0)).encoded
        val factory = CertificateFactory.getInstance("X.509")
        return factory.generateCertificate(ByteArrayInputStream(certDer)) as X509Certificate
    }

    /** [parseLdsSecurityObject] 결과: 해시 알고리즘 이름과 DG별 해시. */
    class LdsHashes(val digestAlgorithm: String, val hashes: Map<Int, ByteArray>)
}
