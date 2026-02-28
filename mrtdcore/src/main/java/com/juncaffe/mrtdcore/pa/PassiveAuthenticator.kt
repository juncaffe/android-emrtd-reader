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
package com.juncaffe.mrtdcore.pa

import com.juncaffe.mrtdcore.debug.MrtdDebug
import com.juncaffe.mrtdcore.domain.error.MrtdException
import com.juncaffe.mrtdcore.domain.model.PaResult
import com.juncaffe.mrtdcore.lds.LdsTag
import com.juncaffe.mrtdcore.lds.sod.SodParser
import com.juncaffe.mrtdcore.lds.tlv.BerTlvReader
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.Selector
import java.security.MessageDigest
import java.security.Provider
import java.security.cert.X509Certificate

/**
 * Passive Authentication. (ICAO Doc 9303 Part 12)
 *
 * 1) EF.SOD 의 CMS SignedData 서명을 DSC 로 검증한다(서명 속성·eContent 다이제스트 포함, BC CMS 위임).
 * 2) eContent(LDSSecurityObject)의 DG 해시와 실제로 읽은 DG 의 해시를 비교한다.
 *
 * DSC→CSCA 신뢰 체인 검증은 별도 트러스트 스토어가 필요하므로 본 범위 밖이다.
 */
class PassiveAuthenticator(
    private val provider: Provider = BouncyCastleProvider(),
) {

    /**
     * SOD 서명과 DG 해시를 검증한다.
     * @param sodFileBytes EF.SOD 전체 바이트(태그 0x77 포함)
     * @param dataGroups 읽은 DG 번호 → 원본 파일 바이트
     * @return [PaResult]
     * @throws MrtdException.ParseError SOD/CMS 구조 오류
     */
    fun verify(sodFileBytes: ByteArray, dataGroups: Map<Int, ByteArray>): PaResult {
        MrtdDebug.log("PA") { "start SOD=${sodFileBytes.size}bytes readDGs=${dataGroups.keys.sorted()}" }
        val cms = parseCms(sodFileBytes)
        val signer = cms.signerInfos.signers.firstOrNull()
            ?: throw MrtdException.ParseError("SOD has no SignerInfo")
        val certHolder = findSignerCertificate(cms, signer)
            ?: throw MrtdException.ParseError("SOD has no Document Signer certificate")

        val signatureValid = verifySignature(signer, certHolder)
        val certificate = JcaX509CertificateConverter().setProvider(provider).getCertificate(certHolder)
        MrtdDebug.log("PA") { "DSC subject=${certificate.subjectX500Principal.name}" }
        MrtdDebug.log("PA") { "step1 SOD signature valid=$signatureValid" }

        // eContent = LDSSecurityObject → DG 해시 추출(파서 재사용)
        val eContent = cms.signedContent?.content as? ByteArray
            ?: throw MrtdException.ParseError("SOD has no encapsulated content")
        val lds = SodParser.parseLdsSecurityObject(eContent)
        MrtdDebug.log("PA") { "step2 digestAlg=${lds.digestAlgorithm} sodHashes=${lds.hashes.keys.sorted()}" }

        val digest = MessageDigest.getInstance(lds.digestAlgorithm)
        val perDataGroup = dataGroups.mapValues { (number, bytes) ->
            val expected = lds.hashes[number]
            val ok = expected != null && digest.digest(bytes).contentEquals(expected)
            MrtdDebug.log("PA") { "step2 DG$number hash match=$ok" }
            ok
        }
        val hashesValid = perDataGroup.isNotEmpty() && perDataGroup.values.all { it }
        MrtdDebug.log("PA") { "result signatureValid=$signatureValid hashesValid=$hashesValid" }

        return PaResult(
            signatureValid = signatureValid,
            hashesValid = hashesValid,
            perDataGroup = perDataGroup,
            documentSignerSubject = certificate.subjectX500Principal.name,
            documentSignerCertificate = certificate,
        )
    }

    /** EF.SOD(0x77)에서 ContentInfo 를 꺼내 CMS SignedData 로 파싱한다. */
    private fun parseCms(sodFileBytes: ByteArray): CMSSignedData {
        val tlv = BerTlvReader(sodFileBytes).readTlv()
        if (tlv.tag != LdsTag.SOD) throw MrtdException.ParseError("not a SOD (tag=0x%X)".format(tlv.tag))
        return try {
            CMSSignedData(tlv.value)
        } catch (e: Exception) {
            throw MrtdException.ParseError("invalid CMS SignedData in SOD", e)
        }
    }

    /** SignerInfo 의 sid 와 일치하는 인증서를 찾는다. (SignerId 는 raw Selector 를 구현) */
    @Suppress("UNCHECKED_CAST")
    private fun findSignerCertificate(cms: CMSSignedData, signer: SignerInformation): X509CertificateHolder? {
        val selector = signer.sid as Selector<X509CertificateHolder>
        return cms.certificates.getMatches(selector).firstOrNull()
    }

    /** 서명 검증(예외는 검증 실패로 간주). */
    private fun verifySignature(signer: SignerInformation, certHolder: X509CertificateHolder): Boolean = try {
        val verifier = JcaSimpleSignerInfoVerifierBuilder().setProvider(provider).build(certHolder)
        signer.verify(verifier)
    } catch (e: Exception) {
        false
    }
}
