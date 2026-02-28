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
package com.juncaffe.mrtdcore.auth.ca

import com.juncaffe.mrtdcore.apdu.ApduSpec
import com.juncaffe.mrtdcore.apdu.CommandApdu
import com.juncaffe.mrtdcore.apdu.EacSpec
import com.juncaffe.mrtdcore.channel.ApduChannel
import com.juncaffe.mrtdcore.domain.error.MrtdException
import com.juncaffe.mrtdcore.domain.model.ChipAuthInfo
import com.juncaffe.mrtdcore.domain.model.ChipAuthPublicKeyInfo
import com.juncaffe.mrtdcore.crypto.KeyDerivation
import com.juncaffe.mrtdcore.debug.MrtdDebug
import com.juncaffe.mrtdcore.lds.tlv.berEncodeLength
import com.juncaffe.mrtdcore.security.Zeroizer
import com.juncaffe.mrtdcore.sm.AesSecureMessaging
import com.juncaffe.mrtdcore.sm.DesSecureMessaging
import com.juncaffe.mrtdcore.sm.SecureMessaging
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.pkcs.DHParameter
import org.bouncycastle.asn1.x9.X962Parameters
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.crypto.ec.CustomNamedCurves
import java.math.BigInteger
import java.security.SecureRandom

/**
 * Chip Authentication (EAC-CA). (ICAO Doc 9303 Part 11 §6.2, BSI TR-03110)
 *
 * DG14 의 칩 정적 공개키와 단말 ephemeral 키로 ECDH 를 수행해 새 세션키를 도출하고
 * Secure Messaging 을 재협상한다. CA 명령은 **현재 보안 채널**([ApduChannel])로 전송하며,
 * 성공 시 새 [SecureMessaging] 으로 교체하는 것은 오케스트레이터 책임이다.
 *
 * CA v1 = MSE:Set KAT(단말 공개키 즉시 전달), v2+ = MSE:Set AT + General Authenticate.
 * 공유비밀·세션키는 사용 직후 0화한다.
 */
class EacCaProtocol(
    private val channel: ApduChannel,
    private val random: SecureRandom = SecureRandom(),
) {

    /**
     * CA 를 수행하고 재협상된 [SecureMessaging] 을 반환한다.
     * @param caInfo DG14 의 ChipAuthenticationInfo @param publicKeyInfo DG14 의 칩 공개키
     * @throws MrtdException.ChipAuthenticationFailed 칩 응답 실패
     */
    fun run(caInfo: ChipAuthInfo, publicKeyInfo: ChipAuthPublicKeyInfo): SecureMessaging {
        val params = CaParameterResolver.resolve(caInfo.oid)
        val keyAgreement = when (params.agreement) {
            CaParameters.Agreement.DH -> createDhAgreement(publicKeyInfo.subjectPublicKeyInfo)
            CaParameters.Agreement.ECDH -> createEcAgreement(publicKeyInfo.subjectPublicKeyInfo)
        }
        MrtdDebug.log("CA") {
            "start oid=${caInfo.oid} version=${caInfo.version} keyId=${caInfo.keyId} " +
                "agreement=${params.agreement} cipher=${params.cipher} keyBits=${params.keyBits}"
        }

        val ephemeralPublic = keyAgreement.terminalPublic
        MrtdDebug.hex("CA", "terminal ephemeral pubkey", ephemeralPublic)

        when (params.cipher) {
            CaParameters.Cipher.TDES -> {
                if (caInfo.version != 1) {
                    throw MrtdException.UnsupportedFeature("3DES CA version ${caInfo.version} is not supported")
                }
                MrtdDebug.log("CA") { "3DES v1: MSE:Set KAT" }
                mseSetKat(ephemeralPublic, caInfo.keyId)
            }
            CaParameters.Cipher.AES -> {
                MrtdDebug.log("CA") { "AES v${caInfo.version}: MSE:Set AT + General Authenticate" }
                mseSetAt(caInfo.oid, caInfo.keyId)
                generalAuthenticate(ephemeralPublic)
            }
        }
        MrtdDebug.log("CA") { "chip accepted terminal pubkey" }

        var sharedSecret = ByteArray(0)
        try {
            sharedSecret = keyAgreement.sharedSecret
            val ksEnc = when (params.cipher) {
                CaParameters.Cipher.TDES -> KeyDerivation.deriveTDES(sharedSecret, KeyDerivation.MODE_ENC)
                CaParameters.Cipher.AES -> KeyDerivation.deriveAES(sharedSecret, KeyDerivation.MODE_ENC, params.keyBits)
            }
            val ksMac = when (params.cipher) {
                CaParameters.Cipher.TDES -> KeyDerivation.deriveTDES(sharedSecret, KeyDerivation.MODE_MAC)
                CaParameters.Cipher.AES -> KeyDerivation.deriveAES(sharedSecret, KeyDerivation.MODE_MAC, params.keyBits)
            }
            MrtdDebug.hex("CA", "sharedSecret(x)", sharedSecret)
            MrtdDebug.hex("CA", "KSenc", ksEnc)
            MrtdDebug.hex("CA", "KSmac", ksMac)
            MrtdDebug.log("CA") { "session re-negotiated, SSC=0" }
            val sm = when (params.cipher) {
                CaParameters.Cipher.TDES -> DesSecureMessaging(ksEnc, ksMac, ByteArray(8))
                CaParameters.Cipher.AES -> AesSecureMessaging(ksEnc, ksMac, ByteArray(16))
            }
            Zeroizer.wipe(ksEnc); Zeroizer.wipe(ksMac)
            return sm
        } finally {
            Zeroizer.wipe(sharedSecret)
        }
    }

    /** CA v1: MSE:Set KAT — 단말 공개키(EacSpec.TAG_CA_TERMINAL_PUBKEY)와 키 참조(ApduSpec.TAG_MSE_KEY_REF)를 전달한다. */
    private fun mseSetKat(ephemeralPublic: ByteArray, keyId: BigInteger?) {
        var data = byteArrayOf(EacSpec.TAG_CA_TERMINAL_PUBKEY.toByte()) + berEncodeLength(ephemeralPublic.size) + ephemeralPublic
        if (keyId != null) data += byteArrayOf(ApduSpec.TAG_MSE_KEY_REF.toByte()) + keyIdBytes(keyId).let { berEncodeLength(it.size) + it }
        transmitOk(CommandApdu(ApduSpec.CLA_PLAIN, ApduSpec.INS_MANAGE_SECURITY_ENVIRONMENT, ApduSpec.P1_MSE_CA_SET, ApduSpec.P2_MSE_KAT, data = data))
    }

    /** CA v2+: MSE:Set AT — CA OID(ApduSpec.TAG_MSE_OID)와 키 참조(ApduSpec.TAG_MSE_KEY_REF)를 설정한다. */
    private fun mseSetAt(oid: String, keyId: BigInteger?) {
        val oidContent = oidContentBytes(oid)
        var data = byteArrayOf(ApduSpec.TAG_MSE_OID.toByte()) + berEncodeLength(oidContent.size) + oidContent
        if (keyId != null) data += byteArrayOf(ApduSpec.TAG_MSE_KEY_REF.toByte()) + keyIdBytes(keyId).let { berEncodeLength(it.size) + it }
        transmitOk(CommandApdu(ApduSpec.CLA_PLAIN, ApduSpec.INS_MANAGE_SECURITY_ENVIRONMENT, ApduSpec.P1_MSE_CA_SET, ApduSpec.P2_MSE_AT, data = data))
    }

    /** CA v2+: General Authenticate 로 단말 공개키(`7C{TAG_GA_NONCE_OR_PK ...}`)를 전달한다. */
    private fun generalAuthenticate(ephemeralPublic: ByteArray) {
        // TAG_GA_NONCE_OR_PK(0x80): CA GA 에서는 단말 임시 공개키 DO 태그 (BSI TR-03110-3 Table 3.18)
        val dyn = byteArrayOf(ApduSpec.TAG_GA_NONCE_OR_PK.toByte()) + berEncodeLength(ephemeralPublic.size) + ephemeralPublic
        val data = byteArrayOf(ApduSpec.TAG_GA_WRAPPER.toByte()) + berEncodeLength(dyn.size) + dyn
        transmitOk(CommandApdu(ApduSpec.CLA_PLAIN, ApduSpec.INS_GENERAL_AUTHENTICATE, 0x00, 0x00, data = data, ne = 256))
    }

    /** 현재 보안 채널로 명령을 보내고 성공 SW 를 확인한다. */
    private fun transmitOk(command: CommandApdu) {
        val response = channel.transmit(command)
        MrtdDebug.log("CA") { "INS=%02X SW=${response.statusWord}".format(command.ins) }
        if (!response.isSuccess) throw MrtdException.ChipAuthenticationFailed("CA: ${response.statusWord}")
    }

    /** ECDH 칩 공개키로부터 단말 임시 공개키와 공유비밀을 생성한다. */
    private fun createEcAgreement(der: ByteArray): KeyAgreementResult {
        val spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(der))
        val x962 = X962Parameters.getInstance(spki.algorithm.parameters)
        val x9: X9ECParameters = if (x962.isNamedCurve) {
            val oid = ASN1ObjectIdentifier.getInstance(x962.parameters)
            CustomNamedCurves.getByOID(oid)
                ?: org.bouncycastle.asn1.x9.ECNamedCurveTable.getByOID(oid)
                ?: throw MrtdException.UnsupportedFeature("unknown CA curve OID: $oid")
        } else {
            X9ECParameters.getInstance(x962.parameters)
        }
        val point = x9.curve.decodePoint(spki.publicKeyData.bytes)
        val sk = randomScalar(x9.n)
        val terminalPublic = x9.g.multiply(sk).normalize().getEncoded(false)
        val sharedPoint = point.multiply(sk).normalize()
        val fieldBytes = (x9.curve.fieldSize + 7) / 8
        val sharedSecret = toFixedLength(sharedPoint.affineXCoord.toBigInteger(), fieldBytes)
        return KeyAgreementResult(terminalPublic, sharedSecret)
    }

    /** DH 칩 공개키 SubjectPublicKeyInfo에서 p/g/y를 읽어 단말 임시키와 공유비밀을 생성한다. */
    private fun createDhAgreement(der: ByteArray): KeyAgreementResult {
        val spki = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(der))
        val params = DHParameter.getInstance(spki.algorithm.parameters)
        val p = params.p
        val g = params.g
        val chipPublic = ASN1Integer.getInstance(spki.parsePublicKey()).positiveValue
        val privateValue = randomScalar(p.subtract(BigInteger.TWO))
        val terminalPublicValue = g.modPow(privateValue, p)
        val sharedSecretValue = chipPublic.modPow(privateValue, p)
        val modulusBytes = (p.bitLength() + 7) / 8
        return KeyAgreementResult(
            unsignedMinimal(terminalPublicValue),
            toFixedLength(sharedSecretValue, modulusBytes),
        )
    }

    /** keyId 를 최소 바이트 표현으로 변환한다(선행 0 제거). */
    private fun keyIdBytes(keyId: BigInteger): ByteArray {
        val b = keyId.toByteArray()
        return if (b.size > 1 && b[0] == 0.toByte()) b.copyOfRange(1, b.size) else b
    }

    /** OID DER 에서 06/길이 헤더를 제외한 내용 바이트. */
    private fun oidContentBytes(oid: String): ByteArray {
        val der = ASN1ObjectIdentifier(oid).encoded
        return der.copyOfRange(2, der.size)
    }

    private fun randomScalar(n: BigInteger): BigInteger {
        var d: BigInteger
        do { d = BigInteger(n.bitLength(), random) } while (d < BigInteger.ONE || d >= n)
        return d
    }

    private fun toFixedLength(value: BigInteger, length: Int): ByteArray {
        val raw = value.toByteArray()
        val out = ByteArray(length)
        val src = if (raw.size > length) raw.copyOfRange(raw.size - length, raw.size) else raw
        System.arraycopy(src, 0, out, length - src.size, src.size)
        return out
    }

    private fun unsignedMinimal(value: BigInteger): ByteArray {
        val bytes = value.toByteArray()
        return if (bytes.size > 1 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes
    }

    private data class KeyAgreementResult(
        val terminalPublic: ByteArray,
        val sharedSecret: ByteArray,
    )
}
