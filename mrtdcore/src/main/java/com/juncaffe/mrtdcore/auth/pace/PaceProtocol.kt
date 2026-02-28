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
package com.juncaffe.mrtdcore.auth.pace

import com.juncaffe.mrtdcore.apdu.ApduSpec
import com.juncaffe.mrtdcore.apdu.CommandApdu
import com.juncaffe.mrtdcore.apdu.EacSpec
import com.juncaffe.mrtdcore.apdu.ResponseApdu
import com.juncaffe.mrtdcore.crypto.AesCrypto
import com.juncaffe.mrtdcore.crypto.KeyDerivation
import com.juncaffe.mrtdcore.debug.MrtdDebug
import com.juncaffe.mrtdcore.domain.error.MrtdException
import com.juncaffe.mrtdcore.domain.port.CardTransport
import com.juncaffe.mrtdcore.lds.tlv.BerTlvReader
import com.juncaffe.mrtdcore.lds.tlv.berEncodeLength
import com.juncaffe.mrtdcore.security.Zeroizer
import com.juncaffe.mrtdcore.sm.AesSecureMessaging
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.SecureRandom

/**
 * PACE(Password Authenticated Connection Establishment) — Generic Mapping + ECDH + AES.
 * (ICAO Doc 9303 Part 11 §4.4, BSI TR-03110)
 *
 * 흐름: MSE:Set AT → GA(암호화 nonce) → GA(매핑) → GA(키 합의) → GA(상호 인증 토큰) → AES SM 수립.
 * 도메인 곡선/암호는 [PaceParameterResolver] 로 해석한다. 패스워드·nonce·공유비밀은 사용 직후 0화.
 */
class PaceProtocol(
    private val transport: CardTransport,
    private val random: SecureRandom = SecureRandom(),
) {

    /**
     * PACE 를 수행하고 수립된 [AesSecureMessaging] 을 반환한다.
     * @param oid PACEInfo OID @param parameterId 표준화 도메인 파라미터 ID @param mrzInfo MRZ information(호출자 소유)
     * @throws MrtdException.AccessDenied 토큰 검증 실패 @throws MrtdException.UnsupportedFeature 미지원 파라미터
     */
    fun run(oid: String, parameterId: Int, mrzInfo: ByteArray): AesSecureMessaging {
        val params = PaceParameterResolver.resolve(oid, parameterId)
        val spec = ECNamedCurveTable.getParameterSpec(params.curveName)
        val curve = spec.curve
        val generator = spec.g
        val order = spec.n
        val fieldBytes = (curve.fieldSize + 7) / 8

        val kPi = KeyDerivation.pacePasswordKey(mrzInfo, params.keyBits)
        var nonce = ByteArray(0)
        var sharedSecret = ByteArray(0)
        try {
            MrtdDebug.log("PACE") { "start oid=$oid parameterId=$parameterId curve=${params.curveName} keyBits=${params.keyBits}" }
            mseSetAt(oid, parameterId)
            MrtdDebug.log("PACE") { "step0 MSE:Set AT OK" }

            // 1. 암호화된 nonce 수신 후 복호 → s
            val z = generalAuthenticate(ApduSpec.CLA_CHAINING, ByteArray(0), ApduSpec.TAG_GA_NONCE_OR_PK, "step1-nonce")
            nonce = AesCrypto.decryptCbc(kPi, ZERO_IV16, z)
            val s = BigInteger(1, nonce)
            MrtdDebug.hex("PACE", "step1 encryptedNonce(Z)", z)
            MrtdDebug.hex("PACE", "step1 decryptedNonce(s)", nonce)

            // 2. Generic Mapping: G' = s·G + H, H = SK1·PK1.IC
            val sk1 = randomScalar(order)
            val pk1Ifd = generator.multiply(sk1).normalize()
            MrtdDebug.hex("PACE", "step2 PK1.IFD", pk1Ifd.getEncoded(false))
            val pk1Ic = curve.decodePoint(
                generalAuthenticate(
                    ApduSpec.CLA_CHAINING,
                    dynData(ApduSpec.TAG_GA_MAP_PK_IFD, pk1Ifd.getEncoded(false)),
                    ApduSpec.TAG_GA_MAP_PK_IC,
                    "step2-mapping",
                )
            )
            MrtdDebug.hex("PACE", "step2 PK1.IC", pk1Ic.getEncoded(false))
            val h = pk1Ic.multiply(sk1).normalize()
            val mappedGenerator = generator.multiply(s).add(h).normalize()
            MrtdDebug.hex("PACE", "step2 mappedGenerator G'", mappedGenerator.getEncoded(false))

            // 3. 매핑된 생성자로 키 합의 → 공유비밀 x 좌표
            val sk2 = randomScalar(order)
            val pk2Ifd = mappedGenerator.multiply(sk2).normalize()
            MrtdDebug.hex("PACE", "step3 PK2.IFD", pk2Ifd.getEncoded(false))
            val pk2Ic = curve.decodePoint(
                generalAuthenticate(
                    ApduSpec.CLA_CHAINING,
                    dynData(ApduSpec.TAG_GA_KA_PK_IFD, pk2Ifd.getEncoded(false)),
                    ApduSpec.TAG_GA_KA_PK_IC,
                    "step3-keyagree",
                )
            )
            MrtdDebug.hex("PACE", "step3 PK2.IC", pk2Ic.getEncoded(false))
            val sharedPoint = pk2Ic.multiply(sk2).normalize()
            sharedSecret = toFixedLength(sharedPoint.affineXCoord.toBigInteger(), fieldBytes)
            MrtdDebug.hex("PACE", "step3 sharedSecret(x)", sharedSecret)

            val ksEnc = KeyDerivation.deriveAES(sharedSecret, KeyDerivation.MODE_ENC, params.keyBits)
            val ksMac = KeyDerivation.deriveAES(sharedSecret, KeyDerivation.MODE_MAC, params.keyBits)
            MrtdDebug.hex("PACE", "step3 KSenc", ksEnc)
            MrtdDebug.hex("PACE", "step3 KSmac", ksMac)

            // 4. 상호 인증 토큰 교환/검증
            val tIfd = authToken(ksMac, oid, pk2Ic)
            MrtdDebug.hex("PACE", "step4 T.IFD(sent)", tIfd)
            val tIc = generalAuthenticate(
                ApduSpec.CLA_PLAIN,
                dynData(ApduSpec.TAG_GA_TOKEN_IFD, tIfd),
                ApduSpec.TAG_GA_PUBKEY_POINT,
                "step4-token",
            )
            val tIcExpected = authToken(ksMac, oid, pk2Ifd)
            MrtdDebug.hex("PACE", "step4 T.IC(received)", tIc)
            MrtdDebug.hex("PACE", "step4 T.IC(expected)", tIcExpected)
            if (!tIc.contentEquals(tIcExpected)) {
                MrtdDebug.log("PACE") { "step4 TOKEN MISMATCH — wrong MRZ key or domain params" }
                throw MrtdException.AccessDenied("PACE: chip authentication token mismatch")
            }
            MrtdDebug.log("PACE") { "step4 mutual auth OK — session established, SSC=0" }

            val sm = AesSecureMessaging(ksEnc, ksMac, ByteArray(16)) // SSC = 0
            Zeroizer.wipe(ksEnc); Zeroizer.wipe(ksMac)
            return sm
        } finally {
            Zeroizer.wipe(kPi); Zeroizer.wipe(nonce); Zeroizer.wipe(sharedSecret)
        }
    }

    /** MSE:Set AT — PACE OID, 패스워드 참조(MRZ=1), 도메인 파라미터를 설정한다. */
    private fun mseSetAt(oid: String, parameterId: Int) {
        val oidContent = oidContentBytes(oid)
        val data = byteArrayOf(ApduSpec.TAG_MSE_OID.toByte()) + berEncodeLength(oidContent.size) + oidContent +
            byteArrayOf(ApduSpec.TAG_MSE_PWD_REF.toByte(), 0x01, EacSpec.PWD_REF_MRZ.toByte()) +
            byteArrayOf(ApduSpec.TAG_MSE_KEY_REF.toByte(), 0x01, parameterId.toByte())
        val command = CommandApdu(ApduSpec.CLA_PLAIN, ApduSpec.INS_MANAGE_SECURITY_ENVIRONMENT, ApduSpec.P1_MSE_PACE_SET_AT, ApduSpec.P2_MSE_AT, data = data)
        val response = ResponseApdu(transport.transceive(command.toBytes()))
        if (!response.isSuccess) throw MrtdException.AccessDenied("PACE: MSE:Set AT failed ${response.statusWord}")
    }

    /**
     * General Authenticate 한 단계를 수행한다. `7C{...}` 동적 인증 데이터를 보내고
     * 응답 `7C{expectedTag value}` 의 내부 값을 반환한다.
     */
    private fun generalAuthenticate(cla: Int, dynAuthData: ByteArray, expectedTag: Int, step: String): ByteArray {
        val data = byteArrayOf(ApduSpec.TAG_GA_WRAPPER.toByte()) + berEncodeLength(dynAuthData.size) + dynAuthData
        val command = CommandApdu(cla, ApduSpec.INS_GENERAL_AUTHENTICATE, 0x00, 0x00, data = data, ne = 256)
        MrtdDebug.hex("PACE.GA", "$step >> CLA=%02X".format(cla), command.toBytes())
        val response = ResponseApdu(transport.transceive(command.toBytes()))
        MrtdDebug.log("PACE.GA") { "$step << SW=${response.statusWord} dataLen=${response.data.size}" }
        if (!response.isSuccess) {
            // GA 마지막 단계(token)에서 6300 = 상호인증 실패 = MRZ 패스워드 불일치(문서번호/생년월일/만료일/체크디지트).
            throw MrtdException.AccessDenied("PACE: General Authenticate failed at $step, ${response.statusWord}")
        }
        val outer = BerTlvReader(response.data).readTlv()
        if (outer.tag != ApduSpec.TAG_GA_WRAPPER) throw MrtdException.AccessDenied("PACE: malformed GA response at $step")
        val inner = BerTlvReader(outer.value).readTlv()
        if (inner.tag != expectedTag) {
            throw MrtdException.AccessDenied(
                "PACE: unexpected GA response tag at $step expected=%02X actual=%02X".format(expectedTag, inner.tag)
            )
        }
        return inner.value
    }

    /** PACE 인증 토큰: `CMAC(KSmac, 7F49{OID, 공개키 점})`의 앞 8바이트. */
    private fun authToken(ksMac: ByteArray, oid: String, point: ECPoint): ByteArray {
        val pointBytes = point.getEncoded(false)
        val oidDer = ASN1ObjectIdentifier(oid).encoded
        val pointObject = byteArrayOf(ApduSpec.TAG_GA_PUBKEY_POINT.toByte()) + berEncodeLength(pointBytes.size) + pointBytes
        val inner = oidDer + pointObject
        // EacSpec.TAG_AUTH_TOKEN_TEMPLATE = 0x7F49 (BSI TR-03110-3 §3.2.1)
        val tokenInput = byteArrayOf((EacSpec.TAG_AUTH_TOKEN_TEMPLATE ushr 8).toByte(), EacSpec.TAG_AUTH_TOKEN_TEMPLATE.toByte()) +
            berEncodeLength(inner.size) + inner
        return AesCrypto.cmac(ksMac, tokenInput).copyOfRange(0, 8)
    }

    /** `tag L value` 동적 인증 데이터 한 항목을 만든다. */
    private fun dynData(tag: Int, value: ByteArray): ByteArray =
        byteArrayOf(tag.toByte()) + berEncodeLength(value.size) + value

    /** OID 의 DER 인코딩에서 06/길이 헤더를 제외한 내용 바이트만 반환한다(MSE 의 0x80 DO 용). */
    private fun oidContentBytes(oid: String): ByteArray {
        val der = ASN1ObjectIdentifier(oid).encoded
        return der.copyOfRange(2, der.size)
    }

    /** [1, n-1] 범위의 난수 스칼라를 만든다. */
    private fun randomScalar(n: BigInteger): BigInteger {
        val bits = n.bitLength()
        var d: BigInteger
        do {
            d = BigInteger(bits, random)
        } while (d < BigInteger.ONE || d >= n)
        return d
    }

    /** BigInteger 를 [length]바이트 빅엔디언으로 좌측 0패딩한다. */
    private fun toFixedLength(value: BigInteger, length: Int): ByteArray {
        val raw = value.toByteArray()
        val out = ByteArray(length)
        val src = if (raw.size > length) raw.copyOfRange(raw.size - length, raw.size) else raw
        System.arraycopy(src, 0, out, length - src.size, src.size)
        return out
    }

    private companion object {
        val ZERO_IV16 = ByteArray(16)
    }
}
