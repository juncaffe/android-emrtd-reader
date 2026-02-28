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
package com.juncaffe.mrtdcore.auth.bac

import com.juncaffe.mrtdcore.apdu.CommandApdu
import com.juncaffe.mrtdcore.apdu.MrtdCommands
import com.juncaffe.mrtdcore.apdu.ResponseApdu
import com.juncaffe.mrtdcore.crypto.Bytes
import com.juncaffe.mrtdcore.crypto.DesCrypto
import com.juncaffe.mrtdcore.crypto.KeyDerivation
import com.juncaffe.mrtdcore.debug.MrtdDebug
import com.juncaffe.mrtdcore.domain.error.MrtdException
import com.juncaffe.mrtdcore.domain.port.CardTransport
import com.juncaffe.mrtdcore.domain.port.RandomSource
import com.juncaffe.mrtdcore.security.Zeroizer
import com.juncaffe.mrtdcore.sm.DesSecureMessaging

/**
 * BAC(Basic Access Control) 상호 인증. (ICAO Doc 9303 Part 11 §4.3)
 *
 * MRZ 정보로 접근키(Kenc/Kmac)를 유도하고, GET CHALLENGE → EXTERNAL AUTHENTICATE 로
 * 칩과 상호 인증한 뒤 3DES Secure Messaging 세션을 수립한다. 애플릿 선택은 호출자(오케스트레이터)
 * 책임이며, 여기서는 인증 단계만 수행한다.
 *
 * 모든 중간 키/난수 버퍼는 사용 직후 0으로 소거한다.
 */
class BacProtocol(
    private val transport: CardTransport,
    private val random: RandomSource,
) {

    /**
     * BAC 를 수행하고 수립된 [DesSecureMessaging] 을 반환한다.
     * @param mrzInfo MRZ information 바이트(문서번호+CD‖생년월일+CD‖만료일+CD), 호출자 소유
     * @throws MrtdException.AccessDenied 챌린지 응답/난수 검증 실패
     */
    fun run(mrzInfo: ByteArray): DesSecureMessaging {
        val seed = KeyDerivation.bacSeed(mrzInfo)
        val kEnc = KeyDerivation.deriveTDES(seed, KeyDerivation.MODE_ENC)
        val kMac = KeyDerivation.deriveTDES(seed, KeyDerivation.MODE_MAC)

        var rndIfd = ByteArray(0)
        var kIfd = ByteArray(0)
        var s = ByteArray(0)
        var r = ByteArray(0)
        var kIc = ByteArray(0)
        var kSeed = ByteArray(0)
        try {
            MrtdDebug.log("BAC") { "start" }
            MrtdDebug.hex("BAC", "Kenc", kEnc)
            MrtdDebug.hex("BAC", "Kmac", kMac)

            // 1. 칩 챌린지
            val rndIc = expectOk(MrtdCommands.getChallenge()).copyOfRange(0, 8)
            MrtdDebug.hex("BAC", "step1 RND.IC", rndIc)

            // 2. 단말 난수와 상호 인증 데이터 구성: E.IFD = 3DES(Kenc, RND.IFD||RND.IC||K.IFD)
            rndIfd = random.nextBytes(8)
            kIfd = random.nextBytes(16)
            s = rndIfd + rndIc + kIfd
            val eIfd = DesCrypto.encryptCbcNoPad(kEnc, ZERO_IV, s)
            val mIfd = DesCrypto.retailMac(kMac, eIfd)
            MrtdDebug.hex("BAC", "step2 RND.IFD", rndIfd)
            MrtdDebug.hex("BAC", "step2 E.IFD||M.IFD", eIfd + mIfd)

            // 3. EXTERNAL AUTHENTICATE → E.IC || M.IC
            MrtdDebug.log("BAC") { "step3 EXTERNAL AUTHENTICATE Le=28" }
            val resp = expectOk(MrtdCommands.externalAuthenticate(eIfd + mIfd))
            if (resp.size != MUTUAL_AUTH_RESPONSE_LENGTH) {
                throw MrtdException.AccessDenied(
                    "BAC: EXTERNAL AUTHENTICATE returned ${resp.size} data bytes, expected $MUTUAL_AUTH_RESPONSE_LENGTH"
                )
            }
            val eIc = resp.copyOfRange(0, 32)
            val mIc = resp.copyOfRange(32, 40)
            val mIcExpected = DesCrypto.retailMac(kMac, eIc)
            MrtdDebug.hex("BAC", "step3 M.IC(received)", mIc)
            MrtdDebug.hex("BAC", "step3 M.IC(expected)", mIcExpected)
            if (!mIcExpected.contentEquals(mIc)) {
                MrtdDebug.log("BAC") { "step3 CHIP MAC MISMATCH — wrong MRZ key" }
                throw MrtdException.AccessDenied("BAC: chip MAC mismatch")
            }
            MrtdDebug.log("BAC") { "step3 chip MAC OK" }

            // 4. 복호 후 난수 일치 검증
            r = DesCrypto.decryptCbcNoPad(kEnc, ZERO_IV, eIc)
            val rndIfdEcho = r.copyOfRange(8, 16)
            MrtdDebug.hex("BAC", "step4 RND.IFD(echo)", rndIfdEcho)
            if (!rndIfdEcho.contentEquals(rndIfd)) {
                MrtdDebug.log("BAC") { "step4 RND.IFD ECHO MISMATCH" }
                throw MrtdException.AccessDenied("BAC: RND.IFD echo mismatch")
            }
            MrtdDebug.log("BAC") { "step4 RND.IFD echo OK" }
            kIc = r.copyOfRange(16, 32)

            // 5. 세션키·SSC 유도
            kSeed = Bytes.xor(kIfd, kIc)
            val ksEnc = KeyDerivation.deriveTDES(kSeed, KeyDerivation.MODE_ENC)
            val ksMac = KeyDerivation.deriveTDES(kSeed, KeyDerivation.MODE_MAC)
            val ssc = rndIc.copyOfRange(4, 8) + rndIfd.copyOfRange(4, 8)
            MrtdDebug.hex("BAC", "step5 KSenc", ksEnc)
            MrtdDebug.hex("BAC", "step5 KSmac", ksMac)
            MrtdDebug.hex("BAC", "step5 SSC", ssc)
            MrtdDebug.log("BAC") { "session established" }

            val sm = DesSecureMessaging(ksEnc, ksMac, ssc)
            Zeroizer.wipe(ksEnc); Zeroizer.wipe(ksMac)
            return sm
        } finally {
            Zeroizer.wipe(kEnc); Zeroizer.wipe(kMac)
            Zeroizer.wipe(seed); Zeroizer.wipe(rndIfd); Zeroizer.wipe(kIfd)
            Zeroizer.wipe(s); Zeroizer.wipe(r); Zeroizer.wipe(kIc); Zeroizer.wipe(kSeed)
        }
    }

    /** 명령을 전송하고 성공 SW(9000)면 데이터를, 아니면 예외를 반환한다. */
    private fun expectOk(command: CommandApdu): ByteArray {
        val resp = ResponseApdu(transport.transceive(command.toBytes()))
        if (!resp.isSuccess) throw MrtdException.AccessDenied("BAC: unexpected ${resp.statusWord}")
        return resp.data
    }

    private companion object {
        val ZERO_IV = ByteArray(8)
        const val MUTUAL_AUTH_RESPONSE_LENGTH = 40
    }
}
