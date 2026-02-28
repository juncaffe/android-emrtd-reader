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
package com.juncaffe.mrtdcore.sm

import com.juncaffe.mrtdcore.apdu.ApduSpec
import com.juncaffe.mrtdcore.apdu.CommandApdu
import com.juncaffe.mrtdcore.apdu.ResponseApdu
import com.juncaffe.mrtdcore.crypto.DesCrypto
import com.juncaffe.mrtdcore.crypto.Padding
import com.juncaffe.mrtdcore.debug.MrtdDebug
import com.juncaffe.mrtdcore.domain.error.MrtdException
import com.juncaffe.mrtdcore.security.Zeroizer

/**
 * 3DES 기반 Secure Messaging(BAC 세션). (ICAO Doc 9303 Part 11 §9.8)
 * 암호=3DES-CBC(IV=0), MAC=Retail-MAC. 명령/응답마다 SSC(8바이트)를 증가시킨다.
 * 공통 DO 인코딩은 [SmDataObjects] 와 공유한다. 세션키는 내부 복사본으로 보관하며 [wipe] 시 0화.
 */
class DesSecureMessaging(
    ksEnc: ByteArray,
    ksMac: ByteArray,
    ssc: ByteArray,
) : SecureMessaging {

    private val ksEnc = ksEnc.copyOf()
    private val ksMac = ksMac.copyOf()
    private val ssc = SendSequenceCounter(ssc)
    private val zeroIv = ByteArray(8)

    override fun wrap(command: CommandApdu): CommandApdu {
        val sscBytes = ssc.increment()
        val maskedHeader = byteArrayOf(
            (command.cla or ApduSpec.CLA_SM).toByte(), command.ins.toByte(),
            command.p1.toByte(), command.p2.toByte(),
        )
        val do87 = if (command.nc > 0) {
            SmDataObjects.do87(DesCrypto.encryptCbcNoPad(ksEnc, zeroIv, Padding.pad(command.data, BLOCK)))
        } else EMPTY
        val do97 = if (command.ne > 0) SmDataObjects.do97(command.ne) else EMPTY

        val macInput = sscBytes + Padding.pad(maskedHeader, BLOCK) + do87 + do97
        val cc = DesCrypto.retailMac(ksMac, macInput)
        val do8e = SmDataObjects.do8e(cc)

        MrtdDebug.log("SM3DES.wrap") {
            "INS=%02X P1=%02X P2=%02X Nc=%d Ne=%d".format(command.ins, command.p1, command.p2, command.nc, command.ne)
        }
        MrtdDebug.hex("SM3DES.wrap", "SSC", sscBytes)
        MrtdDebug.hex("SM3DES.wrap", "DO87", do87)
        MrtdDebug.hex("SM3DES.wrap", "DO97", do97)
        MrtdDebug.hex("SM3DES.wrap", "macInput(SSC|paddedHeader|DO87|DO97)", macInput)
        MrtdDebug.hex("SM3DES.wrap", "DO8E(MAC)", do8e)

        val data = do87 + do97 + do8e
        return CommandApdu(command.cla or ApduSpec.CLA_SM, command.ins, command.p1, command.p2, data = data, ne = 256)
    }

    override fun unwrap(response: ResponseApdu): ResponseApdu {
        val sscBytes = ssc.increment()
        val p = SmDataObjects.parseResponse(response.data)
        val macInput = sscBytes + p.do87Raw + p.do99Raw
        val cc = DesCrypto.retailMac(ksMac, macInput)

        MrtdDebug.hex("SM3DES.unwrap", "rawResponse(incl SW)", response.toBytes())
        MrtdDebug.hex("SM3DES.unwrap", "SSC", sscBytes)
        MrtdDebug.hex("SM3DES.unwrap", "DO87Raw", p.do87Raw)
        MrtdDebug.hex("SM3DES.unwrap", "DO99Raw", p.do99Raw)
        MrtdDebug.log("SM3DES.unwrap") { "DO99 statusWord = %04X".format(p.statusWord) }
        MrtdDebug.hex("SM3DES.unwrap", "computedMAC", cc)
        MrtdDebug.hex("SM3DES.unwrap", "receivedMAC(DO8E)", p.mac)

        // DO8E가 없으면 보호되지 않은 응답이므로 APDU의 SW를 그대로 보고한다.
        if (p.mac == null) {
            MrtdDebug.log("SM3DES.unwrap") {
                "no DO8E in response — chip returned PLAIN response (not SM-protected). SW=%04X".format(response.sw)
            }
            throw MrtdException.TransportError(
                "Secure Messaging: chip returned plain (non-SM) response: SW=%04X".format(response.sw)
            )
        }
        if (!cc.contentEquals(p.mac)) {
            MrtdDebug.log("SM3DES.unwrap") { "MAC MISMATCH: computed != received (SSC desync or wrong KSmac)" }
            throw MrtdException.TransportError("Secure Messaging MAC verification failed")
        }
        MrtdDebug.log("SM3DES.unwrap") { "MAC OK" }

        var decrypted: ByteArray? = null
        var plain: ByteArray? = null
        var responseBytes: ByteArray? = null
        try {
            plain = p.encryptedData?.let {
                decrypted = DesCrypto.decryptCbcNoPad(ksEnc, zeroIv, it)
                Padding.unpad(decrypted)
            } ?: EMPTY
            MrtdDebug.hex("SM3DES.unwrap", "decryptedData", plain)
            responseBytes = plain + byteArrayOf((p.statusWord ushr 8).toByte(), p.statusWord.toByte())
            return ResponseApdu(responseBytes)
        } finally {
            Zeroizer.wipe(decrypted)
            if (plain !== EMPTY) Zeroizer.wipe(plain)
            Zeroizer.wipe(responseBytes)
        }
    }

    override fun wipe() {
        ksEnc.fill(0)
        ksMac.fill(0)
    }

    private companion object {
        const val BLOCK = 8
        val EMPTY = ByteArray(0)
    }
}
