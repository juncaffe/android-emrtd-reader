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
import com.juncaffe.mrtdcore.crypto.AesCrypto
import com.juncaffe.mrtdcore.crypto.Padding
import com.juncaffe.mrtdcore.debug.MrtdDebug
import com.juncaffe.mrtdcore.domain.error.MrtdException
import com.juncaffe.mrtdcore.security.Zeroizer

/**
 * AES 기반 Secure Messaging(PACE/CA 세션). (ICAO Doc 9303 Part 11 §9.8)
 * 암호=AES-CBC(IV=E(KSenc, SSC)), MAC=AES-CMAC(앞 8바이트). SSC 는 16바이트, PACE 후 0에서 시작.
 * 공통 DO 인코딩은 [SmDataObjects] 와 공유한다. 세션키는 내부 복사본으로 보관하며 [wipe] 시 0화.
 */
class AesSecureMessaging(
    ksEnc: ByteArray,
    ksMac: ByteArray,
    ssc: ByteArray,
) : SecureMessaging {

    private val ksEnc = ksEnc.copyOf()
    private val ksMac = ksMac.copyOf()
    private val ssc = SendSequenceCounter(ssc)

    override fun wrap(command: CommandApdu): CommandApdu {
        val sscBytes = ssc.increment()
        val maskedHeader = byteArrayOf(
            (command.cla or ApduSpec.CLA_SM).toByte(), command.ins.toByte(),
            command.p1.toByte(), command.p2.toByte(),
        )
        val paddedHeader = Padding.pad(maskedHeader, BLOCK)
        val do87 = if (command.nc > 0) {
            val iv = AesCrypto.encryptEcbBlock(ksEnc, sscBytes)
            SmDataObjects.do87(AesCrypto.encryptCbc(ksEnc, iv, Padding.pad(command.data, BLOCK)))
        } else EMPTY
        val do97 = if (command.ne > 0) SmDataObjects.do97(command.ne) else EMPTY

        val macInput = sscBytes + paddedHeader + do87 + do97
        val paddedMacInput = Padding.pad(macInput, BLOCK)
        val cc = AesCrypto.cmac(ksMac, paddedMacInput).copyOfRange(0, 8)
        val do8e = SmDataObjects.do8e(cc)

        MrtdDebug.log("SM.wrap") {
            "INS=%02X P1=%02X P2=%02X Nc=%d Ne=%d".format(command.ins, command.p1, command.p2, command.nc, command.ne)
        }
        MrtdDebug.hex("SM.wrap", "SSC", sscBytes)
        MrtdDebug.hex("SM.wrap", "maskedHeader", maskedHeader)
        MrtdDebug.hex("SM.wrap", "DO87", do87)
        MrtdDebug.hex("SM.wrap", "DO97", do97)
        MrtdDebug.hex("SM.wrap", "macInput(SSC|paddedHeader|DO87|DO97)", macInput)
        MrtdDebug.hex("SM.wrap", "paddedMacInput", paddedMacInput)
        MrtdDebug.hex("SM.wrap", "DO8E(MAC)", do8e)

        val data = do87 + do97 + do8e
        return CommandApdu(command.cla or ApduSpec.CLA_SM, command.ins, command.p1, command.p2, data = data, ne = 256)
    }

    override fun unwrap(response: ResponseApdu): ResponseApdu {
        val sscBytes = ssc.increment()
        val p = SmDataObjects.parseResponse(response.data)
        val macInput = sscBytes + p.do87Raw + p.do99Raw
        val paddedMacInput = Padding.pad(macInput, BLOCK)
        val cc = AesCrypto.cmac(ksMac, paddedMacInput).copyOfRange(0, 8)

        MrtdDebug.hex("SM.unwrap", "rawResponse(incl SW)", response.toBytes())
        MrtdDebug.hex("SM.unwrap", "SSC", sscBytes)
        MrtdDebug.hex("SM.unwrap", "DO87Raw", p.do87Raw)
        MrtdDebug.hex("SM.unwrap", "DO99Raw", p.do99Raw)
        MrtdDebug.log("SM.unwrap") { "DO99 statusWord = %04X".format(p.statusWord) }
        MrtdDebug.hex("SM.unwrap", "macInput(SSC|DO87Raw|DO99Raw)", macInput)
        MrtdDebug.hex("SM.unwrap", "paddedMacInput", paddedMacInput)
        MrtdDebug.hex("SM.unwrap", "computedMAC", cc)
        MrtdDebug.hex("SM.unwrap", "receivedMAC(DO8E)", p.mac)

        // DO8E가 없으면 보호되지 않은 응답이므로 APDU의 SW를 그대로 보고한다.
        if (p.mac == null) {
            MrtdDebug.log("SM.unwrap") {
                "no DO8E in response — chip returned PLAIN response (not SM-protected). SW=%04X".format(response.sw)
            }
            throw MrtdException.TransportError(
                "Secure Messaging: chip returned plain (non-SM) response: SW=%04X".format(response.sw)
            )
        }
        if (!cc.contentEquals(p.mac)) {
            MrtdDebug.log("SM.unwrap") { "MAC MISMATCH: computed != received (SSC desync or wrong KSmac)" }
            throw MrtdException.TransportError("Secure Messaging MAC verification failed")
        }
        MrtdDebug.log("SM.unwrap") { "MAC OK" }

        var decrypted: ByteArray? = null
        var plain: ByteArray? = null
        var responseBytes: ByteArray? = null
        try {
            plain = p.encryptedData?.let {
                val iv = AesCrypto.encryptEcbBlock(ksEnc, sscBytes)
                decrypted = AesCrypto.decryptCbc(ksEnc, iv, it)
                Padding.unpad(decrypted)
            } ?: EMPTY
            MrtdDebug.hex("SM.unwrap", "decryptedData", plain)
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
        const val BLOCK = 16
        val EMPTY = ByteArray(0)
    }
}
