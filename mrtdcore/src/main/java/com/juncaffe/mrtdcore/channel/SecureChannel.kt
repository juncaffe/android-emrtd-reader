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
package com.juncaffe.mrtdcore.channel

import com.juncaffe.mrtdcore.apdu.CommandApdu
import com.juncaffe.mrtdcore.apdu.ResponseApdu
import com.juncaffe.mrtdcore.apdu.StatusWord
import com.juncaffe.mrtdcore.debug.MrtdDebug
import com.juncaffe.mrtdcore.domain.error.MrtdException
import com.juncaffe.mrtdcore.domain.port.CardTransport
import com.juncaffe.mrtdcore.sm.SecureMessaging

/**
 * Secure Messaging 이 적용된 채널. 명령을 [SecureMessaging] 으로 wrap 해 전송하고 응답을 unwrap 한다.
 * 인증(BAC/PACE) 성공 후 [PlainChannel] 을 대체하며, CA 성공 시 새 [SecureMessaging] 으로 교체된다.
 */
class SecureChannel(
    private val transport: CardTransport,
    private val secureMessaging: SecureMessaging,
) : ApduChannel {
    override fun transmit(command: CommandApdu): ResponseApdu {
        val protected = secureMessaging.wrap(command)
        val protectedBytes = protected.toBytes()
        MrtdDebug.log("SM.tx") { "plain=${command.summary()}" }
        MrtdDebug.hex("SM.tx", "protectedApdu", protectedBytes)

        val response = ResponseApdu(transport.transceive(protectedBytes))
        MrtdDebug.log("SM.rx") { "SW=${StatusWord(response.sw)} dataLen=${response.data.size}" }
        MrtdDebug.hex("SM.rx", "rawResponse", response.toBytes())

        return try {
            secureMessaging.unwrap(response)
        } catch (e: Exception) {
            MrtdDebug.log("SM.tx") {
                "unwrap FAILED plain=${command.summary()} SW=${StatusWord(response.sw)} cause=${e.message}"
            }
            throw MrtdException.TransportError(
                "Secure Messaging unwrap failed for INS=${command.ins} P1=${command.p1} P2=${command.p2}, " +
                    "response ${StatusWord(response.sw)}, dataLen=${response.data.size}",
                e,
            )
        }
    }

    private fun CommandApdu.summary(): String =
        "CLA=%02X INS=%02X P1=%02X P2=%02X Nc=%d Ne=%d".format(cla, ins, p1, p2, nc, ne)
}
