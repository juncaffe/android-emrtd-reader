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
import com.juncaffe.mrtdcore.domain.port.CardTransport

/**
 * Secure Messaging 적용 전의 평문 채널. [CardTransport] 로 그대로 전달한다.
 */
class PlainChannel(private val transport: CardTransport) : ApduChannel {
    override fun transmit(command: CommandApdu): ResponseApdu {
        val bytes = transport.transceive(command.toBytes())
        return try {
            ResponseApdu(bytes)
        } finally {
            bytes.fill(0)
        }
    }
}
