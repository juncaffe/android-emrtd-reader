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

/**
 * APDU 전송 추상화. Secure Messaging 적용 여부를 호출자에게 숨긴다.
 * - 인증 전: [PlainChannel]
 * - 인증 후: [SecureChannel]
 */
interface ApduChannel {
    /** 명령을 전송하고 응답을 반환한다. 보안채널이면 자동으로 wrap/unwrap 한다. */
    fun transmit(command: CommandApdu): ResponseApdu
}
