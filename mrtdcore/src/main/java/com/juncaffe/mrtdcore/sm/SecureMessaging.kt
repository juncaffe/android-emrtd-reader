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

import com.juncaffe.mrtdcore.apdu.CommandApdu
import com.juncaffe.mrtdcore.apdu.ResponseApdu
import com.juncaffe.mrtdcore.security.Wipeable

/**
 * Secure Messaging 래퍼. 평문 APDU 를 보호 APDU 로 변환하고 응답을 검증·복호한다.
 * (ICAO Doc 9303 Part 11 §9.8). 구현은 BAC=3DES, PACE/CA=AES.
 */
interface SecureMessaging : Wipeable {
    /** 평문 명령을 보호 명령으로 변환한다(SSC 증가 포함). */
    fun wrap(command: CommandApdu): CommandApdu

    /** 보호 응답의 MAC 을 검증하고 복호해 평문 응답을 돌려준다(SSC 증가 포함). */
    fun unwrap(response: ResponseApdu): ResponseApdu
}
