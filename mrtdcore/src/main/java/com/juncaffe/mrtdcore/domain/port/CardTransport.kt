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
package com.juncaffe.mrtdcore.domain.port

/**
 * 카드와의 원시 APDU 송수신 포트 (out-port).
 *
 * 코어는 NFC/Android 에 의존하지 않고 이 인터페이스에만 의존한다.
 * - 실 환경: `:ePassport` 의 IsoDep 기반 구현
 * - 테스트: 녹화된 APDU 시퀀스를 재생하는 구현
 *
 * 구현체는 평문(또는 이미 SM 으로 감싼) 명령 바이트를 그대로 전송하고
 * 응답 바이트를 반환한다. Secure Messaging 적용은 상위 채널의 책임이다.
 */
fun interface CardTransport {
    /**
     * @param commandApdu 전송할 명령 APDU 바이트
     * @return 응답 APDU 바이트 (최소 SW1 SW2 2바이트 포함)
     */
    fun transceive(commandApdu: ByteArray): ByteArray
}
