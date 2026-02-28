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
 * 난수 공급 포트 (out-port).
 *
 * BAC/PACE 의 nonce·ephemeral key 생성에 사용. 테스트에서 결정적 값 주입을 위해
 * 인터페이스로 분리한다. 실 구현은 `SecureRandom` 기반(infra) 이다.
 */
fun interface RandomSource {
    /** @param length 생성할 바이트 수 @return 길이가 [length] 인 난수 바이트 */
    fun nextBytes(length: Int): ByteArray
}
