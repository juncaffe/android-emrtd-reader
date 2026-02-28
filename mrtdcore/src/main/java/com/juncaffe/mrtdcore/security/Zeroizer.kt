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
package com.juncaffe.mrtdcore.security

/**
 * 민감 버퍼를 0으로 덮어쓴다.
 */
object Zeroizer {
    /** 바이트 배열을 0 으로 덮어쓴다. */
    fun wipe(bytes: ByteArray?) { bytes?.fill(0) }

    /** 문자 배열을 NUL(code 0) 로 덮어쓴다. */
    fun wipe(chars: CharArray?) { chars?.fill(Char(0)) }

    /** 여러 [Wipeable] 을 일괄 소거한다. */
    fun wipe(vararg targets: Wipeable?) { targets.forEach { it?.wipe() } }
}
