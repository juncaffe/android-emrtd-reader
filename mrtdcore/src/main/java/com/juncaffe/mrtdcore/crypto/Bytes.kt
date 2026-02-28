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
package com.juncaffe.mrtdcore.crypto

/** 바이트 배열 연산 헬퍼. */
object Bytes {
    /**
     * 같은 길이의 두 바이트 배열을 XOR 한다.
     * @throws IllegalArgumentException 길이가 다름
     */
    fun xor(a: ByteArray, b: ByteArray): ByteArray {
        require(a.size == b.size) { "length mismatch: ${a.size} != ${b.size}" }
        return ByteArray(a.size) { (a[it].toInt() xor b[it].toInt()).toByte() }
    }
}
