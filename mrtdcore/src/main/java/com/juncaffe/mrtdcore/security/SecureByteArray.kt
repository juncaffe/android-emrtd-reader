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
 * 민감 바이트를 담는 가변 버퍼. 사용 후 [wipe] 또는 [close] 로 0화한다.
 * 외부로 값을 넘길 때만 [copyOf] 로 복사한다.
 *
 * `AutoCloseable` 이므로 `SecureByteArray(n).use { ... }` 로 자동 소거가 가능하다.
 */
class SecureByteArray private constructor(
    private val data: ByteArray,
) : Wipeable, AutoCloseable {

    /** [size] 바이트의 0으로 초기화된 버퍼 생성 */
    constructor(size: Int) : this(ByteArray(size))

    val size: Int get() = data.size

    operator fun get(index: Int): Byte = data[index]
    operator fun set(index: Int, value: Byte) { data[index] = value }

    /** 외부 전달용 복사본 */
    fun copyOf(): ByteArray = data.copyOf()
    fun copyOfRange(fromIndex: Int, toIndex: Int): ByteArray = data.copyOfRange(fromIndex, toIndex)

    override fun wipe() { data.fill(0) }
    override fun close() = wipe()

    companion object {
        /** 바이트를 복사해서 보관 (원본은 호출자가 별도 소거) */
        fun of(bytes: ByteArray): SecureByteArray = SecureByteArray(bytes.copyOf())

        /** 바이트 배열의 소유권을 가져와 래핑 (복사 없음 — 이후 원본 사용 금지) */
        fun wrap(bytes: ByteArray): SecureByteArray = SecureByteArray(bytes)
    }
}
