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
 * 민감 문자열을 담는 가변 CharArray 버퍼. String 으로 변환하지 않고 문자 데이터를 다루기 위한 타입.
 * 사용 후 [wipe]/[close] 로 모든 칸을 NUL로 덮어쓴다.
 */
class SecureCharArray private constructor(
    private val data: CharArray,
) : Wipeable, AutoCloseable {

    /** [size] 칸의 NUL 로 초기화된 버퍼 생성 */
    constructor(size: Int) : this(CharArray(size))

    val size: Int get() = data.size

    operator fun get(index: Int): Char = data[index]
    operator fun set(index: Int, value: Char) { data[index] = value }

    /** 외부 전달용 복사본(호출자가 사용 후 소거 책임) */
    fun copyOf(): CharArray = data.copyOf()

    override fun wipe() { data.fill(Char(0)) }
    override fun close() = wipe()

    companion object {
        /** 문자를 복사해서 보관(원본은 호출자가 별도 소거) */
        fun of(chars: CharArray): SecureCharArray = SecureCharArray(chars.copyOf())

        /** 소유권을 가져와 래핑(복사 없음 — 이후 원본 사용 금지) */
        fun wrap(chars: CharArray): SecureCharArray = SecureCharArray(chars)
    }
}
