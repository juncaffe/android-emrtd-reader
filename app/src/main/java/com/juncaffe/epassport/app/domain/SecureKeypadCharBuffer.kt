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
package com.juncaffe.epassport.app.domain

import androidx.compose.runtime.Stable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.setValue

@Stable
class SecureKeypadCharBuffer(capacity: Int) {
    private var buf = CharArray(capacity)
    private var _size by mutableIntStateOf(0)

    val size: Int get() = _size
    val max: Int = capacity

    fun append(c: Char): Boolean {
        if(size >= buf.size)
            return false
        buf[_size++] = c
        return true
    }

    fun peak(idx: Int): Char? = if(idx in 0 until size) buf[idx] else null

    fun backspace() {
        if(size > 0) {
            buf[size-1] = ' '
            _size--
        }
    }

    fun toByteArray(): ByteArray {
        val out = ByteArray(size)
        var i = 0
        while(i < size) {
            out[i] = buf[i].code.toByte()
            i++
        }
        return out
    }

    fun wipe() {
        buf.fill(' ')
        _size = 0
    }

    fun remaining() = buf.size - size
}