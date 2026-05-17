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

import org.bouncycastle.crypto.engines.DESEngine
import org.bouncycastle.crypto.engines.DESedeEngine
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.ISO7816d4Padding
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV

/**
 * BAC/3DES Secure Messaging 용 대칭 암호 연산.
 * - 3DES-CBC(NoPadding): 데이터는 호출 전 패딩되어 블록 정렬돼 있어야 한다.
 * - Retail-MAC: ISO/IEC 9797-1 MAC Algorithm 3 + DES + 패딩 방법 2(8바이트 출력).
 */
object DesCrypto {

    /** 2-key 3DES-CBC 암호화(NoPadding). [iv8] 는 8바이트, [data] 는 8의 배수. */
    fun encryptCbcNoPad(key16: ByteArray, iv8: ByteArray, data: ByteArray): ByteArray =
        cbc(true, key16, iv8, data)

    /** 2-key 3DES-CBC 복호화(NoPadding). */
    fun decryptCbcNoPad(key16: ByteArray, iv8: ByteArray, data: ByteArray): ByteArray =
        cbc(false, key16, iv8, data)

    /**
     * Retail-MAC(ISO 9797-1 Alg 3, DES, 패딩 방법 2)를 계산한다.
     * @param key16 2-key 3DES MAC 키(16바이트) @return 8바이트 MAC
     */
    fun retailMac(key16: ByteArray, data: ByteArray): ByteArray {
        val mac = ISO9797Alg3Mac(DESEngine(), 64, ISO7816d4Padding())
        mac.init(KeyParameter(key16))
        mac.update(data, 0, data.size)
        val out = ByteArray(8)
        mac.doFinal(out, 0)
        return out
    }

    /** 2-key/3-key 3DES CBC(NoPadding)를 블록 단위로 처리한다. */
    private fun cbc(encrypt: Boolean, key16: ByteArray, iv8: ByteArray, data: ByteArray): ByteArray {
        require(key16.size == 16 || key16.size == 24) { "DESede key must be 16 or 24 bytes" }
        require(iv8.size == BLOCK_SIZE) { "DESede IV must be $BLOCK_SIZE bytes" }
        require(data.size % BLOCK_SIZE == 0) { "DESede CBC input must be a multiple of $BLOCK_SIZE bytes" }
        val cipher = CBCBlockCipher.newInstance(DESedeEngine())
        return try {
            cipher.init(encrypt, ParametersWithIV(KeyParameter(key16), iv8))
            ByteArray(data.size).also { output ->
                var offset = 0
                while (offset < data.size) {
                    cipher.processBlock(data, offset, output, offset)
                    offset += BLOCK_SIZE
                }
            }
        } finally {
            cipher.reset()
        }
    }

    private const val BLOCK_SIZE = 8
}