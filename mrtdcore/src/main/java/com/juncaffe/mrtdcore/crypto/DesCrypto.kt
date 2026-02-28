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
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac
import org.bouncycastle.crypto.paddings.ISO7816d4Padding
import org.bouncycastle.crypto.params.KeyParameter
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * BAC/3DES Secure Messaging 용 대칭 암호 연산.
 * - 3DES-CBC(NoPadding): 데이터는 호출 전 패딩되어 블록 정렬돼 있어야 한다.
 * - Retail-MAC: ISO/IEC 9797-1 MAC Algorithm 3 + DES + 패딩 방법 2(8바이트 출력).
 */
object DesCrypto {

    private const val DESEDE = "DESede"
    private const val TRANSFORM = "DESede/CBC/NoPadding"

    /** 2-key 3DES-CBC 암호화(NoPadding). [iv8] 는 8바이트, [data] 는 8의 배수. */
    fun encryptCbcNoPad(key16: ByteArray, iv8: ByteArray, data: ByteArray): ByteArray =
        cbc(Cipher.ENCRYPT_MODE, key16, iv8, data)

    /** 2-key 3DES-CBC 복호화(NoPadding). */
    fun decryptCbcNoPad(key16: ByteArray, iv8: ByteArray, data: ByteArray): ByteArray =
        cbc(Cipher.DECRYPT_MODE, key16, iv8, data)

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

    /** 16바이트 2-key 를 24바이트(Ka‖Kb‖Ka)로 확장해 CBC 연산을 수행한다. */
    private fun cbc(mode: Int, key16: ByteArray, iv8: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(mode, SecretKeySpec(expandKey(key16), DESEDE), IvParameterSpec(iv8))
        return cipher.doFinal(data)
    }

    /** 16바이트 키를 24바이트로 확장한다(이미 24바이트면 그대로). */
    private fun expandKey(key: ByteArray): ByteArray =
        if (key.size == 24) key else key + key.copyOfRange(0, 8)
}
