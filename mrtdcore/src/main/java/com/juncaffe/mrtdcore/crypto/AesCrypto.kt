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

import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.macs.CMac
import org.bouncycastle.crypto.params.KeyParameter
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * PACE/CA 의 AES Secure Messaging 용 대칭 암호 연산.
 * - AES-CBC(NoPadding): 데이터는 호출 전 16바이트 정렬돼 있어야 한다.
 * - AES-CMAC: 16바이트 MAC(SM 에서는 앞 8바이트 사용).
 */
object AesCrypto {

    private const val AES = "AES"

    /** AES-CBC 암호화(NoPadding). */
    fun encryptCbc(key: ByteArray, iv16: ByteArray, data: ByteArray): ByteArray =
        cbc(Cipher.ENCRYPT_MODE, key, iv16, data)

    /** AES-CBC 복호화(NoPadding). */
    fun decryptCbc(key: ByteArray, iv16: ByteArray, data: ByteArray): ByteArray =
        cbc(Cipher.DECRYPT_MODE, key, iv16, data)

    /** 단일 16바이트 블록을 AES-ECB 로 암호화한다(SM 의 IV = E(KSenc, SSC) 계산용). */
    fun encryptEcbBlock(key: ByteArray, block16: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, AES))
        return cipher.doFinal(block16)
    }

    /** AES-CMAC(16바이트). */
    fun cmac(key: ByteArray, data: ByteArray): ByteArray {
        val mac = CMac(AESEngine.newInstance())
        mac.init(KeyParameter(key))
        mac.update(data, 0, data.size)
        val out = ByteArray(mac.macSize)
        mac.doFinal(out, 0)
        return out
    }

    private fun cbc(mode: Int, key: ByteArray, iv16: ByteArray, data: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/CBC/NoPadding")
        cipher.init(mode, SecretKeySpec(key, AES), IvParameterSpec(iv16))
        return cipher.doFinal(data)
    }
}
