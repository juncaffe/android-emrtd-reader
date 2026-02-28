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

import com.juncaffe.mrtdcore.security.Zeroizer
import java.security.MessageDigest

/**
 * ICAO Doc 9303 Part 11 §9.7 키 유도 함수(3DES/SHA-1 및 AES 변형)와 BAC/PACE 패스워드 유도.
 * BAC/PACE/CA 가 공유하는 KDF 를 담당한다.
 */
object KeyDerivation {

    /** 암호화 키 유도 카운터 */
    const val MODE_ENC = 1

    /** MAC 키 유도 카운터 */
    const val MODE_MAC = 2

    /** PACE 패스워드 키 유도 카운터 */
    const val MODE_PACE = 3

    /**
     * BAC 키 시드: `SHA-1(MRZ_information)` 의 앞 16바이트. (9303 Part 11 §9.7.2)
     */
    fun bacSeed(mrzInfo: ByteArray): ByteArray = sha1(mrzInfo).copyOfRange(0, 16)

    /**
     * 3DES 2-key 키를 유도한다: `H=SHA-1(seed||counter)`, `Ka=H[0:8]`, `Kb=H[8:16]`,
     * 각 키에 DES 홀수 패리티를 적용해 `Ka||Kb`(16바이트) 반환. 임시 버퍼는 사용 직후 0화.
     *
     * @param seed 16바이트 키 시드 @param mode [MODE_ENC]/[MODE_MAC]
     */
    fun deriveTDES(seed: ByteArray, mode: Int): ByteArray {
        val d = seed + intToBytes(mode)
        val h = sha1(d)
        val ka = h.copyOfRange(0, 8)
        val kb = h.copyOfRange(8, 16)
        adjustParity(ka)
        adjustParity(kb)
        val key = ka + kb
        Zeroizer.wipe(d)
        Zeroizer.wipe(h)
        return key
    }

    /**
     * AES 키를 유도한다(9303 §9.7.1.2). AES-128=SHA-1[0:16], AES-192=SHA-256[0:24], AES-256=SHA-256[0:32].
     * 임시 버퍼는 사용 직후 0화.
     *
     * @param sharedSecret 공유 비밀(K) @param mode [MODE_ENC]/[MODE_MAC]/[MODE_PACE] @param keyBits 128/192/256
     */
    fun deriveAES(sharedSecret: ByteArray, mode: Int, keyBits: Int = 128): ByteArray {
        val d = sharedSecret + intToBytes(mode)
        val key = when (keyBits) {
            128 -> sha1(d).copyOfRange(0, 16)
            192 -> sha256(d).copyOfRange(0, 24)
            256 -> sha256(d).copyOfRange(0, 32)
            else -> throw IllegalArgumentException("unsupported AES key size: $keyBits")
        }
        Zeroizer.wipe(d)
        return key
    }

    /**
     * MRZ 기반 PACE 패스워드 키 Kπ 를 유도한다: `Kπ = KDF(SHA-1(MRZ_information), c=3)`.
     * (9303 Part 11 §9.7.3) 중간값 π 는 사용 직후 0화.
     *
     * @param mrzInfo MRZ information 바이트 @param keyBits PACE 암호 키 길이(기본 128)
     */
    fun pacePasswordKey(mrzInfo: ByteArray, keyBits: Int = 128): ByteArray {
        val pi = sha1(mrzInfo)
        val k = deriveAES(pi, MODE_PACE, keyBits)
        Zeroizer.wipe(pi)
        return k
    }

    private fun sha1(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(data)
    private fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    /** 정수를 4바이트 빅엔디언으로 변환한다(KDF 카운터). */
    private fun intToBytes(v: Int): ByteArray =
        byteArrayOf((v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte())

    /** 각 바이트의 LSB 를 조정해 DES 홀수 패리티를 적용한다(in-place). */
    private fun adjustParity(key: ByteArray) {
        for (i in key.indices) {
            val b = key[i].toInt() and 0xFF
            var ones = 0
            for (bit in 1..7) ones += (b ushr bit) and 1
            key[i] = ((b and 0xFE) or (if (ones % 2 == 0) 1 else 0)).toByte()
        }
    }
}
