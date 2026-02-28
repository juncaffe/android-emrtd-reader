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
package com.juncaffe.mrtdcore.io

import com.juncaffe.mrtdcore.apdu.MrtdCommands
import com.juncaffe.mrtdcore.apdu.StatusWord
import com.juncaffe.mrtdcore.channel.ApduChannel
import com.juncaffe.mrtdcore.domain.error.MrtdException

/**
 * EF(파일)를 [ApduChannel] 로 읽는다: SELECT 후 READ BINARY 를 반복해 전체 파일을 모은다.
 * 채널이 [com.juncaffe.mrtdcore.channel.SecureChannel] 이면 SM 이 투명하게 적용된다.
 *
 * 짧은 오프셋 주소(0..0x7FFF)를 사용하므로 32KB 이하 파일을 지원한다(일반 DG1/DG2/DG14 범위).
 *
 * @param maxBlockSize 한 번에 읽을 최대 바이트(SM 오버헤드를 고려한 안전값)
 */
class CardFileReader(
    private val channel: ApduChannel,
    private val maxBlockSize: Int = 0xDF,
) {

    /**
     * [fileId]로 EF 를 선택하고 전체 내용을 읽어 반환한다.
     *
     * @param onProgress 블록을 읽을 때마다 (읽은 누적 바이트, 전체 바이트)로 호출된다.
     *                   전체 바이트는 선두 BER-TLV 헤더로 계산되므로 첫 블록 직후부터 정확하다.
     *                   DG2 처럼 큰 파일의 0~100% 진행률 표시에 사용한다.
     * @throws MrtdException.TransportError SELECT/READ 실패
     */
    fun readFile(
        fileId: ByteArray,
        onProgress: ((read: Int, total: Int) -> Unit)? = null,
    ): ByteArray {
        val select = channel.transmit(MrtdCommands.selectFile(fileId))
        try {
            if (!select.isSuccess) throw MrtdException.TransportError("SELECT failed ${select.statusWord}")
        } finally {
            select.wipe()
        }

        val firstBlock = readBinary(0, maxBlockSize)
        try {
            if (firstBlock.isEmpty()) throw MrtdException.ParseError("empty file")
            val total = totalLength(firstBlock)
            val result = ByteArray(total)
            firstBlock.copyInto(result, 0, endIndex = minOf(firstBlock.size, total))
            if (total <= firstBlock.size) {
                onProgress?.invoke(total, total)
                return result
            }

            var offset = firstBlock.size
            onProgress?.invoke(offset, total)
            while (offset < total) {
                val block = readBinary(offset, minOf(maxBlockSize, total - offset))
                try {
                    if (block.isEmpty()) break
                    block.copyInto(result, offset)
                    offset += block.size
                    onProgress?.invoke(offset, total)
                } finally {
                    block.fill(0)
                }
            }
            return result
        } finally {
            firstBlock.fill(0)
        }
    }

    /** [offset]부터 [length]바이트를 읽는다. EOF 상태워드는 부분 데이터로 처리한다. */
    private fun readBinary(offset: Int, length: Int): ByteArray {
        val response = channel.transmit(MrtdCommands.readBinary(offset, length))
        return try {
            when {
                response.isSuccess -> response.data
                response.sw == EOF_NO_INFO || response.sw == StatusWord.END_OF_FILE_REACHED -> response.data
                else -> throw MrtdException.TransportError("READ BINARY failed ${response.statusWord}")
            }
        } finally {
            response.wipe()
        }
    }

    /** 파일 선두의 BER-TLV 헤더(태그+길이)로 전체 파일 길이를 계산한다. */
    private fun totalLength(prefix: ByteArray): Int {
        var i = if ((prefix[0].toInt() and 0x1F) == 0x1F) {
            var j = 1
            while ((prefix[j].toInt() and 0x80) != 0) j++
            j + 1
        } else {
            1
        }
        val first = prefix[i].toInt() and 0xFF
        i++
        val valueLength = if (first < 0x80) {
            first
        } else {
            var len = 0
            repeat(first and 0x7F) { len = (len shl 8) or (prefix[i++].toInt() and 0xFF) }
            len
        }
        return i + valueLength
    }

    private companion object {
        const val EOF_NO_INFO = 0x6B00
    }
}
