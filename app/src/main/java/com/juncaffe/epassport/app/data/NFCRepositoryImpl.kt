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
package com.juncaffe.epassport.app.data

import android.nfc.Tag
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import javax.inject.Inject

class NFCRepositoryImpl @Inject constructor(
    private val nfcManager: NFCManager
): NFCRepository {

    // replay=0: 신규 구독자에게 과거 태그를 재전달하지 않는다(스테일 태그 방지).
    // extraBufferCapacity=1 + DROP_OLDEST: tryEmit이 항상 성공하도록 버퍼 1슬롯을 둔다.
    // (capacity=0이면 tryEmit은 활성 구독자가 있어도 항상 false를 반환해 태그가 유실된다.)
    // 구독자가 바쁜 동안 새 태그가 오면 이전 미처리 태그를 버리고 최신 태그만 유지한다.
    private val _nfcDataFlow = MutableSharedFlow<Tag>(
        replay = 0,
        extraBufferCapacity = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST,
    )
    private var isEnabled = false

    override suspend fun enableReaderMode() {
        if(!isEnabled) {
            nfcManager.enableReaderMode { tag ->
                _nfcDataFlow.tryEmit(tag)
            }
            isEnabled = true
        }
    }

    override suspend fun disableReaderMode() {
        nfcManager.disableReaderMode()
        isEnabled = false
    }

    override fun observedNFCData(): Flow<Tag> = _nfcDataFlow.asSharedFlow()

    override fun isReaderModeEnabled(): Boolean = isEnabled
}