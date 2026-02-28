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

import android.nfc.Tag
import com.juncaffe.epassport.app.data.NFCRepository
import kotlinx.coroutines.flow.Flow
import javax.inject.Inject

class NFCUseCase @Inject constructor(
    private val nfcRepository: NFCRepository
) {
    suspend fun startNFCReader() {
        nfcRepository.enableReaderMode()
    }

    suspend fun stopNFCReader() {
        nfcRepository.disableReaderMode()
    }

    fun observeNFCData(): Flow<Tag> {
        return nfcRepository.observedNFCData()
    }
}