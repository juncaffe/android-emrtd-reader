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
import kotlinx.coroutines.flow.Flow

interface NFCRepository {
    suspend fun enableReaderMode()
    suspend fun disableReaderMode()
    fun observedNFCData(): Flow<Tag>
    fun isReaderModeEnabled(): Boolean
}