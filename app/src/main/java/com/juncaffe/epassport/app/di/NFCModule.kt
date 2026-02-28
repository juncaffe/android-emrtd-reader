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
package com.juncaffe.epassport.app.di

import android.content.Context
import com.juncaffe.epassport.app.data.NFCManager
import com.juncaffe.epassport.app.data.NFCRepository
import com.juncaffe.epassport.app.data.NFCRepositoryImpl
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton


@Module
@InstallIn(SingletonComponent::class)
object NFCModule {

    @Provides
    @Singleton
    fun provideNFCManager(@ApplicationContext context: Context): NFCManager {
        return NFCManager(context)
    }

    @Provides
    @Singleton
    fun provideNFCRepository(nfcManager: NFCManager): NFCRepository {
        return NFCRepositoryImpl(nfcManager)
    }
}