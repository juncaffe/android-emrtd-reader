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
package com.juncaffe.epassport.app

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.navigation.compose.rememberNavController
import com.juncaffe.epassport.app.data.NFCManager
import com.juncaffe.epassport.app.ui.screen.AppNavHost
import dagger.hilt.android.AndroidEntryPoint
import java.io.ByteArrayOutputStream
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : ComponentActivity() {

    @Inject
    lateinit var nfcManager: NFCManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
//        enableEdgeToEdge()

        nfcManager.setCurrentActivity(this)
        setContent {
            val navController = rememberNavController()
            AppNavHost(navController)
        }
    }

    override fun onResume() {
        super.onResume()
        nfcManager.setCurrentActivity(this)
        nfcManager.onActivityResumed()
    }

    override fun onPause() {
        nfcManager.onActivityPaused()
        super.onPause()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        nfcManager.handleIntent(intent)
    }

//    @Composable
//    fun ScreenHost(viewModel: EPassportViewModel = hiltViewModel()) {
//        val uiState by viewModel.uiState.collectAsStateWithLifecycle()
//        SecureKeypadScreen() { passportNo, birth, expire ->  }
////        ScannerScreen(
////            uiState = uiState,
////            onStartScan = {
////                viewModel.onStart()
////            }
////        )
//    }

    /**
     * ByteArrayOutputStream 사용한 메모리 0으로 덮어쓰기 (클리어)
     */
    fun ByteArrayOutputStream.clear(fillByte: Byte = 0) {
        // 메모리 덮어쓰기 (클리어)
        val bufferField = ByteArrayOutputStream::class.java.getDeclaredField("buf")
        bufferField.isAccessible = true
        val internalBuffer = bufferField.get(this) as ByteArray
        internalBuffer.fill(fillByte)
        this.reset()
    }

//    override fun onStart() {
//        super.onStart()
//        val nfcManager = applicationContext.getSystemService(NFC_SERVICE) as NfcManager
//        nfcManager.defaultAdapter.enableReaderMode(this, readerCallback, NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B, Bundle())
//    }
//
//    override fun onStop() {
//        super.onStop()
//        val nfcManager = applicationContext.getSystemService(NFC_SERVICE) as NfcManager
//        nfcManager.defaultAdapter.disableReaderMode(this)
//    }
}
