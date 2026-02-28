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

import android.app.Activity
import android.content.Context
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.os.Bundle
import javax.inject.Inject

class NFCManager @Inject constructor(private val context: Context) {
    private var nfcAdapter: NfcAdapter? = null
    private var currentActivity: Activity? = null
    private var readerCallback: NfcAdapter.ReaderCallback? = null
    private var readerModeRequested = false

    fun enableReaderMode(callback: NfcAdapter.ReaderCallback) {
        nfcAdapter = NfcAdapter.getDefaultAdapter(context)
        readerCallback = callback
        readerModeRequested = true
        enableReaderModeInternal()
    }

    fun disableReaderMode() {
        readerModeRequested = false
        disableReaderModeInternal()
        readerCallback = null
    }

    fun setCurrentActivity(activity: Activity) {
        currentActivity = activity
        if (readerModeRequested) enableReaderModeInternal()
    }

    fun onActivityResumed() {
        if (readerModeRequested) enableReaderModeInternal()
    }

    fun onActivityPaused() {
        disableReaderModeInternal()
    }

    /**
     * eMRTD 전용 reader mode 를 켠다.
     *
     * - [NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK]: 태그 발견 직후 플랫폼이 NDEF 를 탐침하지 않게 해
     *   칩이 곧바로 BAC/PACE 명령을 받을 수 있는 상태로 둔다(구형 칩의 초기 불안정 회피).
     * - [NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY]: 응답이 느린 구형 칩은 EXTERNAL AUTHENTICATE 등의
     *   3DES 연산에 ~1초가 걸려, 짧은 주기의 presence-check 프레임이 그 사이를 끊으면 TagLost 가 된다.
     *   점검 간격을 길게 잡아 무거운 명령 도중 칩이 방해받지 않게 한다.
     */
    private fun enableReaderModeInternal() {
        val activity = currentActivity ?: return
        val callback = readerCallback ?: return
        val adapter = nfcAdapter ?: NfcAdapter.getDefaultAdapter(context).also { nfcAdapter = it } ?: return
        val extras = Bundle().apply {
            putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, PRESENCE_CHECK_DELAY_MILLIS)
        }
        adapter.enableReaderMode(
            activity,
            // IsoDep 를 지원하는 태그만 콜백으로 전달한다(다른 기술 무시).
            NfcAdapter.ReaderCallback { tag -> if (IsoDep.get(tag) != null) callback.onTagDiscovered(tag) },
            READER_FLAGS,
            extras,
        )
    }

    private fun disableReaderModeInternal() {
        val activity = currentActivity ?: return
        runCatching { nfcAdapter?.disableReaderMode(activity) }
    }

    /** 외부 호환을 위해 남겨둔다. reader mode 사용 시 NFC 인텐트는 전달되지 않아 동작하지 않는다. */
    fun handleIntent(intent: android.content.Intent?) {
        val action = intent?.action ?: return
        if (action != NfcAdapter.ACTION_TECH_DISCOVERED &&
            action != NfcAdapter.ACTION_TAG_DISCOVERED
        ) {
            return
        }
        val tag = intent.tagExtra() ?: return
        if (IsoDep.get(tag) != null) readerCallback?.onTagDiscovered(tag)
    }

    @Suppress("DEPRECATION")
    private fun android.content.Intent.tagExtra(): Tag? =
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            getParcelableExtra(NfcAdapter.EXTRA_TAG, Tag::class.java)
        } else {
            getParcelableExtra(NfcAdapter.EXTRA_TAG)
        }

    private companion object {
        const val READER_FLAGS =
            NfcAdapter.FLAG_READER_NFC_A or
                NfcAdapter.FLAG_READER_NFC_B or
                NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK

        // 구형 칩의 1초 내외 암호 연산이 끊기지 않도록 presence-check 간격을 넉넉히 잡는다.
        const val PRESENCE_CHECK_DELAY_MILLIS = 5_000
    }
}
