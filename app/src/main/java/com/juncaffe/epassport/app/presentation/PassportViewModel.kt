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
package com.juncaffe.epassport.app.presentation

import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import com.juncaffe.epassport.BACKey

@HiltViewModel
class PassportViewModel @Inject constructor(
): ViewModel() {

    private var passportNo: ByteArray? = null
    private var birth: ByteArray? = null
    private var expire: ByteArray? = null

    fun submit(passportNo: ByteArray, birth: ByteArray, expire: ByteArray): String? {
        try {
            val validated = BACKey(passportNo, birth, expire)
            validated.wipe()
            wipeStoredFields()
            this.passportNo = passportNo.copyOf()
            this.birth = birth.copyOf()
            this.expire = expire.copyOf()
            passportNo.fill(0)
            birth.fill(0)
            expire.fill(0)
            return null
        }catch(e: Exception) {
            e.printStackTrace()
            return e.message
        }
    }

    /** 저장된 입력으로 태깅 세션마다 새 접근키를 생성한다. 반환값은 사용 후 소거해도 재시도에 영향이 없다. */
    fun getBACKey(): BACKey? {
        val passportNo = passportNo ?: return null
        val birth = birth ?: return null
        val expire = expire ?: return null
        return BACKey(passportNo, birth, expire)
    }

    override fun onCleared() {
        wipeStoredFields()
        super.onCleared()
    }

    private fun wipeStoredFields() {
        passportNo?.fill(0)
        birth?.fill(0)
        expire?.fill(0)
        passportNo = null
        birth = null
        expire = null
    }
}
