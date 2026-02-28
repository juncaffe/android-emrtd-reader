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
package com.juncaffe.epassport.api

import com.juncaffe.epassport.model.State

/** 여권 읽기 콜백. */
interface EPassportCallback {
    /** 진행 상태 변경 */
    fun onState(state: State) {}

    /** 모든 단계 완료 */
    fun onComplete() {}

    /** 오류 발생 */
    fun onError(t: Throwable) {}
}
