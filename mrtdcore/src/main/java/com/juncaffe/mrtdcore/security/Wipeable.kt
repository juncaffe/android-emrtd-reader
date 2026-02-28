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
package com.juncaffe.mrtdcore.security

/** 민감 데이터를 보유하는 타입. [wipe] 로 내부 버퍼를 0으로 덮어쓴다. */
interface Wipeable {
    fun wipe()
}
