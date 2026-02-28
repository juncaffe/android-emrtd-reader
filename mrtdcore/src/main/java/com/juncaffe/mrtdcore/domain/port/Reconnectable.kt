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
package com.juncaffe.mrtdcore.domain.port

/**
 * 카드 세션을 다시 연결할 수 있는 전송 인터페이스.
 * 느린 구형 칩에서 연결이 끊겼을 때 BAC를 처음부터 재시도하는 데 사용한다.
 */
interface Reconnectable {
    /**
     * 카드 세션을 끊고 다시 연결한다.
     * @throws com.juncaffe.mrtdcore.domain.error.MrtdException.TransportError 재연결 실패
     */
    fun reconnect()
}
