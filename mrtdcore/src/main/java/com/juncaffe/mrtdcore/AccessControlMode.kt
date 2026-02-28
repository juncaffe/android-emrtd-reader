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
package com.juncaffe.mrtdcore

/**
 * 여권 보안 채널 수립에 사용할 접근 제어 방식.
 *
 * - [PACE] : PACE 우선. EF.CardAccess 에 PACEInfo 가 존재하면 PACE 로 수립하고, 실패시 BAC 로 폴백한다
 * - [BAC]  : BAC 만 사용. PACE 를 시도하지 않는다.
 */
enum class AccessControlMode { PACE, BAC }
