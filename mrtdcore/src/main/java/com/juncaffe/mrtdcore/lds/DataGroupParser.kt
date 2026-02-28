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
package com.juncaffe.mrtdcore.lds

import com.juncaffe.mrtdcore.domain.model.DataGroupId

/**
 * 단일 데이터 그룹/파일 파서. 파일 추가 시 구현 1개 + 레지스트리 등록으로 끝난다(OCP).
 *
 * @param T 파싱 결과 타입
 */
interface DataGroupParser<out T> {
    /** 이 파서가 담당하는 파일 식별자 */
    val id: DataGroupId

    /**
     * 파일 콘텐츠(태그 포함 원본 바이트)를 파싱한다.
     * @param content SELECT/READ BINARY 로 읽은 파일 전체 바이트
     */
    fun parse(content: ByteArray): T
}
