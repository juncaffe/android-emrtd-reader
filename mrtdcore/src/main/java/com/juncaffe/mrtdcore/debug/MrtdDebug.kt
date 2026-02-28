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
package com.juncaffe.mrtdcore.debug

/**
 * 단계별 진단 로거. [enabled] 가 true 일 때만 [sink] 로 메시지를 흘려보낸다.
 *
 * mrtdcore 는 Android 비의존이므로 기본 [sink] 는 println 이다. Android 계층(EPassportReader)에서
 * [sink] 를 Logcat 으로 교체할 수 있다. 비활성 시에는 메시지 람다를 평가하지 않아 오버헤드가 없다.
 *
 * 보안 주의: 디버그 활성 시 APDU/세션 데이터의 바이트가 노출된다. 개발자가 명시적으로 켰을 때만
 * 동작하며, 운영 빌드에서는 기본값(false)으로 비활성 상태를 유지한다. MRZ 평문/패스워드 키는 로깅하지 않는다.
 */
object MrtdDebug {

    /** true 일 때만 로그를 출력한다. 기본 false. */
    @Volatile
    @JvmStatic
    var enabled: Boolean = false

    /** 로그 출력 대상. 기본은 표준출력. Android 에서는 Logcat 으로 교체 가능. */
    @Volatile
    @JvmStatic
    var sink: (String) -> Unit = { println(it) }

    /** [tag] 분류로 메시지를 남긴다. 비활성 시 람다를 호출하지 않는다. */
    inline fun log(tag: String, message: () -> String) {
        if (enabled) sink("[mrtd:$tag] ${message()}")
    }

    /** [tag] 분류로 [label] = hex(bytes) 를 남긴다. */
    fun hex(tag: String, label: String, bytes: ByteArray?) {
        if (enabled) sink("[mrtd:$tag] $label(${bytes?.size ?: 0}) = ${toHex(bytes)}")
    }

    /** 바이트 배열을 공백 구분 16진 문자열로 변환한다(null 은 "<null>"). */
    @JvmStatic
    fun toHex(bytes: ByteArray?): String =
        bytes?.joinToString(separator = " ") { "%02X".format(it.toInt() and 0xFF) } ?: "<null>"
}
