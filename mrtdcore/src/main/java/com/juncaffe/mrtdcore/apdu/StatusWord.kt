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
package com.juncaffe.mrtdcore.apdu

/**
 * ISO/IEC 7816-4 상태워드(SW1 SW2). [value] 는 16비트 정수(SW1<<8 | SW2).
 */
@JvmInline
value class StatusWord(val value: Int) {

    val sw1: Int get() = (value ushr 8) and 0xFF
    val sw2: Int get() = value and 0xFF
    val isSuccess: Boolean get() = value == SUCCESS

    override fun toString(): String = "SW=%04X".format(value)

    companion object {
        const val SUCCESS = 0x9000
        const val END_OF_FILE_REACHED = 0x6282
        const val SECURITY_STATUS_NOT_SATISFIED = 0x6982
        const val CONDITIONS_NOT_SATISFIED = 0x6985
        const val FILE_NOT_FOUND = 0x6A82
        const val INCORRECT_PARAMETERS_P1P2 = 0x6A86
        const val WRONG_LENGTH = 0x6700
        const val SM_DATA_OBJECTS_INCORRECT = 0x6988
    }
}
