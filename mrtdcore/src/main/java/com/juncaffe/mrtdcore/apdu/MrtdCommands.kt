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
 * eMRTD 명령 APDU 빌더 (ISO/IEC 7816-4, ICAO Doc 9303). 프로토콜·파일읽기에서 공유한다.
 */
object MrtdCommands {

    /** eMRTD 애플리케이션을 AID 로 선택한다(FCI 미반환). */
    fun selectApplet(aid: ByteArray): CommandApdu =
        CommandApdu(ApduSpec.CLA_PLAIN, ApduSpec.INS_SELECT, ApduSpec.P1_SELECT_BY_AID, ApduSpec.P2_SELECT_NO_FCI, data = aid)

    /** File ID(2바이트)로 EF 를 선택한다(FCI 미반환). */
    fun selectFile(fileId: ByteArray): CommandApdu =
        CommandApdu(ApduSpec.CLA_PLAIN, ApduSpec.INS_SELECT, ApduSpec.P1_SELECT_BY_FILE_ID, ApduSpec.P2_SELECT_NO_FCI, data = fileId)

    /** 8바이트 챌린지를 요청한다(BAC). */
    fun getChallenge(): CommandApdu =
        CommandApdu(ApduSpec.CLA_PLAIN, ApduSpec.INS_GET_CHALLENGE, 0x00, 0x00, ne = 8)

    /** 상호 인증 데이터를 전송한다(BAC, Le=40). */
    fun externalAuthenticate(data: ByteArray): CommandApdu =
        CommandApdu(
            ApduSpec.CLA_PLAIN,
            ApduSpec.INS_EXTERNAL_AUTHENTICATE,
            0x00,
            0x00,
            data = data,
            ne = data.size,
        )

    /** 현재 선택된 EF 에서 [offset] 부터 [length] 바이트를 읽는다. */
    fun readBinary(offset: Int, length: Int): CommandApdu =
        CommandApdu(ApduSpec.CLA_PLAIN, ApduSpec.INS_READ_BINARY, (offset ushr 8) and 0x7F, offset and 0xFF, ne = length)
}
