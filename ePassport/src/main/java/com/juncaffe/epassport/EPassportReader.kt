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
package com.juncaffe.epassport

import android.nfc.Tag
import com.juncaffe.epassport.api.EPassportCallback
import com.juncaffe.epassport.model.MrzInfo
import com.juncaffe.epassport.model.State
import com.juncaffe.epassport.nfc.IsoDepCardTransport
import com.juncaffe.mrtdcore.AccessControlMode
import com.juncaffe.mrtdcore.PassportReader
import com.juncaffe.mrtdcore.ReadEvent
import com.juncaffe.mrtdcore.debug.MrtdDebug
import com.juncaffe.mrtdcore.domain.model.DataGroupId
import com.juncaffe.mrtdcore.domain.model.FaceImage
import com.juncaffe.mrtdcore.domain.model.Mrz
import com.juncaffe.mrtdcore.domain.model.PassportData
import com.juncaffe.mrtdcore.security.SecureByteArray

/**
 * 여권 NFC 읽기 파사드. mrtdcore 의 [PassportReader] 를 NFC IsoDep 위에서 구동하고
 * 콜백으로 진행/결과를 전달한다.
 *
 * @param tag NFC 태그
 * @param dataGroups 읽을 데이터 그룹(기본 DG1·DG2·DG14)
 * @param accessControlMode 접근 제어 방식([AccessControlMode.PACE] 기본, [AccessControlMode.BAC] 강제 BAC)
 * @param chipAuthentication false 면 Chip Authentication(복제 방지)을 건너뛴다(기본 true).
 * @param passiveAuthentication false 면 Passive Authentication(EF.SOD 위변조 검증)을 건너뛴다(기본 true).
 * @param debug true 면 BAC/PACE/CA/PA 전 단계 검증 로그를 [logger] 로 출력한다(사용 측에서 결정).
 * @param logger 디버그 로그 출력 대상. null 이면 mrtdcore 기본(println)을 사용한다.
 *               사용 측에서 Timber/Logcat 등 원하는 로거를 주입할 수 있다.
 */
class EPassportReader(
    tag: Tag,
    private val dataGroups: List<DataGroupId> = listOf(DataGroupId.DG1, DataGroupId.DG2, DataGroupId.DG14),
    private val accessControlMode: AccessControlMode = AccessControlMode.PACE,
    private val chipAuthentication: Boolean = true,
    private val passiveAuthentication: Boolean = true,
    private val debug: Boolean = false,
    logger: ((String) -> Unit)? = null,
) {
    private val transport = IsoDepCardTransport(tag)
    private var callback: EPassportCallback? = null
    private var data: PassportData? = null

    init {
        // 로그 출력 대상을 사용 측에서 주입받는다(Android 비의존 유지, Timber 등 사용 가능).
        if (logger != null) MrtdDebug.sink = logger
    }

    /** 콜백을 등록한다. */
    fun setCallback(callback: EPassportCallback) {
        this.callback = callback
    }

    /**
     * 여권을 읽는다(blocking). 진행 상태는 콜백으로 전달되며 접근키는 사용 후 소거된다.
     */
    fun readPassport(bacKey: BACKey) {
        try {
            transport.open()
            data = PassportReader(transport, debug = debug)
                .read(
                    bacKey.accessKey,
                    dataGroups,
                    accessControlMode,
                    chipAuthentication,
                    passiveAuthentication,
                ) { event ->
                    callback?.onState(event.toState())
                }
            callback?.onComplete()
        } catch (e: Exception) {
            callback?.onError(e)
        } finally {
            bacKey.wipe()
        }
    }

    /** DG1 MRZ(없으면 null). */
    fun getMrz(): Mrz? = data?.mrz

    /**
     * 화면 표시용 MRZ 스냅샷을 만든다(없으면 null).
     *
     * mrtdcore 의 [SecureByteArray] 필드를 가변 [CharArray] 로 복사한다. 반환된 [MrzInfo] 는
     * 호출자가 사용 후 [MrzInfo.clear] 로 소거해야 한다(원본 [data] 는 그대로 유지).
     */
    fun getMrzInfo(): MrzInfo? {
        val mrz = data?.mrz ?: return null
        return MrzInfo(
            documentCode = mrz.documentCode.toMrzChars(),
            issuingState = mrz.issuingState.toMrzChars(),
            surname = mrz.surname.toMrzChars(),
            givenNames = mrz.givenNames.toMrzChars(),
            documentNumber = mrz.documentNumber.toMrzChars(),
            nationality = mrz.nationality.toMrzChars(),
            dateOfBirth = mrz.dateOfBirth.toMrzChars(),
            gender = mrz.gender.name,
            dateOfExpiry = mrz.dateOfExpiry.toMrzChars(),
        )
    }

    /** DG2 얼굴 이미지 목록. */
    fun getFaceImages(): List<FaceImage> = data?.faceImages ?: emptyList()

    /** 여권 읽기 결과. 사용 후 [PassportData.wipe] 소거해야 한다. */
    fun getPassportData(): PassportData? = data

    /** 가장 큰 얼굴 이미지의 원시 바이트(JPEG/JP2). 표시 계층에서 디코딩한다. */
    fun getProfileImage(): ByteArray? =
        data?.faceImages?.maxByOrNull { it.width * it.height }?.imageData?.copyOf()

    /** Passive Authentication 통과 여부. */
    fun isPassiveAuthenticationValid(): Boolean = data?.passiveAuthentication?.isValid == true

    /** 보관 중인 민감 데이터를 0으로 소거한다. */
    fun wipe() {
        data?.wipe()
    }

    /** NFC 세션을 종료한다. */
    fun closeService() {
        transport.close()
    }

    /**
     * MRZ 필드(ASCII 바이트, 채움문자 '<' 포함)를 표시용 [CharArray] 로 변환한다.
     * '<' → 공백, 뒤쪽 공백 제거. 중간 byte 복사본은 즉시 0 으로 소거한다.
     */
    private fun SecureByteArray.toMrzChars(): CharArray {
        val bytes = copyOf()
        val filler = '<'.code.toByte()
        var end = bytes.size
        while (end > 0 && (bytes[end - 1] == filler || bytes[end - 1].toInt() == 0)) end--
        val chars = CharArray(end) { i ->
            val c = (bytes[i].toInt() and 0xFF).toChar()
            if (c == '<') ' ' else c
        }
        bytes.fill(0)
        return chars
    }

    private fun ReadEvent.toState(): State = when (this) {
        ReadEvent.EstablishingSecureChannel -> State.EstablishingSecureChannel
        is ReadEvent.AccessControlEstablished -> State.AccessControlEstablished(
            if (method == ReadEvent.AccessControl.PACE) State.AccessControl.PACE else State.AccessControl.BAC
        )
        is ReadEvent.AccessControlFailed -> State.AccessControlFailed(
            if (method == ReadEvent.AccessControl.PACE) State.AccessControl.PACE else State.AccessControl.BAC,
            reason,
        )
        ReadEvent.ChipAuthenticating -> State.ChipAuthentication
        is ReadEvent.ChipAuthenticationCompleted -> State.ChipAuthenticationCompleted(success, reason)
        is ReadEvent.ReadingDataGroup -> State.Reading(dataGroup)
        is ReadEvent.DataGroupProgress -> State.ReadingProgress(dataGroup, bytesRead, totalBytes)
        is ReadEvent.DataGroupRead -> State.DataGroupRead(dataGroup)
        ReadEvent.SodRead -> State.SodRead
        ReadEvent.PassiveAuthenticating -> State.PassiveAuthentication
        is ReadEvent.PassiveAuthenticationCompleted -> State.PassiveAuthenticationCompleted(success, reason)
    }
}
