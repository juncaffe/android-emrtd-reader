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

import com.juncaffe.mrtdcore.apdu.ApduSpec
import com.juncaffe.mrtdcore.apdu.MrtdCommands
import com.juncaffe.mrtdcore.apdu.ResponseApdu
import com.juncaffe.mrtdcore.auth.bac.BacProtocol
import com.juncaffe.mrtdcore.auth.ca.EacCaProtocol
import com.juncaffe.mrtdcore.auth.pace.PaceProtocol
import com.juncaffe.mrtdcore.channel.ApduChannel
import com.juncaffe.mrtdcore.channel.PlainChannel
import com.juncaffe.mrtdcore.channel.SecureChannel
import com.juncaffe.mrtdcore.debug.MrtdDebug
import com.juncaffe.mrtdcore.domain.error.MrtdException
import com.juncaffe.mrtdcore.domain.model.AccessKey
import com.juncaffe.mrtdcore.domain.model.ChipAuthInfo
import com.juncaffe.mrtdcore.domain.model.ChipAuthPublicKeyInfo
import com.juncaffe.mrtdcore.domain.model.DataGroupId
import com.juncaffe.mrtdcore.domain.model.FaceImage
import com.juncaffe.mrtdcore.domain.model.Mrz
import com.juncaffe.mrtdcore.domain.model.PaResult
import com.juncaffe.mrtdcore.domain.model.PaceInfo
import com.juncaffe.mrtdcore.domain.model.PassportData
import com.juncaffe.mrtdcore.domain.model.SecurityInfo
import com.juncaffe.mrtdcore.domain.port.CardTransport
import com.juncaffe.mrtdcore.domain.port.RandomSource
import com.juncaffe.mrtdcore.domain.port.Reconnectable
import com.juncaffe.mrtdcore.io.CardFileReader
import com.juncaffe.mrtdcore.lds.cardaccess.CardAccessParser
import com.juncaffe.mrtdcore.lds.dg1.Dg1Parser
import com.juncaffe.mrtdcore.lds.dg14.Dg14Parser
import com.juncaffe.mrtdcore.lds.dg2.Dg2Parser
import com.juncaffe.mrtdcore.pa.PassiveAuthenticator
import com.juncaffe.mrtdcore.sm.SecureMessaging
import java.security.SecureRandom

/**
 * 여권 읽기 과정을 순서대로 실행한다:
 * `open → (PACE | BAC) → Chip Authentication → READ DG → Passive Authentication`.
 *
 * NFC 통신은 [CardTransport]를 통해 처리한다.
 * 세션키/접근키는 사용 후 0으로 소거한다.
 */
class PassportReader(
    private val transport: CardTransport,
    private val random: SecureRandom = SecureRandom(),
    private val debug: Boolean = false,
) {

    /**
     * 여권을 읽어 [PassportData] 를 반환한다.
     * @param accessKey MRZ 기반 접근키 @param dataGroups 읽을 데이터 그룹(기본 DG1·DG2)
     * @param accessControlMode 접근 제어 방식([AccessControlMode.PACE] 기본, [AccessControlMode.BAC] 강제 BAC)
     * @param chipAuthentication false 면 Chip Authentication(복제 방지)을 건너뛴다(기본 true).
     * @param passiveAuthentication false 면 Passive Authentication(EF.SOD 위변조 검증)을 건너뛴다(기본 true).
     * @param onEvent 진행 단계 이벤트 콜백
     * @throws MrtdException.AccessDenied 접근 제어 실패
     */
    fun read(
        accessKey: AccessKey,
        dataGroups: List<DataGroupId> = listOf(DataGroupId.DG1, DataGroupId.DG2),
        accessControlMode: AccessControlMode = AccessControlMode.PACE,
        chipAuthentication: Boolean = true,
        passiveAuthentication: Boolean = true,
        onEvent: ((ReadEvent) -> Unit)? = null,
    ): PassportData {
        MrtdDebug.enabled = debug
        var sessionSm: SecureMessaging? = null
        var chipAuthSm: SecureMessaging? = null
        try {
            MrtdDebug.log("read") { "begin dataGroups=${dataGroups.map { it.name }}" }
            onEvent?.invoke(ReadEvent.EstablishingSecureChannel)
            val established = establishSecureChannel(accessKey, accessControlMode, onEvent)
            sessionSm = established.secureMessaging
            onEvent?.invoke(ReadEvent.AccessControlEstablished(established.method))
            var channel: ApduChannel = SecureChannel(transport, sessionSm)

            // Chip Authentication (DG14 존재 시)
            val securityInfos: List<SecurityInfo>
            val dg14Raw = runCatching {
                CardFileReader(channel).readFile(DataGroupId.DG14.fileIdBytes()) { read, total ->
                    onEvent?.invoke(ReadEvent.DataGroupProgress(DataGroupId.DG14, read, total))
                }
            }.getOrNull()
            if (!chipAuthentication) {
                // 사용 측에서 CA 를 끔. DG14 가 있으면 보안정보만 파싱하고 CA 프로토콜은 수행하지 않는다.
                MrtdDebug.log("read") { "Chip Authentication disabled by caller" }
                securityInfos = dg14Raw?.let {
                    onEvent?.invoke(ReadEvent.DataGroupRead(DataGroupId.DG14))
                    Dg14Parser.parse(it)
                } ?: emptyList()
            } else if (dg14Raw != null) {
                onEvent?.invoke(ReadEvent.DataGroupRead(DataGroupId.DG14))
                securityInfos = Dg14Parser.parse(dg14Raw)
                onEvent?.invoke(ReadEvent.ChipAuthenticating)
                // Chip Authentication 은 선택적(복제 방지)이다. 실패해도 데이터 그룹 읽기/PA 는 계속한다.
                var chipAuthFailure: String? = null
                chipAuthSm = runCatching { chipAuthenticate(channel, securityInfos) }
                    .onFailure {
                        MrtdDebug.log("read") { "Chip Authentication skipped: ${it.message}" }
                        chipAuthFailure = it.message
                    }
                    .getOrNull()
                if (chipAuthSm != null) {
                    channel = SecureChannel(transport, chipAuthSm)
                    onEvent?.invoke(ReadEvent.ChipAuthenticationCompleted(true))
                } else {
                    onEvent?.invoke(
                        ReadEvent.ChipAuthenticationCompleted(
                            false,
                            chipAuthFailure ?: "호환되는 CA 키 정보 없음",
                        )
                    )
                }
            } else {
                securityInfos = emptyList()
                onEvent?.invoke(ReadEvent.ChipAuthenticationCompleted(false, "DG14 없음"))
            }

            // 데이터 그룹 읽기
            val reader = CardFileReader(channel)
            val rawFiles = mutableMapOf<Int, ByteArray>()
            val encodedDataGroups = mutableMapOf<DataGroupId, ByteArray>()
            dg14Raw?.let {
                rawFiles[14] = it
                encodedDataGroups[DataGroupId.DG14] = it
            }
            var mrz: Mrz? = null
            var faceImages: List<FaceImage> = emptyList()
            for (dataGroup in dataGroups) {
                if (dataGroup == DataGroupId.DG14) continue // 이미 읽음
                onEvent?.invoke(ReadEvent.ReadingDataGroup(dataGroup))
                MrtdDebug.log("read") { "reading ${dataGroup.name}" }
                val bytes = reader.readFile(dataGroup.fileIdBytes()) { read, total ->
                    onEvent?.invoke(ReadEvent.DataGroupProgress(dataGroup, read, total))
                }
                MrtdDebug.log("read") { "${dataGroup.name} read ${bytes.size} bytes" }
                onEvent?.invoke(ReadEvent.DataGroupRead(dataGroup))
                dataGroup.dgNumber?.let { rawFiles[it] = bytes }
                encodedDataGroups[dataGroup] = bytes
                when (dataGroup) {
                    DataGroupId.DG1 -> mrz = Dg1Parser.parse(bytes)
                    DataGroupId.DG2 -> faceImages = Dg2Parser.parse(bytes)
                    else -> {}
                }
            }

            // Passive Authentication — 검증 실패는 PaResult(isValid=false) 로, SOD 읽기/파싱 실패는
            // PaResult.notPerformed 로 구분한다. 어느 쪽이든 여권 데이터는 반환한다(읽기를 중단하지 않음).
            // 사용 측에서 PA 를 끄면 EF.SOD 를 읽지 않고 notPerformed 로 둔다.
            val paResult = if (!passiveAuthentication) {
                MrtdDebug.log("read") { "Passive Authentication disabled by caller" }
                PaResult.notPerformed("Passive Authentication 사용 안 함")
            } else {
                onEvent?.invoke(ReadEvent.PassiveAuthenticating)
                val result = try {
                    val sod = reader.readFile(DataGroupId.SOD.fileIdBytes()) { read, total ->
                        onEvent?.invoke(ReadEvent.DataGroupProgress(DataGroupId.SOD, read, total))
                    }
                    onEvent?.invoke(ReadEvent.SodRead)
                    PassiveAuthenticator().verify(sod, rawFiles)
                } catch (e: Exception) {
                    PaResult.notPerformed(e.message ?: e.toString())
                }
                onEvent?.invoke(
                    ReadEvent.PassiveAuthenticationCompleted(
                        result.isValid,
                        result.error ?: if (result.isValid) null else "SOD 서명 또는 DG 해시 불일치",
                    )
                )
                result
            }

            return PassportData(mrz, faceImages, securityInfos, encodedDataGroups, paResult)
        } finally {
            sessionSm?.wipe()
            chipAuthSm?.wipe()
            accessKey.wipe()
        }
    }

    /**
     * 선택한 [mode] 에 따라 Secure Messaging 을 수립한다.
     * [AccessControlMode.PACE] 는 PACE 우선·실패 시 BAC 폴백, [AccessControlMode.BAC] 는 BAC 만 사용한다.
     */
    private fun establishSecureChannel(
        accessKey: AccessKey,
        mode: AccessControlMode,
        onEvent: ((ReadEvent) -> Unit)?,
    ): EstablishedChannel {
        val paceInfo = tryReadPaceInfo()
        if (mode == AccessControlMode.PACE && paceInfo?.parameterId != null) {
            try {
                return EstablishedChannel(establishViaPace(paceInfo, accessKey), ReadEvent.AccessControl.PACE)
            } catch (e: MrtdException) {
                // PACE 수립 실패(예: AES SM 6988) 시 BAC 로 폴백한다. 칩이 BAC 도 지원하면 읽기가 가능하다.
                MrtdDebug.log("read") { "PACE failed (${e.message}) — falling back to BAC" }
                onEvent?.invoke(ReadEvent.AccessControlFailed(ReadEvent.AccessControl.PACE, e.message))
            }
        }
        return EstablishedChannel(
            establishViaBac(accessKey, isLegacyPassport = paceInfo == null),
            ReadEvent.AccessControl.BAC,
        )
    }

    /** PACE 로 SM 을 수립하고 애플릿을 보안 채널로 선택한다. */
    private fun establishViaPace(paceInfo: PaceInfo, accessKey: AccessKey): SecureMessaging {
        MrtdDebug.log("read") { "access control = PACE (oid=${paceInfo.oid}, parameterId=${paceInfo.parameterId})" }
        val sm = PaceProtocol(transport, random).run(paceInfo.oid, paceInfo.parameterId!!.toInt(), accessKey.mrzInfo)
        MrtdDebug.log("read") { "PACE done — selecting applet over SM" }
        val selected = SecureChannel(transport, sm).transmit(MrtdCommands.selectApplet(ApduSpec.AID_MRTD))
        if (!selected.isSuccess) throw MrtdException.AccessDenied("select applet after PACE: ${selected.statusWord}")
        MrtdDebug.log("read") { "applet selected over SM: ${selected.statusWord}" }
        return sm
    }

    /**
     * BAC: 애플릿 선택(평문) 후 상호 인증.
     *
     * 응답이 느린 구형 칩은 EXTERNAL AUTHENTICATE 의 3DES 복호/검증 도중 NFC 컨트롤러의
     * FWT(frame waiting time)를 넘겨 일시적 TagLost([MrtdException.TransportError])를 낸다.
     * 같은 challenge 로 명령만 재전송할 수는 없으므로(재연결 시 칩 상태 초기화), 전송이
     * 재연결을 지원하면([Reconnectable]) 세션을 다시 연결해 BAC 전체를 처음부터 재시도한다.
     */
    private fun establishViaBac(
        accessKey: AccessKey,
        isLegacyPassport: Boolean,
    ): SecureMessaging {
        MrtdDebug.log("read") {
            "access control = BAC externalAuthLe=28 legacy=$isLegacyPassport"
        }
        val randomSource = RandomSource { length -> ByteArray(length).also { random.nextBytes(it) } }
        var attempt = 0
        while (true) {
            try {
                val selected = ResponseApdu(transport.transceive(MrtdCommands.selectApplet(ApduSpec.AID_MRTD).toBytes()))
                if (!selected.isSuccess) throw MrtdException.AccessDenied("select applet: ${selected.statusWord}")
                if (isLegacyPassport) {
                    // 일부 구형 ISO-DEP 칩은 앱 선택 직후 첫 BAC 명령에서 FWT(약 619ms)를 넘겨
                    // Android가 TagLostException으로 처리한다. RF 전력을 유지한 채 칩이 안정화될
                    // 시간을 준 뒤 GET CHALLENGE를 전송한다.
                    MrtdDebug.log("read") { "legacy BAC chip warm-up ${LEGACY_BAC_WARM_UP_MILLIS}ms" }
                    legacyWarmUp()
                }
                return BacProtocol(transport, randomSource).run(accessKey.mrzInfo)
            } catch (e: MrtdException.TransportError) {
                // 재연결 불가하거나 재시도 소진이면 그대로 던진다.
                if (transport !is Reconnectable || attempt >= MAX_BAC_TRANSPORT_RETRIES) throw e
                attempt++
                MrtdDebug.log("read") {
                    "BAC transport lost (${e.message}) — reconnecting, retry $attempt/$MAX_BAC_TRANSPORT_RETRIES"
                }
                transport.reconnect()
            }
        }
    }

    /** 느린 구형 칩이 안정화될 시간을 RF 전력을 유지한 채 기다린다. */
    private fun legacyWarmUp() {
        try {
            Thread.sleep(LEGACY_BAC_WARM_UP_MILLIS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw MrtdException.TransportError("legacy BAC warm-up interrupted", e)
        }
    }

    /** EF.CardAccess(평문)에서 PACEInfo 를 읽는다. 실패/부재 시 null. */
    private fun tryReadPaceInfo(): PaceInfo? = runCatching {
        val bytes = CardFileReader(PlainChannel(transport)).readFile(DataGroupId.CARD_ACCESS.fileIdBytes())
        CardAccessParser.parse(bytes).filterIsInstance<PaceInfo>().firstOrNull()
    }.getOrNull()

    /** DG14 의 CA 정보로 Chip Authentication 을 수행한다. 정보 부재 시 null. */
    private fun chipAuthenticate(channel: ApduChannel, securityInfos: List<SecurityInfo>): SecureMessaging? {
        securityInfos.forEach { info ->
            val detail = when (info) {
                is ChipAuthInfo -> "CAInfo oid=${info.oid} version=${info.version} keyId=${info.keyId}"
                is ChipAuthPublicKeyInfo -> "CAPublicKey oid=${info.oid} keyId=${info.keyId}"
                else -> "${info::class.simpleName} oid=${info.oid}"
            }
            MrtdDebug.log("CA") { "DG14 $detail" }
        }
        val selected = selectChipAuthenticationPair(securityInfos)
        if (selected == null) {
            MrtdDebug.log("CA") { "no compatible CAInfo/CAPublicKey pair" }
            return null
        }
        val (caInfo, publicKeyInfo) = selected
        MrtdDebug.log("CA") {
            "selected caOid=${caInfo.oid} version=${caInfo.version} " +
                "caKeyId=${caInfo.keyId} publicKeyOid=${publicKeyInfo.oid} publicKeyId=${publicKeyInfo.keyId}"
        }
        return EacCaProtocol(channel, random).run(caInfo, publicKeyInfo)
    }

    private data class EstablishedChannel(
        val secureMessaging: SecureMessaging,
        val method: ReadEvent.AccessControl,
    )

    private companion object {
        const val LEGACY_BAC_WARM_UP_MILLIS = 750L

        /** 느린 구형 칩의 일시적 TagLost 시 재연결 후 BAC 를 재시도하는 최대 횟수. */
        const val MAX_BAC_TRANSPORT_RETRIES = 2
    }

}

/**
 * DG14 에 CA 키가 여러 개 있을 때 같은 keyId 의 프로토콜 정보와 공개키만 짝짓는다.
 * keyId 가 생략된 단일 공개키는 기본 키로 취급한다.
 */
internal fun selectChipAuthenticationPair(
    securityInfos: List<SecurityInfo>,
): Pair<ChipAuthInfo, ChipAuthPublicKeyInfo>? {
    val caInfos = securityInfos.filterIsInstance<ChipAuthInfo>()
    val publicKeys = securityInfos.filterIsInstance<ChipAuthPublicKeyInfo>()
    for (caInfo in caInfos) {
        val publicKey = when {
            caInfo.keyId != null ->
                publicKeys.firstOrNull { it.keyId == caInfo.keyId }
                    ?: publicKeys.singleOrNull()?.takeIf { it.keyId == null }
            else -> publicKeys.firstOrNull { it.keyId == null } ?: publicKeys.singleOrNull()
        }
        if (publicKey != null) return caInfo to publicKey
    }

    // 구형 EAC 1.x DG14는 CA 공개키만 싣고 ChipAuthenticationInfo를 생략할 수 있다.
    // 이때 공개키 프로토콜(DH/ECDH)에서 legacy 3DES CA v1 OID를 추론한다.
    if (caInfos.isEmpty() && publicKeys.size == 1) {
        val publicKey = publicKeys.single()
        val inferredOid = when {
            publicKey.oid.startsWith(CA_PUBLIC_KEY_DH_OID) -> LEGACY_CA_DH_TDES_OID
            publicKey.oid.startsWith(CA_PUBLIC_KEY_ECDH_OID) -> LEGACY_CA_ECDH_TDES_OID
            else -> null
        }
        if (inferredOid != null) {
            return ChipAuthInfo(inferredOid, version = 1, keyId = publicKey.keyId) to publicKey
        }
    }
    return null
}

private const val CA_PUBLIC_KEY_DH_OID = "0.4.0.127.0.7.2.2.1.1"
private const val CA_PUBLIC_KEY_ECDH_OID = "0.4.0.127.0.7.2.2.1.2"
private const val LEGACY_CA_DH_TDES_OID = "0.4.0.127.0.7.2.2.3.1.1"
private const val LEGACY_CA_ECDH_TDES_OID = "0.4.0.127.0.7.2.2.3.2.1"
