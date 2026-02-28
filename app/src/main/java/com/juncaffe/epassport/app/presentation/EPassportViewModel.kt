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
package com.juncaffe.epassport.app.presentation

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.juncaffe.epassport.BACKey
import com.juncaffe.epassport.EPassportReader
import com.juncaffe.epassport.api.EPassportCallback
import com.juncaffe.epassport.model.MrzInfo
import com.juncaffe.epassport.model.State
import com.juncaffe.mrtdcore.AccessControlMode
import com.juncaffe.epassport.app.domain.NFCUseCase
import com.juncaffe.epassport.app.model.ScanStatus
import com.juncaffe.epassport.app.model.ScanUiState
import com.juncaffe.epassport.app.model.CheckStatus
import com.juncaffe.epassport.app.model.PassportCheck
import com.juncaffe.mrtdcore.domain.model.DataGroupId
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.inject.Inject

@HiltViewModel
class EPassportViewModel @Inject constructor(
    private val nfcUseCase: NFCUseCase
): ViewModel() {

    private val _uiState = MutableStateFlow(ScanUiState())
    val uiState = _uiState.asStateFlow()

    private var bacKeyProvider: (() -> BACKey?)? = null

    // 스캔 완료 후 MRZ 조회를 위해 리더를 유지한다(wipe 는 클리어/화면 이탈 시 수행).
    private var passportReader: EPassportReader? = null
    // 가져온 MRZ 의 가변 char 버퍼. 클리어 시 0 으로 소거한다.
    private var mrzInfo: MrzInfo? = null

    init {
        observeData()
    }

    fun setBacKeyProvider(provider: () -> BACKey?) {
        bacKeyProvider = provider
        _uiState.update {
            it.copy(status = ScanStatus.Idle)
        }
    }

    /** 접근 제어 방식(PACE 우선 / BAC 전용)을 선택한다. 스캔 시작 전에 호출한다. */
    fun selectAccessControlMode(mode: AccessControlMode) {
        _uiState.update { it.copy(accessControlMode = mode) }
    }

    /** Chip Authentication(복제 방지) 사용 여부를 설정한다. 스캔 시작 전에 호출한다. */
    fun setChipAuthentication(enabled: Boolean) {
        _uiState.update {
            it.copy(
                useChipAuthentication = enabled,
                checks = initialChecks(enabled, it.usePassiveAuthentication),
            )
        }
    }

    /** Passive Authentication(EF.SOD 위변조 검증) 사용 여부를 설정한다. 스캔 시작 전에 호출한다. */
    fun setPassiveAuthentication(enabled: Boolean) {
        _uiState.update {
            it.copy(
                usePassiveAuthentication = enabled,
                checks = initialChecks(it.useChipAuthentication, enabled),
            )
        }
    }

    /**
     * 토글 상태를 반영한 초기 검증 항목 맵을 만든다. 끈 항목은 [CheckStatus.Skipped] 로 둔다
     * (CA → CA 항목, PA → PA·SOD 항목). SOD 는 PA 를 위해서만 읽으므로 PA 와 함께 건너뛴다.
     */
    private fun initialChecks(
        useChipAuthentication: Boolean,
        usePassiveAuthentication: Boolean,
    ): Map<PassportCheck, CheckStatus> = PassportCheck.entries.associateWith { check ->
        when {
            check == PassportCheck.CA && !useChipAuthentication -> CheckStatus.Skipped
            (check == PassportCheck.PA || check == PassportCheck.SOD) && !usePassiveAuthentication ->
                CheckStatus.Skipped
            else -> CheckStatus.Pending
        }
    }

    fun onAuthentication(message: String) {
        _uiState.update {
            it.copy(status = ScanStatus.Authentication,
                message = message
            )
        }
    }

    private fun updateCheck(check: PassportCheck, status: CheckStatus) {
        _uiState.update { state ->
            val newChecks = state.checks + (check to status)
            state.copy(
                checks = newChecks,
                overallProgress = computeOverall(newChecks, state.stageProgress),
            )
        }
    }

    /**
     * 한 단계(DG/SOD)의 0~100% 진행률을 갱신하고 가중치 기반 전체 진행률을 다시 계산한다.
     * 전체 진행률 계산은 표시 계층의 책임이라 mrtdcore 가 아닌 ViewModel 에 둔다.
     */
    private fun setStageProgress(stage: String, percent: Int) {
        _uiState.update { state ->
            val newStages = LinkedHashMap(state.stageProgress).apply {
                this[stage] = percent.coerceIn(0, 100)
            }
            state.copy(
                status = ScanStatus.Scanning,
                stageProgress = newStages,
                overallProgress = computeOverall(state.checks, newStages),
            )
        }
    }

    /**
     * 인증 단계(PACE/BAC·CA·PA)의 마일스톤과 파일 읽기 단계(DG/SOD)의 바이트 진행률을
     * 가중 합산해 전체 진행률(0~100)을 계산한다. DG2 가 시간의 대부분을 차지하므로 가중치도 가장 크다.
     */
    private fun computeOverall(
        checks: Map<PassportCheck, CheckStatus>,
        stages: Map<String, Int>,
    ): Int {
        fun byteFrac(name: String) = (stages[name] ?: 0).coerceIn(0, 100) / 100f
        fun authFrac(check: PassportCheck) = when (checks[check]) {
            CheckStatus.Success, CheckStatus.Failed, CheckStatus.Skipped -> 1f
            CheckStatus.InProgress -> 0.5f
            else -> 0f
        }
        val access = if (checks[PassportCheck.PACE] == CheckStatus.Success ||
            checks[PassportCheck.BAC] == CheckStatus.Success
        ) 1f else 0f
        // PA 를 끄면 EF.SOD 를 읽지 않으므로 해당 가중치를 완료로 간주한다.
        val sodFrac = if (checks[PassportCheck.SOD] == CheckStatus.Skipped) 1f else byteFrac("SOD")
        val weighted =
            WEIGHT_ACCESS * access +
                WEIGHT_CA * authFrac(PassportCheck.CA) +
                WEIGHT_DG14 * byteFrac("DG14") +
                WEIGHT_DG1 * byteFrac("DG1") +
                WEIGHT_DG2 * byteFrac("DG2") +
                WEIGHT_SOD * sodFrac +
                WEIGHT_PA * authFrac(PassportCheck.PA)
        return weighted.toInt().coerceIn(0, 100)
    }

    fun onComplete(dg2Image: ByteArray?) {
        _uiState.update {
            it.copy(status = ScanStatus.Done,
                overallProgress = 100,
                dg2ImageBytes = dg2Image
            )
        }
        stop()
    }

    /** 스캔 결과의 MRZ를 소거 가능한 문자 버퍼로 가져온다. */
    fun fetchMrz() {
        mrzInfo?.clear()
        mrzInfo = passportReader?.getMrzInfo()
        _uiState.update { it.copy(mrzFetched = mrzInfo != null, mrzText = null) }
    }

    /** 보관 중인 MRZ를 화면에 표시한다. */
    fun showMrz() {
        val info = mrzInfo ?: return
        _uiState.update { it.copy(mrzText = info.toDisplayText()) }
    }

    /** MRZ 버퍼를 소거하고 표시 문자열을 비운다. */
    fun clearMrz() {
        mrzInfo?.clear()
        mrzInfo = null
        _uiState.update { it.copy(mrzFetched = false, mrzText = null) }
    }

    /** MRZ 표시 문자열을 만든다. */
    private fun MrzInfo.toDisplayText(): String = buildString {
        appendLine("성명: ${String(surname)} ${String(givenNames)}")
        appendLine("문서종류: ${String(documentCode)}")
        appendLine("문서번호: ${String(documentNumber)}")
        appendLine("국적: ${String(nationality)}")
        appendLine("발급국: ${String(issuingState)}")
        appendLine("생년월일(YYMMDD): ${String(dateOfBirth)}")
        appendLine("만료일(YYMMDD): ${String(dateOfExpiry)}")
        append("성별: $gender")
    }

    /** 보관 중인 여권 PII(리더 데이터 + MRZ 버퍼)를 모두 소거한다. */
    private fun releasePassportData() {
        mrzInfo?.clear()
        mrzInfo = null
        passportReader?.wipe()
        passportReader?.closeService()
        passportReader = null
    }

    override fun onCleared() {
        releasePassportData()
        super.onCleared()
    }

    fun onError(message: String) {
        _uiState.update {
            it.copy(status = ScanStatus.Error,
                errorMessage = message
            )
        }
        stop()
    }

    fun onStart() {
        viewModelScope.launch {
            try {
                releasePassportData()
                val prev = _uiState.value
                _uiState.value = ScanUiState(
                    status = ScanStatus.Scanning,
                    accessControlMode = prev.accessControlMode,
                    useChipAuthentication = prev.useChipAuthentication,
                    usePassiveAuthentication = prev.usePassiveAuthentication,
                    checks = initialChecks(prev.useChipAuthentication, prev.usePassiveAuthentication),
                )
                nfcUseCase.startNFCReader()
            }catch(e: Exception) {
                onError("NFC 시작 실패: ${e.message}")
            }
        }
    }

    fun retryTagging() {
        viewModelScope.launch {
            try {
                nfcUseCase.stopNFCReader()
                val prev = _uiState.value
                _uiState.value = ScanUiState(
                    status = ScanStatus.Scanning,
                    accessControlMode = prev.accessControlMode,
                    useChipAuthentication = prev.useChipAuthentication,
                    usePassiveAuthentication = prev.usePassiveAuthentication,
                    checks = initialChecks(prev.useChipAuthentication, prev.usePassiveAuthentication),
                    message = "여권을 다시 태깅해 주세요.",
                )
                nfcUseCase.startNFCReader()
            } catch (e: Exception) {
                onError("NFC 재시작 실패: ${e.message}")
            }
        }
    }

    fun stop() {
        viewModelScope.launch {
            nfcUseCase.stopNFCReader()
        }
    }

    fun observeData() {
        viewModelScope.launch {
            nfcUseCase.observeNFCData().collect { tag ->
                // withContext: 현재 읽기가 끝날 때까지 다음 태그 수집을 블록.
                // launch 대신 withContext 를 쓰지 않으면 빠른 재태깅 시 두 읽기 세션이
                // 같은 칩에 동시 접근해 SSC 가 디싱크되고 SM MAC 검증이 실패한다.
                withContext(Dispatchers.Default) {
                    try {
                        val ePassport = EPassportReader(
                            tag = tag,
                            accessControlMode = _uiState.value.accessControlMode,
                            chipAuthentication = _uiState.value.useChipAuthentication,
                            passiveAuthentication = _uiState.value.usePassiveAuthentication,
                            debug = false,
                            logger = { Log.d("mrtd", it) },
                        )
                        ePassport.setCallback(object : EPassportCallback {
                            override fun onState(state: State) {
                                when (state) {
                                    is State.EstablishingSecureChannel -> this@EPassportViewModel.onAuthentication("카드 연결")
                                    is State.AccessControlEstablished -> {
                                        val success = if (state.method == State.AccessControl.PACE) PassportCheck.PACE else PassportCheck.BAC
                                        val skipped = if (success == PassportCheck.PACE) PassportCheck.BAC else PassportCheck.PACE
                                        updateCheck(success, CheckStatus.Success)
                                        if (_uiState.value.checks[skipped] == CheckStatus.Pending) {
                                            updateCheck(skipped, CheckStatus.Skipped)
                                        }
                                    }
                                    is State.AccessControlFailed -> {
                                        val check = if (state.method == State.AccessControl.PACE) PassportCheck.PACE else PassportCheck.BAC
                                        updateCheck(check, CheckStatus.Failed)
                                    }
                                    is State.ChipAuthentication -> {
                                        updateCheck(PassportCheck.CA, CheckStatus.InProgress)
                                        this@EPassportViewModel.onAuthentication("칩 인증")
                                    }
                                    is State.ChipAuthenticationCompleted ->
                                        updateCheck(PassportCheck.CA, if (state.success) CheckStatus.Success else CheckStatus.Failed)
                                    is State.PassiveAuthentication -> {
                                        updateCheck(PassportCheck.PA, CheckStatus.InProgress)
                                        this@EPassportViewModel.onAuthentication("패시브 인증")
                                    }
                                    is State.PassiveAuthenticationCompleted ->
                                        updateCheck(PassportCheck.PA, if (state.success) CheckStatus.Success else CheckStatus.Failed)
                                    is State.Reading -> {
                                        dataGroupCheck(state.dataGroup)?.let { updateCheck(it, CheckStatus.InProgress) }
                                        setStageProgress(state.dataGroup.name, 0)
                                    }
                                    is State.ReadingProgress -> {
                                        val percent = if (state.totalBytes > 0)
                                            state.bytesRead * 100 / state.totalBytes else 0
                                        setStageProgress(state.dataGroup.name, percent)
                                    }
                                    is State.DataGroupRead -> {
                                        dataGroupCheck(state.dataGroup)?.let { updateCheck(it, CheckStatus.Success) }
                                        setStageProgress(state.dataGroup.name, 100)
                                    }
                                    State.SodRead -> {
                                        updateCheck(PassportCheck.SOD, CheckStatus.Success)
                                        setStageProgress("SOD", 100)
                                    }
                                }
                            }

                            override fun onComplete() {
                                // MRZ 를 사용자가 "가져오기" 할 수 있도록 리더(PII 데이터)를 유지한다.
                                // NFC 세션만 종료하고 wipe 는 클리어/재스캔/화면 이탈 시 수행한다.
                                passportReader = ePassport
                                this@EPassportViewModel.onComplete(ePassport.getProfileImage())
                                ePassport.wipe()
                                ePassport.closeService()
                            }

                            override fun onError(t: Throwable) {
                                t.printStackTrace()
                                onError(t.message.toString())
                                ePassport.wipe()
                                ePassport.closeService()
                            }
                        })
                        val bacKey = bacKeyProvider?.invoke()
                        if (bacKey != null) {
                            ePassport.readPassport(bacKey)
                        } else {
                            onError("BACKey가 설정되지 않았습니다.")
                            ePassport.wipe()
                            ePassport.closeService()
                        }
                    }catch (e: Exception) {
                        Log.e("EPassportViewModel", "Error processing ePassport", e)
                        onError("전자여권 처리 중 오류가 발생했습니다: ${e.message}")
                    }
                }
            }
        }
    }

    private fun dataGroupCheck(dataGroup: DataGroupId): PassportCheck? =
        when (dataGroup) {
            DataGroupId.DG1 -> PassportCheck.DG1
            DataGroupId.DG2 -> PassportCheck.DG2
            DataGroupId.DG14 -> PassportCheck.DG14
            else -> null
        }

    fun generateAESKey(alias: String, useGcm: Boolean = false) {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        val keyParamBuilder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT)
            .setBlockModes(
                if(useGcm)
                    KeyProperties.BLOCK_MODE_GCM
                else
                    KeyProperties.BLOCK_MODE_CBC
            )
            .setEncryptionPaddings(
                if(useGcm)
                    KeyProperties.ENCRYPTION_PADDING_NONE
                else
                    KeyProperties.ENCRYPTION_PADDING_PKCS7
            )
            .setKeySize(256)

        val keyGenParameterSpec = if(Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try{
                keyParamBuilder.setIsStrongBoxBacked(true)
                keyParamBuilder.build()
            }catch(e: StrongBoxUnavailableException) {
                keyParamBuilder.setIsStrongBoxBacked(false)
                keyParamBuilder.build()
            }
        }else {
            keyParamBuilder.build()
        }
        keyGenerator.init(keyGenParameterSpec)
        keyGenerator.generateKey()
    }

    fun getKeyStoreKey(alias: String): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val secretKeyEntry = keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry
        return secretKeyEntry.secretKey
    }

    private companion object {
        // 전체 진행률 가중치(합계 100). DG2 가 읽기 시간의 대부분을 차지하므로 가장 크다.
        const val WEIGHT_ACCESS = 10f   // PACE 또는 BAC
        const val WEIGHT_CA = 10f       // Chip Authentication
        const val WEIGHT_DG14 = 5f
        const val WEIGHT_DG1 = 3f
        const val WEIGHT_DG2 = 50f
        const val WEIGHT_SOD = 12f
        const val WEIGHT_PA = 10f
    }
}
