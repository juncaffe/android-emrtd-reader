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

package com.juncaffe.epassport.app.ui.screen

import android.graphics.BitmapFactory
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavController
import com.juncaffe.epassport.app.model.CheckStatus
import com.juncaffe.epassport.app.model.PassportCheck
import com.juncaffe.epassport.app.model.ScanStatus
import com.juncaffe.epassport.app.model.ScanUiState
import com.juncaffe.epassport.app.presentation.EPassportViewModel
import com.juncaffe.epassport.app.presentation.PassportViewModel
import com.juncaffe.epassport.app.ui.component.PulsingPlaceholderBar
import com.juncaffe.epassport.app.ui.component.SmoothProgress
import com.juncaffe.epassport.app.ui.component.StageProgress
import com.juncaffe.mrtdcore.AccessControlMode

@Composable
fun ScannerScreen(
    navController: NavController,
    sharedViewModel: PassportViewModel,
    viewModel: EPassportViewModel = hiltViewModel(),
) {
    LaunchedEffect(Unit) {
        viewModel.setBacKeyProvider { sharedViewModel.getBACKey() }
    }

    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    val scroll = rememberScrollState()

    val imageBitmap = remember(uiState.dg2ImageBytes) {
        uiState.dg2ImageBytes?.let { bytes ->
            runCatching { BitmapFactory.decodeByteArray(bytes, 0, bytes.size)?.asImageBitmap() }.getOrNull()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(scroll),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalAlignment = Alignment.Start
    ) {
        Text(
            text = "여권 스캔",
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier
                .fillMaxWidth()
                .align(Alignment.Start)
                .padding(horizontal = 16.dp, vertical = 12.dp)
        )
        PassportChecklist(
            checks = uiState.checks,
            modifier = Modifier.padding(horizontal = 16.dp),
        )
        AnimatedContent(
            targetState = uiState.status,
            transitionSpec = {(fadeIn(animationSpec = tween(200)) togetherWith fadeOut(animationSpec = tween(200)))},
            label = "status-content"
        ) { status ->
            when(status) {
                ScanStatus.Idle -> IdleContent(
                    selectedMode = uiState.accessControlMode,
                    onSelectMode = viewModel::selectAccessControlMode,
                    useChipAuthentication = uiState.useChipAuthentication,
                    onToggleChipAuthentication = viewModel::setChipAuthentication,
                    usePassiveAuthentication = uiState.usePassiveAuthentication,
                    onTogglePassiveAuthentication = viewModel::setPassiveAuthentication,
                    onStartScan = { viewModel.onStart() },
                )
                ScanStatus.Authentication -> AuthenticationContent(uiState)
                ScanStatus.Scanning -> ScanningContent(uiState)
                ScanStatus.Done -> DoneContent(
                    imageBitmap = imageBitmap,
                    mrzFetched = uiState.mrzFetched,
                    mrzText = uiState.mrzText,
                    onFetchMrz = viewModel::fetchMrz,
                    onShowMrz = viewModel::showMrz,
                    onClearMrz = viewModel::clearMrz,
                )
                ScanStatus.Error -> ErrorContent(
                    error = uiState.errorMessage ?: "알 수 없는 오류",
                    onRetag = viewModel::retryTagging,
                    onReenterPassportInfo = {
                        navController.navigate("secure_keypad") {
                            popUpTo("scanner") { inclusive = true }
                        }
                    },
                )
            }
        }
    }
}

@Composable
private fun PassportChecklist(
    checks: Map<PassportCheck, CheckStatus>,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text("여권 검증 항목", style = MaterialTheme.typography.titleMedium)
        PassportCheck.entries.forEach { check ->
            val status = checks[check] ?: CheckStatus.Pending
            val color = when (status) {
                CheckStatus.Success -> Color(0xFF2E7D32)
                CheckStatus.Failed -> MaterialTheme.colorScheme.error
                CheckStatus.InProgress -> MaterialTheme.colorScheme.primary
                CheckStatus.Skipped -> MaterialTheme.colorScheme.outline
                CheckStatus.Pending -> MaterialTheme.colorScheme.surfaceVariant
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Box(
                    modifier = Modifier
                        .size(24.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .background(color),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = when (status) {
                            CheckStatus.Success -> "✓"
                            CheckStatus.Failed -> "!"
                            CheckStatus.InProgress -> "…"
                            CheckStatus.Skipped -> "–"
                            CheckStatus.Pending -> ""
                        },
                        color = Color.White,
                        style = MaterialTheme.typography.labelLarge,
                    )
                }
                Text(check.label, modifier = Modifier.weight(1f))
                Text(
                    text = when (status) {
                        CheckStatus.Pending -> "대기"
                        CheckStatus.InProgress -> "확인 중"
                        CheckStatus.Success -> "성공"
                        CheckStatus.Failed -> "실패"
                        CheckStatus.Skipped -> "미사용"
                    },
                    color = color,
                    style = MaterialTheme.typography.labelMedium,
                )
            }
        }
    }
}

@Composable
fun IdleContent(
    selectedMode: AccessControlMode,
    onSelectMode: (AccessControlMode) -> Unit,
    useChipAuthentication: Boolean,
    onToggleChipAuthentication: (Boolean) -> Unit,
    usePassiveAuthentication: Boolean,
    onTogglePassiveAuthentication: (Boolean) -> Unit,
    onStartScan: () -> Unit,
) {
    Column(Modifier
        .fillMaxSize()
        .padding(horizontal = 16.dp)) {
        Text("대기 중입니다. 스캔을 시작해주세요.")
        Spacer(Modifier.height(12.dp))
        Text("접근 제어 방식", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(6.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AccessModeChip(
                label = "PACE 우선",
                selected = selectedMode == AccessControlMode.PACE,
                onClick = { onSelectMode(AccessControlMode.PACE) },
            )
            AccessModeChip(
                label = "BAC 전용",
                selected = selectedMode == AccessControlMode.BAC,
                onClick = { onSelectMode(AccessControlMode.BAC) },
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(
            text = when (selectedMode) {
                AccessControlMode.PACE -> "PACE 로 시도하고 실패 시 BAC 로 폴백합니다"
                AccessControlMode.BAC -> "BAC 만 사용합니다"
            },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.outline,
        )
        Spacer(Modifier.height(16.dp))
        Text("선택 검증", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(6.dp))
        AuthToggleRow(
            label = "칩 인증 (CA)",
            description = "복제 방지를 위한 칩 인증입니다.",
            checked = useChipAuthentication,
            onCheckedChange = onToggleChipAuthentication,
        )
        Spacer(Modifier.height(8.dp))
        AuthToggleRow(
            label = "패시브 인증 (PA)",
            description = "EF.SOD를 이용한 서명검증 해시 비교로 위변조를 검증합니다.",
            checked = usePassiveAuthentication,
            onCheckedChange = onTogglePassiveAuthentication,
        )
        Spacer(Modifier.height(16.dp))
        Button(onClick = onStartScan) { Text("스캔 시작") }
    }
}

@Composable
private fun AuthToggleRow(
    label: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = description,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.outline,
            )
        }
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
private fun AccessModeChip(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = { Text(label) },
    )
}


@Composable
fun AuthenticationContent(
    uiState: ScanUiState,
) {
    Column(Modifier
        .fillMaxSize()
        .padding(horizontal = 16.dp)) {
        Text("${uiState.message} 진행 중")
    }
}

@Composable
fun ScanningContent(
    uiState: ScanUiState,
) {
    Column(Modifier
        .fillMaxSize()
        .padding(horizontal = 16.dp)) {
        Text("전체 진행률: ${uiState.overallProgress}%")
        SmoothProgress(
            progress = uiState.overallProgress,
            modifier = Modifier.fillMaxWidth()
        )
        Spacer(Modifier.height(8.dp))
        if(uiState.stageProgress.isEmpty()) {
            Text("단계 준비 중...")
            PulsingPlaceholderBar()
        }else {
            uiState.stageProgress.forEach { (stage, progress) ->
                Text("$stage: $progress%")
                StageProgress(
                    progress = progress,
                    modifier = Modifier.fillMaxWidth()
                )
                Spacer(Modifier.height(8.dp))
            }
        }
    }
}

@Composable
fun DoneContent(
    imageBitmap: ImageBitmap?,
    mrzFetched: Boolean,
    mrzText: String?,
    onFetchMrz: () -> Unit,
    onShowMrz: () -> Unit,
    onClearMrz: () -> Unit,
) {
    Column(Modifier
        .fillMaxSize()
        .padding(horizontal = 16.dp)) {
        Text("스캔 완료", style = MaterialTheme.typography.titleMedium)
        LinearProgressIndicator(
            progress = { 1f },
            modifier = Modifier
                .fillMaxWidth()
                .height(8.dp)
        )
        Spacer(Modifier.height(12.dp))
        Text("MRZ (DG1)", style = MaterialTheme.typography.titleMedium)
        Spacer(Modifier.height(6.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Button(onClick = onFetchMrz, modifier = Modifier.weight(1f)) { Text("가져오기") }
            Button(
                onClick = onShowMrz,
                enabled = mrzFetched,
                modifier = Modifier.weight(1f),
            ) { Text("표시") }
            OutlinedButton(
                onClick = onClearMrz,
                enabled = mrzFetched,
                modifier = Modifier.weight(1f),
            ) { Text("클리어") }
        }
        AnimatedVisibility(
            visible = mrzText != null,
            enter = fadeIn(animationSpec = tween(200)),
            exit = fadeOut(animationSpec = tween(200)),
        ) {
            Text(
                text = mrzText ?: "",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(top = 8.dp),
            )
        }
        Spacer(Modifier.height(16.dp))
        Text("DG2 이미지")
        AnimatedVisibility(
            visible = imageBitmap != null,
            enter = fadeIn(animationSpec = tween(250)),
            exit = fadeOut(animationSpec = tween(200)),
        ) {
            imageBitmap?.let {
                Image(
                    bitmap = it,
                    contentDescription = "Face",
                    modifier = Modifier
                        .fillMaxWidth()
                        .aspectRatio(3f / 4f)
                        .clip(RoundedCornerShape(12.dp))
                        .border(1.dp, MaterialTheme.colorScheme.outline, RoundedCornerShape(12.dp)),
                    contentScale = ContentScale.Crop
                )
            }?:run {
                Text("이미지를 표시할 수 없습니다.")
            }
        }
    }
}

@Composable
fun ErrorContent(
    error: String,
    onRetag: () -> Unit,
    onReenterPassportInfo: () -> Unit,
) {
    Column(Modifier
        .fillMaxSize()
        .padding(horizontal = 16.dp)) {
        Text("오류가 발생했습니다.", color = MaterialTheme.colorScheme.error)
        Spacer(Modifier.height(4.dp))
        Text(error)
        Spacer(Modifier.height(12.dp))
        Button(
            onClick = onRetag,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("입력 정보로 여권 다시 태깅")
        }
        Spacer(Modifier.height(8.dp))
        OutlinedButton(
            onClick = onReenterPassportInfo,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text("여권 정보 다시 입력")
        }
    }
}
