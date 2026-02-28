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
package com.juncaffe.epassport.app.ui.component

import androidx.compose.animation.core.FastOutLinearInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun SmoothProgress(
    progress: Int,
    modifier: Modifier = Modifier
) {
    val animated by animateFloatAsState(
        targetValue = (progress/100f).coerceIn(0f, 1f),
        animationSpec = tween(durationMillis = 450, easing = FastOutLinearInEasing),
        label = "overall"
    )
    LinearProgressIndicator(
        progress = { animated },
        modifier = modifier.fillMaxWidth().height(8.dp)
    )
}

@Composable
fun StageProgress(
    progress: Int,
    modifier: Modifier = Modifier
) {
    val animated by animateFloatAsState(
        targetValue = (progress/100f).coerceIn(0f, 1f),
        animationSpec = tween(durationMillis = 350, easing = FastOutLinearInEasing),
        label = "stage"
    )
    LinearProgressIndicator(
        progress = { animated },
        modifier = modifier.fillMaxWidth().height(6.dp)
    )
}

@Composable
fun PulsingPlaceholderBar(
    modifier: Modifier = Modifier
) {
    val infinite = rememberInfiniteTransition(label = "pulse")
    val pulse by infinite.animateFloat(
        initialValue = 0.2f,
        targetValue = 0.8f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 800, easing = FastOutLinearInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pluseValue"
    )

    LinearProgressIndicator(
        progress = { pulse },
        modifier = modifier.fillMaxWidth().height(6.dp)
    )
}