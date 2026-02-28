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

import android.graphics.Paint
import android.widget.Toast
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ElevatedButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.navigation.NavController
import com.juncaffe.epassport.app.domain.SecureKeypadCharBuffer
import com.juncaffe.epassport.app.presentation.PassportViewModel

private enum class KeypadInputMode {
    PASSPORT_NO, BIRTH, EXPIRE
}

private val allowedPassportKeys: Set<Char> = buildSet {
    add('M')
    add('V')
    add('R')
    ('0' .. '9').forEach { add(it) }
}

private val allowedDigits: Set<Char> = ('0' .. '9').toSet()

@Composable
fun SecureKeypadScreen(
    navController: NavController,
    viewModel: PassportViewModel = hiltViewModel()
) {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current

    val passportBuf = remember { SecureKeypadCharBuffer(9) }
    val birthBuf = remember { SecureKeypadCharBuffer(6) }
    val expireBuf = remember { SecureKeypadCharBuffer(6) }

    var mode by remember { mutableStateOf(KeypadInputMode.PASSPORT_NO) }

    DisposableEffect(Unit) {
        val obs = object: DefaultLifecycleObserver {
            override fun onDestroy(owner: LifecycleOwner) {
                passportBuf.wipe()
                birthBuf.wipe()
                expireBuf.wipe()
            }
        }
        lifecycle.lifecycle.addObserver(obs)
        onDispose {
            lifecycle.lifecycle.removeObserver(obs)
            passportBuf.wipe()
            birthBuf.wipe()
            expireBuf.wipe()
        }
    }

    fun onSubmit() {
        if(passportBuf.size in 1 .. passportBuf.max && birthBuf.size == 6 && expireBuf.size == 6) {
            val passNo = passportBuf.toByteArray()
            val birth = birthBuf.toByteArray()
            val expire = expireBuf.toByteArray()

            val res = viewModel.submit(passNo, birth, expire)
            if(res == null) {
                navController.navigate("scanner") {
                    // 뒤로가기에서 제거
                    popUpTo("secure_keypad") { inclusive = true }
                }
                passportBuf.wipe()
                birthBuf.wipe()
                expireBuf.wipe()
            }else {
                Toast.makeText(context, "여권 정보가 올바르지 않습니다: $res", Toast.LENGTH_SHORT).show()
            }
        }else {
            when {
                passportBuf.size < passportBuf.max -> mode = KeypadInputMode.PASSPORT_NO
                birthBuf.size < birthBuf.max -> mode = KeypadInputMode.BIRTH
                expireBuf.size < expireBuf.max -> mode = KeypadInputMode.EXPIRE
            }
        }
    }

    fun tryAppend(c: Char) {
        when(mode) {
            KeypadInputMode.PASSPORT_NO -> {
                if(c in allowedPassportKeys) passportBuf.append(c)
            }
            KeypadInputMode.BIRTH, KeypadInputMode.EXPIRE -> {
                if(c in allowedDigits) {
                    if(mode == KeypadInputMode.BIRTH)
                        birthBuf.append(c)
                    else
                        expireBuf.append(c)
                }
            }
        }
    }

    fun backspace() {
        when(mode) {
            KeypadInputMode.PASSPORT_NO -> passportBuf.backspace()
            KeypadInputMode.BIRTH -> birthBuf.backspace()
            KeypadInputMode.EXPIRE -> expireBuf.backspace()
        }
    }

    fun clearCurrent() {
        when(mode) {
            KeypadInputMode.PASSPORT_NO -> passportBuf.wipe()
            KeypadInputMode.BIRTH -> birthBuf.wipe()
            KeypadInputMode.EXPIRE -> expireBuf.wipe()
        }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.SpaceBetween
    ) {
        Column(Modifier.fillMaxWidth()) {
            SecureFieldRow(
                title = "여권번호",
                buffer = passportBuf,
                isActive = mode == KeypadInputMode.PASSPORT_NO,
                nextFocus = {  mode = KeypadInputMode.BIRTH },
                onClick = { mode = KeypadInputMode.PASSPORT_NO },
            )
            Spacer(Modifier.height(8.dp))
            SecureFieldRow(
                title = "생년월일",
                buffer = birthBuf,
                isActive = mode == KeypadInputMode.BIRTH,
                nextFocus = { mode = KeypadInputMode.EXPIRE },
                onClick = { mode = KeypadInputMode.BIRTH }
            )
            Spacer(Modifier.height(8.dp))
            SecureFieldRow(
                title = "만료일",
                buffer = expireBuf,
                isActive = mode == KeypadInputMode.EXPIRE,
                nextFocus = {
                    onSubmit()
                },
                onClick = { mode = KeypadInputMode.EXPIRE }
            )
        }

        SecureKeypad(
            mode = mode,
            onKey = ::tryAppend,
            onBackspace = ::backspace,
            onClear = ::clearCurrent,
            onSubmit = { onSubmit() }
        )
    }
}

@Composable
private fun SecureKeypad(
    mode: KeypadInputMode,
    onKey: (Char) -> Unit,
    onBackspace: () -> Unit,
    onClear: () -> Unit,
    onSubmit: () -> Unit
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        if(mode == KeypadInputMode.PASSPORT_NO) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                listOf('M','V','R').forEach { c -> KeyButton(c.toString(), Modifier.weight(1f)) { onKey(c) } }
            }
            Spacer(Modifier.height(8.dp))
        }

        for(row in listOf(listOf('1','2','3'), listOf('4','5','6'), listOf('7','8','9'))) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                row.forEach { c -> KeyButton(c.toString(), Modifier.weight(1f)) { onKey(c) } }
            }
            Spacer(Modifier.height(8.dp))
        }

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            ActionButton("Clear", Modifier.weight(1f)) { onClear() }
            KeyButton("0", Modifier.weight(1f)) { onKey('0') }
            ActionButton("Del", Modifier.weight(1f)) { onBackspace() }
        }
        Spacer(Modifier.height(12.dp))

        Button(
            onClick = onSubmit,
            modifier = Modifier
                .fillMaxWidth()
                .height(48.dp),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text("확인")
        }
    }
}

@Composable
private fun SecureFieldRow(
    title: String,
    buffer: SecureKeypadCharBuffer,
    isActive: Boolean = false,
    nextFocus: () -> Unit,
    onClick: () -> Unit
) {
    buffer.size
    val bg = if(isActive)
        MaterialTheme.colorScheme.primary.copy(alpha = 0.08f)
    else
        MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(bg)
            .clickable { onClick() }
            .padding(12.dp)
    ) {
        Text(title, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(6.dp))
        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            repeat(buffer.max) { i ->
                CharCanvas(
                    ch = buffer.peak(i),
                    placeholder = '_',
                    active = isActive
                )
            }
        }
    }

    LaunchedEffect(buffer.size) {
        if(buffer.max == buffer.size) {
            nextFocus()
        }
    }
}

@Composable
private fun KeyButton(label: String, modifier: Modifier = Modifier ,onClick: () -> Unit) {
    Box(
        modifier = modifier
            .height(56.dp)
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .clickable{ onClick() }
    ) {
        Text(label,
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier
                .align(alignment = Alignment.Center)
        )
    }
}

@Composable
private fun ActionButton(label: String, modifier: Modifier = Modifier , onClick: () -> Unit) {
    ElevatedButton(
        onClick = onClick,
        modifier = modifier
            .height(56.dp),
        shape = RoundedCornerShape(12.dp)
    ) {
        Text(label)
    }
}

@Composable
private fun CharCanvas(
    ch: Char?,
    placeholder: Char = '_',
    fontSize: Float = 24f,
    width: Dp = 28.dp,
    height: Dp = 36.dp,
    active: Boolean = false,
    onClick: (() -> Unit)? = null
) {
    val density = LocalDensity.current
    val paint = remember {
        Paint(Paint.ANTI_ALIAS_FLAG).apply {
            color = android.graphics.Color.BLACK
            textAlign = Paint.Align.CENTER
        }
    }

    LaunchedEffect(fontSize, density) {
        paint.textSize = with(density) { fontSize.sp.toPx() }
    }

    val bg = if(active) Color(0xFFE3F2FD) else Color(0xFFF5F5F5)
    val border = if(active) Color(0xFF2196F3) else Color(0xFFBDBDBD)

    val charArray = remember { CharArray(1) }
    val displayChar = ch ?: placeholder

    Box(
        modifier = Modifier
            .size(width, height)
            .background(bg)
            .border(1.dp, border)
            .let {
                m -> if(onClick != null) m.clickable { onClick() } else m
            },
        contentAlignment = Alignment.Center
    ) {
        Canvas(Modifier.fillMaxSize()) {
            drawIntoCanvas { canvas ->
                charArray[0] = displayChar
                val x = size.width/2f
                val y = size.height/2f - (paint.descent() + paint.ascent())/2f
                canvas.nativeCanvas.drawText(charArray, 0, 1, x, y, paint)

            }
        }
    }
}